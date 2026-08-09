// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.doris.httpv2.rest;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapMarker;
import org.apache.doris.massdblicense.MassDbLicenseClockRecoveryCore;
import org.apache.doris.massdblicense.MassDbLicenseCorrectionCore;
import org.apache.doris.massdblicense.MassDbLicenseEnforcementCore;
import org.apache.doris.massdblicense.MassDbLicenseException;
import org.apache.doris.massdblicense.MassDbLicenseImportCore;
import org.apache.doris.massdblicense.MassDbLicenseIngressControlCore;
import org.apache.doris.massdblicense.MassDbLicenseIngressInventory;
import org.apache.doris.massdblicense.MassDbLicenseJettyIdentityController;
import org.apache.doris.massdblicense.MassDbLicenseKeysetControlCore;
import org.apache.doris.massdblicense.MassDbLicenseLocalAudit;
import org.apache.doris.massdblicense.MassDbLicenseManagementIdentity;
import org.apache.doris.massdblicense.MassDbLicenseManager;
import org.apache.doris.massdblicense.MassDbLicenseMetrics;
import org.apache.doris.massdblicense.MassDbLicenseProtocolV1;
import org.apache.doris.massdblicense.MassDbLicenseReadApiCore;
import org.apache.doris.massdblicense.MassDbLicenseSqlBootstrapRuntime;
import org.apache.doris.massdblicense.MassDbLicenseState;
import org.apache.doris.massdblicense.MassDbLicenseUpgradeCore;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/** Component-native, mTLS-only MassDB SQL License management API. */
@RestController
@RequestMapping(path = MassDbLicenseAction.BASE_PATH, produces = "application/json")
public class MassDbLicenseAction {
    public static final String BASE_PATH = "/api/massdb/license/v1";
    private static final String CONTENT_SHA256 = "Content-SHA256";
    private static final String INTENT = "X-MassDB-License-Intent";
    private static final String IDEMPOTENCY_KEY = "Idempotency-Key";
    private static final String CORRECTION_PROPOSAL =
            "X-MassDB-License-Correction-Proposal";
    private static final String CORRECTION_EXECUTION_TOKEN =
            "X-MassDB-License-Correction-Execution-Token";
    private static final Pattern SHA256 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final int MAX_CONTROL_JSON_BYTES = 16 * 1024;
    private static final long CLOCK_CHALLENGE_TTL_SECONDS = 7L * 24 * 60 * 60;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final ObjectMapper STRICT_JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);

    private final RuntimeAccess runtime;

    public MassDbLicenseAction() {
        this(new ProductionRuntime());
    }

    public MassDbLicenseAction(RuntimeAccess runtime) {
        this.runtime = runtime;
    }

    @GetMapping("/capability")
    public Object capability(HttpServletRequest request) {
        return execute(request, Access.READ, false, principal -> {
            RuntimeComponents components = requireComponents(false);
            return response(HttpStatus.OK,
                    components.readCore.capability(components.manager.snapshot()));
        });
    }

    @GetMapping("/status")
    public Object status(HttpServletRequest request) {
        return execute(request, Access.READ, false, principal -> {
            RuntimeComponents components = requireComponents(false);
            MassDbLicenseState state = components.manager.snapshot();
            long wallClock = runtime.wallClockEpochSecond();
            return response(HttpStatus.OK, components.readCore.status(
                    state, effectiveNow(state, wallClock), wallClock));
        });
    }

    @GetMapping(path = "/metrics", produces = MediaType.TEXT_PLAIN_VALUE)
    public Object metrics(HttpServletRequest request) {
        return execute(request, Access.READ, false, principal -> {
            RuntimeComponents components = requireComponents(false);
            MassDbLicenseState state = components.manager.snapshot();
            long wallClock = runtime.wallClockEpochSecond();
            MassDbLicenseReadApiCore.Status status = components.readCore.status(
                    state, effectiveNow(state, wallClock), wallClock);
            return responseBuilder(HttpStatus.OK)
                    .contentType(MediaType.parseMediaType(
                            "text/plain; version=0.0.4; charset=utf-8"))
                    .body(MassDbLicenseMetrics.render(status, state));
        });
    }

    @GetMapping("/diagnostic-events")
    public Object diagnosticEvents(HttpServletRequest request) {
        return execute(request, Access.READ, false, principal -> {
            long afterSequence = parseNonNegativeLong(
                    request.getParameter("afterSequence"), 0,
                    "MASSDB_LICENSE_DIAGNOSTIC_PAGE_INVALID");
            int pageSize = (int) parseNonNegativeLong(
                    request.getParameter("pageSize"),
                    MassDbLicenseState.MAX_DIAGNOSTIC_EVENT_PAGE_SIZE,
                    "MASSDB_LICENSE_DIAGNOSTIC_PAGE_INVALID");
            MassDbLicenseState state = requireComponents(false).manager.snapshot();
            return response(HttpStatus.OK, state.diagnosticEventPage(
                    afterSequence, pageSize,
                    effectiveNow(state, runtime.wallClockEpochSecond())));
        });
    }

    @GetMapping("/topology/minimal")
    public Object minimalTopology(HttpServletRequest request) {
        return execute(request, Access.READ, false, principal -> {
            MassDbLicenseState state = requireComponents(false).manager.snapshot();
            long now = effectiveNow(state, runtime.wallClockEpochSecond());
            return response(HttpStatus.OK,
                    requireSqlRuntime().minimalTopology(state, now));
        });
    }

    @GetMapping("/upgrade/observe/preflight")
    public Object observeUpgradePreflight(HttpServletRequest request) {
        return execute(request, Access.ADMIN, false, principal -> response(HttpStatus.OK,
                requireSqlRuntime().observeUpgradePreflight(
                        requireComponents(false).manager.snapshot(),
                        runtime.wallClockEpochSecond())));
    }

    @PostMapping(path = "/upgrade/observe/validate", consumes = "application/json")
    public Object observeUpgradeValidate(HttpServletRequest request) {
        return execute(request, Access.ADMIN, false, principal -> {
            byte[] plan = readBody(request,
                    MassDbLicenseUpgradeCore.MAX_UPGRADE_PLAN_BYTES, "upgrade plan");
            requireContentSha256(request.getHeader(CONTENT_SHA256), plan);
            MassDbLicenseState state = requireComponents(false).manager.snapshot();
            long now = effectiveNow(state, runtime.wallClockEpochSecond());
            MassDbLicenseUpgradeCore.ValidateResult result =
                    requireUpgradeCore().validate(state, plan, now);
            return responseBuilder(HttpStatus.OK)
                    .header(HttpHeaders.ETAG, quoteEtag(result.preconditionToken))
                    .body(result);
        });
    }

    @PostMapping(path = "/upgrade/observe/apply", consumes = "application/json")
    public Object observeUpgradeApply(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal -> {
            byte[] plan = readBody(request,
                    MassDbLicenseUpgradeCore.MAX_UPGRADE_PLAN_BYTES, "upgrade plan");
            String contentSha256 = requireContentSha256(
                    request.getHeader(CONTENT_SHA256), plan);
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            RuntimeComponents components = requireComponents(false);
            MassDbLicenseState before = components.manager.snapshot();
            String rawIfMatch = request.getHeader(HttpHeaders.IF_MATCH);
            String precondition = before.isInitialized() && rawIfMatch == null
                    ? null : requireIfMatch(rawIfMatch);
            long now = effectiveNow(before, runtime.wallClockEpochSecond());
            MassDbLicenseUpgradeCore core = requireUpgradeCore();
            MassDbLicenseUpgradeCore.PreparedApply prepared = core.prepareApply(
                    before, plan, contentSha256, precondition, idempotencyKey, now);
            if (prepared.isReplay()) {
                MassDbLicenseState.OperationView replay =
                        before.findOperation(prepared.getReplayOperationId());
                if (replay == null) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED",
                            "upgrade幂等终态记录缺失");
                }
                return responseBuilder(HttpStatus.OK)
                        .header(HttpHeaders.LOCATION,
                                BASE_PATH + "/operations/" + replay.operationId)
                        .body(replay);
            }
            String operationId = UUID.randomUUID().toString();
            AtomicReference<MassDbLicenseUpgradeCore.ApplyResult> applied =
                    new AtomicReference<>();
            MassDbLicenseState persisted = components.manager.transition(state -> {
                MassDbLicenseUpgradeCore.ApplyResult result = core.commit(
                        state, prepared, idempotencyKey, operationId, now);
                applied.set(result);
                return result.state;
            });
            MassDbLicenseUpgradeCore.ApplyResult result = applied.get();
            return responseBuilder(HttpStatus.OK)
                    .header(HttpHeaders.LOCATION,
                            BASE_PATH + "/operations/" + result.operationId)
                    .body(persisted.findOperation(result.operationId));
        });
    }

    @GetMapping("/bootstrap/status")
    public Object bootstrapStatus(HttpServletRequest request) {
        return execute(request, Access.READ, false, principal -> {
            MassDbLicenseBootstrapCore core = requireBootstrapCore();
            return response(HttpStatus.OK, core.status(
                    requireComponents(false).manager.snapshot(),
                    runtime.bootstrapAttestation()));
        });
    }

    @PostMapping(path = "/bootstrap/validate", consumes = "application/json")
    public Object bootstrapValidate(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal -> {
            byte[] plan = readBody(request,
                    MassDbLicenseBootstrapCore.MAX_BOOTSTRAP_PLAN_BYTES,
                    "bootstrap plan");
            requireContentSha256(request.getHeader(CONTENT_SHA256), plan);
            MassDbLicenseState state = requireComponents(false).manager.snapshot();
            long now = effectiveNow(state, runtime.wallClockEpochSecond());
            MassDbLicenseBootstrapCore.ValidateResult result = requireBootstrapCore().validate(
                    state, plan, bootstrapWriteHealth(), now);
            return responseBuilder(HttpStatus.OK)
                    .header(HttpHeaders.ETAG, quoteEtag(result.preconditionToken))
                    .body(result);
        });
    }

    @PostMapping(path = "/bootstrap/apply", consumes = "application/json")
    public Object bootstrapApply(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal -> {
            byte[] plan = readBody(request,
                    MassDbLicenseBootstrapCore.MAX_BOOTSTRAP_PLAN_BYTES,
                    "bootstrap plan");
            String contentSha256 = requireContentSha256(
                    request.getHeader(CONTENT_SHA256), plan);
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            RuntimeComponents components = requireComponents(false);
            MassDbLicenseState before = components.manager.snapshot();
            String rawIfMatch = request.getHeader(HttpHeaders.IF_MATCH);
            String precondition = rawIfMatch == null
                    && "SEALED".equals(before.getBootstrapPhase())
                    ? null : requireIfMatch(rawIfMatch);
            long now = effectiveNow(
                    before, runtime.wallClockEpochSecond());
            String operationId = UUID.randomUUID().toString();
            AtomicReference<MassDbLicenseBootstrapCore.ApplyResult> applied =
                    new AtomicReference<>();
            MassDbLicenseState persisted = components.manager.transition(state -> {
                MassDbLicenseBootstrapCore.ApplyResult result = requireBootstrapCore().apply(
                        state, plan, contentSha256, precondition, idempotencyKey,
                        operationId, bootstrapWriteHealth(), now);
                applied.set(result);
                return result.state;
            });
            MassDbLicenseBootstrapCore.ApplyResult result = applied.get();
            return responseBuilder(HttpStatus.OK)
                    .header(HttpHeaders.LOCATION,
                            BASE_PATH + "/operations/" + result.operationId)
                    .body(persisted.findOperation(result.operationId));
        });
    }

    @PostMapping(path = "/validate", consumes = "application/octet-stream")
    public Object validate(HttpServletRequest request) {
        return execute(request, Access.READ, false, principal -> {
            MassDbLicenseState.ImportIntent intent = requireIntent(request);
            byte[] artifact = readArtifact(request);
            requireContentSha256(request.getHeader(CONTENT_SHA256), artifact);
            RuntimeComponents components = requireComponents(false);
            MassDbLicenseState state = components.manager.snapshot();
            long effectiveNow = effectiveNow(state, runtime.wallClockEpochSecond());
            Object result;
            if (intent == MassDbLicenseState.ImportIntent.NORMAL) {
                result = components.readCore.validateNormal(state, artifact, effectiveNow);
            } else if (intent == MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER) {
                result = requireCorrectionCore().validateCorrection(
                        state, artifact, effectiveNow);
            } else {
                result = requireCorrectionCore().validateKeyRotation(
                        state, artifact, effectiveNow);
            }
            ResponseEntity.BodyBuilder builder = responseBuilder(HttpStatus.OK);
            String token = validationToken(result);
            if (token != null) {
                builder.header(HttpHeaders.ETAG, quoteEtag(token));
            }
            return builder.body(result);
        });
    }

    @PostMapping(path = "/import", consumes = "application/octet-stream")
    public Object importLicense(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal -> {
            MassDbLicenseState.ImportIntent intent = requireIntent(request);
            byte[] artifact = readArtifact(request);
            String contentSha256 = requireContentSha256(
                    request.getHeader(CONTENT_SHA256), artifact);
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            String proposalId = null;
            String precondition;
            if (intent == MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER) {
                if (request.getHeader(HttpHeaders.IF_MATCH) != null) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_PRECONDITION_FAILED",
                            "到期更正只能使用专用proposal和execution token，不得携带If-Match");
                }
                proposalId = requireHeader(request, CORRECTION_PROPOSAL);
                precondition = requireHeader(request, CORRECTION_EXECUTION_TOKEN);
            } else {
                precondition = requireIfMatch(request.getHeader(HttpHeaders.IF_MATCH));
            }
            RuntimeComponents components = requireComponents(true);
            long effectiveNow = effectiveNow(
                    components.manager.snapshot(), runtime.wallClockEpochSecond());
            String operationId = UUID.randomUUID().toString();
            long deadlineAt = saturatedAdd(
                    effectiveNow, runtime.operationAckDeadlineSeconds());
            AtomicReference<OperationResult> prepared = new AtomicReference<>();
            final String frozenProposalId = proposalId;
            MassDbLicenseState persisted = components.manager.transition(state -> {
                if (intent == MassDbLicenseState.ImportIntent.NORMAL) {
                    MassDbLicenseImportCore.Result result = components.importCore.prepareNormal(
                            state, artifact, contentSha256, precondition, idempotencyKey,
                            operationId, principal.spiffeId, effectiveNow, deadlineAt);
                    prepared.set(new OperationResult(result.operationId,
                            result.replayed, result.terminal));
                    return result.state;
                }
                MassDbLicenseState.CorrectionProposal proposal = frozenProposalId == null
                        ? null : state.findCorrectionProposal(frozenProposalId, effectiveNow);
                String approver = proposal == null ? "" : proposal.getApprover();
                MassDbLicenseCorrectionCore.Result result = requireCorrectionCore().prepare(
                        state, artifact, contentSha256, precondition, idempotencyKey,
                        operationId, intent, principal.spiffeId, approver,
                        frozenProposalId, effectiveNow, deadlineAt);
                prepared.set(new OperationResult(result.operationId,
                        result.replayed, result.terminal));
                return result.state;
            });
            OperationResult result = prepared.get();
            MassDbLicenseState.OperationView operation =
                    persisted.findOperation(result.operationId);
            HttpStatus status = result.terminal || result.replayed
                    ? HttpStatus.OK : HttpStatus.ACCEPTED;
            return responseBuilder(status)
                    .header(HttpHeaders.LOCATION,
                            BASE_PATH + "/operations/" + result.operationId)
                    .body(operation);
        });
    }

    @PostMapping(path = "/corrections/proposals", consumes = "application/octet-stream")
    public Object createCorrectionProposal(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal -> {
            byte[] artifact = readArtifact(request);
            requireContentSha256(request.getHeader(CONTENT_SHA256), artifact);
            String validationToken = requireIfMatch(
                    request.getHeader(HttpHeaders.IF_MATCH));
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            RuntimeComponents components = requireComponents(true);
            long now = effectiveNow(components.manager.snapshot(),
                    runtime.wallClockEpochSecond());
            AtomicReference<MassDbLicenseCorrectionCore.ProposalResult> created =
                    new AtomicReference<>();
            components.manager.transition(state -> {
                MassDbLicenseCorrectionCore.ProposalResult result =
                        requireCorrectionCore().createProposal(state, artifact,
                                validationToken, principal.spiffeId,
                                UUID.randomUUID().toString(), idempotencyKey, now);
                created.set(result);
                return result.state;
            });
            return response(HttpStatus.OK, created.get().proposal);
        });
    }

    @PostMapping("/corrections/{proposalId}/approve")
    public Object approveCorrectionProposal(HttpServletRequest request,
            @PathVariable("proposalId") String proposalId) {
        return execute(request, Access.CORRECTION, true, principal -> {
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            RuntimeComponents components = requireComponents(true);
            long now = effectiveNow(components.manager.snapshot(),
                    runtime.wallClockEpochSecond());
            AtomicReference<MassDbLicenseCorrectionCore.ProposalResult> approved =
                    new AtomicReference<>();
            components.manager.transition(state -> {
                MassDbLicenseCorrectionCore.ProposalResult result =
                        requireCorrectionCore().approve(state, proposalId,
                                principal.spiffeId, idempotencyKey, now);
                approved.set(result);
                return result.state;
            });
            return response(HttpStatus.OK, approved.get().proposal);
        });
    }

    @PostMapping(path = "/corrections/{proposalId}/prepare-import",
            consumes = "application/octet-stream")
    public Object prepareCorrectionImport(HttpServletRequest request,
            @PathVariable("proposalId") String proposalId) {
        return execute(request, Access.ADMIN, false, principal -> {
            byte[] artifact = readArtifact(request);
            requireContentSha256(request.getHeader(CONTENT_SHA256), artifact);
            MassDbLicenseState state = requireComponents(true).manager.snapshot();
            long now = effectiveNow(state, runtime.wallClockEpochSecond());
            MassDbLicenseCorrectionCore.ValidateResult result =
                    requireCorrectionCore().prepareImport(state, proposalId,
                            artifact, principal.spiffeId, now);
            return responseBuilder(HttpStatus.OK)
                    .header(CORRECTION_EXECUTION_TOKEN, result.preconditionToken)
                    .body(result);
        });
    }

    @PostMapping("/corrections/{proposalId}/cancel")
    public Object cancelCorrectionProposal(HttpServletRequest request,
            @PathVariable("proposalId") String proposalId) {
        return execute(request, Access.ADMIN, true, principal -> {
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            RuntimeComponents components = requireComponents(true);
            long now = effectiveNow(components.manager.snapshot(),
                    runtime.wallClockEpochSecond());
            AtomicReference<MassDbLicenseCorrectionCore.ProposalResult> cancelled =
                    new AtomicReference<>();
            components.manager.transition(state -> {
                MassDbLicenseCorrectionCore.ProposalResult result =
                        requireCorrectionCore().cancel(
                                state, proposalId, idempotencyKey, now);
                cancelled.set(result);
                return result.state;
            });
            return response(HttpStatus.OK, cancelled.get().proposal);
        });
    }

    @GetMapping("/ingress")
    public Object ingress(HttpServletRequest request) {
        return execute(request, Access.READ, false, principal -> {
            MassDbLicenseState state = requireComponents(false).manager.snapshot();
            long now = effectiveNow(state, runtime.wallClockEpochSecond());
            return response(HttpStatus.OK, requireIngressCore().view(state, now));
        });
    }

    @PostMapping(path = "/ingress/validate", consumes = "application/json")
    public Object validateIngress(HttpServletRequest request) {
        return execute(request, Access.ADMIN, false, principal -> {
            MassDbLicenseIngressControlCore.ChangeRequest body = parseJson(request,
                    MassDbLicenseIngressControlCore.ChangeRequest.class);
            MassDbLicenseState state = requireComponents(false).manager.snapshot();
            long now = effectiveNow(state, runtime.wallClockEpochSecond());
            MassDbLicenseIngressControlCore.ValidateResult result =
                    requireIngressCore().validate(state, body, now);
            return responseBuilder(HttpStatus.OK)
                    .header(HttpHeaders.ETAG, quoteEtag(result.preconditionToken))
                    .body(result);
        });
    }

    @PostMapping(path = "/ingress/apply", consumes = "application/json")
    public Object applyIngress(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal -> {
            MassDbLicenseIngressControlCore.ChangeRequest body = parseJson(request,
                    MassDbLicenseIngressControlCore.ChangeRequest.class);
            String precondition = requireIfMatch(request.getHeader(HttpHeaders.IF_MATCH));
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            RuntimeComponents components = requireComponents(false);
            long now = effectiveNow(components.manager.snapshot(),
                    runtime.wallClockEpochSecond());
            String operationId = UUID.randomUUID().toString();
            long deadlineAt = saturatedAdd(now, runtime.operationAckDeadlineSeconds());
            AtomicReference<MassDbLicenseIngressControlCore.Result> applied =
                    new AtomicReference<>();
            MassDbLicenseState persisted = components.manager.transition(state -> {
                MassDbLicenseIngressControlCore.Result result = requireIngressCore().apply(
                        state, body, precondition, idempotencyKey, operationId,
                        now, deadlineAt);
                applied.set(result);
                return result.state;
            });
            return operationResponse(persisted, applied.get().operationId,
                    applied.get().replayed, applied.get().terminal);
        });
    }

    @PostMapping(path = "/ingress/routing-evidence/observe", consumes = "application/json")
    public Object observeRoutingEvidence(HttpServletRequest request) {
        return execute(request, Access.ROUTING_ADAPTER, true, principal -> {
            MassDbLicenseIngressControlCore.RoutingEvidenceRequest body = parseJson(request,
                    MassDbLicenseIngressControlCore.RoutingEvidenceRequest.class);
            RuntimeComponents components = requireComponents(false);
            long now = effectiveNow(components.manager.snapshot(),
                    runtime.wallClockEpochSecond());
            MassDbLicenseState persisted = components.manager.transition(state ->
                    requireIngressCore().observeMachine(
                            state, body, principal.routingAdapterType, now));
            return response(HttpStatus.OK, requireIngressCore().view(persisted, now));
        });
    }

    @PostMapping("/enforcement/validate")
    public Object validateEnforcement(HttpServletRequest request) {
        return execute(request, Access.ADMIN, false, principal -> {
            MassDbLicenseState state = requireComponents(false).manager.snapshot();
            long now = effectiveNow(state, runtime.wallClockEpochSecond());
            MassDbLicenseEnforcementCore.ValidateResult result =
                    requireEnforcementCore().validate(state, now);
            return responseBuilder(HttpStatus.OK)
                    .header(HttpHeaders.ETAG, quoteEtag(result.preconditionToken))
                    .body(result);
        });
    }

    @PostMapping("/enforcement/activate")
    public Object activateEnforcement(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal -> {
            String precondition = requireIfMatch(request.getHeader(HttpHeaders.IF_MATCH));
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            RuntimeComponents components = requireComponents(false);
            long now = effectiveNow(components.manager.snapshot(),
                    runtime.wallClockEpochSecond());
            String operationId = UUID.randomUUID().toString();
            long deadlineAt = saturatedAdd(now, runtime.operationAckDeadlineSeconds());
            AtomicReference<MassDbLicenseEnforcementCore.PrepareResult> prepared =
                    new AtomicReference<>();
            MassDbLicenseState persisted = components.manager.transition(state -> {
                MassDbLicenseEnforcementCore.PrepareResult result =
                        requireEnforcementCore().prepare(state, precondition,
                                idempotencyKey, operationId, now, deadlineAt);
                prepared.set(result);
                return result.state;
            });
            return operationResponse(persisted, prepared.get().operationId,
                    prepared.get().replayed, prepared.get().terminal);
        });
    }

    @PostMapping("/clock-recovery/challenge")
    public Object createClockChallenge(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal -> {
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            String requestHash = sha256("CLOCK_RECOVERY_CHALLENGE_CREATE"
                    .getBytes(StandardCharsets.US_ASCII));
            RuntimeComponents components = requireComponents(false);
            long now = effectiveNow(components.manager.snapshot(),
                    runtime.wallClockEpochSecond());
            String operationId = UUID.randomUUID().toString();
            String challengeId = UUID.randomUUID().toString();
            byte[] challenge = new byte[32];
            SECURE_RANDOM.nextBytes(challenge);
            String challengeHex = hex(challenge);
            long expiresAt = saturatedAdd(now, CLOCK_CHALLENGE_TTL_SECONDS);
            MassDbLicenseState persisted = components.manager.transition(state ->
                    state.createClockChallengeOperation(operationId, idempotencyKey,
                            requestHash, challengeId, challengeHex, now, expiresAt));
            MassDbLicenseState.OperationView operation =
                    persisted.findOperationByIdempotencyKey(idempotencyKey);
            return response(HttpStatus.OK,
                    new ClockChallengeResult(operation, persisted.getClockChallenge()));
        });
    }

    @PostMapping("/clock-recovery/challenge/{challengeId}/cancel")
    public Object cancelClockChallenge(HttpServletRequest request,
            @PathVariable("challengeId") String challengeId) {
        return execute(request, Access.ADMIN, true, principal -> {
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            String requestHash = sha256(("CLOCK_RECOVERY_CHALLENGE_CANCEL\n" + challengeId)
                    .getBytes(StandardCharsets.UTF_8));
            RuntimeComponents components = requireComponents(false);
            long now = effectiveNow(components.manager.snapshot(),
                    runtime.wallClockEpochSecond());
            String operationId = UUID.randomUUID().toString();
            MassDbLicenseState persisted = components.manager.transition(state ->
                    state.cancelClockChallengeOperation(operationId, idempotencyKey,
                            requestHash, challengeId, now));
            MassDbLicenseState.OperationView operation =
                    persisted.findOperationByIdempotencyKey(idempotencyKey);
            return response(HttpStatus.OK,
                    new ClockChallengeResult(operation, persisted.getClockChallenge()));
        });
    }

    @PostMapping(path = "/clock-recovery/validate", consumes = "application/octet-stream")
    public Object validateClockRecovery(HttpServletRequest request) {
        return execute(request, Access.ADMIN, false, principal -> {
            byte[] artifact = readArtifact(request);
            requireContentSha256(request.getHeader(CONTENT_SHA256), artifact);
            MassDbLicenseState state = requireComponents(true).manager.snapshot();
            MassDbLicenseClockRecoveryCore.ValidateResult result =
                    requireClockRecoveryCore().validate(
                            state, artifact, runtime.wallClockEpochSecond());
            return responseBuilder(HttpStatus.OK)
                    .header(HttpHeaders.ETAG, quoteEtag(result.preconditionToken))
                    .body(result);
        });
    }

    @PostMapping(path = "/clock-recovery/import", consumes = "application/octet-stream")
    public Object importClockRecovery(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal -> {
            byte[] artifact = readArtifact(request);
            String contentSha256 = requireContentSha256(
                    request.getHeader(CONTENT_SHA256), artifact);
            String precondition = requireIfMatch(request.getHeader(HttpHeaders.IF_MATCH));
            String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
            RuntimeComponents components = requireComponents(true);
            long now = runtime.wallClockEpochSecond();
            String operationId = UUID.randomUUID().toString();
            long deadlineAt = saturatedAdd(now, runtime.operationAckDeadlineSeconds());
            AtomicReference<MassDbLicenseClockRecoveryCore.Result> prepared =
                    new AtomicReference<>();
            MassDbLicenseState persisted = components.manager.transition(state -> {
                MassDbLicenseClockRecoveryCore.Result result =
                        requireClockRecoveryCore().prepare(state, artifact,
                                contentSha256, precondition, idempotencyKey,
                                operationId, now, deadlineAt);
                prepared.set(result);
                return result.state;
            });
            return operationResponse(persisted, prepared.get().operationId,
                    prepared.get().replayed, prepared.get().terminal);
        });
    }

    @GetMapping("/keyset/status")
    public Object keysetStatus(HttpServletRequest request) {
        return execute(request, Access.READ, false, principal -> {
            MassDbLicenseState state = requireComponents(true).manager.snapshot();
            long now = effectiveNow(state, runtime.wallClockEpochSecond());
            return response(HttpStatus.OK, requireKeysetCore().status(state, now));
        });
    }

    @PostMapping(path = "/keyset/validate", consumes = "application/octet-stream")
    public Object validateKeyset(HttpServletRequest request) {
        return execute(request, Access.ADMIN, false, principal ->
                validateKeysetArtifact(request, false));
    }

    @PostMapping(path = "/keyset/recovery-bundle/validate",
            consumes = "application/octet-stream")
    public Object validateKeysetRecoveryBundle(HttpServletRequest request) {
        return execute(request, Access.ADMIN, false, principal ->
                validateKeysetArtifact(request, true));
    }

    @PostMapping(path = "/keyset/import", consumes = "application/octet-stream")
    public Object importKeyset(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal ->
                importKeysetArtifact(request, false));
    }

    @PostMapping(path = "/keyset/recovery-bundle/import",
            consumes = "application/octet-stream")
    public Object importKeysetRecoveryBundle(HttpServletRequest request) {
        return execute(request, Access.ADMIN, true, principal ->
                importKeysetArtifact(request, true));
    }

    @GetMapping("/operations/{operationId}")
    public Object operation(HttpServletRequest request,
            @PathVariable("operationId") String operationId) {
        return execute(request, Access.READ, false, principal -> {
            MassDbLicenseState.OperationView operation = requireComponents(false)
                    .manager.snapshot().findOperation(operationId);
            return operation == null
                    ? error(HttpStatus.NOT_FOUND, "MASSDB_LICENSE_OPERATION_NOT_FOUND",
                            "没有匹配的operation")
                    : response(HttpStatus.OK, operation);
        });
    }

    @GetMapping("/operations/by-idempotency-key/{idempotencyKey}")
    public Object operationByIdempotencyKey(HttpServletRequest request,
            @PathVariable("idempotencyKey") String idempotencyKey) {
        return execute(request, Access.READ, false, principal -> {
            MassDbLicenseState.OperationView operation = requireComponents(false)
                    .manager.snapshot().findOperationByIdempotencyKey(idempotencyKey);
            return operation == null
                    ? error(HttpStatus.NOT_FOUND, "MASSDB_LICENSE_OPERATION_NOT_FOUND",
                            "没有匹配的operation")
                    : response(HttpStatus.OK, operation);
        });
    }

    @PostMapping("/operations/{operationId}/abort")
    public Object abort(HttpServletRequest request,
            @PathVariable("operationId") String operationId) {
        return execute(request, Access.ADMIN, true, principal -> {
            RuntimeComponents components = requireComponents(false);
            long now = effectiveNow(
                    components.manager.snapshot(), runtime.wallClockEpochSecond());
            MassDbLicenseState state = components.manager.transition(
                    current -> current.abort(operationId, now));
            return response(HttpStatus.OK, state.findOperation(operationId));
        });
    }

    private Object execute(HttpServletRequest request, Access access, boolean write,
            AuthorizedCall call) {
        if (!runtime.enabled()) {
            return error(HttpStatus.NOT_FOUND,
                    "MASSDB_LICENSE_MANAGEMENT_API_DISABLED",
                    "MassDB License组件原生管理API未启用");
        }
        MassDbLicenseManagementIdentity.Principal principal;
        try {
            principal = authorize(request, access);
        } catch (MassDbLicenseException failure) {
            return error(statusFor(failure.getCode()), failure.getCode(), failure.getMessage());
        } catch (RuntimeException failure) {
            return error(HttpStatus.INTERNAL_SERVER_ERROR,
                    "MASSDB_LICENSE_INTERNAL", "License管理请求执行失败");
        }
        long occurredAt = runtime.wallClockEpochSecond();
        MassDbLicenseLocalAudit audit;
        try {
            audit = runtime.localAudit();
            appendManagementAudit(audit, principal, request, occurredAt,
                    "REQUEST", "ACCEPTED", 0);
        } catch (MassDbLicenseException failure) {
            return error(statusFor(failure.getCode()), failure.getCode(), failure.getMessage());
        }
        try {
            if (write && !runtime.readyForWrite()) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_NOT_LEADER", "License写操作只能由就绪的FE Leader处理");
            }
            Object result = call.call(principal);
            appendManagementAudit(audit, principal, request, occurredAt,
                    "RESULT", "OK", responseStatus(result));
            return result;
        } catch (MassDbLicenseException failure) {
            MassDbLicenseException auditFailure = appendFailureAudit(
                    audit, principal, request, occurredAt,
                    failure.getCode(), statusFor(failure.getCode()).value());
            if (auditFailure != null) {
                return error(statusFor(auditFailure.getCode()),
                        auditFailure.getCode(), auditFailure.getMessage());
            }
            return error(statusFor(failure.getCode()), failure.getCode(), failure.getMessage());
        } catch (IOException failure) {
            MassDbLicenseException auditFailure = appendFailureAudit(
                    audit, principal, request, occurredAt,
                    "MASSDB_LICENSE_FILE_INVALID", HttpStatus.BAD_REQUEST.value());
            if (auditFailure != null) {
                return error(statusFor(auditFailure.getCode()),
                        auditFailure.getCode(), auditFailure.getMessage());
            }
            return error(HttpStatus.BAD_REQUEST,
                    "MASSDB_LICENSE_FILE_INVALID", "无法安全读取License工件");
        } catch (RuntimeException failure) {
            MassDbLicenseException auditFailure = appendFailureAudit(
                    audit, principal, request, occurredAt,
                    "MASSDB_LICENSE_INTERNAL", HttpStatus.INTERNAL_SERVER_ERROR.value());
            if (auditFailure != null) {
                return error(statusFor(auditFailure.getCode()),
                        auditFailure.getCode(), auditFailure.getMessage());
            }
            return error(HttpStatus.INTERNAL_SERVER_ERROR,
                    "MASSDB_LICENSE_INTERNAL", "License管理请求执行失败");
        }
    }

    private static void appendManagementAudit(MassDbLicenseLocalAudit audit,
            MassDbLicenseManagementIdentity.Principal principal,
            HttpServletRequest request, long occurredAt, String phase,
            String resultCode, int status) {
        if (audit == null) {
            return;
        }
        MassDbLicenseLocalAudit.Event event = new MassDbLicenseLocalAudit.Event();
        event.occurredAt = occurredAt;
        event.principalSubjectDigest = sha256(
                principal.spiffeId.getBytes(StandardCharsets.UTF_8));
        event.principalRole = principal.role.name();
        event.method = request.getMethod();
        String requestPath = request.getRequestURI();
        event.path = requestPath == null || requestPath.isEmpty() ? BASE_PATH : requestPath;
        String idempotencyKey = request.getHeader(IDEMPOTENCY_KEY);
        if (idempotencyKey != null && !idempotencyKey.isEmpty()) {
            event.idempotencyKeyDigest = sha256(
                    idempotencyKey.getBytes(StandardCharsets.UTF_8));
        }
        event.phase = phase;
        event.resultCode = resultCode;
        event.httpStatus = status;
        audit.append(event);
    }

    private static MassDbLicenseException appendFailureAudit(
            MassDbLicenseLocalAudit audit,
            MassDbLicenseManagementIdentity.Principal principal,
            HttpServletRequest request, long occurredAt, String code, int status) {
        try {
            appendManagementAudit(audit, principal, request, occurredAt,
                    "RESULT", code, status);
            return null;
        } catch (MassDbLicenseException failure) {
            return failure;
        }
    }

    private static int responseStatus(Object response) {
        if (response instanceof ResponseEntity) {
            return ((ResponseEntity<?>) response).getStatusCode().value();
        }
        return HttpStatus.OK.value();
    }

    private MassDbLicenseManagementIdentity.Principal authorize(
            HttpServletRequest request, Access access) {
        if (!request.isSecure()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_HTTPS_REQUIRED", "License管理API必须使用HTTPS和mTLS");
        }
        MassDbLicenseJettyIdentityController controller = runtime.identityController();
        if (controller == null || !controller.isAvailable()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_MANAGEMENT_IDENTITY_UNAVAILABLE", "License管理身份验证器未就绪");
        }
        X509Certificate[] chain = peerCertificates(request);
        if (chain == null || chain.length == 0) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_MTLS_REQUIRED", "License管理请求缺少客户端证书");
        }
        MassDbLicenseManagementIdentity.Principal principal =
                controller.requireAllowedManagementClient(
                        chain, runtime.wallClockEpochSecond());
        if ((access == Access.READ && !principal.canRead())
                || (access == Access.ADMIN && !principal.canAdminister())
                || (access == Access.CORRECTION && !principal.canApproveCorrection())
                || (access == Access.ROUTING_ADAPTER
                        && !principal.canObserveRoutingEvidence())) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_RBAC_FORBIDDEN", "管理身份没有该License端点权限");
        }
        return principal;
    }

    private RuntimeComponents requireComponents(boolean requireImport) {
        MassDbLicenseManager manager = runtime.manager();
        MassDbLicenseReadApiCore readCore = runtime.readCore();
        MassDbLicenseImportCore importCore = runtime.importCore();
        if (manager == null || readCore == null || (requireImport && importCore == null)) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_MANAGEMENT_API_UNAVAILABLE", "License管理核心未就绪");
        }
        return new RuntimeComponents(manager, readCore, importCore);
    }

    private MassDbLicenseBootstrapCore requireBootstrapCore() {
        MassDbLicenseBootstrapCore core = runtime.bootstrapCore();
        if (core == null) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_MANAGEMENT_API_UNAVAILABLE", "bootstrap核心未就绪");
        }
        return core;
    }

    private MassDbLicenseSqlBootstrapRuntime requireSqlRuntime() {
        MassDbLicenseSqlBootstrapRuntime sqlRuntime = runtime.sqlBootstrapRuntime();
        if (sqlRuntime == null) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_SQL_RUNTIME_UNAVAILABLE",
                    "MassDB SQL License拓扑运行时未就绪");
        }
        return sqlRuntime;
    }

    private MassDbLicenseUpgradeCore requireUpgradeCore() {
        MassDbLicenseUpgradeCore core = runtime.upgradeCore();
        if (core == null) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_UPGRADE_ATTESTATION_UNAVAILABLE",
                    "存量集群upgrade marker或mTLS证明运行时未就绪");
        }
        return core;
    }

    private MassDbLicenseCorrectionCore requireCorrectionCore() {
        MassDbLicenseImportCore core = requireComponents(true).importCore;
        return core.createCorrectionCore();
    }

    private MassDbLicenseClockRecoveryCore requireClockRecoveryCore() {
        MassDbLicenseImportCore core = requireComponents(true).importCore;
        return core.createClockRecoveryCore();
    }

    private MassDbLicenseKeysetControlCore requireKeysetCore() {
        MassDbLicenseImportCore core = requireComponents(true).importCore;
        return core.createKeysetControlCore();
    }

    private static MassDbLicenseIngressControlCore requireIngressCore() {
        return new MassDbLicenseIngressControlCore();
    }

    private static MassDbLicenseEnforcementCore requireEnforcementCore() {
        return new MassDbLicenseEnforcementCore();
    }

    private Object validateKeysetArtifact(HttpServletRequest request, boolean bundle)
            throws IOException {
        byte[] artifact = readArtifact(request);
        requireContentSha256(request.getHeader(CONTENT_SHA256), artifact);
        MassDbLicenseState state = requireComponents(true).manager.snapshot();
        long now = effectiveNow(state, runtime.wallClockEpochSecond());
        MassDbLicenseKeysetControlCore.ValidateResult result = bundle
                ? requireKeysetCore().validateBundle(state, artifact, now)
                : requireKeysetCore().validateKeyset(state, artifact, now);
        return responseBuilder(HttpStatus.OK)
                .header(HttpHeaders.ETAG, quoteEtag(result.preconditionToken))
                .body(result);
    }

    private Object importKeysetArtifact(HttpServletRequest request, boolean bundle)
            throws IOException {
        byte[] artifact = readArtifact(request);
        String contentSha256 = requireContentSha256(
                request.getHeader(CONTENT_SHA256), artifact);
        String precondition = requireIfMatch(request.getHeader(HttpHeaders.IF_MATCH));
        String idempotencyKey = requireHeader(request, IDEMPOTENCY_KEY);
        RuntimeComponents components = requireComponents(true);
        long now = effectiveNow(components.manager.snapshot(),
                runtime.wallClockEpochSecond());
        String operationId = UUID.randomUUID().toString();
        long deadlineAt = saturatedAdd(now, runtime.operationAckDeadlineSeconds());
        AtomicReference<MassDbLicenseKeysetControlCore.Result> prepared =
                new AtomicReference<>();
        MassDbLicenseState persisted = components.manager.transition(state -> {
            MassDbLicenseKeysetControlCore.Result result = bundle
                    ? requireKeysetCore().prepareBundle(state, artifact, contentSha256,
                            precondition, idempotencyKey, operationId, now, deadlineAt)
                    : requireKeysetCore().prepareKeyset(state, artifact, contentSha256,
                            precondition, idempotencyKey, operationId, now, deadlineAt);
            prepared.set(result);
            return result.state;
        });
        return operationResponse(persisted, prepared.get().operationId,
                prepared.get().replayed, prepared.get().terminal);
    }

    private MassDbLicenseBootstrapCore.WriteHealth bootstrapWriteHealth() {
        return new MassDbLicenseBootstrapCore.WriteHealth() {
            @Override
            public String requireLocalFeIdentity(String deploymentUuid, long now) {
                if (!runtime.readyForWrite()) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_NOT_LEADER", "bootstrap只能由就绪的FE Leader执行");
                }
                MassDbLicenseJettyIdentityController controller = runtime.identityController();
                if (controller == null || !controller.isAvailable()) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_MANAGEMENT_IDENTITY_UNAVAILABLE",
                            "bootstrap要求当前FE身份已安全应用");
                }
                return controller.requireLocalFeIdentity(deploymentUuid, now);
            }

            @Override
            public void requireFullPlanCompatible(
                    MassDbLicenseBootstrapCore.InstallationPlan plan, long now) {
                MassDbLicenseSqlBootstrapRuntime bootstrapRuntime =
                        runtime.sqlBootstrapRuntime();
                if (bootstrapRuntime == null) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_BOOTSTRAP_RUNTIME_UNAVAILABLE",
                            "完整bootstrap运行时未就绪");
                }
                bootstrapRuntime.requireCompatible(plan, now);
            }

            @Override
            public MassDbLicenseBootstrapCore.InstallationHealth
                    reconcileAndRequireFullHealth(
                            MassDbLicenseBootstrapCore.InstallationPlan plan, long now) {
                MassDbLicenseSqlBootstrapRuntime bootstrapRuntime =
                        runtime.sqlBootstrapRuntime();
                if (bootstrapRuntime == null) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_BOOTSTRAP_RUNTIME_UNAVAILABLE",
                            "完整bootstrap运行时未就绪");
                }
                return bootstrapRuntime.reconcileAndRequireHealthy(plan, now);
            }
        };
    }

    private static MassDbLicenseState.ImportIntent requireIntent(HttpServletRequest request) {
        String value = request.getHeader(INTENT);
        String normalized = value == null || value.trim().isEmpty()
                ? "NORMAL" : value.trim();
        try {
            return MassDbLicenseState.ImportIntent.valueOf(normalized);
        } catch (IllegalArgumentException failure) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_INTENT_UNSUPPORTED",
                    "License intent必须是NORMAL、REPLACE_WITH_SHORTER或KEY_ROTATION_REPLACEMENT");
        }
    }

    private static String validationToken(Object result) {
        if (result instanceof MassDbLicenseReadApiCore.ValidateResult) {
            return ((MassDbLicenseReadApiCore.ValidateResult) result).preconditionToken;
        }
        if (result instanceof MassDbLicenseCorrectionCore.ValidateResult) {
            return ((MassDbLicenseCorrectionCore.ValidateResult) result).preconditionToken;
        }
        return null;
    }

    private static <T> T parseJson(HttpServletRequest request, Class<T> type)
            throws IOException {
        byte[] body = readBody(request, MAX_CONTROL_JSON_BYTES, "License控制请求");
        return STRICT_JSON.readValue(body, type);
    }

    private static Object operationResponse(MassDbLicenseState state,
            String operationId, boolean replayed, boolean terminal) {
        MassDbLicenseState.OperationView operation = state.findOperation(operationId);
        HttpStatus status = replayed || terminal ? HttpStatus.OK : HttpStatus.ACCEPTED;
        return responseBuilder(status)
                .header(HttpHeaders.LOCATION, BASE_PATH + "/operations/" + operationId)
                .body(operation);
    }

    private static byte[] readArtifact(HttpServletRequest request) throws IOException {
        return readBody(request, MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES, "License工件");
    }

    private static byte[] readBody(HttpServletRequest request, int maximum, String label)
            throws IOException {
        long declared = request.getContentLengthLong();
        if (declared == 0) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_FILE_INVALID", label + "不能为空");
        }
        if (declared > maximum) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_FILE_TOO_LARGE", label + "超过允许上限");
        }
        try (ServletInputStream input = request.getInputStream();
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count == 0) {
                    continue;
                }
                if (output.size() + count > maximum) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_FILE_TOO_LARGE", label + "超过允许上限");
                }
                output.write(buffer, 0, count);
            }
            if (output.size() == 0) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_FILE_INVALID", label + "不能为空");
            }
            return output.toByteArray();
        }
    }

    private static String requireContentSha256(String header, byte[] artifact) {
        if (header == null || !SHA256.matcher(header).matches()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_CONTENT_SHA256_REQUIRED",
                    "Content-SHA256必须是64位十六进制摘要");
        }
        String actual = sha256(artifact);
        byte[] suppliedBytes = header.toLowerCase(Locale.ROOT)
                .getBytes(StandardCharsets.US_ASCII);
        byte[] actualBytes = actual.getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(suppliedBytes, actualBytes)) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_CONTENT_SHA256_MISMATCH",
                    "Content-SHA256与实际License工件不一致");
        }
        return actual;
    }

    private static String requireHeader(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        if (value == null || value.trim().isEmpty()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_HEADER_REQUIRED", name + "不能为空");
        }
        return value.trim();
    }

    private static long parseNonNegativeLong(String value, long defaultValue, String errorCode) {
        if (value == null || value.trim().isEmpty()) {
            return defaultValue;
        }
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0) {
                throw new NumberFormatException("negative");
            }
            return parsed;
        } catch (NumberFormatException failure) {
            throw new MassDbLicenseException(errorCode, "License诊断分页参数非法");
        }
    }

    private static String requireIfMatch(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_HEADER_REQUIRED", "If-Match不能为空");
        }
        String normalized = value.trim();
        if (normalized.startsWith("W/")) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_PRECONDITION_FAILED", "If-Match不接受weak ETag");
        }
        if (normalized.length() >= 2 && normalized.startsWith("\"")
                && normalized.endsWith("\"")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        if (normalized.isEmpty() || normalized.indexOf('"') >= 0
                || normalized.indexOf(',') >= 0 || "*".equals(normalized)) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_PRECONDITION_FAILED", "If-Match ETag格式非法");
        }
        return normalized;
    }

    private static String quoteEtag(String value) {
        return "\"" + value + "\"";
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return result.toString();
    }

    private static long effectiveNow(MassDbLicenseState state, long wallClock) {
        long result = Math.max(wallClock, state.getMaxSeenWallClock());
        if (state.isInitialized()) {
            Map<String, MassDbLicenseIngressInventory.IngressNode> nodes =
                    state.getIngressInventory().getNodes();
            for (MassDbLicenseIngressInventory.IngressNode node : nodes.values()) {
                result = Math.max(result, node.getLastVerifiedEffectiveNow());
            }
        }
        return result;
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static X509Certificate[] peerCertificates(HttpServletRequest request) {
        Object value = request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (!(value instanceof X509Certificate[])) {
            value = request.getAttribute("javax.servlet.request.X509Certificate");
        }
        return value instanceof X509Certificate[] ? (X509Certificate[]) value : null;
    }

    private static HttpStatus statusFor(String code) {
        if ("MASSDB_LICENSE_HTTPS_REQUIRED".equals(code)) {
            return HttpStatus.UPGRADE_REQUIRED;
        }
        if ("MASSDB_LICENSE_MTLS_REQUIRED".equals(code)) {
            return HttpStatus.UNAUTHORIZED;
        }
        if (code.startsWith("MASSDB_LICENSE_MTLS_")
                || "MASSDB_LICENSE_ROLE_IDENTITY_REVOKED".equals(code)
                || "MASSDB_LICENSE_RBAC_FORBIDDEN".equals(code)) {
            return HttpStatus.FORBIDDEN;
        }
        if ("MASSDB_LICENSE_OPERATION_NOT_FOUND".equals(code)) {
            return HttpStatus.NOT_FOUND;
        }
        if ("MASSDB_LICENSE_NOT_LEADER".equals(code)
                || code.endsWith("_UNAVAILABLE")) {
            return HttpStatus.SERVICE_UNAVAILABLE;
        }
        if ("MASSDB_LICENSE_FILE_TOO_LARGE".equals(code)) {
            return HttpStatus.PAYLOAD_TOO_LARGE;
        }
        if ("MASSDB_LICENSE_AUDIT_FULL".equals(code)) {
            return HttpStatus.INSUFFICIENT_STORAGE;
        }
        if (code.startsWith("MASSDB_LICENSE_AUDIT_")) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
        if ("MASSDB_LICENSE_PRECONDITION_FAILED".equals(code)
                || "MASSDB_LICENSE_PRECONDITION_INVALID".equals(code)
                || "MASSDB_LICENSE_PRECONDITION_EXPIRED".equals(code)
                || code.contains("BOOTSTRAP_PRECONDITION")
                || code.contains("UPGRADE_PRECONDITION")) {
            return HttpStatus.PRECONDITION_FAILED;
        }
        if ("MASSDB_LICENSE_HEADER_REQUIRED".equals(code)) {
            return HttpStatus.BAD_REQUEST;
        }
        if ("MASSDB_LICENSE_BOOTSTRAP_REQUIRED".equals(code)
                || "MASSDB_LICENSE_BOOTSTRAP_SEALED".equals(code)
                || "MASSDB_LICENSE_BOOTSTRAP_NOT_SEALED".equals(code)
                || "MASSDB_LICENSE_BOOTSTRAP_PLAN_MISMATCH".equals(code)
                || "MASSDB_LICENSE_BOOTSTRAP_STATE_CONFLICT".equals(code)
                || "MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH".equals(code)
                || "MASSDB_LICENSE_BOOTSTRAP_NOT_READY".equals(code)
                || "MASSDB_LICENSE_BOOTSTRAP_TOPOLOGY_CONFLICT".equals(code)
                || "MASSDB_LICENSE_BOOTSTRAP_ACCOUNT_CONFLICT".equals(code)
                || "MASSDB_LICENSE_BOOTSTRAP_ROUTE_CONFLICT".equals(code)
                || "MASSDB_LICENSE_UPGRADE_ALREADY_INITIALIZED".equals(code)
                || "MASSDB_LICENSE_UPGRADE_NOT_EXISTING_CLUSTER".equals(code)
                || "MASSDB_LICENSE_UPGRADE_MARKER_REQUIRED".equals(code)
                || "MASSDB_LICENSE_UPGRADE_MARKER_MISMATCH".equals(code)
                || "MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED".equals(code)
                || "MASSDB_LICENSE_UPGRADE_ATTESTATION_FAILED".equals(code)
                || "MASSDB_LICENSE_UPGRADE_ATTESTATION_MISMATCH".equals(code)
                || code.contains("IDEMPOTENCY_CONFLICT")
                || code.contains("MUTATION_IN_PROGRESS")
                || code.contains("OPERATION_NOT_ABORTABLE")
                || code.contains("CLOCK_RECOVERY_CHALLENGE_ACTIVE")) {
            return HttpStatus.CONFLICT;
        }
        return HttpStatus.UNPROCESSABLE_ENTITY;
    }

    private static ResponseEntity.BodyBuilder responseBuilder(HttpStatus status) {
        return ResponseEntity.status(status)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header("X-Content-Type-Options", "nosniff");
    }

    private static ResponseEntity<Object> response(HttpStatus status, Object body) {
        return responseBuilder(status).body(body);
    }

    private static ResponseEntity<ErrorBody> error(
            HttpStatus status, String code, String message) {
        return responseBuilder(status).body(new ErrorBody(code, message));
    }

    enum Access {
        READ,
        ADMIN,
        CORRECTION,
        ROUTING_ADAPTER
    }

    interface AuthorizedCall {
        Object call(MassDbLicenseManagementIdentity.Principal principal) throws IOException;
    }

    public interface RuntimeAccess {
        boolean enabled();

        long wallClockEpochSecond();

        MassDbLicenseJettyIdentityController identityController();

        boolean readyForWrite();

        MassDbLicenseManager manager();

        MassDbLicenseReadApiCore readCore();

        MassDbLicenseImportCore importCore();

        default MassDbLicenseBootstrapCore bootstrapCore() {
            return null;
        }

        default MassDbLicenseBootstrapMarker.Attestation bootstrapAttestation() {
            return null;
        }

        default MassDbLicenseSqlBootstrapRuntime sqlBootstrapRuntime() {
            return null;
        }

        default MassDbLicenseUpgradeCore upgradeCore() {
            return null;
        }

        default MassDbLicenseLocalAudit localAudit() {
            return null;
        }

        long operationAckDeadlineSeconds();
    }

    private static final class RuntimeComponents {
        private final MassDbLicenseManager manager;
        private final MassDbLicenseReadApiCore readCore;
        private final MassDbLicenseImportCore importCore;

        private RuntimeComponents(MassDbLicenseManager manager,
                MassDbLicenseReadApiCore readCore, MassDbLicenseImportCore importCore) {
            this.manager = manager;
            this.readCore = readCore;
            this.importCore = importCore;
        }
    }

    private static final class ProductionRuntime implements RuntimeAccess {
        private volatile MassDbLicenseLocalAudit localAudit;

        @Override
        public boolean enabled() {
            return Config.massdb_license_management_api_enabled;
        }

        @Override
        public long wallClockEpochSecond() {
            return Instant.now().getEpochSecond();
        }

        @Override
        public MassDbLicenseJettyIdentityController identityController() {
            return Env.getServingEnv().getMassDbLicenseJettyIdentityController();
        }

        @Override
        public boolean readyForWrite() {
            Env env = Env.getServingEnv();
            return env.isReady() && env.isMaster();
        }

        @Override
        public MassDbLicenseManager manager() {
            return Env.getServingEnv().getMassDbLicenseManager();
        }

        @Override
        public MassDbLicenseReadApiCore readCore() {
            return Env.getServingEnv().getMassDbLicenseReadApiCore();
        }

        @Override
        public MassDbLicenseImportCore importCore() {
            return Env.getServingEnv().getMassDbLicenseImportCore();
        }

        @Override
        public MassDbLicenseBootstrapCore bootstrapCore() {
            return Env.getServingEnv().getMassDbLicenseBootstrapCore();
        }

        @Override
        public MassDbLicenseBootstrapMarker.Attestation bootstrapAttestation() {
            return Env.getServingEnv().getMassDbLicenseBootstrapAttestation();
        }

        @Override
        public MassDbLicenseSqlBootstrapRuntime sqlBootstrapRuntime() {
            return new MassDbLicenseSqlBootstrapRuntime();
        }

        @Override
        public MassDbLicenseUpgradeCore upgradeCore() {
            return Env.getServingEnv().getMassDbLicenseUpgradeCore();
        }

        @Override
        public MassDbLicenseLocalAudit localAudit() {
            MassDbLicenseLocalAudit current = localAudit;
            if (current != null) {
                return current;
            }
            synchronized (this) {
                if (localAudit == null) {
                    localAudit = MassDbLicenseLocalAudit.open(Paths.get(Config.meta_dir));
                }
                return localAudit;
            }
        }

        @Override
        public long operationAckDeadlineSeconds() {
            return Config.massdb_license_operation_ack_deadline_seconds;
        }
    }

    public static final class ErrorBody {
        public final String code;
        public final String message;

        private ErrorBody(String code, String message) {
            this.code = code;
            this.message = message;
        }
    }

    private static final class OperationResult {
        private final String operationId;
        private final boolean replayed;
        private final boolean terminal;

        private OperationResult(String operationId, boolean replayed, boolean terminal) {
            this.operationId = operationId;
            this.replayed = replayed;
            this.terminal = terminal;
        }
    }

    public static final class ClockChallengeResult {
        public final MassDbLicenseState.OperationView operation;
        public final MassDbLicenseState.ClockChallenge challenge;

        private ClockChallengeResult(MassDbLicenseState.OperationView operation,
                MassDbLicenseState.ClockChallenge challenge) {
            this.operation = operation;
            this.challenge = challenge;
        }
    }
}
