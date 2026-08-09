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

package org.apache.doris.massdblicense;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Dual-control expiry correction and same-expiry key-rotation replacement core. */
public final class MassDbLicenseCorrectionCore {
    public static final long PROPOSAL_TTL_SECONDS = 24 * 60 * 60;
    private static final String AUDIENCE = "LICENSE_CONTROLLED_IMPORT";
    private final long maxLicenseTermSeconds;
    private final Map<String, PublicKey> rootKeys;

    public MassDbLicenseCorrectionCore(long maxLicenseTermSeconds,
            Map<String, PublicKey> rootKeys) {
        if (maxLicenseTermSeconds <= 0 || rootKeys == null || rootKeys.isEmpty()) {
            throw new IllegalArgumentException("maxLicenseTermSeconds和rootKeys必须配置");
        }
        this.maxLicenseTermSeconds = maxLicenseTermSeconds;
        this.rootKeys = Collections.unmodifiableMap(new LinkedHashMap<>(rootKeys));
    }

    public ProposalResult createProposal(MassDbLicenseState state, byte[] artifact,
            String requester, String proposalId, long effectiveNow) {
        ValidateResult validation = validateCorrection(state, artifact, effectiveNow);
        return createProposal(state, artifact, validation.preconditionToken,
                requester, proposalId, "proposal-" + proposalId, effectiveNow);
    }

    public ValidateResult validateCorrection(MassDbLicenseState state,
            byte[] artifact, long effectiveNow) {
        if (state.getMutation() != null) {
            fail("MASSDB_LICENSE_MUTATION_IN_PROGRESS", "已有License mutation占用统一槽位");
        }
        return issueValidation(state, verifyCandidate(state, artifact,
                MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER,
                effectiveNow), "", "", effectiveNow);
    }

    public ProposalResult createProposal(MassDbLicenseState state, byte[] artifact,
            String validationToken, String requester, String proposalId,
            String idempotencyKey, long effectiveNow) {
        VerifiedCandidate candidate = verifyCandidate(state, artifact,
                MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER, effectiveNow);
        matchValidationToken(state, candidate, "", validationToken, effectiveNow);
        MassDbLicenseState.ActiveLicense staged = active(candidate.verified, artifact);
        String requestHash = sha256(("CORRECTION_PROPOSAL\n"
                + candidate.verified.getSha256() + "\n" + requester)
                .getBytes(StandardCharsets.UTF_8));
        MassDbLicenseState.CorrectionProposal replay =
                state.findCorrectionProposalByCreateIdempotencyKey(
                        idempotencyKey, effectiveNow);
        String actualProposalId = replay == null ? proposalId : replay.getProposalId();
        MassDbLicenseState next = state.createCorrectionProposal(actualProposalId, staged,
                requester, idempotencyKey, requestHash, effectiveNow,
                saturatedAdd(effectiveNow, PROPOSAL_TTL_SECONDS));
        return new ProposalResult(next,
                next.findCorrectionProposal(actualProposalId, effectiveNow));
    }

    public ProposalResult approve(MassDbLicenseState state, String proposalId,
            String approver, long effectiveNow) {
        return approve(state, proposalId, approver,
                "approve-" + proposalId, effectiveNow);
    }

    public ProposalResult approve(MassDbLicenseState state, String proposalId,
            String approver, String idempotencyKey, long effectiveNow) {
        String requestHash = sha256(("CORRECTION_APPROVE\n" + proposalId
                + "\n" + approver).getBytes(StandardCharsets.UTF_8));
        MassDbLicenseState next = state.approveCorrectionProposal(
                proposalId, approver, idempotencyKey, requestHash, effectiveNow);
        MassDbLicenseState.CorrectionProposal proposal =
                next.findCorrectionProposal(proposalId, effectiveNow);
        if (proposal == null || proposal.getState()
                != MassDbLicenseState.CorrectionProposalState.APPROVED) {
            fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_EXPIRED",
                    "correction proposal已过期");
        }
        return new ProposalResult(next, proposal);
    }

    public ProposalResult cancel(MassDbLicenseState state, String proposalId,
            long effectiveNow) {
        return cancel(state, proposalId, "cancel-" + proposalId, effectiveNow);
    }

    public ProposalResult cancel(MassDbLicenseState state, String proposalId,
            String idempotencyKey, long effectiveNow) {
        String requestHash = sha256(("CORRECTION_CANCEL\n" + proposalId)
                .getBytes(StandardCharsets.UTF_8));
        MassDbLicenseState next = state.cancelCorrectionProposal(
                proposalId, idempotencyKey, requestHash, effectiveNow);
        return new ProposalResult(next,
                next.findCorrectionProposal(proposalId, effectiveNow));
    }

    /** Re-uploading the exact bytes is allowed after staging expiry while the proposal is valid. */
    public ValidateResult prepareImport(MassDbLicenseState state, String proposalId,
            byte[] artifact, long effectiveNow) {
        MassDbLicenseState.CorrectionProposal proposal =
                state.findCorrectionProposal(proposalId, effectiveNow);
        return prepareImport(state, proposalId, artifact,
                proposal == null ? "" : proposal.getRequester(), effectiveNow);
    }

    public ValidateResult prepareImport(MassDbLicenseState state, String proposalId,
            byte[] artifact, String administrator, long effectiveNow) {
        VerifiedCandidate candidate = verifyCandidate(state, artifact,
                MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER, effectiveNow);
        MassDbLicenseState.CorrectionProposal proposal =
                state.findCorrectionProposal(proposalId, effectiveNow);
        if (proposal == null || proposal.getState()
                != MassDbLicenseState.CorrectionProposalState.APPROVED
                || !proposal.getCandidateSha256().equals(candidate.verified.getSha256())
                || !proposal.getActiveLicenseSha256().equals(
                        state.getActiveLicense().getSha256())
                || !proposal.getRequester().equals(administrator)) {
            fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_MISMATCH",
                    "approved proposal与重传工件或active快照不匹配");
        }
        return issueValidation(state, candidate, proposalId, administrator, effectiveNow);
    }

    public ValidateResult validateKeyRotation(MassDbLicenseState state,
            byte[] artifact, long effectiveNow) {
        return issueValidation(state, verifyCandidate(state, artifact,
                MassDbLicenseState.ImportIntent.KEY_ROTATION_REPLACEMENT,
                effectiveNow), "", "", effectiveNow);
    }

    public Result prepare(MassDbLicenseState state, byte[] artifact,
            String contentSha256, String preconditionToken, String idempotencyKey,
            String operationId, MassDbLicenseState.ImportIntent intent,
            String requester, String approver, String proposalId,
            long effectiveNow, long deadlineAt) {
        String actual = sha256(artifact);
        requireDigest(contentSha256, actual);
        String requestHash = sha256(("LICENSE_CONTROLLED_IMPORT\n" + intent.name()
                + "\n" + actual + "\n" + nullToEmpty(proposalId))
                .getBytes(StandardCharsets.US_ASCII));
        String replayId = state.findOperationIdByIdempotency(idempotencyKey, requestHash);
        if (replayId != null) {
            MassDbLicenseState.OperationView replay = state.findOperation(replayId);
            return new Result(state, replayId, true, replay != null && replay.terminal);
        }
        VerifiedCandidate candidate = verifyCandidate(state, artifact, intent, effectiveNow);
        MassDbLicenseControlPreconditionToken.Claims claims =
                MassDbLicenseControlPreconditionToken.verify(
                        state.getPreconditionHmacKey(), preconditionToken, effectiveNow);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        String subject = intent == MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER
                ? correctionSubject(proposalId, requester) : "";
        if (!AUDIENCE.equals(claims.audience) || !intent.name().equals(claims.action)
                || !subject.equals(claims.subjectId)
                || !active.getSha256().equals(claims.activeSha256)
                || claims.activeExpiresAt == null
                || active.getExpiresAt() != claims.activeExpiresAt
                || state.getEnforcementEpoch() != claims.enforcementEpoch
                || state.getTopologyRevision() != claims.topologyRevision
                || !candidate.ingress.inventorySnapshotSha256.equals(
                        claims.inventorySnapshotSha256)
                || !candidate.ingress.routingEvidenceSnapshotSha256.equals(
                        claims.routingEvidenceSnapshotSha256)
                || !actual.equals(claims.candidateSha256)
                || candidate.verified.getPayload().getIssuedAt() != claims.targetValue1
                || candidate.verified.getPayload().getExpiresAt() != claims.targetValue2) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "controlled import token与active、入口或实际工件不匹配");
        }
        MassDbLicenseState prepared = state.prepareControlledLicenseImport(operationId,
                idempotencyKey, requestHash, intent, active(candidate.verified, artifact),
                requester, approver, proposalId, effectiveNow, deadlineAt);
        return new Result(prepared, operationId, false, false);
    }

    public Result recover(MassDbLicenseState state, String operationId,
            long effectiveNow) {
        MassDbLicenseState recovered = state.recoverOrExpireMutation(effectiveNow);
        MassDbLicenseState.OperationView view = recovered.findOperation(operationId);
        if (view == null) {
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的controlled import");
        }
        if (view.terminal) {
            return new Result(recovered, operationId, true, true);
        }
        MassDbLicenseState.Mutation mutation = recovered.getMutation();
        if (mutation == null || mutation.getKind()
                != MassDbLicenseState.MutationKind.LICENSE
                || mutation.getIntent() == MassDbLicenseState.ImportIntent.NORMAL
                || mutation.getCandidateLicense() == null) {
            return failed(recovered, operationId, effectiveNow,
                    "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED");
        }
        try {
            VerifiedCandidate candidate = verifyCandidate(recovered,
                    mutation.getCandidateLicense().getArtifact(),
                    mutation.getIntent(), effectiveNow);
            if (!candidate.verified.getSha256().equals(
                    mutation.getCandidateLicense().getSha256())) {
                return failed(recovered, operationId, effectiveNow,
                        "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED");
            }
            return new Result(recovered, operationId, false, false);
        } catch (MassDbLicenseException error) {
            return failed(recovered, operationId, effectiveNow,
                    "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED");
        }
    }

    public Result commit(MassDbLicenseState state, String operationId,
            List<String> ackedNodeUuids, long effectiveNow) {
        return new Result(state.commitControlledLicenseImport(operationId,
                ackedNodeUuids, effectiveNow), operationId, false, true);
    }

    public MassDbLicenseImportCore.RedriveResult recoverForDistribution(
            MassDbLicenseState state, String operationId, long effectiveNow) {
        Result result = recover(state, operationId, effectiveNow);
        MassDbLicenseState.OperationView view = result.state.findOperation(operationId);
        if (result.terminal) {
            return new MassDbLicenseImportCore.RedriveResult(result.state, null, true,
                    view == null ? "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED"
                            : view.errorCode);
        }
        MassDbLicenseState.Mutation mutation = result.state.getMutation();
        MassDbLicenseState.ActiveLicense candidate = mutation.getCandidateLicense();
        MassDbLicenseImportCore.RecoveryPlan plan = new MassDbLicenseImportCore.RecoveryPlan(
                operationId, candidate.getSha256(), candidate.getExpiresAt(),
                result.state.getEnforcementEpoch(), mutation.getPreparedAt(),
                candidate.getArtifact(), mutation.getRequiredAckNodeUuids(),
                mutation.getDeferredNodeUuids(), mutation.getDeadlineAt());
        return new MassDbLicenseImportCore.RedriveResult(result.state, plan, false, null);
    }

    public MassDbLicenseState commitDistributed(MassDbLicenseState state,
            String operationId, List<String> ackedNodeUuids, long effectiveNow) {
        return commit(state, operationId, ackedNodeUuids, effectiveNow).state;
    }

    private ValidateResult issueValidation(MassDbLicenseState state,
            VerifiedCandidate candidate, String proposalId,
            String administrator, long effectiveNow) {
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        long tokenExpiresAt = saturatedAdd(effectiveNow,
                MassDbLicenseControlPreconditionToken.MAX_TTL_SECONDS);
        String token = MassDbLicenseControlPreconditionToken.issue(
                state.getPreconditionHmacKey(),
                new MassDbLicenseControlPreconditionToken.Claims(AUDIENCE,
                        candidate.intent.name(), proposalId == null || proposalId.isEmpty()
                                ? "" : correctionSubject(proposalId, administrator),
                        active.getSha256(),
                        active.getExpiresAt(), state.getEnforcementEpoch(),
                        state.getTopologyRevision(), candidate.ingress.inventorySnapshotSha256,
                        candidate.ingress.routingEvidenceSnapshotSha256,
                        candidate.verified.getSha256(),
                        candidate.verified.getPayload().getIssuedAt(),
                        candidate.verified.getPayload().getExpiresAt(), 0, 0, 0,
                        effectiveNow, tokenExpiresAt, UUID.randomUUID().toString()));
        return new ValidateResult(candidate, state, proposalId, token);
    }

    private void matchValidationToken(MassDbLicenseState state,
            VerifiedCandidate candidate, String subject, String token, long effectiveNow) {
        MassDbLicenseControlPreconditionToken.Claims claims =
                MassDbLicenseControlPreconditionToken.verify(
                        state.getPreconditionHmacKey(), token, effectiveNow);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        if (!AUDIENCE.equals(claims.audience)
                || !candidate.intent.name().equals(claims.action)
                || !subject.equals(claims.subjectId)
                || !active.getSha256().equals(claims.activeSha256)
                || claims.activeExpiresAt == null
                || active.getExpiresAt() != claims.activeExpiresAt
                || state.getEnforcementEpoch() != claims.enforcementEpoch
                || state.getTopologyRevision() != claims.topologyRevision
                || !candidate.ingress.inventorySnapshotSha256.equals(
                        claims.inventorySnapshotSha256)
                || !candidate.ingress.routingEvidenceSnapshotSha256.equals(
                        claims.routingEvidenceSnapshotSha256)
                || !candidate.verified.getSha256().equals(claims.candidateSha256)
                || candidate.verified.getPayload().getIssuedAt() != claims.targetValue1
                || candidate.verified.getPayload().getExpiresAt() != claims.targetValue2) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "correction validate token与当前active、入口或候选不匹配");
        }
    }

    private VerifiedCandidate verifyCandidate(MassDbLicenseState state,
            byte[] artifact, MassDbLicenseState.ImportIntent intent, long effectiveNow) {
        if (!state.isInitialized() || state.getActiveLicense() == null
                || state.getActiveKeyset() == null) {
            fail("MASSDB_LICENSE_MISSING", "controlled import前必须存在active License和keyset");
        }
        MassDbLicenseState.ActiveKeyset storedKeyset = state.getActiveKeyset();
        MassDbLicenseProtocolV1.VerifiedKeyset keyset =
                MassDbLicenseProtocolV1.verifyKeyset(storedKeyset.getArtifact(),
                        rootKeys, effectiveNow, null);
        if (!storedKeyset.getSha256().equals(keyset.getSha256())
                || storedKeyset.getVersion()
                        != keyset.getPayload().getKeysetVersion()) {
            fail("MASSDB_LICENSE_KEYSET_INVALID", "active keyset复验失败");
        }
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        long activeValidationNow = Math.min(effectiveNow, active.getExpiresAt() - 1);
        MassDbLicenseProtocolV1.VerifiedLicense activeVerified =
                MassDbLicenseProtocolV1.verifyLicense(active.getArtifact(), keyset,
                        activeValidationNow, maxLicenseTermSeconds, null);
        if (!active.getSha256().equals(activeVerified.getSha256())) {
            fail("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT", "active License复验失败");
        }
        MassDbLicenseProtocolV1.VerifiedLicense candidate =
                MassDbLicenseProtocolV1.verifyLicense(artifact, keyset,
                        effectiveNow, maxLicenseTermSeconds, null);
        if (intent == MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER) {
            if (candidate.getPayload().getExpiresAt() >= active.getExpiresAt()) {
                fail("MASSDB_LICENSE_CORRECTION_REQUIRED",
                        "更正候选必须严格缩短active到期时间");
            }
        } else if (intent == MassDbLicenseState.ImportIntent.KEY_ROTATION_REPLACEMENT) {
            if (candidate.getPayload().getExpiresAt() != active.getExpiresAt()
                    || candidate.getSha256().equals(active.getSha256())
                    || candidate.getPayload().getLicenseId().equals(active.getLicenseId())
                    || candidate.getPayload().getIssuedAt() < active.getIssuedAt()) {
                fail("MASSDB_LICENSE_KEY_ROTATION_REPLACEMENT_INVALID",
                        "换签替换必须使用新ID/摘要、相同到期且issuedAt不回退");
            }
        } else {
            fail("MASSDB_LICENSE_INTENT_UNSUPPORTED", "controlled import intent非法");
        }
        MassDbLicenseIngressInventory.Evaluation ingress = state.getIngressInventory().evaluate(
                active, state.getEnforcementEpoch(), effectiveNow, false);
        if (ingress.expectedIngressNodes <= 0
                || ingress.liveIngressNodes != ingress.expectedIngressNodes
                || ingress.coveredIngressNodes != ingress.expectedIngressNodes
                || ingress.deferredOfflineIngressNodes != 0
                || !"FRESH".equals(ingress.coverageFreshness)
                || !ingress.blockers.isEmpty()) {
            fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE",
                    "controlled import要求全部desired入口在线且覆盖完整");
        }
        return new VerifiedCandidate(candidate, ingress, intent);
    }

    private static MassDbLicenseState.ActiveLicense active(
            MassDbLicenseProtocolV1.VerifiedLicense value, byte[] artifact) {
        return new MassDbLicenseState.ActiveLicense(value.getPayload().getLicenseId(),
                value.getSha256(), value.getKid(), value.getPayload().getIssuedAt(),
                value.getPayload().getExpiresAt(), artifact);
    }

    private Result failed(MassDbLicenseState state, String operationId,
            long now, String code) {
        return new Result(state.failOperation(operationId, code, now),
                operationId, false, true);
    }

    private static String sha256(byte[] value) {
        if (value == null || value.length == 0
                || value.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES) {
            fail("MASSDB_LICENSE_FILE_INVALID", "License工件为空或超过上限");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(String.format("%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static void requireDigest(String supplied, String actual) {
        if (supplied == null || !supplied.matches("[0-9a-fA-F]{64}")
                || !MessageDigest.isEqual(supplied.toLowerCase().getBytes(StandardCharsets.US_ASCII),
                        actual.getBytes(StandardCharsets.US_ASCII))) {
            fail("MASSDB_LICENSE_CONTENT_SHA256_MISMATCH",
                    "Content-SHA256与实际License工件不一致");
        }
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String correctionSubject(String proposalId, String administrator) {
        return nullToEmpty(proposalId) + ":" + nullToEmpty(administrator);
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    private static final class VerifiedCandidate {
        private final MassDbLicenseProtocolV1.VerifiedLicense verified;
        private final MassDbLicenseIngressInventory.Evaluation ingress;
        private final MassDbLicenseState.ImportIntent intent;

        private VerifiedCandidate(MassDbLicenseProtocolV1.VerifiedLicense verified,
                MassDbLicenseIngressInventory.Evaluation ingress,
                MassDbLicenseState.ImportIntent intent) {
            this.verified = verified;
            this.ingress = ingress;
            this.intent = intent;
        }
    }

    public static final class ProposalResult {
        public final MassDbLicenseState state;
        public final MassDbLicenseState.CorrectionProposal proposal;

        private ProposalResult(MassDbLicenseState state,
                MassDbLicenseState.CorrectionProposal proposal) {
            this.state = state;
            this.proposal = proposal;
        }
    }

    public static final class ValidateResult {
        public final boolean valid = true;
        public final boolean readyForImport = true;
        public final String action;
        public final String proposalId;
        public final String contentSha256;
        public final String licenseId;
        public final long issuedAt;
        public final long licenseExpiresAt;
        public final long currentLicenseExpiresAt;
        public final long topologyRevision;
        public final int expectedIngressNodes;
        public final int liveIngressNodes;
        public final String preconditionToken;
        public final List<String> warnings;

        private ValidateResult(VerifiedCandidate candidate, MassDbLicenseState state,
                String proposalId, String token) {
            this.action = candidate.intent.name();
            this.proposalId = proposalId;
            this.contentSha256 = candidate.verified.getSha256();
            this.licenseId = candidate.verified.getPayload().getLicenseId();
            this.issuedAt = candidate.verified.getPayload().getIssuedAt();
            this.licenseExpiresAt = candidate.verified.getPayload().getExpiresAt();
            this.currentLicenseExpiresAt = state.getActiveLicense().getExpiresAt();
            this.topologyRevision = state.getTopologyRevision();
            this.expectedIngressNodes = candidate.ingress.expectedIngressNodes;
            this.liveIngressNodes = candidate.ingress.liveIngressNodes;
            this.preconditionToken = token;
            this.warnings = Collections.unmodifiableList(
                    new ArrayList<>(candidate.ingress.warnings));
        }
    }

    public static final class Result {
        public final MassDbLicenseState state;
        public final String operationId;
        public final boolean replayed;
        public final boolean terminal;

        private Result(MassDbLicenseState state, String operationId,
                boolean replayed, boolean terminal) {
            this.state = state;
            this.operationId = operationId;
            this.replayed = replayed;
            this.terminal = terminal;
        }
    }
}
