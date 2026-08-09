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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/** CAS-bound configured-ingress and authenticated routing-evidence control core. */
public final class MassDbLicenseIngressControlCore {
    public static final String ENABLE_PREPARE = "ENABLE_PREPARE";
    public static final String DISABLE = "DISABLE";
    public static final String CONFIRM_ROUTING = "CONFIRM_ROUTING";
    public static final long DEFAULT_MANUAL_EVIDENCE_TTL_SECONDS = 90L * 24 * 60 * 60;
    public static final long MAX_MANUAL_EVIDENCE_TTL_SECONDS = 180L * 24 * 60 * 60;
    public static final long MACHINE_EVIDENCE_STALE_SECONDS = 15 * 60;
    public static final long MAX_ADAPTER_CLOCK_SKEW_SECONDS = 5 * 60;
    private static final String AUDIENCE = "MASSDB_LICENSE_INGRESS";

    public View view(MassDbLicenseState state, long effectiveNow) {
        requireInitialized(state);
        MassDbLicenseIngressInventory.Evaluation evaluation =
                state.getIngressInventory().evaluate(state.getActiveLicense(),
                        state.getEnforcementEpoch(), effectiveNow, true);
        List<MassDbLicenseIngressInventory.IngressNode> nodes = new ArrayList<>(
                state.getIngressInventory().getNodes().values());
        return new View(state.getTopologyRevision(), evaluation, nodes);
    }

    public ValidateResult validate(MassDbLicenseState state, ChangeRequest request,
            long effectiveNow) {
        Candidate candidate = candidate(state, request, effectiveNow);
        if (state.getMutation() != null) {
            fail("MASSDB_LICENSE_MUTATION_IN_PROGRESS", "已有License mutation占用统一槽位");
        }
        MassDbLicenseIngressInventory.Evaluation current = state.getIngressInventory().evaluate(
                state.getActiveLicense(), state.getEnforcementEpoch(), effectiveNow, true);
        long tokenExpiresAt = saturatedAdd(effectiveNow,
                MassDbLicenseControlPreconditionToken.MAX_TTL_SECONDS);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        String token = MassDbLicenseControlPreconditionToken.issue(
                state.getPreconditionHmacKey(),
                new MassDbLicenseControlPreconditionToken.Claims(AUDIENCE,
                        candidate.action, candidate.nodeUuid,
                        active == null ? null : active.getSha256(),
                        active == null ? null : active.getExpiresAt(),
                        state.getEnforcementEpoch(), state.getTopologyRevision(),
                        current.inventorySnapshotSha256,
                        current.routingEvidenceSnapshotSha256,
                        candidate.inventory.fullDigest(), 0, 0, 0, 0, 0,
                        effectiveNow, tokenExpiresAt, UUID.randomUUID().toString()));
        return new ValidateResult(candidate.action, candidate.nodeUuid,
                state.getTopologyRevision(), candidate.inventory.fullDigest(),
                token, tokenExpiresAt);
    }

    public Result apply(MassDbLicenseState state, ChangeRequest request,
            String preconditionToken, String idempotencyKey, String operationId,
            long effectiveNow, long deadlineAt) {
        String requestHash = requestHash(request);
        String replay = state.findOperationIdByIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            MassDbLicenseState.OperationView view = state.findOperation(replay);
            return new Result(state, replay, true, view != null && view.terminal);
        }
        Candidate candidate = candidate(state, request, effectiveNow);
        MassDbLicenseIngressInventory.Evaluation current = state.getIngressInventory().evaluate(
                state.getActiveLicense(), state.getEnforcementEpoch(), effectiveNow, true);
        MassDbLicenseControlPreconditionToken.Claims claims =
                MassDbLicenseControlPreconditionToken.verify(
                        state.getPreconditionHmacKey(), preconditionToken, effectiveNow);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        if (!AUDIENCE.equals(claims.audience) || !candidate.action.equals(claims.action)
                || !candidate.nodeUuid.equals(claims.subjectId)
                || !equalsText(claims.activeSha256,
                        active == null ? null : active.getSha256())
                || !equalsLong(claims.activeExpiresAt,
                        active == null ? null : active.getExpiresAt())
                || claims.enforcementEpoch != state.getEnforcementEpoch()
                || claims.topologyRevision != state.getTopologyRevision()
                || !current.inventorySnapshotSha256.equals(
                        claims.inventorySnapshotSha256)
                || !current.routingEvidenceSnapshotSha256.equals(
                        claims.routingEvidenceSnapshotSha256)
                || !candidate.inventory.fullDigest().equals(claims.candidateSha256)) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "入口清单、active、epoch、topology或路由证据已变化");
        }
        MassDbLicenseState prepared = state.prepareIngressInventory(operationId,
                idempotencyKey, requestHash, candidate.inventory, effectiveNow, deadlineAt);
        MassDbLicenseState committed = prepared.commit(operationId, effectiveNow);
        return new Result(committed, operationId, false, true);
    }

    /** The caller must authenticate ROUTING_ADAPTER before invoking this independent CAS path. */
    public MassDbLicenseState observeMachine(MassDbLicenseState state,
            RoutingEvidenceRequest request, String authenticatedAdapterType, long effectiveNow) {
        requireInitialized(state);
        if (request == null || request.adapterType == null
                || request.adapterType.trim().isEmpty() || request.adapterType.length() > 64
                || authenticatedAdapterType == null
                || !request.adapterType.trim().equals(authenticatedAdapterType)
                || request.observedAt <= 0
                || absoluteDifference(request.observedAt, effectiveNow)
                        > MAX_ADAPTER_CLOCK_SKEW_SECONDS) {
            fail("MASSDB_LICENSE_ROUTING_EVIDENCE_INVALID",
                    "路由适配器证书类型、请求类型或观测时间非法");
        }
        MassDbLicenseIngressInventory.RoutingState routingState =
                parseRoutingState(request.routingState, true);
        return state.recordMachineRoutingEvidence(request.nodeUuid, routingState,
                request.adapterType.trim() + ":" + requireText(request.objectIdentity,
                        "objectIdentity", 192),
                request.objectRevision, request.evidenceDigest,
                effectiveNow, saturatedAdd(effectiveNow, MACHINE_EVIDENCE_STALE_SECONDS));
    }

    private static Candidate candidate(MassDbLicenseState state,
            ChangeRequest request, long effectiveNow) {
        requireInitialized(state);
        if (request == null) {
            fail("MASSDB_LICENSE_INGRESS_ACTION_INVALID", "入口变更请求不能为空");
        }
        String action = requireText(request.action, "action", 32).toUpperCase(Locale.ROOT);
        String nodeUuid = requireText(request.nodeUuid, "nodeUuid", 128);
        MassDbLicenseIngressInventory inventory = state.getIngressInventory();
        Map<String, MassDbLicenseIngressInventory.IngressNode> nodes = inventory.getNodes();
        MassDbLicenseIngressInventory.IngressNode node = nodes.get(nodeUuid);
        if (node == null) {
            fail("MASSDB_LICENSE_INGRESS_NOT_FOUND", "入口不在configured inventory中");
        }
        if (ENABLE_PREPARE.equals(action)) {
            if (node.isDesired()) {
                fail("MASSDB_LICENSE_INGRESS_INVENTORY_UNCHANGED", "入口已经是desired");
            }
            if (!node.isLive(effectiveNow) || !node.isGuardReady()
                    || node.isIdentityConflicted()) {
                fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE",
                        "入口必须在线、guard ready且身份无冲突");
            }
            MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
            if (active != null && (!active.getSha256().equals(node.getAckLicenseSha256())
                    || node.getAckLicenseExpiresAt() == null
                    || active.getExpiresAt() != node.getAckLicenseExpiresAt()
                    || state.getEnforcementEpoch() != node.getAckEnforcementEpoch())) {
                fail("MASSDB_LICENSE_INGRESS_NOT_SYNCED",
                        "ENABLE_PREPARE前必须同步当前active和enforcement epoch");
            }
            String endpoint = request.endpoint == null || request.endpoint.trim().isEmpty()
                    ? node.getEndpoint() : request.endpoint.trim();
            return new Candidate(action, nodeUuid,
                    inventory.upsertConfigured(nodeUuid, endpoint, true));
        }
        if (DISABLE.equals(action)) {
            if (!node.isDesired()) {
                fail("MASSDB_LICENSE_INGRESS_INVENTORY_UNCHANGED", "入口已经不是desired");
            }
            if (node.getRoutingState()
                        != MassDbLicenseIngressInventory.RoutingState.REMOVED
                    || !node.hasFreshRoutingEvidence(effectiveNow)) {
                fail("MASSDB_LICENSE_ROUTING_EVIDENCE_REQUIRED",
                        "DISABLE前必须取得新鲜REMOVED路由证据");
            }
            return new Candidate(action, nodeUuid,
                    inventory.upsertConfigured(nodeUuid, node.getEndpoint(), false));
        }
        if (CONFIRM_ROUTING.equals(action)) {
            MassDbLicenseIngressInventory.RoutingState routingState =
                    parseRoutingState(request.routingState, false);
            long ttl = request.evidenceTtlSeconds == null
                    || request.evidenceTtlSeconds == 0
                    ? DEFAULT_MANUAL_EVIDENCE_TTL_SECONDS
                    : request.evidenceTtlSeconds;
            if (ttl <= 0 || ttl > MAX_MANUAL_EVIDENCE_TTL_SECONDS) {
                fail("MASSDB_LICENSE_ROUTING_EVIDENCE_INVALID",
                        "人工路由证据TTL必须在1秒至180天之间");
            }
            return new Candidate(action, nodeUuid, inventory.observeRouting(nodeUuid,
                    routingState, MassDbLicenseIngressInventory.EvidenceSource.MANUAL,
                    effectiveNow, saturatedAdd(effectiveNow, ttl)));
        }
        fail("MASSDB_LICENSE_INGRESS_ACTION_INVALID",
                "入口action必须是ENABLE_PREPARE、DISABLE或CONFIRM_ROUTING");
        return null;
    }

    private static MassDbLicenseIngressInventory.RoutingState parseRoutingState(
            String value, boolean allowUnknown) {
        try {
            MassDbLicenseIngressInventory.RoutingState parsed =
                    MassDbLicenseIngressInventory.RoutingState.valueOf(
                            requireText(value, "routingState", 32).toUpperCase(Locale.ROOT));
            if (!allowUnknown
                    && parsed == MassDbLicenseIngressInventory.RoutingState.UNKNOWN) {
                fail("MASSDB_LICENSE_ROUTING_EVIDENCE_INVALID",
                        "人工确认只接受IN_SERVICE或REMOVED");
            }
            return parsed;
        } catch (IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_ROUTING_EVIDENCE_INVALID", "routingState非法");
            return null;
        }
    }

    private static String requestHash(ChangeRequest request) {
        String canonical = nullToEmpty(request.action).trim().toUpperCase(Locale.ROOT) + "\n"
                + nullToEmpty(request.nodeUuid).trim() + "\n"
                + nullToEmpty(request.endpoint).trim() + "\n"
                + nullToEmpty(request.routingState).trim().toUpperCase(Locale.ROOT) + "\n"
                + (request.evidenceTtlSeconds == null ? "" : request.evidenceTtlSeconds);
        return sha256(canonical.getBytes(StandardCharsets.UTF_8));
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

    private static String requireText(String value, String label, int maximum) {
        if (value == null || value.trim().isEmpty() || value.trim().length() > maximum) {
            fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID", label + "格式非法");
        }
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) {
                fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID", label + "包含控制字符");
            }
        }
        return value.trim();
    }

    private static void requireInitialized(MassDbLicenseState state) {
        if (state == null || !state.isInitialized()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_REQUIRED", "入口控制前必须完成License bootstrap");
        }
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static long absoluteDifference(long left, long right) {
        return left >= right ? left - right : right - left;
    }

    private static boolean equalsText(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static boolean equalsLong(Long left, Long right) {
        return left == null ? right == null : left.equals(right);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    private static final class Candidate {
        private final String action;
        private final String nodeUuid;
        private final MassDbLicenseIngressInventory inventory;

        private Candidate(String action, String nodeUuid,
                MassDbLicenseIngressInventory inventory) {
            this.action = action;
            this.nodeUuid = nodeUuid;
            this.inventory = inventory;
        }
    }

    public static final class ChangeRequest {
        public String action;
        public String nodeUuid;
        public String endpoint;
        public String routingState;
        public Long evidenceTtlSeconds;
    }

    public static final class RoutingEvidenceRequest {
        public String nodeUuid;
        public String adapterType;
        public String objectIdentity;
        public long objectRevision;
        public String routingState;
        public String evidenceDigest;
        public long observedAt;
    }

    public static final class View {
        public final long topologyRevision;
        public final MassDbLicenseIngressInventory.Evaluation evaluation;
        public final List<MassDbLicenseIngressInventory.IngressNode> nodes;

        private View(long topologyRevision,
                MassDbLicenseIngressInventory.Evaluation evaluation,
                List<MassDbLicenseIngressInventory.IngressNode> nodes) {
            this.topologyRevision = topologyRevision;
            this.evaluation = evaluation;
            this.nodes = Collections.unmodifiableList(new ArrayList<>(nodes));
        }
    }

    public static final class ValidateResult {
        public final boolean valid = true;
        public final boolean readyForApply = true;
        public final String action;
        public final String nodeUuid;
        public final long currentTopologyRevision;
        public final String candidateInventorySha256;
        public final String preconditionToken;
        public final long preconditionTokenExpiresAt;

        private ValidateResult(String action, String nodeUuid,
                long currentTopologyRevision, String candidateInventorySha256,
                String preconditionToken, long preconditionTokenExpiresAt) {
            this.action = action;
            this.nodeUuid = nodeUuid;
            this.currentTopologyRevision = currentTopologyRevision;
            this.candidateInventorySha256 = candidateInventorySha256;
            this.preconditionToken = preconditionToken;
            this.preconditionTokenExpiresAt = preconditionTokenExpiresAt;
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
