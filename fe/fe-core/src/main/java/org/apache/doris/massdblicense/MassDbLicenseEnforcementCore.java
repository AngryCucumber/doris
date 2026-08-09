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
import java.util.UUID;

/**
 * Transport-independent recovery and role-local decision core for enforcement activation.
 *
 * <p>The FE leader must journal {@link RedriveResult#state} before dispatching its plan. Node ACKs
 * can only be built through {@link #prepareLocalAck}; external HTTP input is never an ACK source.</p>
 */
public final class MassDbLicenseEnforcementCore {
    private static final String AUDIENCE = "MASSDB_LICENSE_ENFORCEMENT";
    private static final String ACTION = "ACTIVATE_ENFORCEMENT";

    public enum Decision {
        NONE,
        PENDING,
        COMMIT,
        ABORT,
        RESYNC_REQUIRED,
        UNKNOWN
    }

    /** Read-only preflight that issues a state-bound token without persisting a mutation. */
    public ValidateResult validate(MassDbLicenseState state, long effectiveNow) {
        String validationId = "validate-" + UUID.randomUUID();
        state.prepareEnforcementActivation(validationId, validationId,
                sha256("ENFORCEMENT_VALIDATE"), effectiveNow,
                saturatedAdd(effectiveNow,
                        MassDbLicenseControlPreconditionToken.MAX_TTL_SECONDS));
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        MassDbLicenseIngressInventory.Evaluation ingress = state.getIngressInventory().evaluate(
                active, state.getEnforcementEpoch(), effectiveNow, false);
        long tokenExpiresAt = saturatedAdd(effectiveNow,
                MassDbLicenseControlPreconditionToken.MAX_TTL_SECONDS);
        String token = MassDbLicenseControlPreconditionToken.issue(
                state.getPreconditionHmacKey(),
                new MassDbLicenseControlPreconditionToken.Claims(AUDIENCE, ACTION, "",
                        active.getSha256(), active.getExpiresAt(),
                        state.getEnforcementEpoch(), state.getTopologyRevision(),
                        ingress.inventorySnapshotSha256,
                        ingress.routingEvidenceSnapshotSha256, active.getSha256(),
                        state.getEnforcementEpoch() + 1, 0, 0, 0, 0,
                        effectiveNow, tokenExpiresAt, UUID.randomUUID().toString()));
        return new ValidateResult(active, state, ingress, token, tokenExpiresAt);
    }

    /** Verifies the validate-time snapshot and durably enters the shared mutation slot. */
    public PrepareResult prepare(MassDbLicenseState state, String preconditionToken,
            String idempotencyKey, String operationId, long effectiveNow, long deadlineAt) {
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        if (active == null) {
            fail("MASSDB_LICENSE_MISSING", "激活查询限制前必须安装有效License");
        }
        String requestHash = sha256("ENFORCEMENT\n" + active.getSha256());
        String replayId = state.findOperationIdByIdempotency(idempotencyKey, requestHash);
        if (replayId != null) {
            MassDbLicenseState.OperationView replay = state.findOperation(replayId);
            return new PrepareResult(state, replayId, true,
                    replay != null && replay.terminal);
        }
        MassDbLicenseIngressInventory.Evaluation ingress = state.getIngressInventory().evaluate(
                active, state.getEnforcementEpoch(), effectiveNow, false);
        MassDbLicenseControlPreconditionToken.Claims claims =
                MassDbLicenseControlPreconditionToken.verify(
                        state.getPreconditionHmacKey(), preconditionToken, effectiveNow);
        if (!AUDIENCE.equals(claims.audience) || !ACTION.equals(claims.action)
                || !active.getSha256().equals(claims.activeSha256)
                || claims.activeExpiresAt == null
                || active.getExpiresAt() != claims.activeExpiresAt
                || state.getEnforcementEpoch() != claims.enforcementEpoch
                || state.getTopologyRevision() != claims.topologyRevision
                || !ingress.inventorySnapshotSha256.equals(
                        claims.inventorySnapshotSha256)
                || !ingress.routingEvidenceSnapshotSha256.equals(
                        claims.routingEvidenceSnapshotSha256)
                || !active.getSha256().equals(claims.candidateSha256)
                || state.getEnforcementEpoch() + 1 != claims.targetValue1) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "enforcement active、epoch、topology或入口快照已变化");
        }
        MassDbLicenseState prepared = state.prepareEnforcementActivation(operationId,
                idempotencyKey, requestHash, effectiveNow, deadlineAt);
        return new PrepareResult(prepared, operationId, false, false);
    }

    public RedriveResult recover(MassDbLicenseState state, String operationId, long effectiveNow) {
        MassDbLicenseState recovered = state.recoverOrExpireMutation(effectiveNow);
        MassDbLicenseState.OperationView view = recovered.findOperation(operationId);
        if (view == null) {
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的operation");
        }
        if (view.terminal) {
            return new RedriveResult(recovered, null, true, view.errorCode);
        }
        MassDbLicenseState.Mutation mutation = recovered.getMutation();
        if (mutation == null || mutation.getKind() != MassDbLicenseState.MutationKind.ENFORCEMENT
                || !operationId.equals(mutation.getOperationId())
                || !"ACTIVATE_ENFORCEMENT".equals(mutation.getAction())
                || mutation.getSnapshotActiveSha256() == null
                || mutation.getSnapshotActiveExpiresAt() == null
                || mutation.getSnapshotEnforcementEpoch() == null
                || mutation.getTargetEnforcementEpoch() == null
                || mutation.getSnapshotTopologyRevision() == null
                || mutation.getSnapshotInventorySha256() == null
                || mutation.getSnapshotRoutingSha256() == null
                || !mutation.getDeferredNodeUuids().isEmpty()) {
            return failRecovered(recovered, operationId,
                    "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", effectiveNow);
        }
        MassDbLicenseState.ActiveLicense active = recovered.getActiveLicense();
        if (active == null || effectiveNow >= active.getExpiresAt()) {
            return failRecovered(recovered, operationId,
                    active == null ? "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED"
                            : "MASSDB_LICENSE_EXPIRED",
                    effectiveNow);
        }
        if (recovered.getEnforcementMode() != MassDbLicenseState.EnforcementMode.OBSERVE
                || recovered.getEnforcementEpoch() == Long.MAX_VALUE
                || mutation.getTargetEnforcementEpoch() != recovered.getEnforcementEpoch() + 1
                || !active.getSha256().equals(mutation.getSnapshotActiveSha256())
                || active.getExpiresAt() != mutation.getSnapshotActiveExpiresAt()
                || recovered.getEnforcementEpoch() != mutation.getSnapshotEnforcementEpoch()
                || recovered.getTopologyRevision() != mutation.getSnapshotTopologyRevision()
                || recovered.hasActiveClockChallenge(effectiveNow)) {
            return failRecovered(recovered, operationId,
                    "MASSDB_LICENSE_PRECONDITION_FAILED", effectiveNow);
        }
        MassDbLicenseIngressInventory.Evaluation ingress = recovered.getIngressInventory().evaluate(
                active, recovered.getEnforcementEpoch(), effectiveNow, false);
        if (!mutation.getSnapshotInventorySha256().equals(ingress.inventorySnapshotSha256)
                || !mutation.getSnapshotRoutingSha256().equals(
                        ingress.routingEvidenceSnapshotSha256)
                || !mutation.getRequiredAckNodeUuids().equals(ingress.requiredAckNodeUuids)) {
            return failRecovered(recovered, operationId,
                    "MASSDB_LICENSE_PRECONDITION_FAILED", effectiveNow);
        }
        if (ingress.expectedIngressNodes <= 0
                || ingress.liveIngressNodes != ingress.expectedIngressNodes
                || ingress.coveredIngressNodes != ingress.expectedIngressNodes
                || ingress.deferredOfflineIngressNodes != 0
                || !"FRESH".equals(ingress.coverageFreshness)
                || !ingress.blockers.isEmpty()) {
            return failRecovered(recovered, operationId,
                    "MASSDB_LICENSE_INGRESS_UNAVAILABLE", effectiveNow);
        }
        RecoveryPlan plan = new RecoveryPlan(operationId, active.getSha256(),
                active.getExpiresAt(), recovered.getEnforcementEpoch(),
                mutation.getTargetEnforcementEpoch(), recovered.getTopologyRevision(),
                mutation.getSnapshotInventorySha256(), mutation.getSnapshotRoutingSha256(),
                mutation.getRequiredAckNodeUuids(), mutation.getPreparedAt(),
                mutation.getDeadlineAt());
        return new RedriveResult(recovered, plan, false, null);
    }

    /** Persists role-local pending and converts only its read-back ACK into leader evidence. */
    public MassDbLicenseState.ActivationAckEvidence prepareLocalAck(
            MassDbLicenseLocalSnapshotStore store, RecoveryPlan plan) {
        MassDbLicenseLocalSnapshotStore.ActivationPending pending =
                new MassDbLicenseLocalSnapshotStore.ActivationPending(
                        plan.operationId, plan.targetEnforcementEpoch,
                        plan.activeLicenseSha256, plan.activationCreatedAt);
        MassDbLicenseLocalSnapshotStore.ActivationAck ack =
                store.prepareActivationAck(pending);
        return new MassDbLicenseState.ActivationAckEvidence(
                ack.nodeUuid, ack.operationId, ack.targetEnforcementEpoch,
                ack.activeSha256, ack.pendingSnapshotSha256);
    }

    public Decision resolveDecision(MassDbLicenseState state,
            MassDbLicenseLocalSnapshotStore.ActivationPending pending) {
        if (pending == null) {
            return Decision.NONE;
        }
        MassDbLicenseState.OperationView view = state.findOperation(pending.operationId);
        if (view == null || view.kind != MassDbLicenseState.MutationKind.ENFORCEMENT
                || !"ACTIVATE_ENFORCEMENT".equals(view.action)
                || view.targetEnforcementEpoch == null
                || view.targetEnforcementEpoch != pending.targetEnforcementEpoch
                || !pending.activeSha256.equals(view.contentSha256)) {
            return Decision.UNKNOWN;
        }
        if (view.state == MassDbLicenseState.OperationState.PREPARED) {
            return Decision.PENDING;
        }
        if (view.state == MassDbLicenseState.OperationState.FAILED
                || view.state == MassDbLicenseState.OperationState.ABORTED) {
            return Decision.ABORT;
        }
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        if (view.state == MassDbLicenseState.OperationState.SUCCEEDED
                && state.getEnforcementMode() == MassDbLicenseState.EnforcementMode.ENFORCING
                && state.getEnforcementEpoch() == pending.targetEnforcementEpoch
                && active != null && active.getSha256().equals(pending.activeSha256)) {
            return Decision.COMMIT;
        }
        return view.state == MassDbLicenseState.OperationState.SUCCEEDED
                ? Decision.RESYNC_REQUIRED : Decision.UNKNOWN;
    }

    /** Applies only a proved terminal decision; unresolved state leaves pending fail-closed. */
    public Decision applyAuthoritativeDecision(MassDbLicenseLocalSnapshotStore store,
            MassDbLicenseState state, long now) {
        MassDbLicenseLocalSnapshotStore.ActivationPending pending = store.loadPending();
        Decision decision = resolveDecision(state, pending);
        if (decision == Decision.COMMIT) {
            store.commitActivation(pending.operationId, pending.targetEnforcementEpoch, now);
        } else if (decision == Decision.ABORT) {
            store.abortActivation(pending.operationId);
        }
        return decision;
    }

    private static RedriveResult failRecovered(MassDbLicenseState state,
            String operationId, String errorCode, long now) {
        MassDbLicenseState failed = state.failOperation(operationId, errorCode, now);
        return new RedriveResult(failed, null, true, errorCode);
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                    value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    public static final class RecoveryPlan {
        public final String operationId;
        public final String activeLicenseSha256;
        public final long activeLicenseExpiresAt;
        public final long currentEnforcementEpoch;
        public final long targetEnforcementEpoch;
        public final long topologyRevision;
        public final String inventorySnapshotSha256;
        public final String routingSnapshotSha256;
        public final List<String> requiredAckNodeUuids;
        public final long activationCreatedAt;
        public final long deadlineAt;

        private RecoveryPlan(String operationId, String activeLicenseSha256,
                long activeLicenseExpiresAt, long currentEnforcementEpoch,
                long targetEnforcementEpoch, long topologyRevision,
                String inventorySnapshotSha256, String routingSnapshotSha256,
                List<String> requiredAckNodeUuids, long activationCreatedAt,
                long deadlineAt) {
            this.operationId = operationId;
            this.activeLicenseSha256 = activeLicenseSha256;
            this.activeLicenseExpiresAt = activeLicenseExpiresAt;
            this.currentEnforcementEpoch = currentEnforcementEpoch;
            this.targetEnforcementEpoch = targetEnforcementEpoch;
            this.topologyRevision = topologyRevision;
            this.inventorySnapshotSha256 = inventorySnapshotSha256;
            this.routingSnapshotSha256 = routingSnapshotSha256;
            this.requiredAckNodeUuids = Collections.unmodifiableList(
                    new ArrayList<>(requiredAckNodeUuids));
            this.activationCreatedAt = activationCreatedAt;
            this.deadlineAt = deadlineAt;
        }
    }

    public static final class ValidateResult {
        public final boolean valid = true;
        public final boolean readyForActivation = true;
        public final long currentEnforcementEpoch;
        public final long targetEnforcementEpoch;
        public final String activeLicenseSha256;
        public final long activeLicenseExpiresAt;
        public final int expectedIngressNodes;
        public final int liveIngressNodes;
        public final int coveredIngressNodes;
        public final String preconditionToken;
        public final long preconditionTokenExpiresAt;

        private ValidateResult(MassDbLicenseState.ActiveLicense active,
                MassDbLicenseState state,
                MassDbLicenseIngressInventory.Evaluation ingress,
                String preconditionToken, long preconditionTokenExpiresAt) {
            this.currentEnforcementEpoch = state.getEnforcementEpoch();
            this.targetEnforcementEpoch = state.getEnforcementEpoch() + 1;
            this.activeLicenseSha256 = active.getSha256();
            this.activeLicenseExpiresAt = active.getExpiresAt();
            this.expectedIngressNodes = ingress.expectedIngressNodes;
            this.liveIngressNodes = ingress.liveIngressNodes;
            this.coveredIngressNodes = ingress.coveredIngressNodes;
            this.preconditionToken = preconditionToken;
            this.preconditionTokenExpiresAt = preconditionTokenExpiresAt;
        }
    }

    public static final class PrepareResult {
        public final MassDbLicenseState state;
        public final String operationId;
        public final boolean replayed;
        public final boolean terminal;

        private PrepareResult(MassDbLicenseState state, String operationId,
                boolean replayed, boolean terminal) {
            this.state = state;
            this.operationId = operationId;
            this.replayed = replayed;
            this.terminal = terminal;
        }
    }

    public static final class RedriveResult {
        public final MassDbLicenseState state;
        public final RecoveryPlan plan;
        public final boolean terminal;
        public final String errorCode;

        private RedriveResult(MassDbLicenseState state, RecoveryPlan plan,
                boolean terminal, String errorCode) {
            this.state = state;
            this.plan = plan;
            this.terminal = terminal;
            this.errorCode = errorCode;
        }
    }
}
