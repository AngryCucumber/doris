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

/**
 * Transport-independent NORMAL import core.
 *
 * <p>The HTTP layer must authenticate ADMIN before calling this class and must persist the returned
 * snapshot through {@link MassDbLicenseManager}. The prepared snapshot contains the staged bytes
 * and CAS binding; the final snapshot is returned only after every required ingress independently
 * ACKs the same candidate.</p>
 */
public final class MassDbLicenseImportCore {
    public enum LocalDecision {
        NONE,
        PENDING,
        COMMIT,
        ABORT,
        RESYNC_REQUIRED,
        UNKNOWN
    }

    private final long maxLicenseTermSeconds;
    private final Map<String, PublicKey> rootKeys;

    public MassDbLicenseImportCore(long maxLicenseTermSeconds, Map<String, PublicKey> rootKeys) {
        if (maxLicenseTermSeconds <= 0 || rootKeys == null || rootKeys.isEmpty()) {
            throw new IllegalArgumentException("maxLicenseTermSeconds和rootKeys必须配置");
        }
        this.maxLicenseTermSeconds = maxLicenseTermSeconds;
        this.rootKeys = Collections.unmodifiableMap(new LinkedHashMap<>(rootKeys));
    }

    /** Builds the matching read core without exposing immutable root anchors to the HTTP layer. */
    public MassDbLicenseReadApiCore createReadApiCore(String componentVersion) {
        return new MassDbLicenseReadApiCore(
                componentVersion, maxLicenseTermSeconds, rootKeys);
    }

    /** Builds the signed clock-recovery core from the same immutable component root trust. */
    public MassDbLicenseClockRecoveryCore createClockRecoveryCore() {
        return new MassDbLicenseClockRecoveryCore(rootKeys);
    }

    /** Builds the keyset/recovery-bundle core without exposing component root anchors. */
    public MassDbLicenseKeysetControlCore createKeysetControlCore() {
        return new MassDbLicenseKeysetControlCore(maxLicenseTermSeconds, rootKeys);
    }

    /** Builds the dual-control correction core from the same verification policy. */
    public MassDbLicenseCorrectionCore createCorrectionCore() {
        return new MassDbLicenseCorrectionCore(maxLicenseTermSeconds, rootKeys);
    }

    public Result prepareNormal(MassDbLicenseState state, byte[] artifact,
            String contentSha256, String preconditionToken, String idempotencyKey,
            String operationId, String requester, long effectiveNow, long deadlineAt) {
        if (artifact == null || artifact.length == 0) {
            throw new MassDbLicenseException("MASSDB_LICENSE_FILE_INVALID", "License工件不能为空");
        }
        if (artifact.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_FILE_TOO_LARGE", "License工件超过65536字节");
        }
        String actualSha256 = sha256(artifact);
        requireContentDigest(contentSha256, actualSha256);
        String requestHash = sha256(("LICENSE_IMPORT\nNORMAL\n" + actualSha256)
                .getBytes(StandardCharsets.US_ASCII));
        String replayOperationId = state.findOperationIdByIdempotency(idempotencyKey, requestHash);
        if (replayOperationId != null) {
            MassDbLicenseState.OperationView replay = state.findOperation(replayOperationId);
            return new Result(state, replayOperationId, true,
                    replay == null ? null : replay.action, replay != null && replay.terminal);
        }

        MassDbLicensePreconditionToken.Claims claims = MassDbLicensePreconditionToken.verify(
                state.getPreconditionHmacKey(), preconditionToken, effectiveNow);
        if (!"LICENSE_IMPORT".equals(claims.getAudience())) {
            fail("precondition audience错误");
        }
        MassDbLicenseProtocolV1.VerifiedKeyset keyset = verifyActiveKeyset(state, effectiveNow);
        MassDbLicenseProtocolV1.VerifiedLicense verified = MassDbLicenseProtocolV1.verifyLicense(
                artifact, keyset, effectiveNow, maxLicenseTermSeconds, null);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        MassDbLicenseIngressInventory.Evaluation ingress = state.getIngressInventory().evaluate(
                active, state.getEnforcementEpoch(), effectiveNow, true);
        String action = resolveAction(active, verified, ingress,
                active == null || activeStateHealthy(state, keyset, effectiveNow));
        if (!claims.getCandidateSha256().equals(verified.getSha256())
                || claims.getCandidateIssuedAt() != verified.getPayload().getIssuedAt()
                || claims.getCandidateExpiresAt() != verified.getPayload().getExpiresAt()
                || !claims.getAction().equals(action)
                || claims.getEnforcementEpoch() != state.getEnforcementEpoch()
                || claims.getTopologyRevision() != state.getTopologyRevision()
                || !claims.getInventorySnapshotSha256().equals(ingress.inventorySnapshotSha256)
                || !claims.getRoutingEvidenceSnapshotSha256().equals(
                        ingress.routingEvidenceSnapshotSha256)
                || !equalsText(claims.getActiveSha256(), active == null ? null : active.getSha256())
                || !equalsLong(claims.getActiveExpiresAt(),
                        active == null ? null : active.getExpiresAt())
                || !ingress.isReadyForImport() || state.getMutation() != null
                || state.hasActiveClockChallenge(effectiveNow)) {
            fail("active、epoch、topology、入口或候选语义已变化");
        }
        MassDbLicenseState.ActiveLicense candidate = new MassDbLicenseState.ActiveLicense(
                verified.getPayload().getLicenseId(), verified.getSha256(), verified.getKid(),
                verified.getPayload().getIssuedAt(), verified.getPayload().getExpiresAt(), artifact);
        MassDbLicenseState prepared = state.prepareNormalLicenseImport(operationId,
                idempotencyKey, requestHash, candidate, requester, action,
                state.getTopologyRevision(), ingress.inventorySnapshotSha256,
                ingress.routingEvidenceSnapshotSha256, ingress.requiredAckNodeUuids,
                ingress.deferredNodeUuids, effectiveNow, deadlineAt);
        if ("ALREADY_ACTIVE".equals(action)) {
            MassDbLicenseState terminal = prepared.commitNormalLicenseImport(
                    operationId, Collections.emptyList(), effectiveNow);
            return new Result(terminal, operationId, false, action, true);
        }
        return new Result(prepared, operationId, false, action, false);
    }

    public Result commitNormal(MassDbLicenseState prepared, String operationId,
            List<String> ackedNodeUuids, long effectiveNow) {
        MassDbLicenseState.Mutation mutation = prepared.getMutation();
        if (mutation == null || mutation.getCandidateLicense() == null
                || !operationId.equals(mutation.getOperationId())) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的prepared import");
        }
        MassDbLicenseState.ActiveLicense candidate = mutation.getCandidateLicense();
        MassDbLicenseProtocolV1.VerifiedKeyset keyset = verifyActiveKeyset(prepared, effectiveNow);
        MassDbLicenseProtocolV1.VerifiedLicense verified = MassDbLicenseProtocolV1.verifyLicense(
                candidate.getArtifact(), keyset, effectiveNow, maxLicenseTermSeconds, null);
        if (!verified.getSha256().equals(candidate.getSha256())) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", "staged License摘要不一致");
        }
        MassDbLicenseState terminal = prepared.commitNormalLicenseImport(operationId,
                ackedNodeUuids == null ? new ArrayList<>() : ackedNodeUuids, effectiveNow);
        return new Result(terminal, operationId, false, mutation.getAction(), true);
    }

    /**
     * Rebuilds a trusted node-distribution plan from the durable staged mutation after Leader
     * recovery. The caller must persist the returned state before acting on the plan. A corrupt or
     * no-longer-distributable mutation is converted to a stable FAILED operation here.
     */
    public RedriveResult recoverNormal(MassDbLicenseState state,
            String operationId, long effectiveNow) {
        MassDbLicenseState recovered = state.recoverOrExpireMutation(effectiveNow);
        MassDbLicenseState.OperationView view = recovered.findOperation(operationId);
        if (view == null) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的operation");
        }
        if (view.terminal) {
            return new RedriveResult(recovered, null, true, view.errorCode);
        }
        MassDbLicenseState.Mutation mutation = recovered.getMutation();
        if (mutation == null || !operationId.equals(mutation.getOperationId())
                || mutation.getKind() != MassDbLicenseState.MutationKind.LICENSE
                || mutation.getIntent() != MassDbLicenseState.ImportIntent.NORMAL
                || mutation.getCandidateLicense() == null) {
            MassDbLicenseState failed = recovered.failOperation(operationId,
                    "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", effectiveNow);
            return new RedriveResult(failed, null, true,
                    "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED");
        }
        MassDbLicenseState.ActiveLicense candidate = mutation.getCandidateLicense();
        try {
            MassDbLicenseProtocolV1.VerifiedKeyset keyset =
                    verifyActiveKeyset(recovered, effectiveNow);
            MassDbLicenseProtocolV1.VerifiedLicense verified =
                    MassDbLicenseProtocolV1.verifyLicense(candidate.getArtifact(), keyset,
                            effectiveNow, maxLicenseTermSeconds, null);
            if (!verified.getSha256().equals(candidate.getSha256())
                    || !verified.getKid().equals(candidate.getKid())
                    || !verified.getPayload().getLicenseId().equals(candidate.getLicenseId())
                    || verified.getPayload().getIssuedAt() != candidate.getIssuedAt()
                    || verified.getPayload().getExpiresAt() != candidate.getExpiresAt()) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", "staged License元数据不一致");
            }
            MassDbLicenseIngressInventory.Evaluation ingress =
                    recovered.getIngressInventory().evaluate(recovered.getActiveLicense(),
                            recovered.getEnforcementEpoch(), effectiveNow, true);
            if (!ingress.isReadyForImport()
                    || !mutation.getRequiredAckNodeUuids().equals(ingress.requiredAckNodeUuids)
                    || !mutation.getDeferredNodeUuids().equals(ingress.deferredNodeUuids)) {
                MassDbLicenseState failed = recovered.failOperation(operationId,
                        "MASSDB_LICENSE_INGRESS_UNAVAILABLE", effectiveNow);
                return new RedriveResult(failed, null, true,
                        "MASSDB_LICENSE_INGRESS_UNAVAILABLE");
            }
            MassDbLicenseState.ActiveLicense active = recovered.getActiveLicense();
            if (!equalsText(mutation.getSnapshotActiveSha256(),
                            active == null ? null : active.getSha256())
                    || !equalsLong(mutation.getSnapshotActiveExpiresAt(),
                            active == null ? null : active.getExpiresAt())
                    || !equalsLong(mutation.getSnapshotEnforcementEpoch(),
                            recovered.getEnforcementEpoch())
                    || !equalsLong(mutation.getSnapshotTopologyRevision(),
                            recovered.getTopologyRevision())
                    || !equalsText(mutation.getSnapshotInventorySha256(),
                            ingress.inventorySnapshotSha256)
                    || !equalsText(mutation.getSnapshotRoutingSha256(),
                            ingress.routingEvidenceSnapshotSha256)) {
                MassDbLicenseState failed = recovered.failOperation(operationId,
                        "MASSDB_LICENSE_PRECONDITION_FAILED", effectiveNow);
                return new RedriveResult(failed, null, true,
                        "MASSDB_LICENSE_PRECONDITION_FAILED");
            }
            RecoveryPlan plan = new RecoveryPlan(operationId, candidate.getSha256(),
                    candidate.getExpiresAt(), recovered.getEnforcementEpoch(),
                    mutation.getPreparedAt(), candidate.getArtifact(),
                    mutation.getRequiredAckNodeUuids(), mutation.getDeferredNodeUuids(),
                    mutation.getDeadlineAt());
            return new RedriveResult(recovered, plan, false, null);
        } catch (MassDbLicenseException error) {
            String failureCode = "MASSDB_LICENSE_EXPIRED".equals(error.getCode())
                    ? "MASSDB_LICENSE_EXPIRED" : "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED";
            MassDbLicenseState failed = recovered.failOperation(
                    operationId, failureCode, effectiveNow);
            return new RedriveResult(failed, null, true, failureCode);
        }
    }

    /** Each role verifies independently, then ACKs only durable license.pending read-back. */
    public MassDbLicenseLocalSnapshotStore.LicenseAck prepareLocalAck(
            MassDbLicenseLocalSnapshotStore store, RecoveryPlan plan,
            MassDbLicenseState localJournalState, long effectiveNow) {
        return prepareLocalAck(store, plan,
                verifyActiveKeyset(localJournalState, effectiveNow), effectiveNow);
    }

    /** Each role verifies independently, then ACKs only durable license.pending read-back. */
    public MassDbLicenseLocalSnapshotStore.LicenseAck prepareLocalAck(
            MassDbLicenseLocalSnapshotStore store, RecoveryPlan plan,
            MassDbLicenseProtocolV1.VerifiedKeyset keyset, long effectiveNow) {
        MassDbLicenseProtocolV1.VerifiedLicense verified =
                MassDbLicenseProtocolV1.verifyLicense(
                        plan.artifact, keyset, effectiveNow, maxLicenseTermSeconds, null);
        if (!verified.getSha256().equals(plan.contentSha256)
                || verified.getPayload().getExpiresAt() != plan.licenseExpiresAt) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", "角色节点候选License元数据不一致");
        }
        MassDbLicenseLocalSnapshotStore.LicensePending pending =
                new MassDbLicenseLocalSnapshotStore.LicensePending(
                        plan.operationId, plan.artifact, plan.contentSha256,
                        plan.licenseExpiresAt, plan.enforcementEpoch, plan.stagedCreatedAt);
        return store.prepareLicenseAck(pending);
    }

    public LocalDecision resolveLocalDecision(MassDbLicenseState state,
            MassDbLicenseLocalSnapshotStore.LicensePending pending) {
        if (pending == null) {
            return LocalDecision.NONE;
        }
        MassDbLicenseState.OperationView view = state.findOperation(pending.operationId);
        if (view == null || view.kind != MassDbLicenseState.MutationKind.LICENSE
                || (!"ACTIVATE".equals(view.action) && !"REPAIR".equals(view.action))
                || !pending.contentSha256.equals(view.contentSha256)
                || view.targetLicenseExpiresAt == null
                || view.targetLicenseExpiresAt != pending.expiresAt) {
            return LocalDecision.UNKNOWN;
        }
        if (view.state == MassDbLicenseState.OperationState.PREPARED) {
            return LocalDecision.PENDING;
        }
        if (view.state == MassDbLicenseState.OperationState.FAILED
                || view.state == MassDbLicenseState.OperationState.ABORTED) {
            return LocalDecision.ABORT;
        }
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        if (view.state == MassDbLicenseState.OperationState.SUCCEEDED
                && active != null && active.getSha256().equals(pending.contentSha256)
                && active.getExpiresAt() == pending.expiresAt
                && state.getEnforcementEpoch() == pending.enforcementEpoch) {
            return LocalDecision.COMMIT;
        }
        return view.state == MassDbLicenseState.OperationState.SUCCEEDED
                ? LocalDecision.RESYNC_REQUIRED : LocalDecision.UNKNOWN;
    }

    /** Applies only a proved terminal operation; UNKNOWN leaves staged bytes inert. */
    public LocalDecision applyAuthoritativeDecision(MassDbLicenseLocalSnapshotStore store,
            MassDbLicenseState state, long now) {
        MassDbLicenseLocalSnapshotStore.LicensePending pending = store.loadLicensePending();
        LocalDecision decision = resolveLocalDecision(state, pending);
        if (decision == LocalDecision.COMMIT) {
            store.commitLicense(pending.operationId, pending.contentSha256, now);
        } else if (decision == LocalDecision.ABORT) {
            store.abortLicense(pending.operationId);
        }
        return decision;
    }

    private MassDbLicenseProtocolV1.VerifiedKeyset verifyActiveKeyset(
            MassDbLicenseState state, long effectiveNow) {
        MassDbLicenseState.ActiveKeyset active = state.getActiveKeyset();
        if (active == null) {
            throw new MassDbLicenseException("MASSDB_LICENSE_KEYSET_INVALID", "尚未安装trusted keyset");
        }
        MassDbLicenseProtocolV1.VerifiedKeyset verified = MassDbLicenseProtocolV1.verifyKeyset(
                active.getArtifact(), rootKeys, effectiveNow, null);
        if (verified.getPayload().getKeysetVersion() != active.getVersion()
                || !verified.getSha256().equals(active.getSha256())) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_KEYSET_INVALID", "持久keyset元数据与工件不一致");
        }
        return verified;
    }

    /** Verifies a Leader-supplied public keyset directly from the offline component root trust. */
    MassDbLicenseProtocolV1.VerifiedKeyset verifyControlPlaneKeyset(
            byte[] artifact, long effectiveNow) {
        return MassDbLicenseProtocolV1.verifyKeyset(artifact, rootKeys, effectiveNow, null);
    }

    /** Verifies a Leader-supplied active License with an already root-authenticated keyset. */
    MassDbLicenseProtocolV1.VerifiedLicense verifyControlPlaneLicense(byte[] artifact,
            MassDbLicenseProtocolV1.VerifiedKeyset keyset, long effectiveNow) {
        return MassDbLicenseProtocolV1.verifyLicense(
                artifact, keyset, effectiveNow, maxLicenseTermSeconds, null);
    }

    long getMaxLicenseTermSeconds() {
        return maxLicenseTermSeconds;
    }

    private static String resolveAction(MassDbLicenseState.ActiveLicense active,
            MassDbLicenseProtocolV1.VerifiedLicense candidate,
            MassDbLicenseIngressInventory.Evaluation ingress, boolean activeHealthy) {
        if (active == null) {
            return "ACTIVATE";
        }
        if (active.getSha256().equals(candidate.getSha256())) {
            return activeHealthy && ingress.coveredIngressNodes == ingress.expectedIngressNodes
                    && "FRESH".equals(ingress.coverageFreshness) ? "ALREADY_ACTIVE" : "REPAIR";
        }
        if (candidate.getPayload().getExpiresAt() <= active.getExpiresAt()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_EXPIRY_NOT_EXTENDED", "NORMAL续期必须严格延长");
        }
        return "ACTIVATE";
    }

    private boolean activeStateHealthy(MassDbLicenseState state,
            MassDbLicenseProtocolV1.VerifiedKeyset keyset, long effectiveNow) {
        try {
            MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
            if (active == null || active.getExpiresAt() <= 0) {
                return false;
            }
            long validationNow = Math.min(effectiveNow, active.getExpiresAt() - 1);
            MassDbLicenseProtocolV1.VerifiedLicense verified = MassDbLicenseProtocolV1.verifyLicense(
                    active.getArtifact(), keyset, validationNow, maxLicenseTermSeconds, null);
            return verified.getSha256().equals(active.getSha256())
                    && verified.getKid().equals(active.getKid())
                    && verified.getPayload().getLicenseId().equals(active.getLicenseId())
                    && verified.getPayload().getIssuedAt() == active.getIssuedAt()
                    && verified.getPayload().getExpiresAt() == active.getExpiresAt();
        } catch (MassDbLicenseException error) {
            return false;
        }
    }

    private static String sha256(byte[] value) {
        if (value == null) {
            throw new MassDbLicenseException("MASSDB_LICENSE_FILE_INVALID", "License工件不能为空");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(String.format("%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    private static void requireContentDigest(String supplied, String actual) {
        if (supplied == null || !supplied.matches("[0-9a-fA-F]{64}")
                || !MessageDigest.isEqual(supplied.toLowerCase().getBytes(StandardCharsets.US_ASCII),
                        actual.getBytes(StandardCharsets.US_ASCII))) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_CONTENT_SHA256_MISMATCH", "Content-SHA256与实际请求体不一致");
        }
    }

    private static boolean equalsText(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static boolean equalsLong(Long left, Long right) {
        return left == null ? right == null : left.equals(right);
    }

    private static void fail(String message) {
        throw new MassDbLicenseException("MASSDB_LICENSE_PRECONDITION_FAILED", message);
    }

    public static final class Result {
        public final MassDbLicenseState state;
        public final String operationId;
        public final boolean replayed;
        public final String action;
        public final boolean terminal;

        private Result(MassDbLicenseState state, String operationId, boolean replayed,
                String action, boolean terminal) {
            this.state = state;
            this.operationId = operationId;
            this.replayed = replayed;
            this.action = action;
            this.terminal = terminal;
        }
    }

    public static final class RecoveryPlan {
        public final String operationId;
        public final String contentSha256;
        public final long licenseExpiresAt;
        public final long enforcementEpoch;
        public final long stagedCreatedAt;
        public final byte[] artifact;
        public final List<String> requiredAckNodeUuids;
        public final List<String> deferredNodeUuids;
        public final long deadlineAt;

        RecoveryPlan(String operationId, String contentSha256, long licenseExpiresAt,
                long enforcementEpoch, long stagedCreatedAt, byte[] artifact,
                List<String> requiredAckNodeUuids,
                List<String> deferredNodeUuids, long deadlineAt) {
            this.operationId = operationId;
            this.contentSha256 = contentSha256;
            this.licenseExpiresAt = licenseExpiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.stagedCreatedAt = stagedCreatedAt;
            this.artifact = artifact.clone();
            this.requiredAckNodeUuids = Collections.unmodifiableList(
                    new ArrayList<>(requiredAckNodeUuids));
            this.deferredNodeUuids = Collections.unmodifiableList(
                    new ArrayList<>(deferredNodeUuids));
            this.deadlineAt = deadlineAt;
        }
    }

    public static final class RedriveResult {
        public final MassDbLicenseState state;
        public final RecoveryPlan plan;
        public final boolean terminal;
        public final String errorCode;

        RedriveResult(MassDbLicenseState state, RecoveryPlan plan,
                boolean terminal, String errorCode) {
            this.state = state;
            this.plan = plan;
            this.terminal = terminal;
            this.errorCode = errorCode;
        }
    }
}
