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

/** Root-authenticated monotonic keyset and atomic keyset+License recovery core. */
public final class MassDbLicenseKeysetControlCore {
    private static final String KEYSET_AUDIENCE = "KEYSET_IMPORT";
    private static final String BUNDLE_AUDIENCE = "KEYSET_RECOVERY_BUNDLE";
    private final long maxLicenseTermSeconds;
    private final Map<String, PublicKey> rootKeys;

    public MassDbLicenseKeysetControlCore(long maxLicenseTermSeconds,
            Map<String, PublicKey> rootKeys) {
        if (maxLicenseTermSeconds <= 0 || rootKeys == null || rootKeys.isEmpty()) {
            throw new IllegalArgumentException("maxLicenseTermSeconds和rootKeys必须配置");
        }
        this.maxLicenseTermSeconds = maxLicenseTermSeconds;
        this.rootKeys = Collections.unmodifiableMap(new LinkedHashMap<>(rootKeys));
    }

    public StatusResult status(MassDbLicenseState state, long effectiveNow) {
        MassDbLicenseProtocolV1.VerifiedKeyset keyset = verifyCurrent(state, effectiveNow);
        String activeKid = state.getActiveLicense() == null
                ? null : state.getActiveLicense().getKid();
        boolean activeKidTrusted = activeKid != null
                && keyset.getPayload().getKeys().containsKey(activeKid)
                && !keyset.getPayload().getRevokedKids().contains(activeKid);
        return new StatusResult(keyset, activeKid, activeKidTrusted);
    }

    public ValidateResult validateKeyset(MassDbLicenseState state, byte[] artifact,
            long effectiveNow) {
        StandaloneCandidate candidate = verifyStandalone(state, artifact, effectiveNow);
        return issueValidation(state, candidate.verified.getSha256(),
                candidate.verified.getPayload().getKeysetVersion(), candidate.kind,
                null, null, effectiveNow);
    }

    public ValidateResult validateBundle(MassDbLicenseState state, byte[] artifact,
            long effectiveNow) {
        BundleCandidate candidate = verifyBundle(state, artifact, effectiveNow);
        return issueValidation(state, candidate.verified.getSha256(),
                candidate.verified.getKeyset().getPayload().getKeysetVersion(),
                MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE,
                candidate.verified.getLicense(), candidate.verified.getSha256(), effectiveNow);
    }

    public Result prepareKeyset(MassDbLicenseState state, byte[] artifact,
            String contentSha256, String preconditionToken, String idempotencyKey,
            String operationId, long effectiveNow, long deadlineAt) {
        String actual = sha256(artifact);
        requireDigest(contentSha256, actual);
        String requestHash = sha256(("KEYSET_IMPORT\n" + actual)
                .getBytes(StandardCharsets.US_ASCII));
        Result replay = replay(state, idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        StandaloneCandidate candidate = verifyStandalone(state, artifact, effectiveNow);
        MassDbLicenseIngressInventory.Evaluation ingress = ingressFor(
                state, candidate.kind, effectiveNow);
        matchToken(state, ingress, preconditionToken, KEYSET_AUDIENCE,
                candidate.kind.name(), actual,
                candidate.verified.getPayload().getKeysetVersion(), 0, effectiveNow);
        MassDbLicenseState.ActiveKeyset keyset = new MassDbLicenseState.ActiveKeyset(
                candidate.verified.getPayload().getKeysetVersion(), actual, artifact);
        MassDbLicenseState prepared = state.prepareKeyset(operationId, idempotencyKey,
                requestHash, candidate.kind, keyset, effectiveNow, deadlineAt);
        return new Result(prepared, operationId, false, false);
    }

    public Result prepareBundle(MassDbLicenseState state, byte[] artifact,
            String contentSha256, String preconditionToken, String idempotencyKey,
            String operationId, long effectiveNow, long deadlineAt) {
        String actual = sha256(artifact);
        requireDigest(contentSha256, actual);
        String requestHash = sha256(("KEYSET_RECOVERY_BUNDLE\n" + actual)
                .getBytes(StandardCharsets.US_ASCII));
        Result replay = replay(state, idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        BundleCandidate candidate = verifyBundle(state, artifact, effectiveNow);
        MassDbLicenseIngressInventory.Evaluation ingress = ingressFor(state,
                MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE,
                effectiveNow);
        matchToken(state, ingress, preconditionToken, BUNDLE_AUDIENCE,
                MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE.name(),
                actual, candidate.verified.getKeyset().getPayload().getKeysetVersion(),
                candidate.verified.getLicense().getPayload().getExpiresAt(), effectiveNow);
        MassDbLicenseState.ActiveKeyset keyset = new MassDbLicenseState.ActiveKeyset(
                candidate.verified.getKeyset().getPayload().getKeysetVersion(),
                candidate.verified.getKeyset().getSha256(),
                candidate.verified.getKeysetArtifact());
        MassDbLicenseProtocolV1.VerifiedLicense verifiedLicense =
                candidate.verified.getLicense();
        MassDbLicenseState.ActiveLicense license = new MassDbLicenseState.ActiveLicense(
                verifiedLicense.getPayload().getLicenseId(), verifiedLicense.getSha256(),
                verifiedLicense.getKid(), verifiedLicense.getPayload().getIssuedAt(),
                verifiedLicense.getPayload().getExpiresAt(),
                candidate.verified.getLicenseArtifact());
        MassDbLicenseState prepared = state.prepareRecoveryBundle(operationId,
                idempotencyKey, requestHash, keyset, license, effectiveNow, deadlineAt);
        return new Result(prepared, operationId, false, false);
    }

    /** Leader-only redrive; it never activates key material before every frozen role ACKs. */
    public RedriveResult recover(MassDbLicenseState state, String operationId,
            long effectiveNow) {
        MassDbLicenseState recovered = state.recoverOrExpireMutation(effectiveNow);
        MassDbLicenseState.OperationView view = recovered.findOperation(operationId);
        if (view == null) {
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的keyset operation");
        }
        if (view.terminal) {
            return new RedriveResult(recovered, null, true, view.errorCode);
        }
        MassDbLicenseState.Mutation mutation = recovered.getMutation();
        if (mutation == null || !operationId.equals(mutation.getOperationId())
                || mutation.getCandidateKeyset() == null) {
            return failed(recovered, operationId, effectiveNow);
        }
        try {
            MassDbLicenseIngressInventory.Evaluation ingress;
            if (mutation.getKind()
                    == MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE) {
                if (mutation.getCandidateLicense() == null) {
                    return failed(recovered, operationId, effectiveNow);
                }
                MassDbLicenseProtocolV1.VerifiedKeyset keyset =
                        MassDbLicenseProtocolV1.verifyKeyset(
                                mutation.getCandidateKeyset().getArtifact(), rootKeys,
                                effectiveNow, recovered.getKeysetVersion());
                MassDbLicenseProtocolV1.VerifiedLicense license =
                        MassDbLicenseProtocolV1.verifyLicense(
                                mutation.getCandidateLicense().getArtifact(), keyset,
                                effectiveNow, maxLicenseTermSeconds, null);
                if (!keyset.getSha256().equals(
                                mutation.getCandidateKeyset().getSha256())
                        || !license.getSha256().equals(
                                mutation.getCandidateLicense().getSha256())) {
                    return failed(recovered, operationId, effectiveNow);
                }
                ingress = ingressFor(recovered, mutation.getKind(), effectiveNow);
            } else {
                StandaloneCandidate candidate = verifyStandalone(recovered,
                        mutation.getCandidateKeyset().getArtifact(), effectiveNow);
                if (candidate.kind != mutation.getKind()
                        || !candidate.verified.getSha256().equals(
                                mutation.getCandidateKeyset().getSha256())) {
                    return failed(recovered, operationId, effectiveNow);
                }
                ingress = ingressFor(recovered, mutation.getKind(), effectiveNow);
            }
            if (!equalsText(mutation.getSnapshotInventorySha256(),
                            ingress.inventorySnapshotSha256)
                    || !equalsText(mutation.getSnapshotRoutingSha256(),
                            ingress.routingEvidenceSnapshotSha256)
                    || !mutation.getRequiredAckNodeUuids().equals(
                            ingress.requiredAckNodeUuids)
                    || !mutation.getDeferredNodeUuids().equals(
                            ingress.deferredNodeUuids)) {
                return failed(recovered, operationId, effectiveNow);
            }
            MassDbLicenseState.ActiveLicense license = mutation.getCandidateLicense();
            RecoveryPlan plan = new RecoveryPlan(operationId, mutation.getKind(),
                    mutation.getAction(), mutation.getCandidateKeyset().getArtifact(),
                    mutation.getCandidateKeyset().getSha256(),
                    mutation.getCandidateKeyset().getVersion(),
                    license == null ? null : license.getArtifact(),
                    license == null ? null : license.getSha256(),
                    license == null ? 0 : license.getExpiresAt(),
                    recovered.getEnforcementEpoch(), mutation.getPreparedAt(),
                    mutation.getRequiredAckNodeUuids(), mutation.getDeferredNodeUuids(),
                    mutation.getDeadlineAt());
            return new RedriveResult(recovered, plan, false, null);
        } catch (MassDbLicenseException error) {
            return failed(recovered, operationId, effectiveNow);
        }
    }

    /** Re-verifies candidate bytes and returns ACK only from durable role-local read-back. */
    public MassDbLicenseLocalSnapshotStore.ControlAck prepareLocalAck(
            MassDbLicenseLocalSnapshotStore store, RecoveryPlan plan,
            long effectiveNow) {
        if (store == null || plan == null || effectiveNow <= 0
                || !plan.requiredAckNodeUuids.contains(store.getNodeUuid())
                || effectiveNow >= plan.deadlineAt) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "keyset角色计划已过期或目标不匹配");
        }
        MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint checkpoint =
                store.loadControlPlaneCheckpoint();
        if (checkpoint == null || checkpoint.activeKeysetVersion <= 0
                || checkpoint.enforcementEpoch != plan.enforcementEpoch) {
            fail("MASSDB_LICENSE_CONTROL_PLANE_STALE", "keyset prepare缺少匹配的控制面快照");
        }
        MassDbLicenseProtocolV1.VerifiedKeyset candidate =
                MassDbLicenseProtocolV1.verifyKeyset(plan.keysetArtifact, rootKeys,
                        effectiveNow, checkpoint.activeKeysetVersion);
        if (!candidate.getSha256().equals(plan.keysetSha256)
                || candidate.getPayload().getKeysetVersion() != plan.keysetVersion) {
            fail("MASSDB_LICENSE_KEYSET_INVALID", "keyset角色复验元数据不一致");
        }
        MassDbLicenseLocalSnapshotStore.ActiveSnapshot active = store.loadActive();
        if (checkpoint.activeLicenseSha256 != null) {
            if (active == null || !active.sha256.equals(checkpoint.activeLicenseSha256)
                    || active.expiresAt != checkpoint.activeLicenseExpiresAt) {
                fail("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT", "keyset角色无法读取当前active");
            }
            long validationNow = Math.min(effectiveNow, active.expiresAt - 1);
            try {
                MassDbLicenseProtocolV1.verifyLicense(active.artifact, candidate,
                        validationNow, maxLicenseTermSeconds, null);
            } catch (MassDbLicenseException error) {
                if (plan.kind
                        != MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE) {
                    fail("MASSDB_LICENSE_KEYSET_RECOVERY_BUNDLE_REQUIRED",
                            "候选keyset会使本地active失效");
                }
            }
        }
        if (plan.kind == MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE) {
            MassDbLicenseProtocolV1.VerifiedLicense replacement =
                    MassDbLicenseProtocolV1.verifyLicense(plan.licenseArtifact, candidate,
                            effectiveNow, maxLicenseTermSeconds, null);
            if (!replacement.getSha256().equals(plan.licenseSha256)
                    || replacement.getPayload().getExpiresAt() != plan.licenseExpiresAt) {
                fail("MASSDB_LICENSE_FILE_INVALID", "bundle replacement License复验失败");
            }
        }
        return store.prepareControlAck(new MassDbLicenseLocalSnapshotStore.ControlPending(
                plan.operationId, plan.kind, plan.keysetArtifact, plan.keysetSha256,
                plan.keysetVersion, plan.licenseArtifact, plan.licenseSha256,
                plan.licenseExpiresAt, plan.enforcementEpoch, plan.stagedCreatedAt));
    }

    public MassDbLicenseState commit(MassDbLicenseState state, String operationId,
            List<MassDbLicenseState.KeysetAckEvidence> evidence, long effectiveNow) {
        return state.commitKeysetControl(operationId, evidence, effectiveNow);
    }

    private ValidateResult issueValidation(MassDbLicenseState state,
            String contentSha256, long candidateVersion,
            MassDbLicenseState.MutationKind kind,
            MassDbLicenseProtocolV1.VerifiedLicense replacement,
            String bundleSha256, long effectiveNow) {
        MassDbLicenseIngressInventory.Evaluation ingress =
                ingressFor(state, kind, effectiveNow);
        String audience = kind
                == MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE
                ? BUNDLE_AUDIENCE : KEYSET_AUDIENCE;
        String candidateSha = bundleSha256 == null ? contentSha256 : bundleSha256;
        long replacementExpiresAt = replacement == null
                ? 0 : replacement.getPayload().getExpiresAt();
        long expiresAt = saturatedAdd(effectiveNow,
                MassDbLicenseControlPreconditionToken.MAX_TTL_SECONDS);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        String token = MassDbLicenseControlPreconditionToken.issue(
                state.getPreconditionHmacKey(),
                new MassDbLicenseControlPreconditionToken.Claims(audience, kind.name(), "",
                        active == null ? null : active.getSha256(),
                        active == null ? null : active.getExpiresAt(),
                        state.getEnforcementEpoch(), state.getTopologyRevision(),
                        ingress.inventorySnapshotSha256,
                        ingress.routingEvidenceSnapshotSha256, candidateSha,
                        candidateVersion, replacementExpiresAt, 0,
                        state.getKeysetVersion(), 0, effectiveNow, expiresAt,
                        UUID.randomUUID().toString()));
        return new ValidateResult(kind.name(), candidateSha, candidateVersion,
                state.getKeysetVersion(), replacement, state.getTopologyRevision(),
                ingress, token);
    }

    private void matchToken(MassDbLicenseState state,
            MassDbLicenseIngressInventory.Evaluation ingress, String token,
            String audience, String action, String candidateSha256,
            long candidateVersion, long replacementExpiresAt, long effectiveNow) {
        MassDbLicenseControlPreconditionToken.Claims claims =
                MassDbLicenseControlPreconditionToken.verify(
                        state.getPreconditionHmacKey(), token, effectiveNow);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        if (!audience.equals(claims.audience) || !action.equals(claims.action)
                || !equalsText(claims.activeSha256,
                        active == null ? null : active.getSha256())
                || !equalsLong(claims.activeExpiresAt,
                        active == null ? null : active.getExpiresAt())
                || claims.enforcementEpoch != state.getEnforcementEpoch()
                || claims.topologyRevision != state.getTopologyRevision()
                || !ingress.inventorySnapshotSha256.equals(
                        claims.inventorySnapshotSha256)
                || !ingress.routingEvidenceSnapshotSha256.equals(
                        claims.routingEvidenceSnapshotSha256)
                || !candidateSha256.equals(claims.candidateSha256)
                || candidateVersion != claims.targetValue1
                || replacementExpiresAt != claims.targetValue2
                || state.getKeysetVersion() != claims.snapshotValue1) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "keyset token与当前active、topology、入口或工件不匹配");
        }
    }

    private StandaloneCandidate verifyStandalone(MassDbLicenseState state,
            byte[] artifact, long effectiveNow) {
        MassDbLicenseProtocolV1.VerifiedKeyset current = verifyCurrent(state, effectiveNow);
        MassDbLicenseProtocolV1.VerifiedKeyset candidate =
                MassDbLicenseProtocolV1.verifyKeyset(artifact, rootKeys, effectiveNow,
                        state.getKeysetVersion());
        boolean additive = candidate.getPayload().getRevokedKids().containsAll(
                current.getPayload().getRevokedKids());
        for (Map.Entry<String, MassDbLicenseProtocolV1.TrustedKey> entry
                : current.getPayload().getKeys().entrySet()) {
            MassDbLicenseProtocolV1.TrustedKey replacement =
                    candidate.getPayload().getKeys().get(entry.getKey());
            if (replacement == null
                    || replacement.getUse() != entry.getValue().getUse()
                    || !MessageDigest.isEqual(replacement.getPublicKey().getEncoded(),
                            entry.getValue().getPublicKey().getEncoded())
                    || candidate.getPayload().getRevokedKids().contains(entry.getKey())
                            && !current.getPayload().getRevokedKids().contains(entry.getKey())) {
                additive = false;
            }
        }
        MassDbLicenseState.MutationKind kind = additive
                ? MassDbLicenseState.MutationKind.ADDITIVE_KEYSET
                : MassDbLicenseState.MutationKind.RESTRICTIVE_KEYSET;
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        if (active != null && (!candidate.getPayload().getKeys().containsKey(active.getKid())
                || candidate.getPayload().getRevokedKids().contains(active.getKid()))) {
            fail("MASSDB_LICENSE_KEYSET_RECOVERY_BUNDLE_REQUIRED",
                    "候选keyset不再信任active License kid，必须使用恢复bundle");
        }
        ingressFor(state, kind, effectiveNow);
        return new StandaloneCandidate(candidate, kind);
    }

    private BundleCandidate verifyBundle(MassDbLicenseState state,
            byte[] artifact, long effectiveNow) {
        verifyCurrent(state, effectiveNow);
        MassDbLicenseProtocolV1.VerifiedRecoveryBundle verified =
                MassDbLicenseProtocolV1.verifyRecoveryBundleFull(artifact, rootKeys,
                        effectiveNow, maxLicenseTermSeconds, state.getKeysetVersion());
        ingressFor(state, MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE,
                effectiveNow);
        return new BundleCandidate(verified);
    }

    private MassDbLicenseProtocolV1.VerifiedKeyset verifyCurrent(
            MassDbLicenseState state, long effectiveNow) {
        MassDbLicenseState.ActiveKeyset current = state.getActiveKeyset();
        if (!state.isInitialized() || current == null) {
            fail("MASSDB_LICENSE_KEYSET_INVALID", "尚未安装active keyset");
        }
        MassDbLicenseProtocolV1.VerifiedKeyset verified =
                MassDbLicenseProtocolV1.verifyKeyset(current.getArtifact(),
                        rootKeys, effectiveNow, null);
        if (verified.getPayload().getKeysetVersion() != current.getVersion()
                || !verified.getSha256().equals(current.getSha256())) {
            fail("MASSDB_LICENSE_KEYSET_INVALID", "active keyset元数据或签名无效");
        }
        return verified;
    }

    private MassDbLicenseIngressInventory.Evaluation ingressFor(MassDbLicenseState state,
            MassDbLicenseState.MutationKind kind, long effectiveNow) {
        boolean allowDeferred = kind == MassDbLicenseState.MutationKind.ADDITIVE_KEYSET;
        MassDbLicenseIngressInventory.Evaluation ingress = state.getIngressInventory().evaluate(
                state.getActiveLicense(), state.getEnforcementEpoch(),
                effectiveNow, allowDeferred);
        if (!ingress.isReadyForImport()
                || !allowDeferred && ingress.liveIngressNodes != ingress.expectedIngressNodes) {
            fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE",
                    "keyset变更的入口覆盖不满足安全条件");
        }
        if (kind == MassDbLicenseState.MutationKind.ADDITIVE_KEYSET
                && state.hasActiveClockChallenge(effectiveNow)) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_CHALLENGE_ACTIVE",
                    "active时钟恢复challenge冻结加法keyset");
        }
        return ingress;
    }

    private Result replay(MassDbLicenseState state, String idempotencyKey,
            String requestHash) {
        String operationId = state.findOperationIdByIdempotency(
                idempotencyKey, requestHash);
        if (operationId == null) {
            return null;
        }
        MassDbLicenseState.OperationView view = state.findOperation(operationId);
        return new Result(state, operationId, true, view != null && view.terminal);
    }

    private RedriveResult failed(MassDbLicenseState state, String operationId, long now) {
        MassDbLicenseState failed = state.failOperation(operationId,
                "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", now);
        return new RedriveResult(failed, null, true,
                "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED");
    }

    private static String sha256(byte[] value) {
        if (value == null || value.length == 0
                || value.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES) {
            fail("MASSDB_LICENSE_FILE_INVALID", "keyset工件为空或超过上限");
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
                    "Content-SHA256与实际keyset工件不一致");
        }
    }

    private static boolean equalsText(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static boolean equalsLong(Long left, Long right) {
        return left == null ? right == null : left.equals(right);
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    private static final class StandaloneCandidate {
        private final MassDbLicenseProtocolV1.VerifiedKeyset verified;
        private final MassDbLicenseState.MutationKind kind;

        private StandaloneCandidate(MassDbLicenseProtocolV1.VerifiedKeyset verified,
                MassDbLicenseState.MutationKind kind) {
            this.verified = verified;
            this.kind = kind;
        }
    }

    private static final class BundleCandidate {
        private final MassDbLicenseProtocolV1.VerifiedRecoveryBundle verified;

        private BundleCandidate(MassDbLicenseProtocolV1.VerifiedRecoveryBundle verified) {
            this.verified = verified;
        }
    }

    public static final class StatusResult {
        public final boolean installed = true;
        public final long keysetVersion;
        public final String contentSha256;
        public final String rootKeyId;
        public final String activeLicenseKid;
        public final boolean activeKidTrusted;

        private StatusResult(MassDbLicenseProtocolV1.VerifiedKeyset keyset,
                String activeLicenseKid, boolean activeKidTrusted) {
            this.keysetVersion = keyset.getPayload().getKeysetVersion();
            this.contentSha256 = keyset.getSha256();
            this.rootKeyId = keyset.getRootKid();
            this.activeLicenseKid = activeLicenseKid;
            this.activeKidTrusted = activeKidTrusted;
        }
    }

    public static final class ValidateResult {
        public final boolean valid = true;
        public final boolean readyForImport = true;
        public final String action;
        public final String contentSha256;
        public final long keysetVersion;
        public final long currentKeysetVersion;
        public final String replacementLicenseId;
        public final String replacementLicenseSha256;
        public final Long replacementLicenseExpiresAt;
        public final long topologyRevision;
        public final int expectedIngressNodes;
        public final int liveIngressNodes;
        public final int deferredOfflineIngressNodes;
        public final String preconditionToken;
        public final List<String> warnings;

        private ValidateResult(String action, String contentSha256,
                long keysetVersion, long currentKeysetVersion,
                MassDbLicenseProtocolV1.VerifiedLicense replacement,
                long topologyRevision, MassDbLicenseIngressInventory.Evaluation ingress,
                String preconditionToken) {
            this.action = action;
            this.contentSha256 = contentSha256;
            this.keysetVersion = keysetVersion;
            this.currentKeysetVersion = currentKeysetVersion;
            this.replacementLicenseId = replacement == null
                    ? null : replacement.getPayload().getLicenseId();
            this.replacementLicenseSha256 = replacement == null
                    ? null : replacement.getSha256();
            this.replacementLicenseExpiresAt = replacement == null
                    ? null : replacement.getPayload().getExpiresAt();
            this.topologyRevision = topologyRevision;
            this.expectedIngressNodes = ingress.expectedIngressNodes;
            this.liveIngressNodes = ingress.liveIngressNodes;
            this.deferredOfflineIngressNodes = ingress.deferredOfflineIngressNodes;
            this.preconditionToken = preconditionToken;
            this.warnings = Collections.unmodifiableList(new ArrayList<>(ingress.warnings));
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

    public static final class RecoveryPlan {
        public final String operationId;
        public final MassDbLicenseState.MutationKind kind;
        public final String action;
        public final byte[] keysetArtifact;
        public final String keysetSha256;
        public final long keysetVersion;
        public final byte[] licenseArtifact;
        public final String licenseSha256;
        public final long licenseExpiresAt;
        public final long enforcementEpoch;
        public final long stagedCreatedAt;
        public final List<String> requiredAckNodeUuids;
        public final List<String> deferredNodeUuids;
        public final long deadlineAt;

        private RecoveryPlan(String operationId, MassDbLicenseState.MutationKind kind,
                String action, byte[] keysetArtifact, String keysetSha256,
                long keysetVersion, byte[] licenseArtifact, String licenseSha256,
                long licenseExpiresAt, long enforcementEpoch, long stagedCreatedAt,
                List<String> requiredAckNodeUuids, List<String> deferredNodeUuids,
                long deadlineAt) {
            this.operationId = operationId;
            this.kind = kind;
            this.action = action;
            this.keysetArtifact = keysetArtifact.clone();
            this.keysetSha256 = keysetSha256;
            this.keysetVersion = keysetVersion;
            this.licenseArtifact = licenseArtifact == null
                    ? new byte[0] : licenseArtifact.clone();
            this.licenseSha256 = licenseSha256;
            this.licenseExpiresAt = licenseExpiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.stagedCreatedAt = stagedCreatedAt;
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

        private RedriveResult(MassDbLicenseState state, RecoveryPlan plan,
                boolean terminal, String errorCode) {
            this.state = state;
            this.plan = plan;
            this.terminal = terminal;
            this.errorCode = errorCode;
        }
    }
}
