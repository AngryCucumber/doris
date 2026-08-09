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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;

/** Component-local FE License authority, trusted time and offline query-decision runtime. */
final class MassDbLicenseFeRoleRuntime {
    private MassDbLicenseFeRoleRuntime() {
    }

    static void applyControlPlaneSync(MassDbLicenseLocalSnapshotStore store,
            MassDbLicenseImportCore importCore, String deploymentUuid,
            MassDbLicenseFeRoleProtocol.ControlPlaneSync sync,
            long wallClock, long monotonicNow, long expectedReportSequence) {
        validateSync(sync, deploymentUuid, expectedReportSequence);
        if (wallClock <= 0 || monotonicNow <= 0) {
            fail("MASSDB_LICENSE_CLOCK_ROLLBACK", "本地时钟不可用");
        }

        MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint existing = null;
        try {
            existing = store.loadControlPlaneCheckpoint();
        } catch (MassDbLicenseException error) {
            if (!"MASSDB_LICENSE_LOCAL_STATE_CORRUPT".equals(error.getCode())) {
                throw error;
            }
            // A newly chain-authenticated and cryptographically verified snapshot may repair it.
        }
        if (existing != null) {
            if (!deploymentUuid.equals(existing.deploymentUuid)
                    || !"fe".equals(existing.role)
                    || !store.getNodeUuid().equals(existing.nodeUuid)) {
                fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                        "既有控制面检查点身份与当前FE不一致");
            }
            if (sync.controlPlaneRevision < existing.controlPlaneRevision
                    || sync.activeKeysetVersion < existing.activeKeysetVersion
                    || sync.recoverySequence < existing.recoverySequence
                    || sync.enforcementEpoch < existing.enforcementEpoch) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED", "控制面同步版本或epoch发生回退");
            }
            if (sync.controlPlaneRevision == existing.controlPlaneRevision
                    && !sameAuthority(existing, sync)) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                        "相同控制面revision携带不同权威状态");
            }
        }

        long effectiveNow = maximum(wallClock, monotonicNow, sync.maxSeenWallClock,
                sync.leaderObservedAt);
        if (existing != null && existing.clockRecoveryEpoch == sync.clockRecoveryEpoch) {
            effectiveNow = Math.max(effectiveNow, existing.lastVerifiedEffectiveNow);
        }

        MassDbLicenseProtocolV1.VerifiedKeyset verifiedKeyset = null;
        if (sync.activeKeysetVersion != 0) {
            try {
                verifiedKeyset = importCore.verifyControlPlaneKeyset(
                        sync.activeKeysetArtifact, effectiveNow);
            } catch (MassDbLicenseException error) {
                fail("MASSDB_LICENSE_KEYSET_INVALID", "控制面active keyset验签失败");
            }
            if (verifiedKeyset.getPayload().getKeysetVersion() != sync.activeKeysetVersion
                    || !verifiedKeyset.getSha256().equals(
                            normalizeSha256(sync.activeKeysetSha256))) {
                fail("MASSDB_LICENSE_KEYSET_INVALID", "控制面active keyset元数据不一致");
            }
        }

        MassDbLicenseLocalSnapshotStore.ActiveSnapshot authoritativeActive = null;
        if (sync.activeLicenseSha256 != null) {
            long validationNow = Math.min(effectiveNow, sync.activeLicenseExpiresAt - 1);
            MassDbLicenseProtocolV1.VerifiedLicense verified;
            try {
                verified = importCore.verifyControlPlaneLicense(
                        sync.activeLicenseArtifact, verifiedKeyset, validationNow);
            } catch (MassDbLicenseException error) {
                fail("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT",
                        "控制面active License验签失败");
                return;
            }
            if (!verified.getSha256().equals(normalizeSha256(sync.activeLicenseSha256))
                    || verified.getPayload().getExpiresAt() != sync.activeLicenseExpiresAt) {
                fail("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT",
                        "控制面active License元数据不一致");
            }
            long writtenAt = Math.min(effectiveNow, sync.activeLicenseExpiresAt - 1);
            authoritativeActive = new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                    sync.activeLicenseArtifact, sync.activeLicenseSha256,
                    sync.activeLicenseExpiresAt, sync.enforcementEpoch, writtenAt);
        }

        MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint checkpoint =
                new MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint(
                        deploymentUuid, sync.controlPlaneRevision, "fe", store.getNodeUuid(),
                        sync.activeKeysetVersion, sync.activeKeysetSha256,
                        sync.activeKeysetArtifact, sync.activeLicenseSha256,
                        sync.activeLicenseExpiresAt == null ? 0 : sync.activeLicenseExpiresAt,
                        sync.enforcementMode, sync.enforcementEpoch,
                        sync.clockRecoveryEpoch, sync.recoverySequence,
                        sync.maxSeenWallClock, effectiveNow, wallClock,
                        sync.leaderObservedAt, sync.maxControlPlaneStalenessSeconds);

        if (existing != null && existing.controlPlaneRevision == checkpoint.controlPlaneRevision
                && sameCheckpointAuthority(existing, checkpoint)
                && effectiveNow < saturatedAdd(existing.lastVerifiedEffectiveNow,
                        MassDbLicenseState.DEFAULT_ROLE_STATUS_INTERVAL_SECONDS)
                && activeMatches(store, authoritativeActive)) {
            return;
        }
        store.applyControlPlaneCheckpoint(checkpoint, authoritativeActive);
    }

    static Evaluation evaluate(MassDbLicenseLocalSnapshotStore store,
            MassDbLicenseImportCore importCore, String deploymentUuid,
            long wallClock, long monotonicNow) {
        Evaluation result = new Evaluation();
        result.observedWallClock = wallClock;
        result.clockState = MassDbLicenseFeRoleProtocol.ClockState.UNINITIALIZED;
        result.verificationState = MassDbLicenseFeRoleProtocol.VerificationState.MISSING;
        result.controlPlaneFreshness = "MISSING";
        result.enforcementMode = MassDbLicenseState.EnforcementMode.UNINITIALIZED;
        result.queryDecision = MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                "MASSDB_LICENSE_CONTROL_PLANE_STALE");

        MassDbLicenseLocalSnapshotStore.RoleRuntimeSnapshot local;
        try {
            local = store.loadRoleRuntimeSnapshot();
        } catch (MassDbLicenseException error) {
            result.verificationState = MassDbLicenseFeRoleProtocol.VerificationState.CORRUPT;
            result.errorCode = error.getCode();
            result.queryDecision = MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    "MASSDB_LICENSE_LOCAL_STATE_CORRUPT");
            return result;
        }
        result.active = local.active;
        result.activationPending = local.activationPending;
        result.licensePending = local.licensePending;
        result.controlPending = local.controlPending;
        result.checkpoint = local.checkpoint;
        result.identityConflict = local.identityConflict;
        boolean identityConflicted = local.identityConflict != null
                && local.identityConflict.active;
        if (identityConflicted) {
            result.errorCode = "MASSDB_LICENSE_DUPLICATE_NODE_UUID";
            result.queryDecision = MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    result.errorCode);
        }
        if (local.checkpoint == null) {
            if (local.active != null) {
                result.verificationState =
                        MassDbLicenseFeRoleProtocol.VerificationState.UNVERIFIED;
            }
            return result;
        }
        if (!deploymentUuid.equals(local.checkpoint.deploymentUuid)
                || !"fe".equals(local.checkpoint.role)
                || !store.getNodeUuid().equals(local.checkpoint.nodeUuid)) {
            result.checkpoint = null;
            result.verificationState = MassDbLicenseFeRoleProtocol.VerificationState.MISMATCH;
            if (!identityConflicted) {
                result.errorCode = "MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH";
            }
            return result;
        }

        MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint checkpoint = local.checkpoint;
        result.enforcementMode = checkpoint.enforcementMode;
        result.enforcementEpoch = checkpoint.enforcementEpoch;
        result.controlPlaneRevision = checkpoint.controlPlaneRevision;
        result.clockRecoveryEpoch = checkpoint.clockRecoveryEpoch;
        result.recoverySequence = checkpoint.recoverySequence;
        result.keysetVersion = checkpoint.activeKeysetVersion;
        result.keysetSha256 = checkpoint.activeKeysetSha256;
        result.lastAuthenticatedControlPlaneAt = checkpoint.authenticatedAtWallClock;
        observeClock(result, checkpoint, wallClock, monotonicNow);

        long elapsed = positiveDifference(
                result.effectiveNow, checkpoint.lastVerifiedEffectiveNow);
        elapsed = Math.max(elapsed, positiveDifference(
                wallClock, checkpoint.authenticatedAtWallClock));
        if (elapsed <= checkpoint.maxControlPlaneStalenessSeconds) {
            result.controlPlaneFreshness = "FRESH";
            result.controlPlaneStalenessRemainingSeconds =
                    checkpoint.maxControlPlaneStalenessSeconds - elapsed;
        } else {
            result.controlPlaneFreshness = "STALE";
            result.controlPlaneStalenessRemainingSeconds = 0L;
        }

        Verification verification = verifyRuntimeActive(
                importCore, local.active, checkpoint, result.effectiveNow);
        result.verificationState = verification.state;
        if (!identityConflicted) {
            result.errorCode = verification.errorCode;
        }
        result.queryDecision = evaluateQuery(checkpoint.enforcementMode,
                identityConflicted, local.activationPending, local.controlPending,
                result.verificationState,
                result.controlPlaneFreshness, result.clockState,
                local.active, result.effectiveNow);
        if (identityConflicted) {
            result.errorCode = "MASSDB_LICENSE_DUPLICATE_NODE_UUID";
        } else if (result.errorCode == null && !result.queryDecision.allowed) {
            result.errorCode = result.queryDecision.errorCode;
        }
        return result;
    }

    private static void observeClock(Evaluation result,
            MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint checkpoint,
            long wallClock, long monotonicNow) {
        long floor = Math.max(checkpoint.committedMaxSeenWallClock,
                checkpoint.lastVerifiedEffectiveNow);
        result.effectiveNow = maximum(wallClock, monotonicNow, floor);
        result.clockState = MassDbLicenseFeRoleProtocol.ClockState.NORMAL;
        if (saturatedAdd(wallClock, MassDbLicenseState.DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS)
                < floor) {
            result.clockState = saturatedAdd(monotonicNow,
                    MassDbLicenseState.DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS) < floor
                    ? MassDbLicenseFeRoleProtocol.ClockState.ROLLBACK
                    : MassDbLicenseFeRoleProtocol.ClockState.SKEW_WARNING;
        } else if (saturatedAdd(wallClock,
                MassDbLicenseState.DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS) < monotonicNow) {
            result.clockState = MassDbLicenseFeRoleProtocol.ClockState.SKEW_WARNING;
        }
    }

    private static Verification verifyRuntimeActive(MassDbLicenseImportCore importCore,
            MassDbLicenseLocalSnapshotStore.ActiveSnapshot active,
            MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint checkpoint,
            long effectiveNow) {
        if (checkpoint.activeLicenseSha256 == null) {
            return active == null
                    ? new Verification(MassDbLicenseFeRoleProtocol.VerificationState.MISSING, null)
                    : new Verification(MassDbLicenseFeRoleProtocol.VerificationState.MISMATCH,
                            "MASSDB_LICENSE_ACTIVE_MISMATCH");
        }
        if (active == null) {
            return new Verification(MassDbLicenseFeRoleProtocol.VerificationState.MISSING,
                    "MASSDB_LICENSE_REQUIRED");
        }
        if (!active.sha256.equals(checkpoint.activeLicenseSha256)
                || active.expiresAt != checkpoint.activeLicenseExpiresAt
                || active.enforcementEpoch != checkpoint.enforcementEpoch) {
            return new Verification(MassDbLicenseFeRoleProtocol.VerificationState.MISMATCH,
                    "MASSDB_LICENSE_ACTIVE_MISMATCH");
        }
        try {
            MassDbLicenseProtocolV1.VerifiedKeyset keyset =
                    importCore.verifyControlPlaneKeyset(
                            checkpoint.activeKeysetArtifact, effectiveNow);
            if (keyset.getPayload().getKeysetVersion() != checkpoint.activeKeysetVersion
                    || !keyset.getSha256().equals(checkpoint.activeKeysetSha256)) {
                return new Verification(MassDbLicenseFeRoleProtocol.VerificationState.CORRUPT,
                        "MASSDB_LICENSE_KEYSET_INVALID");
            }
            long validationNow = Math.min(effectiveNow, active.expiresAt - 1);
            MassDbLicenseProtocolV1.VerifiedLicense verified =
                    importCore.verifyControlPlaneLicense(active.artifact, keyset, validationNow);
            if (!verified.getSha256().equals(active.sha256)
                    || verified.getPayload().getExpiresAt() != active.expiresAt) {
                return new Verification(MassDbLicenseFeRoleProtocol.VerificationState.CORRUPT,
                        "MASSDB_LICENSE_ACTIVE_FILE_CORRUPT");
            }
            return new Verification(MassDbLicenseFeRoleProtocol.VerificationState.VERIFIED, null);
        } catch (MassDbLicenseException error) {
            String code = error.getCode().contains("KEYSET")
                    ? "MASSDB_LICENSE_KEYSET_INVALID"
                    : "MASSDB_LICENSE_ACTIVE_FILE_CORRUPT";
            return new Verification(MassDbLicenseFeRoleProtocol.VerificationState.CORRUPT, code);
        }
    }

    private static MassDbLicenseLocalSnapshotStore.QueryDecision evaluateQuery(
            MassDbLicenseState.EnforcementMode mode, boolean identityConflict,
            MassDbLicenseLocalSnapshotStore.ActivationPending activationPending,
            MassDbLicenseLocalSnapshotStore.ControlPending controlPending,
            MassDbLicenseFeRoleProtocol.VerificationState verification,
            String freshness, MassDbLicenseFeRoleProtocol.ClockState clockState,
            MassDbLicenseLocalSnapshotStore.ActiveSnapshot active, long effectiveNow) {
        if (identityConflict) {
            return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    "MASSDB_LICENSE_DUPLICATE_NODE_UUID");
        }
        if (activationPending != null) {
            return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    "MASSDB_LICENSE_ACTIVATION_PENDING");
        }
        if (controlPending != null && controlPending.failClosed()) {
            return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    "MASSDB_LICENSE_KEYSET_RECOVERY_PENDING");
        }
        if (mode != MassDbLicenseState.EnforcementMode.ENFORCING) {
            return MassDbLicenseLocalSnapshotStore.QueryDecision.allow();
        }
        if (!"FRESH".equals(freshness)) {
            return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    "MASSDB_LICENSE_CONTROL_PLANE_STALE");
        }
        if (clockState == MassDbLicenseFeRoleProtocol.ClockState.ROLLBACK
                || clockState == MassDbLicenseFeRoleProtocol.ClockState.RECOVERY_PENDING) {
            return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    "MASSDB_LICENSE_CLOCK_ROLLBACK");
        }
        switch (verification) {
            case MISSING:
                return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                        "MASSDB_LICENSE_REQUIRED");
            case CORRUPT:
            case UNVERIFIED:
                return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                        "MASSDB_LICENSE_INVALID");
            case MISMATCH:
                return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                        "MASSDB_LICENSE_ACTIVE_MISMATCH");
            case VERIFIED:
                break;
            default:
                return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                        "MASSDB_LICENSE_INVALID");
        }
        if (active == null) {
            return MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    "MASSDB_LICENSE_REQUIRED");
        }
        return effectiveNow >= active.expiresAt
                ? MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                        "MASSDB_LICENSE_EXPIRED")
                : MassDbLicenseLocalSnapshotStore.QueryDecision.allow();
    }

    private static void validateSync(MassDbLicenseFeRoleProtocol.ControlPlaneSync sync,
            String deploymentUuid, long expectedReportSequence) {
        boolean keysetPresent = sync != null && (sync.activeKeysetVersion != 0
                || sync.activeKeysetSha256 != null
                || sync.activeKeysetArtifact != null && sync.activeKeysetArtifact.length != 0);
        boolean licensePresent = sync != null && (sync.activeLicenseSha256 != null
                || sync.activeLicenseExpiresAt != null
                || sync.activeLicenseArtifact != null && sync.activeLicenseArtifact.length != 0);
        if (sync == null || sync.reportSequence <= 0
                || sync.reportSequence != expectedReportSequence
                || sync.controlPlaneRevision <= 0
                || !isCanonicalVersion4Uuid(sync.deploymentUuid)
                || !deploymentUuid.equals(sync.deploymentUuid)
                || sync.leaderObservedAt <= 0 || sync.maxSeenWallClock < 0
                || sync.maxControlPlaneStalenessSeconds
                        != MassDbLicenseState.DEFAULT_CONTROL_PLANE_STALENESS_SECONDS
                || sync.enforcementMode == null
                || sync.enforcementMode == MassDbLicenseState.EnforcementMode.UNINITIALIZED
                || sync.enforcementEpoch < 0 || sync.clockRecoveryEpoch < 0
                || sync.clockRecoveryEpoch != sync.recoverySequence
                || keysetPresent && (sync.activeKeysetVersion <= 0
                        || !isSha256(sync.activeKeysetSha256)
                        || sync.activeKeysetArtifact == null
                        || sync.activeKeysetArtifact.length == 0
                        || sync.activeKeysetArtifact.length
                                > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                        || !sync.activeKeysetSha256.equalsIgnoreCase(
                                sha256(sync.activeKeysetArtifact)))
                || !keysetPresent && licensePresent
                || licensePresent && (!isSha256(sync.activeLicenseSha256)
                        || sync.activeLicenseExpiresAt == null
                        || sync.activeLicenseExpiresAt <= 0
                        || sync.activeLicenseArtifact == null
                        || sync.activeLicenseArtifact.length == 0
                        || sync.activeLicenseArtifact.length
                                > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                        || !sync.activeLicenseSha256.equalsIgnoreCase(
                                sha256(sync.activeLicenseArtifact)))) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "Leader控制面同步字段无效");
        }
    }

    private static boolean sameAuthority(
            MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint existing,
            MassDbLicenseFeRoleProtocol.ControlPlaneSync sync) {
        return existing.activeKeysetVersion == sync.activeKeysetVersion
                && equalsText(existing.activeKeysetSha256,
                        normalizeSha256(sync.activeKeysetSha256))
                && equalsText(existing.activeLicenseSha256,
                        normalizeSha256(sync.activeLicenseSha256))
                && existing.activeLicenseExpiresAt
                        == (sync.activeLicenseExpiresAt == null ? 0 : sync.activeLicenseExpiresAt)
                && existing.enforcementMode == sync.enforcementMode
                && existing.enforcementEpoch == sync.enforcementEpoch
                && existing.clockRecoveryEpoch == sync.clockRecoveryEpoch
                && existing.recoverySequence == sync.recoverySequence
                && existing.committedMaxSeenWallClock == sync.maxSeenWallClock;
    }

    private static boolean sameCheckpointAuthority(
            MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint left,
            MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint right) {
        return left.activeKeysetVersion == right.activeKeysetVersion
                && equalsText(left.activeKeysetSha256, right.activeKeysetSha256)
                && Arrays.equals(left.activeKeysetArtifact, right.activeKeysetArtifact)
                && equalsText(left.activeLicenseSha256, right.activeLicenseSha256)
                && left.activeLicenseExpiresAt == right.activeLicenseExpiresAt
                && left.enforcementMode == right.enforcementMode
                && left.enforcementEpoch == right.enforcementEpoch
                && left.clockRecoveryEpoch == right.clockRecoveryEpoch
                && left.recoverySequence == right.recoverySequence
                && left.committedMaxSeenWallClock == right.committedMaxSeenWallClock;
    }

    private static boolean activeMatches(MassDbLicenseLocalSnapshotStore store,
            MassDbLicenseLocalSnapshotStore.ActiveSnapshot expected) {
        try {
            MassDbLicenseLocalSnapshotStore.ActiveSnapshot current = store.loadActive();
            return current == null && expected == null || current != null && expected != null
                    && current.sha256.equals(expected.sha256)
                    && current.expiresAt == expected.expiresAt
                    && current.enforcementEpoch == expected.enforcementEpoch
                    && Arrays.equals(current.artifact, expected.artifact);
        } catch (MassDbLicenseException error) {
            return false;
        }
    }

    private static long maximum(long... values) {
        long result = 0;
        for (long value : values) {
            result = Math.max(result, value);
        }
        return result;
    }

    private static long positiveDifference(long left, long right) {
        return left > right ? left - right : 0;
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static boolean isCanonicalVersion4Uuid(String value) {
        if (value == null || value.length() != 36) {
            return false;
        }
        try {
            UUID parsed = UUID.fromString(value);
            return parsed.version() == 4 && parsed.variant() == 2
                    && parsed.toString().equals(value);
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    private static boolean isSha256(String value) {
        return value != null && value.matches("[0-9a-fA-F]{64}");
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    private static String normalizeSha256(String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    private static boolean equalsText(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    private static final class Verification {
        private final MassDbLicenseFeRoleProtocol.VerificationState state;
        private final String errorCode;

        private Verification(MassDbLicenseFeRoleProtocol.VerificationState state,
                String errorCode) {
            this.state = state;
            this.errorCode = errorCode;
        }
    }

    static final class Evaluation {
        MassDbLicenseLocalSnapshotStore.ActiveSnapshot active;
        MassDbLicenseLocalSnapshotStore.ActivationPending activationPending;
        MassDbLicenseLocalSnapshotStore.LicensePending licensePending;
        MassDbLicenseLocalSnapshotStore.ControlPending controlPending;
        MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint checkpoint;
        MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot identityConflict;
        long observedWallClock;
        long effectiveNow;
        MassDbLicenseFeRoleProtocol.ClockState clockState;
        MassDbLicenseFeRoleProtocol.VerificationState verificationState;
        String controlPlaneFreshness;
        Long controlPlaneStalenessRemainingSeconds;
        MassDbLicenseState.EnforcementMode enforcementMode;
        long enforcementEpoch;
        long controlPlaneRevision;
        long clockRecoveryEpoch;
        long recoverySequence;
        long keysetVersion;
        String keysetSha256;
        long lastAuthenticatedControlPlaneAt;
        MassDbLicenseLocalSnapshotStore.QueryDecision queryDecision;
        String errorCode;

        MassDbLicenseFeRoleProtocol.RoleStatus toRoleStatus(long reportSequence) {
            MassDbLicenseFeRoleProtocol.RoleStatus result =
                    new MassDbLicenseFeRoleProtocol.RoleStatus();
            result.reportSequence = reportSequence;
            result.identityConflict = identityConflict != null && identityConflict.active;
            result.identityConflictRevision = identityConflict == null
                    ? 0 : identityConflict.controlPlaneRevision;
            result.licenseQueryAllowed = queryDecision != null && queryDecision.allowed;
            result.localStateErrorCode = errorCode;
            result.observedWallClock = observedWallClock;
            result.clockState = clockState;
            result.verificationState = verificationState;
            result.controlPlaneFreshness = controlPlaneFreshness;
            result.controlPlaneStalenessRemainingSeconds =
                    controlPlaneStalenessRemainingSeconds;
            result.enforcementMode = enforcementMode;
            result.enforcementEpoch = enforcementEpoch;
            result.controlPlaneRevision = controlPlaneRevision;
            result.clockRecoveryEpoch = clockRecoveryEpoch;
            result.recoverySequence = recoverySequence;
            result.keysetVersion = keysetVersion;
            result.keysetSha256 = keysetSha256;
            result.lastAuthenticatedControlPlaneAt = lastAuthenticatedControlPlaneAt;
            if (clockState != MassDbLicenseFeRoleProtocol.ClockState.UNINITIALIZED) {
                result.effectiveNow = effectiveNow;
                result.licenseExpiredUnderEffectiveNow = active != null
                        && effectiveNow >= active.expiresAt;
            }
            if (active != null) {
                result.activeLicenseSha256 = active.sha256;
                result.activeLicenseExpiresAt = active.expiresAt;
                if (clockState != MassDbLicenseFeRoleProtocol.ClockState.UNINITIALIZED) {
                    result.remainingSecondsAtCheck = effectiveNow < active.expiresAt
                            ? active.expiresAt - effectiveNow : 0L;
                }
                result.licenseExpiredAtObservedWallClock =
                        observedWallClock >= active.expiresAt;
            }
            result.activationPendingOperationId = activationPending == null
                    ? null : activationPending.operationId;
            result.licensePendingOperationId = licensePending == null
                    ? null : licensePending.operationId;
            result.controlPendingOperationId = controlPending == null
                    ? null : controlPending.operationId;
            return result;
        }
    }
}
