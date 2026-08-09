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

/** Signed, deployment-bound wall-clock recovery validate/prepare/commit core. */
public final class MassDbLicenseClockRecoveryCore {
    private static final String AUDIENCE = "CLOCK_RECOVERY";
    private final Map<String, PublicKey> rootKeys;

    public MassDbLicenseClockRecoveryCore(Map<String, PublicKey> rootKeys) {
        if (rootKeys == null || rootKeys.isEmpty()) {
            throw new IllegalArgumentException("rootKeys必须配置");
        }
        this.rootKeys = Collections.unmodifiableMap(new LinkedHashMap<>(rootKeys));
    }

    public ValidateResult validate(MassDbLicenseState state, byte[] artifact,
            long currentWallClock) {
        VerifiedCandidate value = verifyCandidate(state, artifact, currentWallClock);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        long tokenExpiresAt = Math.min(saturatedAdd(currentWallClock,
                MassDbLicenseControlPreconditionToken.MAX_TTL_SECONDS),
                value.verified.getPayload().getArtifactExpiresAt());
        MassDbLicenseControlPreconditionToken.Claims claims =
                new MassDbLicenseControlPreconditionToken.Claims(
                        AUDIENCE, "RECOVER_CLOCK", value.challengeId,
                        active.getSha256(), active.getExpiresAt(),
                        state.getEnforcementEpoch(), state.getTopologyRevision(),
                        value.ingress.inventorySnapshotSha256,
                        value.ingress.routingEvidenceSnapshotSha256,
                        value.verified.getSha256(),
                        value.verified.getPayload().getRecoverySequence(),
                        value.verified.getPayload().getResetMaxSeenWallClockTo(),
                        value.verified.getPayload().getArtifactExpiresAt(),
                        state.getMaxSeenWallClock(),
                        state.getMaxAcceptedRecoverySequence(), currentWallClock,
                        tokenExpiresAt, UUID.randomUUID().toString());
        String token = MassDbLicenseControlPreconditionToken.issue(
                state.getPreconditionHmacKey(), claims);
        return new ValidateResult(value.verified, state, value.ingress,
                value.challengeId, token);
    }

    public Result prepare(MassDbLicenseState state, byte[] artifact,
            String contentSha256, String preconditionToken, String idempotencyKey,
            String operationId, long currentWallClock, long deadlineAt) {
        String actual = sha256(artifact);
        requireContentSha256(contentSha256, actual);
        String requestHash = sha256(("CLOCK_RECOVERY\n" + actual)
                .getBytes(StandardCharsets.US_ASCII));
        String replayId = state.findOperationIdByIdempotency(idempotencyKey, requestHash);
        if (replayId != null) {
            MassDbLicenseState.OperationView replay = state.findOperation(replayId);
            return new Result(state, replayId, true, replay != null && replay.terminal);
        }
        VerifiedCandidate value = verifyCandidate(state, artifact, currentWallClock);
        MassDbLicenseControlPreconditionToken.Claims claims =
                MassDbLicenseControlPreconditionToken.verify(
                        state.getPreconditionHmacKey(), preconditionToken, currentWallClock);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        if (!AUDIENCE.equals(claims.audience) || !"RECOVER_CLOCK".equals(claims.action)
                || !value.challengeId.equals(claims.subjectId)
                || !active.getSha256().equals(claims.activeSha256)
                || claims.activeExpiresAt == null
                || active.getExpiresAt() != claims.activeExpiresAt
                || state.getEnforcementEpoch() != claims.enforcementEpoch
                || state.getTopologyRevision() != claims.topologyRevision
                || !value.ingress.inventorySnapshotSha256.equals(
                        claims.inventorySnapshotSha256)
                || !value.ingress.routingEvidenceSnapshotSha256.equals(
                        claims.routingEvidenceSnapshotSha256)
                || !actual.equals(claims.candidateSha256)
                || value.verified.getPayload().getRecoverySequence() != claims.targetValue1
                || value.verified.getPayload().getResetMaxSeenWallClockTo()
                        != claims.targetValue2
                || value.verified.getPayload().getArtifactExpiresAt() != claims.targetValue3
                || state.getMaxSeenWallClock() != claims.snapshotValue1
                || state.getMaxAcceptedRecoverySequence() != claims.snapshotValue2) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "clock recovery token与当前权威状态或实际工件不匹配");
        }
        MassDbLicenseProtocolV1.ClockRecovery payload = value.verified.getPayload();
        MassDbLicenseState.StagedClockRecovery staged =
                new MassDbLicenseState.StagedClockRecovery(actual, artifact,
                        value.challengeId, payload.getRecoverySequence(),
                        payload.getObservedMaxSeenWallClock(),
                        payload.getResetMaxSeenWallClockTo(), payload.getIssuedAt(),
                        payload.getArtifactExpiresAt());
        MassDbLicenseState prepared = state.prepareClockRecovery(operationId,
                idempotencyKey, requestHash, staged, currentWallClock, deadlineAt);
        return new Result(prepared, operationId, false, false);
    }

    /** Re-verifies the durable artifact after leader recovery, then commits one journal entry. */
    public Result recover(MassDbLicenseState state, String operationId,
            long currentWallClock) {
        MassDbLicenseState recovered = state.recoverOrExpireMutation(currentWallClock);
        MassDbLicenseState.OperationView view = recovered.findOperation(operationId);
        if (view == null) {
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的clock recovery operation");
        }
        if (view.terminal) {
            return new Result(recovered, operationId, true, true);
        }
        MassDbLicenseState.Mutation mutation = recovered.getMutation();
        if (mutation == null || mutation.getKind()
                != MassDbLicenseState.MutationKind.CLOCK_RECOVERY
                || !operationId.equals(mutation.getOperationId())
                || mutation.getCandidateClockRecovery() == null) {
            return failed(recovered, operationId,
                    "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", currentWallClock);
        }
        try {
            MassDbLicenseState.StagedClockRecovery staged =
                    mutation.getCandidateClockRecovery();
            VerifiedCandidate verified = verifyCandidate(
                    recovered, staged.getArtifact(), currentWallClock);
            if (!staged.getContentSha256().equals(verified.verified.getSha256())) {
                return failed(recovered, operationId,
                        "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", currentWallClock);
            }
            return new Result(recovered.commitClockRecovery(
                    operationId, currentWallClock), operationId, false, true);
        } catch (MassDbLicenseException error) {
            String code = "MASSDB_LICENSE_EXPIRED".equals(error.getCode())
                    ? error.getCode() : "MASSDB_LICENSE_OPERATION_RECOVERY_FAILED";
            return failed(recovered, operationId, code, currentWallClock);
        }
    }

    private Result failed(MassDbLicenseState state, String operationId,
            String code, long now) {
        return new Result(state.failOperation(operationId, code, now),
                operationId, false, true);
    }

    private VerifiedCandidate verifyCandidate(MassDbLicenseState state,
            byte[] artifact, long currentWallClock) {
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        MassDbLicenseState.ActiveKeyset keysetState = state.getActiveKeyset();
        MassDbLicenseState.ClockChallenge challenge = state.getClockChallenge();
        if (!state.isInitialized() || active == null || keysetState == null
                || challenge == null || !state.hasActiveClockChallenge(currentWallClock)) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_CONTEXT_MISMATCH",
                    "当前没有可消费的active clock recovery challenge");
        }
        MassDbLicenseProtocolV1.VerifiedKeyset keyset =
                MassDbLicenseProtocolV1.verifyKeyset(keysetState.getArtifact(),
                        rootKeys, currentWallClock, null);
        if (keyset.getPayload().getKeysetVersion() != keysetState.getVersion()
                || !keyset.getSha256().equals(keysetState.getSha256())) {
            fail("MASSDB_LICENSE_KEYSET_INVALID", "active keyset无法通过root trust复验");
        }
        MassDbLicenseProtocolV1.ClockContext context =
                new MassDbLicenseProtocolV1.ClockContext(
                        hex32(challenge.getChallengeHex()),
                        state.getLicenseControlDeploymentUuid(),
                        hex32(active.getSha256()), state.getMaxSeenWallClock(),
                        state.getMaxAcceptedRecoverySequence(), currentWallClock);
        MassDbLicenseProtocolV1.VerifiedClockRecovery verified =
                MassDbLicenseProtocolV1.verifyClockRecovery(artifact, keyset, context);
        MassDbLicenseIngressInventory.Evaluation ingress = state.getIngressInventory().evaluate(
                active, state.getEnforcementEpoch(), currentWallClock, true);
        if (!ingress.isReadyForImport()) {
            fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE",
                    "clock recovery存在不安全的desired入口");
        }
        return new VerifiedCandidate(verified, ingress, challenge.getChallengeId());
    }

    private static byte[] hex32(String value) {
        if (value == null || !value.matches("[0-9a-fA-F]{64}")) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_CONTEXT_MISMATCH", "32字节摘要编码损坏");
        }
        byte[] result = new byte[32];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(
                    value.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    private static String sha256(byte[] value) {
        if (value == null || value.length == 0
                || value.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES) {
            fail("MASSDB_LICENSE_FILE_INVALID", "clock recovery工件为空或超过上限");
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

    private static void requireContentSha256(String supplied, String actual) {
        if (supplied == null || !supplied.matches("[0-9a-fA-F]{64}")
                || !MessageDigest.isEqual(supplied.toLowerCase().getBytes(StandardCharsets.US_ASCII),
                        actual.getBytes(StandardCharsets.US_ASCII))) {
            fail("MASSDB_LICENSE_CONTENT_SHA256_MISMATCH",
                    "Content-SHA256与实际clock recovery工件不一致");
        }
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    private static final class VerifiedCandidate {
        private final MassDbLicenseProtocolV1.VerifiedClockRecovery verified;
        private final MassDbLicenseIngressInventory.Evaluation ingress;
        private final String challengeId;

        private VerifiedCandidate(MassDbLicenseProtocolV1.VerifiedClockRecovery verified,
                MassDbLicenseIngressInventory.Evaluation ingress, String challengeId) {
            this.verified = verified;
            this.ingress = ingress;
            this.challengeId = challengeId;
        }
    }

    public static final class ValidateResult {
        public final boolean valid = true;
        public final boolean readyForImport = true;
        public final String action = "RECOVER_CLOCK";
        public final String contentSha256;
        public final String challengeId;
        public final long recoverySequence;
        public final long observedMaxSeenWallClock;
        public final long resetMaxSeenWallClockTo;
        public final long artifactIssuedAt;
        public final long artifactExpiresAt;
        public final long topologyRevision;
        public final int expectedIngressNodes;
        public final int liveIngressNodes;
        public final int deferredOfflineIngressNodes;
        public final String preconditionToken;
        public final List<String> warnings;

        private ValidateResult(MassDbLicenseProtocolV1.VerifiedClockRecovery verified,
                MassDbLicenseState state, MassDbLicenseIngressInventory.Evaluation ingress,
                String challengeId, String preconditionToken) {
            MassDbLicenseProtocolV1.ClockRecovery payload = verified.getPayload();
            this.contentSha256 = verified.getSha256();
            this.challengeId = challengeId;
            this.recoverySequence = payload.getRecoverySequence();
            this.observedMaxSeenWallClock = payload.getObservedMaxSeenWallClock();
            this.resetMaxSeenWallClockTo = payload.getResetMaxSeenWallClockTo();
            this.artifactIssuedAt = payload.getIssuedAt();
            this.artifactExpiresAt = payload.getArtifactExpiresAt();
            this.topologyRevision = state.getTopologyRevision();
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
}
