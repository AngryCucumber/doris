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

import org.apache.doris.common.io.Text;
import org.apache.doris.common.io.Writable;
import org.apache.doris.persist.gson.GsonUtils;

import com.google.gson.annotations.SerializedName;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Replicated MassDB SQL License control-plane state.
 *
 * <p>The FE master persists a complete post-transition snapshot in one journal record. Followers
 * replay that exact snapshot, so random identifiers, deadlines, correction barriers and challenge
 * invalidation never diverge across FE members. Artifact signature verification happens before a
 * candidate reaches this class; this class enforces the durable transition invariants.</p>
 */
public class MassDbLicenseState implements Writable {
    public static final int FORMAT_VERSION = 1;
    public static final long ISSUED_AT_FUTURE_TOLERANCE_SECONDS = 300;
    public static final int MAX_IDEMPOTENCY_KEY_BYTES = 191;

    public enum EnforcementMode {
        UNINITIALIZED,
        OBSERVE,
        ENFORCING
    }

    public enum ImportIntent {
        NORMAL,
        REPLACE_WITH_SHORTER,
        KEY_ROTATION_REPLACEMENT
    }

    public enum MutationKind {
        LICENSE,
        ADDITIVE_KEYSET,
        RESTRICTIVE_KEYSET,
        KEYSET_LICENSE_RECOVERY_BUNDLE,
        CLOCK_RECOVERY,
        ENFORCEMENT,
        INGRESS
    }

    public enum OperationState {
        PREPARED,
        SUCCEEDED,
        ABORTED
    }

    public enum ClockChallengeState {
        NONE,
        ACTIVE,
        CANCELLED,
        CONSUMED,
        INVALIDATED_BY_KEYSET_RECOVERY
    }

    public static class ActiveLicense {
        @SerializedName("licenseId")
        private String licenseId;
        @SerializedName("sha256")
        private String sha256;
        @SerializedName("kid")
        private String kid;
        @SerializedName("issuedAt")
        private long issuedAt;
        @SerializedName("expiresAt")
        private long expiresAt;
        @SerializedName("artifact")
        private byte[] artifact;

        public ActiveLicense() {
        }

        public ActiveLicense(String licenseId, String sha256, String kid, long issuedAt,
                long expiresAt, byte[] artifact) {
            requireText(licenseId, "licenseId");
            requireSha256(sha256);
            requireText(kid, "kid");
            if (issuedAt < 0 || expiresAt <= issuedAt || artifact == null || artifact.length == 0) {
                fail("MASSDB_LICENSE_FILE_INVALID", "License时间或工件为空");
            }
            this.licenseId = licenseId;
            this.sha256 = sha256.toLowerCase();
            this.kid = kid;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.artifact = artifact.clone();
        }

        public String getLicenseId() {
            return licenseId;
        }

        public String getSha256() {
            return sha256;
        }

        public String getKid() {
            return kid;
        }

        public long getIssuedAt() {
            return issuedAt;
        }

        public long getExpiresAt() {
            return expiresAt;
        }

        public byte[] getArtifact() {
            return artifact == null ? null : artifact.clone();
        }
    }

    /** The exact trusted keyset artifact installed by a committed keyset transition. */
    public static class ActiveKeyset {
        @SerializedName("version")
        private long version;
        @SerializedName("sha256")
        private String sha256;
        @SerializedName("artifact")
        private byte[] artifact;

        public ActiveKeyset() {
        }

        public ActiveKeyset(long version, String sha256, byte[] artifact) {
            requireSha256(sha256);
            if (version <= 0 || artifact == null || artifact.length == 0) {
                fail("MASSDB_LICENSE_FILE_INVALID", "keyset版本或工件为空");
            }
            this.version = version;
            this.sha256 = sha256.toLowerCase();
            this.artifact = artifact.clone();
        }

        public long getVersion() {
            return version;
        }

        public String getSha256() {
            return sha256;
        }

        public byte[] getArtifact() {
            return artifact == null ? null : artifact.clone();
        }
    }

    /** Permanent rule preventing a NORMAL import from undoing an approved expiry correction. */
    public static class CorrectionBarrier {
        @SerializedName("supersededExpiresAt")
        private long supersededExpiresAt;
        @SerializedName("supersededIssuedAtCutoff")
        private long supersededIssuedAtCutoff;
        @SerializedName("correctedAt")
        private long correctedAt;
        @SerializedName("supersededLicenseId")
        private String supersededLicenseId;
        @SerializedName("supersededSha256")
        private String supersededSha256;

        public CorrectionBarrier() {
        }

        private CorrectionBarrier(ActiveLicense superseded, long correctedAt) {
            this.supersededExpiresAt = superseded.expiresAt;
            this.correctedAt = correctedAt;
            this.supersededIssuedAtCutoff = saturatedAdd(
                    correctedAt, ISSUED_AT_FUTURE_TOLERANCE_SECONDS);
            this.supersededLicenseId = superseded.licenseId;
            this.supersededSha256 = superseded.sha256;
        }

        public long getSupersededExpiresAt() {
            return supersededExpiresAt;
        }

        public long getSupersededIssuedAtCutoff() {
            return supersededIssuedAtCutoff;
        }

        public long getCorrectedAt() {
            return correctedAt;
        }
    }

    public static class ClockChallenge {
        @SerializedName("challengeId")
        private String challengeId;
        @SerializedName("challengeHex")
        private String challengeHex;
        @SerializedName("createdAt")
        private long createdAt;
        @SerializedName("expiresAt")
        private long expiresAt;
        @SerializedName("state")
        private ClockChallengeState state;
        @SerializedName("invalidatedAt")
        private Long invalidatedAt;

        public ClockChallenge() {
        }

        private ClockChallenge(String challengeId, String challengeHex, long createdAt, long expiresAt) {
            requireText(challengeId, "challengeId");
            requireText(challengeHex, "challenge");
            if (expiresAt <= createdAt) {
                fail("MASSDB_LICENSE_FILE_INVALID", "challenge expiresAt必须晚于createdAt");
            }
            this.challengeId = challengeId;
            this.challengeHex = challengeHex;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.state = ClockChallengeState.ACTIVE;
        }

        public ClockChallengeState getState() {
            return state == null ? ClockChallengeState.NONE : state;
        }

        public String getChallengeId() {
            return challengeId;
        }

        public long getExpiresAt() {
            return expiresAt;
        }

        private boolean isActive(long now) {
            return getState() == ClockChallengeState.ACTIVE && now < expiresAt;
        }
    }

    public static class Mutation {
        @SerializedName("operationId")
        private String operationId;
        @SerializedName("kind")
        private MutationKind kind;
        @SerializedName("intent")
        private ImportIntent intent;
        @SerializedName("idempotencyKey")
        private String idempotencyKey;
        @SerializedName("requestHash")
        private String requestHash;
        @SerializedName("requester")
        private String requester;
        @SerializedName("approver")
        private String approver;
        @SerializedName("preparedAt")
        private long preparedAt;
        @SerializedName("deadlineAt")
        private long deadlineAt;
        @SerializedName("candidateLicense")
        private ActiveLicense candidateLicense;
        @SerializedName("candidateKeyset")
        private ActiveKeyset candidateKeyset;
        @SerializedName("state")
        private OperationState state;

        public Mutation() {
        }

        public String getOperationId() {
            return operationId;
        }

        public OperationState getState() {
            return state;
        }

        public long getDeadlineAt() {
            return deadlineAt;
        }
    }

    public static class IdempotencyRecord {
        @SerializedName("requestHash")
        private String requestHash;
        @SerializedName("operationId")
        private String operationId;
        @SerializedName("state")
        private OperationState state;

        public IdempotencyRecord() {
        }

        private IdempotencyRecord(String requestHash, String operationId, OperationState state) {
            this.requestHash = requestHash;
            this.operationId = operationId;
            this.state = state;
        }
    }

    @SerializedName("formatVersion")
    private int formatVersion = FORMAT_VERSION;
    @SerializedName("licenseControlDeploymentUuid")
    private String licenseControlDeploymentUuid;
    @SerializedName("enforcementMode")
    private EnforcementMode enforcementMode = EnforcementMode.UNINITIALIZED;
    @SerializedName("enforcementEpoch")
    private long enforcementEpoch;
    @SerializedName("topologyRevision")
    private long topologyRevision;
    @SerializedName("activeKeyset")
    private ActiveKeyset activeKeyset;
    @SerializedName("activeLicense")
    private ActiveLicense activeLicense;
    @SerializedName("mutation")
    private Mutation mutation;
    @SerializedName("lastOperation")
    private Mutation lastOperation;
    @SerializedName("idempotency")
    private Map<String, IdempotencyRecord> idempotency = new LinkedHashMap<>();
    @SerializedName("licenseCorrectionBarriers")
    private List<CorrectionBarrier> licenseCorrectionBarriers = new ArrayList<>();
    @SerializedName("clockChallenge")
    private ClockChallenge clockChallenge;
    @SerializedName("clockRecoveryEpoch")
    private long clockRecoveryEpoch;
    @SerializedName("maxAcceptedRecoverySequence")
    private long maxAcceptedRecoverySequence;
    @SerializedName("bootstrapPhase")
    private String bootstrapPhase = "UNINITIALIZED";
    @SerializedName("bootstrapSealGeneration")
    private long bootstrapSealGeneration;
    @SerializedName("bootstrapPlanSha256")
    private String bootstrapPlanSha256;

    public MassDbLicenseState() {
    }

    public static MassDbLicenseState empty() {
        return new MassDbLicenseState();
    }

    public MassDbLicenseState copy() {
        return GsonUtils.GSON.fromJson(GsonUtils.GSON.toJson(this), MassDbLicenseState.class);
    }

    public MassDbLicenseState bootstrap(boolean existingMetadata, String planSha256) {
        if (enforcementMode != EnforcementMode.UNINITIALIZED) {
            if (equalsText(bootstrapPlanSha256, planSha256)) {
                return copy();
            }
            fail("MASSDB_LICENSE_BOOTSTRAP_SEALED", "License bootstrap已经SEALED");
        }
        requireSha256(planSha256);
        MassDbLicenseState next = copy();
        next.licenseControlDeploymentUuid = UUID.randomUUID().toString();
        next.enforcementMode = existingMetadata ? EnforcementMode.OBSERVE : EnforcementMode.ENFORCING;
        next.bootstrapPhase = "SEALED";
        next.bootstrapSealGeneration = 1;
        next.bootstrapPlanSha256 = planSha256.toLowerCase();
        return next;
    }

    public MassDbLicenseState prepareLicense(String operationId, String idempotencyKey,
            String requestHash, ImportIntent intent, ActiveLicense candidate, String requester,
            String approver, long now, long deadlineAt) {
        requireInitialized();
        requireOperation(operationId, idempotencyKey, requestHash, now, deadlineAt);
        requireText(requester, "requester");
        if (candidate == null) {
            fail("MASSDB_LICENSE_FILE_INVALID", "候选License不能为空");
        }
        MassDbLicenseState replay = replayIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        requireNoMutation();
        rejectWhenChallengeActive(MutationKind.LICENSE, now);
        if (intent == ImportIntent.NORMAL) {
            validateNormal(candidate);
        } else if (intent == ImportIntent.REPLACE_WITH_SHORTER) {
            validateCorrection(candidate, requester, approver);
        } else {
            validateKeyRotationReplacement(candidate);
        }
        MassDbLicenseState next = copy();
        next.mutation = new Mutation();
        next.mutation.operationId = operationId;
        next.mutation.kind = MutationKind.LICENSE;
        next.mutation.intent = intent;
        next.mutation.idempotencyKey = idempotencyKey;
        next.mutation.requestHash = requestHash;
        next.mutation.requester = requester;
        next.mutation.approver = approver;
        next.mutation.preparedAt = now;
        next.mutation.deadlineAt = deadlineAt;
        next.mutation.candidateLicense = candidate;
        next.mutation.state = OperationState.PREPARED;
        next.idempotency.put(idempotencyKey,
                new IdempotencyRecord(requestHash, operationId, OperationState.PREPARED));
        return next;
    }

    public MassDbLicenseState prepareKeyset(String operationId, String idempotencyKey,
            String requestHash, MutationKind kind, ActiveKeyset candidate, long now, long deadlineAt) {
        requireInitialized();
        requireOperation(operationId, idempotencyKey, requestHash, now, deadlineAt);
        if (kind != MutationKind.ADDITIVE_KEYSET && kind != MutationKind.RESTRICTIVE_KEYSET) {
            fail("MASSDB_LICENSE_FILE_INVALID", "非法keyset mutation类型");
        }
        MassDbLicenseState replay = replayIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        requireNoMutation();
        validateCandidateKeyset(candidate);
        rejectWhenChallengeActive(kind, now);
        MassDbLicenseState next = copy();
        next.mutation = new Mutation();
        next.mutation.operationId = operationId;
        next.mutation.kind = kind;
        next.mutation.idempotencyKey = idempotencyKey;
        next.mutation.requestHash = requestHash;
        next.mutation.preparedAt = now;
        next.mutation.deadlineAt = deadlineAt;
        next.mutation.candidateKeyset = candidate;
        next.mutation.state = OperationState.PREPARED;
        next.idempotency.put(idempotencyKey,
                new IdempotencyRecord(requestHash, operationId, OperationState.PREPARED));
        return next;
    }

    public MassDbLicenseState prepareRecoveryBundle(String operationId, String idempotencyKey,
            String requestHash, ActiveKeyset candidateKeyset, ActiveLicense candidateLicense,
            long now, long deadlineAt) {
        requireInitialized();
        requireOperation(operationId, idempotencyKey, requestHash, now, deadlineAt);
        MassDbLicenseState replay = replayIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        requireNoMutation();
        validateCandidateKeyset(candidateKeyset);
        if (candidateLicense == null) {
            fail("MASSDB_LICENSE_FILE_INVALID", "恢复bundle必须包含License工件");
        }
        MassDbLicenseState next = copy();
        next.mutation = new Mutation();
        next.mutation.operationId = operationId;
        next.mutation.kind = MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE;
        next.mutation.idempotencyKey = idempotencyKey;
        next.mutation.requestHash = requestHash;
        next.mutation.preparedAt = now;
        next.mutation.deadlineAt = deadlineAt;
        next.mutation.candidateKeyset = candidateKeyset;
        next.mutation.candidateLicense = candidateLicense;
        next.mutation.state = OperationState.PREPARED;
        next.idempotency.put(idempotencyKey,
                new IdempotencyRecord(requestHash, operationId, OperationState.PREPARED));
        return next;
    }

    public MassDbLicenseState commit(String operationId, long now) {
        requirePrepared(operationId, now);
        MassDbLicenseState next = copy();
        Mutation committed = next.mutation;
        if (committed.kind == MutationKind.LICENSE) {
            if (committed.intent == ImportIntent.REPLACE_WITH_SHORTER) {
                next.licenseCorrectionBarriers.add(new CorrectionBarrier(next.activeLicense, now));
            }
            next.activeLicense = committed.candidateLicense;
        } else if (committed.kind == MutationKind.ADDITIVE_KEYSET
                || committed.kind == MutationKind.RESTRICTIVE_KEYSET
                || committed.kind == MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE) {
            if (committed.candidateKeyset == null) {
                fail("MASSDB_LICENSE_FILE_INVALID", "prepared mutation缺少keyset工件");
            }
            next.activeKeyset = committed.candidateKeyset;
            if (committed.kind == MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE) {
                if (committed.candidateLicense == null) {
                    fail("MASSDB_LICENSE_FILE_INVALID", "恢复bundle缺少License工件");
                }
                next.activeLicense = committed.candidateLicense;
            }
            if ((committed.kind == MutationKind.RESTRICTIVE_KEYSET
                    || committed.kind == MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE)
                    && next.clockChallenge != null && next.clockChallenge.isActive(now)) {
                next.clockChallenge.state = ClockChallengeState.INVALIDATED_BY_KEYSET_RECOVERY;
                next.clockChallenge.invalidatedAt = now;
            }
        }
        committed.state = OperationState.SUCCEEDED;
        next.idempotency.get(committed.idempotencyKey).state = OperationState.SUCCEEDED;
        next.lastOperation = committed;
        next.mutation = null;
        return next;
    }

    public MassDbLicenseState abort(String operationId) {
        if (mutation == null || !equalsText(mutation.operationId, operationId)) {
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的active mutation");
        }
        MassDbLicenseState next = copy();
        next.mutation.state = OperationState.ABORTED;
        next.idempotency.get(next.mutation.idempotencyKey).state = OperationState.ABORTED;
        next.lastOperation = next.mutation;
        next.mutation = null;
        return next;
    }

    public MassDbLicenseState createClockChallenge(String challengeId, String challengeHex,
            long now, long expiresAt) {
        requireInitialized();
        requireNoMutation();
        if (clockChallenge != null && clockChallenge.isActive(now)) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_CHALLENGE_ACTIVE", "已有未消费时钟恢复challenge");
        }
        MassDbLicenseState next = copy();
        next.clockChallenge = new ClockChallenge(challengeId, challengeHex, now, expiresAt);
        return next;
    }

    public MassDbLicenseState cancelClockChallenge(String challengeId, long now) {
        requireNoMutation();
        if (clockChallenge == null || !clockChallenge.isActive(now)
                || !equalsText(clockChallenge.challengeId, challengeId)) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_CHALLENGE_NOT_FOUND", "没有匹配的active challenge");
        }
        MassDbLicenseState next = copy();
        next.clockChallenge.state = ClockChallengeState.CANCELLED;
        next.clockChallenge.invalidatedAt = now;
        return next;
    }

    public EnforcementMode getEnforcementMode() {
        return enforcementMode;
    }

    public boolean isInitialized() {
        return enforcementMode != EnforcementMode.UNINITIALIZED;
    }

    public String getLicenseControlDeploymentUuid() {
        return licenseControlDeploymentUuid;
    }

    public ActiveLicense getActiveLicense() {
        return activeLicense;
    }

    public Mutation getMutation() {
        return mutation;
    }

    public long getKeysetVersion() {
        return activeKeyset == null ? 0 : activeKeyset.version;
    }

    public ActiveKeyset getActiveKeyset() {
        return activeKeyset;
    }

    public ClockChallenge getClockChallenge() {
        return clockChallenge;
    }

    public List<CorrectionBarrier> getLicenseCorrectionBarriers() {
        return Collections.unmodifiableList(licenseCorrectionBarriers);
    }

    public long getBootstrapSealGeneration() {
        return bootstrapSealGeneration;
    }

    private void validateNormal(ActiveLicense candidate) {
        if (activeLicense != null && candidate.expiresAt <= activeLicense.expiresAt) {
            fail("MASSDB_LICENSE_EXPIRY_NOT_EXTENDED", "NORMAL续期必须严格延长到期时间");
        }
        for (CorrectionBarrier barrier : licenseCorrectionBarriers) {
            if (candidate.expiresAt >= barrier.supersededExpiresAt
                    && candidate.issuedAt <= barrier.supersededIssuedAtCutoff) {
                fail("MASSDB_LICENSE_SUPERSEDED", "候选License会撤销已批准的到期更正");
            }
        }
    }

    private void validateCorrection(ActiveLicense candidate, String requester, String approver) {
        if (activeLicense == null || candidate.expiresAt >= activeLicense.expiresAt) {
            fail("MASSDB_LICENSE_CORRECTION_REQUIRED", "到期更正必须严格缩短当前到期时间");
        }
        requireText(approver, "approver");
        if (requester.equals(approver)) {
            fail("MASSDB_LICENSE_CORRECTION_DUAL_CONTROL_REQUIRED", "到期更正必须由不同主体批准");
        }
    }

    private void validateKeyRotationReplacement(ActiveLicense candidate) {
        if (activeLicense == null || candidate.expiresAt != activeLicense.expiresAt
                || candidate.sha256.equals(activeLicense.sha256)) {
            fail("MASSDB_LICENSE_KEY_ROTATION_REPLACEMENT_INVALID",
                    "key换签替换必须保持同一到期时间且使用不同工件");
        }
    }

    private void validateCandidateKeyset(ActiveKeyset candidate) {
        if (candidate == null || candidate.version <= getKeysetVersion()) {
            fail("MASSDB_LICENSE_KEYSET_VERSION_NOT_INCREASED", "keysetVersion必须严格递增");
        }
    }

    private void requireOperation(String operationId, String idempotencyKey,
            String requestHash, long now, long deadlineAt) {
        requireText(operationId, "operationId");
        requireIdempotencyKey(idempotencyKey);
        requireSha256(requestHash);
        if (deadlineAt <= now) {
            fail("MASSDB_LICENSE_OPERATION_DEADLINE_EXCEEDED", "operation deadline已经到期");
        }
    }

    private void requirePrepared(String operationId, long now) {
        if (mutation == null || mutation.state != OperationState.PREPARED
                || !equalsText(mutation.operationId, operationId)) {
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的prepared mutation");
        }
        if (now > mutation.deadlineAt) {
            fail("MASSDB_LICENSE_OPERATION_DEADLINE_EXCEEDED", "prepared mutation已经超时");
        }
    }

    private void rejectWhenChallengeActive(MutationKind kind, long now) {
        if (clockChallenge == null || !clockChallenge.isActive(now)) {
            return;
        }
        if (kind == MutationKind.RESTRICTIVE_KEYSET
                || kind == MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE
                || kind == MutationKind.CLOCK_RECOVERY) {
            return;
        }
        fail("MASSDB_LICENSE_CLOCK_RECOVERY_CHALLENGE_ACTIVE",
                "active时钟恢复challenge冻结普通License和加法keyset写入");
    }

    private MassDbLicenseState replayIdempotency(String key, String requestHash) {
        IdempotencyRecord previous = idempotency.get(key);
        if (previous == null) {
            return null;
        }
        if (!equalsText(previous.requestHash, requestHash)) {
            fail("MASSDB_LICENSE_IDEMPOTENCY_CONFLICT", "Idempotency-Key已绑定不同请求");
        }
        return copy();
    }

    private void requireInitialized() {
        if (enforcementMode == EnforcementMode.UNINITIALIZED || licenseControlDeploymentUuid == null) {
            fail("MASSDB_LICENSE_BOOTSTRAP_REQUIRED", "License一致性状态尚未bootstrap");
        }
    }

    private void requireNoMutation() {
        if (mutation != null) {
            fail("MASSDB_LICENSE_MUTATION_IN_PROGRESS", "已有License mutation占用统一槽位");
        }
    }

    private static void requireIdempotencyKey(String value) {
        requireText(value, "Idempotency-Key");
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        if (bytes.length > MAX_IDEMPOTENCY_KEY_BYTES || value.length() != bytes.length) {
            fail("MASSDB_LICENSE_IDEMPOTENCY_KEY_INVALID", "Idempotency-Key必须为1至191 ASCII字节");
        }
        for (byte b : bytes) {
            if (b < 0x21 || b > 0x7e) {
                fail("MASSDB_LICENSE_IDEMPOTENCY_KEY_INVALID", "Idempotency-Key含非法ASCII字符");
            }
        }
    }

    private static void requireSha256(String value) {
        if (value == null || !value.matches("[0-9a-fA-F]{64}")) {
            fail("MASSDB_LICENSE_FILE_INVALID", "SHA-256必须为64位十六进制");
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.trim().isEmpty()) {
            fail("MASSDB_LICENSE_FILE_INVALID", field + "不能为空");
        }
    }

    private static boolean equalsText(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    @Override
    public void write(DataOutput out) throws IOException {
        Text.writeString(out, GsonUtils.GSON.toJson(this));
    }

    public static MassDbLicenseState read(DataInput in) throws IOException {
        MassDbLicenseState state = GsonUtils.GSON.fromJson(Text.readString(in), MassDbLicenseState.class);
        if (state == null || state.formatVersion != FORMAT_VERSION) {
            throw new IOException("unsupported MassDB License state format");
        }
        if (state.idempotency == null) {
            state.idempotency = new LinkedHashMap<>();
        }
        if (state.licenseCorrectionBarriers == null) {
            state.licenseCorrectionBarriers = new ArrayList<>();
        }
        return state;
    }
}
