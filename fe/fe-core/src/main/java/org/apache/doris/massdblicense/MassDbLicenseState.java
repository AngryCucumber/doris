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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

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
    public static final long DEFAULT_ROLE_STATUS_INTERVAL_SECONDS = 30;
    public static final long DEFAULT_ROLE_LIVE_LEASE_SECONDS = 90;
    public static final long DEFAULT_CLOCK_PERSISTENCE_SECONDS = 300;
    public static final long DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS = 300;
    public static final long DEFAULT_CONTROL_PLANE_STALENESS_SECONDS = 7 * 24 * 60 * 60;
    public static final long DIAGNOSTIC_EVENT_RETENTION_SECONDS = 14 * 24 * 60 * 60;
    public static final int DEFAULT_DIAGNOSTIC_EVENT_CAPACITY = 50_000;
    public static final int MAX_DIAGNOSTIC_EVENT_PAGE_SIZE = 200;
    private static final int MAX_DIAGNOSTIC_EVENT_STATE_BYTES = 64 << 20;
    private static final Pattern DIAGNOSTIC_EVENT_KIND =
            Pattern.compile("[A-Z][A-Z0-9_]{0,95}");
    private static final Pattern DIAGNOSTIC_ERROR_CODE =
            Pattern.compile("MASSDB_LICENSE_[A-Z0-9_]{1,96}");
    private static final Pattern DIAGNOSTIC_HEX = Pattern.compile("[0-9a-f]+");

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
        BOOTSTRAP_CONTROL,
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
        FAILED,
        ABORTED
    }

    public enum ClockChallengeState {
        NONE,
        ACTIVE,
        CANCELLED,
        CONSUMED,
        INVALIDATED_BY_KEYSET_RECOVERY
    }

    public enum CorrectionProposalState {
        PENDING,
        APPROVED,
        CANCELLED,
        EXPIRED,
        CONSUMED
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
        @SerializedName("correctedExpiresAt")
        private long correctedExpiresAt;
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
        @SerializedName("correctionOperationId")
        private String correctionOperationId;

        public CorrectionBarrier() {
        }

        private CorrectionBarrier(ActiveLicense superseded, ActiveLicense corrected,
                String operationId, long correctedAt) {
            this.correctedExpiresAt = corrected.expiresAt;
            this.supersededExpiresAt = superseded.expiresAt;
            this.correctedAt = correctedAt;
            this.supersededIssuedAtCutoff = saturatedAdd(
                    correctedAt, ISSUED_AT_FUTURE_TOLERANCE_SECONDS);
            this.supersededLicenseId = superseded.licenseId;
            this.supersededSha256 = superseded.sha256;
            this.correctionOperationId = operationId;
        }

        public long getCorrectedExpiresAt() {
            return correctedExpiresAt;
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

        public Long getInvalidatedAt() {
            return invalidatedAt;
        }

        public String getChallengeHex() {
            return challengeHex;
        }

        private boolean isActive(long now) {
            return getState() == ClockChallengeState.ACTIVE && now < expiresAt;
        }
    }

    /** Durable, payload-free dual-control record for a shorter-expiry replacement. */
    public static class CorrectionProposal {
        @SerializedName("proposalId")
        private String proposalId;
        @SerializedName("candidateSha256")
        private String candidateSha256;
        @SerializedName("candidateLicenseId")
        private String candidateLicenseId;
        @SerializedName("candidateExpiresAt")
        private long candidateExpiresAt;
        @SerializedName("activeLicenseSha256")
        private String activeLicenseSha256;
        @SerializedName("activeLicenseExpiresAt")
        private long activeLicenseExpiresAt;
        @SerializedName("requester")
        private String requester;
        @SerializedName("createIdempotencyKey")
        private String createIdempotencyKey;
        @SerializedName("createRequestHash")
        private String createRequestHash;
        @SerializedName("approver")
        private String approver;
        @SerializedName("approveIdempotencyKey")
        private String approveIdempotencyKey;
        @SerializedName("approveRequestHash")
        private String approveRequestHash;
        @SerializedName("cancelIdempotencyKey")
        private String cancelIdempotencyKey;
        @SerializedName("cancelRequestHash")
        private String cancelRequestHash;
        @SerializedName("createdAt")
        private long createdAt;
        @SerializedName("expiresAt")
        private long expiresAt;
        @SerializedName("approvedAt")
        private Long approvedAt;
        @SerializedName("consumedAt")
        private Long consumedAt;
        @SerializedName("state")
        private CorrectionProposalState state;

        public CorrectionProposal() {
        }

        private CorrectionProposal(String proposalId, ActiveLicense candidate,
                ActiveLicense active, String requester, String createIdempotencyKey,
                String createRequestHash, long createdAt, long expiresAt) {
            this.proposalId = proposalId;
            this.candidateSha256 = candidate.sha256;
            this.candidateLicenseId = candidate.licenseId;
            this.candidateExpiresAt = candidate.expiresAt;
            this.activeLicenseSha256 = active.sha256;
            this.activeLicenseExpiresAt = active.expiresAt;
            this.requester = requester;
            this.createIdempotencyKey = createIdempotencyKey;
            this.createRequestHash = createRequestHash;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.state = CorrectionProposalState.PENDING;
        }

        public String getProposalId() {
            return proposalId;
        }

        public String getCandidateSha256() {
            return candidateSha256;
        }

        public String getActiveLicenseSha256() {
            return activeLicenseSha256;
        }

        public String getRequester() {
            return requester;
        }

        public String getApprover() {
            return approver;
        }

        public long getExpiresAt() {
            return expiresAt;
        }

        public CorrectionProposalState getState() {
            return state;
        }
    }

    /** Complete signed clock-recovery bytes and their verified semantic projection. */
    public static class StagedClockRecovery {
        @SerializedName("contentSha256")
        private String contentSha256;
        @SerializedName("artifact")
        private byte[] artifact;
        @SerializedName("challengeId")
        private String challengeId;
        @SerializedName("recoverySequence")
        private long recoverySequence;
        @SerializedName("observedMaxSeenWallClock")
        private long observedMaxSeenWallClock;
        @SerializedName("resetMaxSeenWallClockTo")
        private long resetMaxSeenWallClockTo;
        @SerializedName("artifactIssuedAt")
        private long artifactIssuedAt;
        @SerializedName("artifactExpiresAt")
        private long artifactExpiresAt;

        public StagedClockRecovery() {
        }

        public StagedClockRecovery(String contentSha256, byte[] artifact,
                String challengeId, long recoverySequence,
                long observedMaxSeenWallClock, long resetMaxSeenWallClockTo,
                long artifactIssuedAt, long artifactExpiresAt) {
            requireSha256(contentSha256);
            requireText(challengeId, "challengeId");
            if (artifact == null || artifact.length == 0 || recoverySequence <= 0
                    || artifactExpiresAt <= artifactIssuedAt) {
                fail("MASSDB_LICENSE_FILE_INVALID", "clock recovery staged字段错误");
            }
            this.contentSha256 = contentSha256.toLowerCase();
            this.artifact = artifact.clone();
            this.challengeId = challengeId;
            this.recoverySequence = recoverySequence;
            this.observedMaxSeenWallClock = observedMaxSeenWallClock;
            this.resetMaxSeenWallClockTo = resetMaxSeenWallClockTo;
            this.artifactIssuedAt = artifactIssuedAt;
            this.artifactExpiresAt = artifactExpiresAt;
        }

        public String getContentSha256() {
            return contentSha256;
        }

        public byte[] getArtifact() {
            return artifact == null ? null : artifact.clone();
        }

        public String getChallengeId() {
            return challengeId;
        }

        public long getRecoverySequence() {
            return recoverySequence;
        }

        public long getObservedMaxSeenWallClock() {
            return observedMaxSeenWallClock;
        }

        public long getResetMaxSeenWallClockTo() {
            return resetMaxSeenWallClockTo;
        }

        public long getArtifactIssuedAt() {
            return artifactIssuedAt;
        }

        public long getArtifactExpiresAt() {
            return artifactExpiresAt;
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
        @SerializedName("candidateIngressInventory")
        private MassDbLicenseIngressInventory candidateIngressInventory;
        @SerializedName("candidateClockRecovery")
        private StagedClockRecovery candidateClockRecovery;
        @SerializedName("correctionProposalId")
        private String correctionProposalId;
        @SerializedName("action")
        private String action;
        @SerializedName("snapshotActiveSha256")
        private String snapshotActiveSha256;
        @SerializedName("snapshotActiveExpiresAt")
        private Long snapshotActiveExpiresAt;
        @SerializedName("snapshotEnforcementEpoch")
        private Long snapshotEnforcementEpoch;
        @SerializedName("targetEnforcementEpoch")
        private Long targetEnforcementEpoch;
        @SerializedName("snapshotTopologyRevision")
        private Long snapshotTopologyRevision;
        @SerializedName("snapshotInventorySha256")
        private String snapshotInventorySha256;
        @SerializedName("snapshotRoutingSha256")
        private String snapshotRoutingSha256;
        @SerializedName("requiredAckNodeUuids")
        private List<String> requiredAckNodeUuids;
        @SerializedName("deferredNodeUuids")
        private List<String> deferredNodeUuids;
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

        public long getPreparedAt() {
            return preparedAt;
        }

        public String getAction() {
            return action;
        }

        public ActiveLicense getCandidateLicense() {
            return candidateLicense;
        }

        public ActiveKeyset getCandidateKeyset() {
            return candidateKeyset;
        }

        public StagedClockRecovery getCandidateClockRecovery() {
            return candidateClockRecovery;
        }

        public String getCorrectionProposalId() {
            return correctionProposalId;
        }

        public MutationKind getKind() {
            return kind;
        }

        public ImportIntent getIntent() {
            return intent;
        }

        public List<String> getRequiredAckNodeUuids() {
            return requiredAckNodeUuids == null
                    ? Collections.emptyList() : new ArrayList<>(requiredAckNodeUuids);
        }

        public List<String> getDeferredNodeUuids() {
            return deferredNodeUuids == null
                    ? Collections.emptyList() : new ArrayList<>(deferredNodeUuids);
        }

        public String getSnapshotActiveSha256() {
            return snapshotActiveSha256;
        }

        public Long getSnapshotActiveExpiresAt() {
            return snapshotActiveExpiresAt;
        }

        public Long getSnapshotEnforcementEpoch() {
            return snapshotEnforcementEpoch;
        }

        public Long getTargetEnforcementEpoch() {
            return targetEnforcementEpoch;
        }

        public Long getSnapshotTopologyRevision() {
            return snapshotTopologyRevision;
        }

        public String getSnapshotInventorySha256() {
            return snapshotInventorySha256;
        }

        public String getSnapshotRoutingSha256() {
            return snapshotRoutingSha256;
        }
    }

    public static class IdempotencyRecord {
        @SerializedName("requestHash")
        private String requestHash;
        @SerializedName("operationId")
        private String operationId;
        @SerializedName("state")
        private OperationState state;
        @SerializedName("kind")
        private MutationKind kind;
        @SerializedName("action")
        private String action;
        @SerializedName("contentSha256")
        private String contentSha256;
        @SerializedName("targetLicenseExpiresAt")
        private Long targetLicenseExpiresAt;
        @SerializedName("targetEnforcementEpoch")
        private Long targetEnforcementEpoch;
        @SerializedName("targetBootstrapPhase")
        private String targetBootstrapPhase;
        @SerializedName("createdAt")
        private long createdAt;
        @SerializedName("deadlineAt")
        private long deadlineAt;
        @SerializedName("updatedAt")
        private long updatedAt;
        @SerializedName("errorCode")
        private String errorCode;

        public IdempotencyRecord() {
        }

        private IdempotencyRecord(String requestHash, String operationId, OperationState state) {
            this.requestHash = requestHash;
            this.operationId = operationId;
            this.state = state;
        }

        private IdempotencyRecord(Mutation mutation) {
            this(mutation.requestHash, mutation.operationId, mutation.state);
            this.kind = mutation.kind;
            this.action = mutation.action;
            if (mutation.candidateLicense == null) {
                this.contentSha256 = mutation.snapshotActiveSha256;
                this.targetLicenseExpiresAt = mutation.snapshotActiveExpiresAt;
            } else {
                this.contentSha256 = mutation.candidateLicense.sha256;
                this.targetLicenseExpiresAt = mutation.candidateLicense.expiresAt;
            }
            this.targetEnforcementEpoch = mutation.targetEnforcementEpoch;
            this.targetBootstrapPhase = mutation.kind == MutationKind.BOOTSTRAP_CONTROL
                    ? "SEALED" : null;
            this.createdAt = mutation.preparedAt;
            this.deadlineAt = mutation.deadlineAt;
            this.updatedAt = mutation.preparedAt;
        }
    }

    public static final class OperationView {
        public final String operationId;
        public final MutationKind kind;
        public final String action;
        public final String contentSha256;
        public final Long targetLicenseExpiresAt;
        public final Long targetEnforcementEpoch;
        public final String targetBootstrapPhase;
        public final String apiState;
        public final OperationState state;
        public final boolean terminal;
        public final long createdAt;
        public final long deadlineAt;
        public final long updatedAt;
        public final String errorCode;

        private OperationView(IdempotencyRecord record) {
            this.operationId = record.operationId;
            this.kind = record.kind;
            this.action = record.action;
            this.contentSha256 = record.contentSha256;
            this.targetLicenseExpiresAt = record.targetLicenseExpiresAt;
            this.targetEnforcementEpoch = record.targetEnforcementEpoch;
            this.targetBootstrapPhase = record.targetBootstrapPhase;
            this.state = record.state;
            this.apiState = operationApiState(record);
            this.terminal = record.state != OperationState.PREPARED;
            this.createdAt = record.createdAt;
            this.deadlineAt = record.deadlineAt;
            this.updatedAt = record.updatedAt;
            this.errorCode = record.errorCode;
        }
    }

    /** Trusted role-local proof that the activation pending file was durably persisted. */
    public static final class ActivationAckEvidence {
        public final String nodeUuid;
        public final String operationId;
        public final long targetEnforcementEpoch;
        public final String activeLicenseSha256;
        public final String pendingSnapshotSha256;

        public ActivationAckEvidence(String nodeUuid, String operationId,
                long targetEnforcementEpoch, String activeLicenseSha256,
                String pendingSnapshotSha256) {
            this.nodeUuid = nodeUuid;
            this.operationId = operationId;
            this.targetEnforcementEpoch = targetEnforcementEpoch;
            this.activeLicenseSha256 = activeLicenseSha256;
            this.pendingSnapshotSha256 = pendingSnapshotSha256;
        }
    }

    /** Keyset ACK is accepted only when the component-internal mTLS identity binds nodeUuid. */
    public static final class KeysetAckEvidence {
        public final String nodeUuid;
        public final String operationId;
        public final String keysetSha256;
        public final long keysetVersion;
        public final String licenseSha256;
        public final long licenseExpiresAt;
        public final String pendingSnapshotSha256;

        public KeysetAckEvidence(String nodeUuid, String operationId,
                String keysetSha256, long keysetVersion, String licenseSha256,
                long licenseExpiresAt, String pendingSnapshotSha256) {
            this.nodeUuid = nodeUuid;
            this.operationId = operationId;
            this.keysetSha256 = keysetSha256 == null
                    ? null : keysetSha256.toLowerCase();
            this.keysetVersion = keysetVersion;
            this.licenseSha256 = licenseSha256 == null
                    ? null : licenseSha256.toLowerCase();
            this.licenseExpiresAt = licenseExpiresAt;
            this.pendingSnapshotSha256 = pendingSnapshotSha256 == null
                    ? null : pendingSnapshotSha256.toLowerCase();
        }
    }

    /** A bounded, payload-free event accepted by the component-local diagnostic ledger. */
    public static final class DiagnosticEventInput {
        public final String severity;
        public final String eventKind;
        public final String errorCode;
        public final String nodeUuid;
        public final String operationId;
        public final String subjectKey;
        public final String digestPrefix;
        public final String guardState;
        public final String routingState;
        public final boolean critical;

        public DiagnosticEventInput(String severity, String eventKind, String errorCode,
                String nodeUuid, String operationId, String subjectKey, String digestPrefix,
                String guardState, String routingState, boolean critical) {
            this.severity = nullToEmpty(severity);
            this.eventKind = nullToEmpty(eventKind);
            this.errorCode = nullToEmpty(errorCode);
            this.nodeUuid = nullToEmpty(nodeUuid);
            this.operationId = nullToEmpty(operationId);
            this.subjectKey = nullToEmpty(subjectKey);
            this.digestPrefix = nullToEmpty(digestPrefix).toLowerCase();
            this.guardState = nullToEmpty(guardState);
            this.routingState = nullToEmpty(routingState);
            this.critical = critical;
        }
    }

    /** Replicated diagnostic metadata. It never contains SQL, stack traces or License bytes. */
    public static final class DiagnosticEvent {
        @SerializedName("sequence")
        public long sequence;
        @SerializedName("eventId")
        public String eventId;
        @SerializedName("occurredAt")
        public long occurredAt;
        @SerializedName("lastSeenAt")
        public long lastSeenAt;
        @SerializedName("count")
        public long count;
        @SerializedName("severity")
        public String severity;
        @SerializedName("eventKind")
        public String eventKind;
        @SerializedName("errorCode")
        public String errorCode;
        @SerializedName("nodeUuid")
        public String nodeUuid;
        @SerializedName("operationId")
        public String operationId;
        @SerializedName("subjectKey")
        public String subjectKey;
        @SerializedName("digestPrefix")
        public String digestPrefix;
        @SerializedName("enforcementEpoch")
        public long enforcementEpoch;
        @SerializedName("clockRecoveryEpoch")
        public long clockRecoveryEpoch;
        @SerializedName("keysetVersion")
        public long keysetVersion;
        @SerializedName("guardState")
        public String guardState;
        @SerializedName("routingState")
        public String routingState;
        @SerializedName("active")
        public boolean active;
        @SerializedName("resolvedAt")
        public Long resolvedAt;
        @SerializedName("pinnedUntil")
        public Long pinnedUntil;

        public DiagnosticEvent() {
        }

        private DiagnosticEvent(DiagnosticEventInput input, MassDbLicenseState state, long now) {
            sequence = state.diagnosticSequence;
            eventId = UUID.randomUUID().toString();
            occurredAt = now;
            lastSeenAt = now;
            count = 1;
            severity = input.severity;
            eventKind = input.eventKind;
            errorCode = input.errorCode;
            nodeUuid = input.nodeUuid;
            operationId = input.operationId;
            subjectKey = input.subjectKey;
            digestPrefix = input.digestPrefix;
            enforcementEpoch = state.enforcementEpoch;
            clockRecoveryEpoch = state.clockRecoveryEpoch;
            keysetVersion = state.getKeysetVersion();
            guardState = input.guardState;
            routingState = input.routingState;
            active = input.critical;
        }
    }

    public static final class DiagnosticEventPage {
        public final List<DiagnosticEvent> items;
        public final long nextSequence;
        public final boolean hasMore;
        public final int pageSize;
        public final long retentionSeconds = DIAGNOSTIC_EVENT_RETENTION_SECONDS;
        public final int capacity = DEFAULT_DIAGNOSTIC_EVENT_CAPACITY;
        public final long maxControlPlaneStalenessSeconds =
                DEFAULT_CONTROL_PLANE_STALENESS_SECONDS;

        private DiagnosticEventPage(List<DiagnosticEvent> items, long nextSequence,
                boolean hasMore, int pageSize) {
            this.items = Collections.unmodifiableList(items);
            this.nextSequence = nextSequence;
            this.hasMore = hasMore;
            this.pageSize = pageSize;
        }
    }

    @SerializedName("formatVersion")
    private int formatVersion = FORMAT_VERSION;
    @SerializedName("licenseControlDeploymentUuid")
    private String licenseControlDeploymentUuid;
    @SerializedName("preconditionHmacKey")
    private byte[] preconditionHmacKey;
    @SerializedName("enforcementMode")
    private EnforcementMode enforcementMode = EnforcementMode.UNINITIALIZED;
    @SerializedName("enforcementEpoch")
    private long enforcementEpoch;
    @SerializedName("topologyRevision")
    private long topologyRevision;
    @SerializedName("controlPlaneRevision")
    private long controlPlaneRevision;
    @SerializedName("maxSeenWallClock")
    private long maxSeenWallClock;
    @SerializedName("ingressInventory")
    private MassDbLicenseIngressInventory ingressInventory = MassDbLicenseIngressInventory.empty();
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
    @SerializedName("correctionProposals")
    private Map<String, CorrectionProposal> correctionProposals = new LinkedHashMap<>();
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
    @SerializedName("bootstrapMarkerId")
    private String bootstrapMarkerId;
    @SerializedName("bootstrapMarkerCreatedAt")
    private long bootstrapMarkerCreatedAt;
    @SerializedName("bootstrapMarkerConsumedAt")
    private long bootstrapMarkerConsumedAt;
    @SerializedName("bootstrapOperationId")
    private String bootstrapOperationId;
    @SerializedName("bootstrapRequestHash")
    private String bootstrapRequestHash;
    @SerializedName("initializationSource")
    private String initializationSource;
    @SerializedName("minimumEnforcementVersion")
    private String minimumEnforcementVersion;
    @SerializedName("upgradeAttestationSha256")
    private String upgradeAttestationSha256;
    @SerializedName("diagnosticSequence")
    private long diagnosticSequence;
    @SerializedName("diagnosticEvents")
    private List<DiagnosticEvent> diagnosticEvents = new ArrayList<>();

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
        next.preconditionHmacKey = new byte[32];
        new SecureRandom().nextBytes(next.preconditionHmacKey);
        next.enforcementMode = existingMetadata ? EnforcementMode.OBSERVE : EnforcementMode.ENFORCING;
        next.bootstrapPhase = "SEALED";
        next.bootstrapSealGeneration = 1;
        next.bootstrapPlanSha256 = planSha256.toLowerCase();
        return next;
    }

    /**
     * Opens the one-time bootstrap window from a component-created, fresh-meta attestation.
     * The deployment UUID is generated before FE identity enrollment, avoiding any Manager-owned
     * identity root or a circular dependency on already initialized License state.
     */
    public MassDbLicenseState openBootstrap(String markerId, String deploymentUuid,
            String planSha256, long markerCreatedAt) {
        requireUuidV4(markerId, "bootstrapMarkerId");
        requireUuidV4(deploymentUuid, "licenseControlDeploymentUuid");
        requireSha256(planSha256);
        if (markerCreatedAt <= 0) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "bootstrap marker createdAt无效");
        }
        if (enforcementMode != EnforcementMode.UNINITIALIZED) {
            if ("OPEN".equals(bootstrapPhase)
                    && markerId.equals(bootstrapMarkerId)
                    && deploymentUuid.equals(licenseControlDeploymentUuid)
                    && planSha256.equalsIgnoreCase(bootstrapPlanSha256)
                    && markerCreatedAt == bootstrapMarkerCreatedAt) {
                return copy();
            }
            fail("MASSDB_LICENSE_BOOTSTRAP_SEALED", "License bootstrap已经初始化或SEALED");
        }
        if (!"UNINITIALIZED".equals(bootstrapPhase) || bootstrapSealGeneration != 0
                || bootstrapPlanSha256 != null || bootstrapMarkerId != null
                || bootstrapMarkerCreatedAt != 0 || bootstrapMarkerConsumedAt != 0
                || bootstrapOperationId != null || bootstrapRequestHash != null
                || initializationSource != null || minimumEnforcementVersion != null
                || upgradeAttestationSha256 != null
                || activeKeyset != null || activeLicense != null || mutation != null
                || lastOperation != null || !idempotency.isEmpty()
                || !licenseCorrectionBarriers.isEmpty() || !correctionProposals.isEmpty()
                || clockChallenge != null
                || !getIngressInventory().getNodes().isEmpty()
                || enforcementEpoch != 0 || topologyRevision != 0
                || clockRecoveryEpoch != 0 || maxAcceptedRecoverySequence != 0) {
            fail("MASSDB_LICENSE_BOOTSTRAP_STATE_CONFLICT",
                    "UNINITIALIZED状态包含既有License控制面或运行态数据");
        }
        MassDbLicenseState next = copy();
        next.licenseControlDeploymentUuid = deploymentUuid;
        next.preconditionHmacKey = new byte[32];
        new SecureRandom().nextBytes(next.preconditionHmacKey);
        next.enforcementMode = EnforcementMode.ENFORCING;
        next.bootstrapPhase = "OPEN";
        next.bootstrapSealGeneration = 0;
        next.bootstrapPlanSha256 = planSha256.toLowerCase();
        next.bootstrapMarkerId = markerId;
        next.bootstrapMarkerCreatedAt = markerCreatedAt;
        return next;
    }

    /**
     * Atomically creates the first License journal for an existing cluster after every persisted
     * FE has returned an exact build/capability proof over the component-native mTLS channel.
     */
    public MassDbLicenseState initializeObserve(String operationId, String idempotencyKey,
            String requestHash, String upgradeSessionId, String deploymentUuid,
            String planSha256, long markerCreatedAt, String minimumVersion,
            String attestationSha256, ActiveKeyset keyset,
            MassDbLicenseIngressInventory inventory, long now) {
        requireOperation(operationId, idempotencyKey, requestHash, now, saturatedAdd(now, 1));
        requireUuidV4(upgradeSessionId, "upgradeSessionId");
        requireUuidV4(deploymentUuid, "licenseControlDeploymentUuid");
        requireSha256(planSha256);
        requireSha256(attestationSha256);
        requireText(minimumVersion, "minimumEnforcementVersion");
        if (markerCreatedAt <= 0 || markerCreatedAt > saturatedAdd(
                now, ISSUED_AT_FUTURE_TOLERANCE_SECONDS)) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker createdAt无效");
        }
        IdempotencyRecord existing = idempotency.get(idempotencyKey);
        if (existing != null) {
            if (!requestHash.equals(existing.requestHash)) {
                fail("MASSDB_LICENSE_IDEMPOTENCY_CONFLICT", "Idempotency-Key已绑定不同请求");
            }
            return copy();
        }
        if (enforcementMode != EnforcementMode.UNINITIALIZED) {
            if (enforcementMode == EnforcementMode.OBSERVE
                    && "EXISTING_UPGRADE".equals(initializationSource)
                    && upgradeSessionId.equals(bootstrapMarkerId)
                    && deploymentUuid.equals(licenseControlDeploymentUuid)
                    && planSha256.equals(bootstrapPlanSha256)
                    && requestHash.equals(bootstrapRequestHash)
                    && bootstrapOperationId != null) {
                MassDbLicenseState alias = copy();
                IdempotencyRecord canonical = findIdempotencyByOperation(bootstrapOperationId);
                if (canonical == null || canonical.state != OperationState.SUCCEEDED) {
                    fail("MASSDB_LICENSE_OPERATION_RECOVERY_FAILED",
                            "upgrade幂等终态记录缺失");
                }
                alias.idempotency.put(idempotencyKey, copyIdempotency(canonical));
                return alias;
            }
            fail("MASSDB_LICENSE_UPGRADE_ALREADY_INITIALIZED", "License一致性状态已经初始化");
        }
        if (!"UNINITIALIZED".equals(bootstrapPhase) || bootstrapSealGeneration != 0
                || bootstrapPlanSha256 != null || bootstrapMarkerId != null
                || bootstrapMarkerCreatedAt != 0 || bootstrapMarkerConsumedAt != 0
                || bootstrapOperationId != null || bootstrapRequestHash != null
                || initializationSource != null || minimumEnforcementVersion != null
                || upgradeAttestationSha256 != null
                || licenseControlDeploymentUuid != null || preconditionHmacKey != null
                || activeKeyset != null || activeLicense != null || mutation != null
                || lastOperation != null || !idempotency.isEmpty()
                || !licenseCorrectionBarriers.isEmpty() || !correctionProposals.isEmpty()
                || clockChallenge != null
                || !getIngressInventory().getNodes().isEmpty()
                || enforcementEpoch != 0 || topologyRevision != 0
                || controlPlaneRevision <= 0 || maxSeenWallClock != 0
                || clockRecoveryEpoch != 0 || maxAcceptedRecoverySequence != 0) {
            fail("MASSDB_LICENSE_UPGRADE_STATE_CONFLICT",
                    "UNINITIALIZED状态包含既有License控制面或运行态数据");
        }
        if (keyset == null || inventory == null || inventory.getNodes().isEmpty()) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "upgrade keyset和FE入口清单不能为空");
        }
        MassDbLicenseState next = copy();
        next.licenseControlDeploymentUuid = deploymentUuid;
        next.preconditionHmacKey = new byte[32];
        new SecureRandom().nextBytes(next.preconditionHmacKey);
        next.enforcementMode = EnforcementMode.OBSERVE;
        next.enforcementEpoch = 0;
        next.topologyRevision = incrementRevision(next.topologyRevision);
        next.maxSeenWallClock = now;
        next.activeKeyset = keyset;
        next.ingressInventory = inventory.copy();
        next.bootstrapPhase = "SEALED";
        next.bootstrapSealGeneration = 1;
        next.bootstrapPlanSha256 = planSha256.toLowerCase();
        next.bootstrapMarkerId = upgradeSessionId;
        next.bootstrapMarkerCreatedAt = markerCreatedAt;
        next.bootstrapMarkerConsumedAt = now;
        next.bootstrapOperationId = operationId;
        next.bootstrapRequestHash = requestHash.toLowerCase();
        next.initializationSource = "EXISTING_UPGRADE";
        next.minimumEnforcementVersion = minimumVersion;
        next.upgradeAttestationSha256 = attestationSha256.toLowerCase();

        Mutation terminal = new Mutation();
        terminal.operationId = operationId;
        terminal.kind = MutationKind.BOOTSTRAP_CONTROL;
        terminal.idempotencyKey = idempotencyKey;
        terminal.requestHash = requestHash.toLowerCase();
        terminal.preparedAt = now;
        terminal.deadlineAt = now;
        terminal.action = "INITIALIZE_OBSERVE";
        terminal.state = OperationState.SUCCEEDED;
        IdempotencyRecord record = new IdempotencyRecord(terminal);
        record.contentSha256 = planSha256.toLowerCase();
        record.targetBootstrapPhase = "SEALED";
        record.updatedAt = now;
        next.idempotency.put(idempotencyKey, record);
        next.lastOperation = terminal;
        return next;
    }

    /** Atomically installs first trust/topology state, consumes the marker and permanently seals. */
    public MassDbLicenseState sealBootstrap(String operationId, String idempotencyKey,
            String requestHash, String markerId, String planSha256, ActiveKeyset keyset,
            MassDbLicenseIngressInventory inventory, long now) {
        requireOperation(operationId, idempotencyKey, requestHash, now, saturatedAdd(now, 1));
        requireUuidV4(markerId, "bootstrapMarkerId");
        requireSha256(planSha256);
        IdempotencyRecord existing = idempotency.get(idempotencyKey);
        if (existing != null) {
            if (!requestHash.equals(existing.requestHash)) {
                fail("MASSDB_LICENSE_IDEMPOTENCY_CONFLICT", "Idempotency-Key已绑定不同请求");
            }
            return copy();
        }
        if ("SEALED".equals(bootstrapPhase)) {
            if (equalsText(bootstrapPlanSha256, planSha256.toLowerCase())
                    && equalsText(bootstrapRequestHash, requestHash)
                    && bootstrapOperationId != null) {
                MassDbLicenseState alias = copy();
                IdempotencyRecord canonical = findIdempotencyByOperation(bootstrapOperationId);
                if (canonical == null || canonical.state != OperationState.SUCCEEDED) {
                    fail("MASSDB_LICENSE_OPERATION_RECOVERY_FAILED",
                            "bootstrap幂等终态记录缺失");
                }
                alias.idempotency.put(idempotencyKey, copyIdempotency(canonical));
                return alias;
            }
            fail("MASSDB_LICENSE_BOOTSTRAP_SEALED", "License bootstrap已经SEALED");
        }
        if (!"OPEN".equals(bootstrapPhase) || bootstrapSealGeneration != 0
                || enforcementMode != EnforcementMode.ENFORCING
                || !equalsText(bootstrapMarkerId, markerId)) {
            fail("MASSDB_LICENSE_BOOTSTRAP_SEALED", "License bootstrap不处于可消费的OPEN状态");
        }
        if (!planSha256.equalsIgnoreCase(bootstrapPlanSha256)) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_MISMATCH", "bootstrap plan与首启marker不匹配");
        }
        requireNoMutation();
        if (activeKeyset != null || !getIngressInventory().getNodes().isEmpty()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_STATE_CONFLICT", "bootstrap前已存在keyset或入口清单");
        }
        if (keyset == null || inventory == null || inventory.getNodes().isEmpty()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "bootstrap keyset和入口清单不能为空");
        }
        MassDbLicenseState next = copy();
        next.activeKeyset = keyset;
        next.ingressInventory = inventory.copy();
        next.topologyRevision = incrementRevision(next.topologyRevision);
        next.bootstrapPhase = "SEALED";
        next.bootstrapSealGeneration = 1;
        next.bootstrapMarkerConsumedAt = now;
        next.bootstrapOperationId = operationId;
        next.bootstrapRequestHash = requestHash.toLowerCase();

        Mutation terminal = new Mutation();
        terminal.operationId = operationId;
        terminal.kind = MutationKind.BOOTSTRAP_CONTROL;
        terminal.idempotencyKey = idempotencyKey;
        terminal.requestHash = requestHash.toLowerCase();
        terminal.preparedAt = now;
        terminal.deadlineAt = now;
        terminal.action = "SEAL";
        terminal.state = OperationState.SUCCEEDED;
        IdempotencyRecord record = new IdempotencyRecord(terminal);
        record.contentSha256 = planSha256.toLowerCase();
        record.targetBootstrapPhase = "SEALED";
        record.updatedAt = now;
        next.idempotency.put(idempotencyKey, record);
        next.lastOperation = terminal;
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
        next.idempotency.put(idempotencyKey, new IdempotencyRecord(next.mutation));
        return next;
    }

    /** Prepares a NORMAL import and atomically binds the validate-time CAS snapshot. */
    public MassDbLicenseState prepareNormalLicenseImport(String operationId,
            String idempotencyKey, String requestHash, ActiveLicense candidate, String requester,
            String action, long snapshotTopologyRevision, String snapshotInventorySha256,
            String snapshotRoutingSha256, List<String> requiredAckNodeUuids,
            List<String> deferredNodeUuids, long now, long deadlineAt) {
        MassDbLicenseState next = prepareLicense(operationId, idempotencyKey, requestHash,
                ImportIntent.NORMAL, candidate, requester, "", now, deadlineAt);
        IdempotencyRecord existing = idempotency.get(idempotencyKey);
        if (existing != null) {
            return next;
        }
        requireText(action, "action");
        requireSha256(snapshotInventorySha256);
        requireSha256(snapshotRoutingSha256);
        if (snapshotTopologyRevision < 0 || requiredAckNodeUuids == null
                || deferredNodeUuids == null) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "import snapshot字段错误");
        }
        next.mutation.action = action;
        next.mutation.snapshotActiveSha256 = activeLicense == null ? null : activeLicense.sha256;
        next.mutation.snapshotActiveExpiresAt = activeLicense == null ? null : activeLicense.expiresAt;
        next.mutation.snapshotEnforcementEpoch = enforcementEpoch;
        next.mutation.snapshotTopologyRevision = snapshotTopologyRevision;
        next.mutation.snapshotInventorySha256 = snapshotInventorySha256.toLowerCase();
        next.mutation.snapshotRoutingSha256 = snapshotRoutingSha256.toLowerCase();
        next.mutation.requiredAckNodeUuids = new ArrayList<>(requiredAckNodeUuids);
        next.mutation.deferredNodeUuids = new ArrayList<>(deferredNodeUuids);
        next.idempotency.put(idempotencyKey, new IdempotencyRecord(next.mutation));
        return next;
    }

    public MassDbLicenseState createCorrectionProposal(String proposalId,
            ActiveLicense candidate, String requester, long now, long expiresAt) {
        return createCorrectionProposal(proposalId, candidate, requester,
                "proposal-" + proposalId, requestDigest("proposal\n" + proposalId),
                now, expiresAt);
    }

    public MassDbLicenseState createCorrectionProposal(String proposalId,
            ActiveLicense candidate, String requester, String idempotencyKey,
            String requestHash, long now, long expiresAt) {
        requireInitialized();
        requireUuidV4(proposalId, "proposalId");
        requireText(requester, "requester");
        requireIdempotencyKey(idempotencyKey);
        requireSha256(requestHash);
        if (candidate == null || activeLicense == null
                || candidate.expiresAt >= activeLicense.expiresAt
                || expiresAt <= now) {
            fail("MASSDB_LICENSE_CORRECTION_REQUIRED",
                    "到期更正proposal必须绑定严格缩短的候选和有效审批窗口");
        }
        for (CorrectionProposal item : correctionProposals.values()) {
            if (idempotencyKey.equals(item.createIdempotencyKey)) {
                if (requestHash.equals(item.createRequestHash)
                        && proposalId.equals(item.proposalId)) {
                    return copy();
                }
                fail("MASSDB_LICENSE_IDEMPOTENCY_CONFLICT",
                        "correction proposal幂等键已绑定不同请求");
            }
        }
        CorrectionProposal existing = correctionProposals.get(proposalId);
        if (existing != null) {
            if (candidate.sha256.equals(existing.candidateSha256)
                    && activeLicense.sha256.equals(existing.activeLicenseSha256)
                    && requester.equals(existing.requester)) {
                return copy();
            }
            fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_MISMATCH",
                    "proposalId已经绑定其他候选或active快照");
        }
        MassDbLicenseState next = copy();
        next.correctionProposals.put(proposalId,
                new CorrectionProposal(proposalId, candidate, activeLicense,
                        requester, idempotencyKey, requestHash, now, expiresAt));
        return next;
    }

    public MassDbLicenseState approveCorrectionProposal(String proposalId,
            String approver, long now) {
        return approveCorrectionProposal(proposalId, approver,
                "approve-" + proposalId,
                requestDigest("approve\n" + proposalId + "\n" + approver), now);
    }

    public MassDbLicenseState approveCorrectionProposal(String proposalId,
            String approver, String idempotencyKey, String requestHash, long now) {
        requireText(approver, "approver");
        requireIdempotencyKey(idempotencyKey);
        requireSha256(requestHash);
        CorrectionProposal proposal = correctionProposals.get(proposalId);
        if (proposal == null) {
            fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_NOT_FOUND", "没有匹配的correction proposal");
        }
        if (proposal.state == CorrectionProposalState.APPROVED
                && approver.equals(proposal.approver)
                && idempotencyKey.equals(proposal.approveIdempotencyKey)
                && requestHash.equals(proposal.approveRequestHash)) {
            return copy();
        }
        if (proposal.approveIdempotencyKey != null
                && idempotencyKey.equals(proposal.approveIdempotencyKey)) {
            fail("MASSDB_LICENSE_IDEMPOTENCY_CONFLICT",
                    "correction approve幂等键已绑定不同请求");
        }
        if (proposal.state != CorrectionProposalState.PENDING) {
            fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_NOT_APPROVABLE",
                    "correction proposal不是PENDING");
        }
        if (now >= proposal.expiresAt) {
            MassDbLicenseState expired = copy();
            expired.correctionProposals.get(proposalId).state = CorrectionProposalState.EXPIRED;
            return expired;
        }
        if (approver.equals(proposal.requester)) {
            fail("MASSDB_LICENSE_CORRECTION_DUAL_CONTROL_REQUIRED",
                    "到期更正必须由不同主体批准");
        }
        MassDbLicenseState next = copy();
        CorrectionProposal approved = next.correctionProposals.get(proposalId);
        approved.approver = approver;
        approved.approveIdempotencyKey = idempotencyKey;
        approved.approveRequestHash = requestHash;
        approved.approvedAt = now;
        approved.state = CorrectionProposalState.APPROVED;
        return next;
    }

    public MassDbLicenseState cancelCorrectionProposal(String proposalId, long now) {
        return cancelCorrectionProposal(proposalId,
                "cancel-" + proposalId, requestDigest("cancel\n" + proposalId), now);
    }

    public MassDbLicenseState cancelCorrectionProposal(String proposalId,
            String idempotencyKey, String requestHash, long now) {
        requireIdempotencyKey(idempotencyKey);
        requireSha256(requestHash);
        CorrectionProposal proposal = correctionProposals.get(proposalId);
        if (proposal == null) {
            fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_NOT_FOUND", "没有匹配的correction proposal");
        }
        if (proposal.state == CorrectionProposalState.CANCELLED) {
            if (idempotencyKey.equals(proposal.cancelIdempotencyKey)
                    && requestHash.equals(proposal.cancelRequestHash)) {
                return copy();
            }
            fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_NOT_CANCELLABLE",
                    "correction proposal已经由其他请求取消");
        }
        if (proposal.state == CorrectionProposalState.CONSUMED) {
            fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_NOT_CANCELLABLE",
                    "已消费的correction proposal不能取消");
        }
        MassDbLicenseState next = copy();
        CorrectionProposal cancelled = next.correctionProposals.get(proposalId);
        cancelled.cancelIdempotencyKey = idempotencyKey;
        cancelled.cancelRequestHash = requestHash;
        cancelled.state = now >= cancelled.expiresAt
                ? CorrectionProposalState.EXPIRED : CorrectionProposalState.CANCELLED;
        return next;
    }

    public CorrectionProposal findCorrectionProposal(String proposalId, long now) {
        CorrectionProposal proposal = correctionProposals.get(proposalId);
        if (proposal == null) {
            return null;
        }
        CorrectionProposal copy = GsonUtils.GSON.fromJson(
                GsonUtils.GSON.toJson(proposal), CorrectionProposal.class);
        if (copy.state == CorrectionProposalState.PENDING && now >= copy.expiresAt) {
            copy.state = CorrectionProposalState.EXPIRED;
        }
        return copy;
    }

    public CorrectionProposal findCorrectionProposalByCreateIdempotencyKey(
            String idempotencyKey, long now) {
        requireIdempotencyKey(idempotencyKey);
        for (CorrectionProposal proposal : correctionProposals.values()) {
            if (idempotencyKey.equals(proposal.createIdempotencyKey)) {
                return findCorrectionProposal(proposal.proposalId, now);
            }
        }
        return null;
    }

    /** Prepares a correction/key-rotation replacement using the same role-local pending protocol. */
    public MassDbLicenseState prepareControlledLicenseImport(String operationId,
            String idempotencyKey, String requestHash, ImportIntent intent,
            ActiveLicense candidate, String requester, String approver,
            String proposalId, long now, long deadlineAt) {
        if (intent == ImportIntent.NORMAL) {
            fail("MASSDB_LICENSE_INTENT_UNSUPPORTED", "controlled import不能使用NORMAL intent");
        }
        MassDbLicenseState next = prepareLicense(operationId, idempotencyKey, requestHash,
                intent, candidate, requester, approver, now, deadlineAt);
        if (idempotency.containsKey(idempotencyKey)) {
            return next;
        }
        MassDbLicenseIngressInventory.Evaluation ingress = getIngressInventory().evaluate(
                activeLicense, enforcementEpoch, now, false);
        if (ingress.expectedIngressNodes <= 0
                || ingress.liveIngressNodes != ingress.expectedIngressNodes
                || ingress.coveredIngressNodes != ingress.expectedIngressNodes
                || ingress.deferredOfflineIngressNodes != 0
                || !"FRESH".equals(ingress.coverageFreshness)
                || !ingress.blockers.isEmpty()) {
            fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE",
                    "减权或换签替换要求全部desired入口在线且当前active覆盖完整");
        }
        if (intent == ImportIntent.REPLACE_WITH_SHORTER) {
            CorrectionProposal proposal = findCorrectionProposal(proposalId, now);
            if (proposal == null || proposal.state != CorrectionProposalState.APPROVED
                    || !candidate.sha256.equals(proposal.candidateSha256)
                    || activeLicense == null
                    || !activeLicense.sha256.equals(proposal.activeLicenseSha256)
                    || !requester.equals(proposal.requester)
                    || !approver.equals(proposal.approver)) {
                fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_MISMATCH",
                        "approved proposal与候选、active或双人主体不匹配");
            }
        }
        next.mutation.action = intent.name();
        next.mutation.correctionProposalId = proposalId;
        next.mutation.snapshotActiveSha256 = activeLicense.sha256;
        next.mutation.snapshotActiveExpiresAt = activeLicense.expiresAt;
        next.mutation.snapshotEnforcementEpoch = enforcementEpoch;
        next.mutation.snapshotTopologyRevision = topologyRevision;
        next.mutation.snapshotInventorySha256 = ingress.inventorySnapshotSha256;
        next.mutation.snapshotRoutingSha256 = ingress.routingEvidenceSnapshotSha256;
        next.mutation.requiredAckNodeUuids = new ArrayList<>(ingress.requiredAckNodeUuids);
        next.mutation.deferredNodeUuids = new ArrayList<>();
        next.idempotency.put(idempotencyKey, new IdempotencyRecord(next.mutation));
        return next;
    }

    public MassDbLicenseState commitControlledLicenseImport(String operationId,
            List<String> ackedNodeUuids, long now) {
        requirePrepared(operationId, now);
        Mutation pending = mutation;
        if (pending.kind != MutationKind.LICENSE || pending.intent == ImportIntent.NORMAL
                || pending.candidateLicense == null || pending.snapshotEnforcementEpoch == null
                || pending.snapshotTopologyRevision == null
                || pending.requiredAckNodeUuids == null
                || pending.deferredNodeUuids == null || !pending.deferredNodeUuids.isEmpty()) {
            fail("MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", "controlled import缺少冻结快照");
        }
        MassDbLicenseIngressInventory.Evaluation ingress = getIngressInventory().evaluate(
                activeLicense, enforcementEpoch, now, false);
        if (activeLicense == null || now >= pending.candidateLicense.expiresAt
                || !activeLicense.sha256.equals(pending.snapshotActiveSha256)
                || activeLicense.expiresAt != pending.snapshotActiveExpiresAt
                || enforcementEpoch != pending.snapshotEnforcementEpoch
                || topologyRevision != pending.snapshotTopologyRevision
                || !pending.snapshotInventorySha256.equals(ingress.inventorySnapshotSha256)
                || !pending.snapshotRoutingSha256.equals(ingress.routingEvidenceSnapshotSha256)
                || !pending.requiredAckNodeUuids.equals(ingress.requiredAckNodeUuids)
                || ingress.liveIngressNodes != ingress.expectedIngressNodes
                || !ingress.blockers.isEmpty()) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "controlled import的active、topology、入口或时间已变化");
        }
        if (pending.intent == ImportIntent.REPLACE_WITH_SHORTER) {
            CorrectionProposal proposal = findCorrectionProposal(
                    pending.correctionProposalId, now);
            if (proposal == null || proposal.state != CorrectionProposalState.APPROVED
                    || !pending.candidateLicense.sha256.equals(proposal.candidateSha256)
                    || !activeLicense.sha256.equals(proposal.activeLicenseSha256)) {
                fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_MISMATCH",
                        "correction proposal在提交前已变化");
            }
        }
        MassDbLicenseState withAcks = copy();
        withAcks.ingressInventory = getIngressInventory().applyImportAcks(
                pending.requiredAckNodeUuids, Collections.emptyList(), ackedNodeUuids,
                activeLicense, pending.candidateLicense, enforcementEpoch, now);
        return withAcks.commit(operationId, now);
    }

    /** Final CAS and ACK barrier for a prepared NORMAL import. */
    public MassDbLicenseState commitNormalLicenseImport(String operationId,
            List<String> ackedNodeUuids, long now) {
        requirePrepared(operationId, now);
        Mutation pending = mutation;
        if (pending.kind != MutationKind.LICENSE || pending.intent != ImportIntent.NORMAL
                || pending.action == null || pending.snapshotEnforcementEpoch == null
                || pending.snapshotTopologyRevision == null
                || pending.requiredAckNodeUuids == null || pending.deferredNodeUuids == null) {
            fail("MASSDB_LICENSE_OPERATION_RECOVERY_FAILED", "prepared import缺少CAS快照");
        }
        if (now >= pending.candidateLicense.expiresAt) {
            fail("MASSDB_LICENSE_EXPIRED", "候选License在提交前已经到期");
        }
        MassDbLicenseIngressInventory.Evaluation currentIngress = getIngressInventory().evaluate(
                activeLicense, enforcementEpoch, now, true);
        if (enforcementEpoch != pending.snapshotEnforcementEpoch
                || topologyRevision != pending.snapshotTopologyRevision
                || !equalsText(pending.snapshotActiveSha256,
                        activeLicense == null ? null : activeLicense.sha256)
                || !equalsLong(pending.snapshotActiveExpiresAt,
                        activeLicense == null ? null : activeLicense.expiresAt)
                || !equalsText(pending.snapshotInventorySha256,
                        currentIngress.inventorySnapshotSha256)
                || !equalsText(pending.snapshotRoutingSha256,
                        currentIngress.routingEvidenceSnapshotSha256)
                || !pending.requiredAckNodeUuids.equals(currentIngress.requiredAckNodeUuids)
                || !pending.deferredNodeUuids.equals(currentIngress.deferredNodeUuids)) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "active、epoch、topology或入口快照已变化");
        }
        rejectWhenChallengeActive(MutationKind.LICENSE, now);
        if ("ALREADY_ACTIVE".equals(pending.action)) {
            if (activeLicense == null || !activeLicense.sha256.equals(pending.candidateLicense.sha256)
                    || currentIngress.coveredIngressNodes != currentIngress.expectedIngressNodes) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED", "already-active状态已变化");
            }
            return commit(operationId, now);
        }
        if (!"ACTIVATE".equals(pending.action) && !"REPAIR".equals(pending.action)) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "NORMAL import action错误");
        }
        validateNormal(pending.candidateLicense);
        MassDbLicenseState withAcks = copy();
        withAcks.ingressInventory = getIngressInventory().applyImportAcks(
                pending.requiredAckNodeUuids, pending.deferredNodeUuids, ackedNodeUuids,
                activeLicense, pending.candidateLicense, enforcementEpoch, now);
        return withAcks.commit(operationId, now);
    }

    public String findOperationIdByIdempotency(String idempotencyKey, String requestHash) {
        requireIdempotencyKey(idempotencyKey);
        requireSha256(requestHash);
        IdempotencyRecord record = idempotency.get(idempotencyKey);
        if (record == null) {
            return null;
        }
        if (!record.requestHash.equals(requestHash)) {
            fail("MASSDB_LICENSE_IDEMPOTENCY_CONFLICT", "Idempotency-Key已绑定不同请求");
        }
        return record.operationId;
    }

    public OperationView findOperation(String operationId) {
        requireText(operationId, "operationId");
        for (IdempotencyRecord record : idempotency.values()) {
            if (operationId.equals(record.operationId)) {
                return new OperationView(record);
            }
        }
        return null;
    }

    public OperationView findOperationByIdempotencyKey(String idempotencyKey) {
        requireIdempotencyKey(idempotencyKey);
        IdempotencyRecord record = idempotency.get(idempotencyKey);
        return record == null ? null : new OperationView(record);
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
        boolean allowDeferred = kind == MutationKind.ADDITIVE_KEYSET;
        boolean initialBootstrapKeyset = activeKeyset == null && activeLicense == null
                && kind == MutationKind.ADDITIVE_KEYSET;
        MassDbLicenseIngressInventory.Evaluation ingress = getIngressInventory().evaluate(
                activeLicense, enforcementEpoch, now, allowDeferred);
        if (!initialBootstrapKeyset && (!ingress.isReadyForImport()
                || !allowDeferred
                        && ingress.liveIngressNodes != ingress.expectedIngressNodes)) {
            fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE",
                    "keyset变更的入口覆盖不满足安全条件");
        }
        MassDbLicenseState next = copy();
        next.mutation = new Mutation();
        next.mutation.operationId = operationId;
        next.mutation.kind = kind;
        next.mutation.idempotencyKey = idempotencyKey;
        next.mutation.requestHash = requestHash;
        next.mutation.preparedAt = now;
        next.mutation.deadlineAt = deadlineAt;
        next.mutation.candidateKeyset = candidate;
        next.mutation.action = initialBootstrapKeyset ? "INITIAL_KEYSET" : kind.name();
        next.mutation.snapshotActiveSha256 = activeLicense == null ? null : activeLicense.sha256;
        next.mutation.snapshotActiveExpiresAt = activeLicense == null ? null : activeLicense.expiresAt;
        next.mutation.snapshotEnforcementEpoch = enforcementEpoch;
        next.mutation.snapshotTopologyRevision = topologyRevision;
        next.mutation.snapshotInventorySha256 = ingress.inventorySnapshotSha256;
        next.mutation.snapshotRoutingSha256 = ingress.routingEvidenceSnapshotSha256;
        next.mutation.requiredAckNodeUuids = new ArrayList<>(ingress.requiredAckNodeUuids);
        next.mutation.deferredNodeUuids = new ArrayList<>(ingress.deferredNodeUuids);
        next.mutation.state = OperationState.PREPARED;
        next.idempotency.put(idempotencyKey, new IdempotencyRecord(next.mutation));
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
        MassDbLicenseIngressInventory.Evaluation ingress = getIngressInventory().evaluate(
                activeLicense, enforcementEpoch, now, false);
        if (!ingress.isReadyForImport()
                || ingress.liveIngressNodes != ingress.expectedIngressNodes
                || ingress.deferredOfflineIngressNodes != 0) {
            fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE",
                    "keyset recovery bundle要求全部desired入口在线");
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
        next.mutation.action = MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE.name();
        next.mutation.snapshotActiveSha256 = activeLicense == null ? null : activeLicense.sha256;
        next.mutation.snapshotActiveExpiresAt = activeLicense == null ? null : activeLicense.expiresAt;
        next.mutation.snapshotEnforcementEpoch = enforcementEpoch;
        next.mutation.snapshotTopologyRevision = topologyRevision;
        next.mutation.snapshotInventorySha256 = ingress.inventorySnapshotSha256;
        next.mutation.snapshotRoutingSha256 = ingress.routingEvidenceSnapshotSha256;
        next.mutation.requiredAckNodeUuids = new ArrayList<>(ingress.requiredAckNodeUuids);
        next.mutation.deferredNodeUuids = new ArrayList<>();
        next.mutation.state = OperationState.PREPARED;
        next.idempotency.put(idempotencyKey, new IdempotencyRecord(next.mutation));
        return next;
    }

    public MassDbLicenseState prepareIngressInventory(String operationId, String idempotencyKey,
            String requestHash, MassDbLicenseIngressInventory candidate, long now, long deadlineAt) {
        requireInitialized();
        requireOperation(operationId, idempotencyKey, requestHash, now, deadlineAt);
        MassDbLicenseState replay = replayIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        requireNoMutation();
        MassDbLicenseIngressInventory currentInventory = getIngressInventory();
        if (candidate == null || candidate.fullDigest().equals(currentInventory.fullDigest())) {
            fail("MASSDB_LICENSE_INGRESS_INVENTORY_UNCHANGED", "入口清单没有变化");
        }
        MassDbLicenseIngressInventory.Evaluation current = currentInventory.evaluate(
                activeLicense, enforcementEpoch, now, true);
        MassDbLicenseState next = copy();
        next.mutation = new Mutation();
        next.mutation.operationId = operationId;
        next.mutation.kind = MutationKind.INGRESS;
        next.mutation.idempotencyKey = idempotencyKey;
        next.mutation.requestHash = requestHash;
        next.mutation.preparedAt = now;
        next.mutation.deadlineAt = deadlineAt;
        next.mutation.candidateIngressInventory = candidate.copy();
        next.mutation.action = "INGRESS_INVENTORY_CHANGE";
        next.mutation.snapshotActiveSha256 = activeLicense == null ? null : activeLicense.sha256;
        next.mutation.snapshotActiveExpiresAt = activeLicense == null
                ? null : activeLicense.expiresAt;
        next.mutation.snapshotEnforcementEpoch = enforcementEpoch;
        next.mutation.snapshotTopologyRevision = topologyRevision;
        next.mutation.snapshotInventorySha256 = current.inventorySnapshotSha256;
        next.mutation.snapshotRoutingSha256 = current.routingEvidenceSnapshotSha256;
        next.mutation.state = OperationState.PREPARED;
        next.idempotency.put(idempotencyKey, new IdempotencyRecord(next.mutation));
        return next;
    }

    /**
     * Freezes the exact OBSERVE state that every query ingress must persist before enforcement.
     * The caller must first strictly verify the active License artifact through the read API core.
     */
    public MassDbLicenseState prepareEnforcementActivation(String operationId,
            String idempotencyKey, String requestHash, long now, long deadlineAt) {
        requireInitialized();
        requireOperation(operationId, idempotencyKey, requestHash, now, deadlineAt);
        MassDbLicenseState replay = replayIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        requireNoMutation();
        if (enforcementMode != EnforcementMode.OBSERVE) {
            fail("MASSDB_LICENSE_ENFORCEMENT_MODE_INVALID", "只有OBSERVE集群可以激活查询限制");
        }
        if (activeLicense == null) {
            fail("MASSDB_LICENSE_MISSING", "激活查询限制前必须安装有效License");
        }
        if (now >= activeLicense.expiresAt) {
            fail("MASSDB_LICENSE_EXPIRED", "激活查询限制前License必须有效");
        }
        rejectWhenChallengeActive(MutationKind.ENFORCEMENT, now);
        if (enforcementEpoch == Long.MAX_VALUE) {
            fail("MASSDB_LICENSE_ENFORCEMENT_EPOCH_EXHAUSTED", "enforcement epoch已耗尽");
        }
        MassDbLicenseIngressInventory.Evaluation ingress = getIngressInventory().evaluate(
                activeLicense, enforcementEpoch, now, false);
        if (ingress.expectedIngressNodes <= 0
                || ingress.liveIngressNodes != ingress.expectedIngressNodes
                || ingress.coveredIngressNodes != ingress.expectedIngressNodes
                || ingress.deferredOfflineIngressNodes != 0
                || !"FRESH".equals(ingress.coverageFreshness)
                || !ingress.blockers.isEmpty()
                || ingress.requiredAckNodeUuids.size() != ingress.expectedIngressNodes) {
            fail("MASSDB_LICENSE_ENFORCEMENT_NOT_READY",
                    "全部desired查询入口必须在线、guard ready、已同步active且路由证据新鲜");
        }
        MassDbLicenseState next = copy();
        next.mutation = new Mutation();
        next.mutation.operationId = operationId;
        next.mutation.kind = MutationKind.ENFORCEMENT;
        next.mutation.idempotencyKey = idempotencyKey;
        next.mutation.requestHash = requestHash;
        next.mutation.preparedAt = now;
        next.mutation.deadlineAt = deadlineAt;
        next.mutation.action = "ACTIVATE_ENFORCEMENT";
        next.mutation.snapshotActiveSha256 = activeLicense.sha256;
        next.mutation.snapshotActiveExpiresAt = activeLicense.expiresAt;
        next.mutation.snapshotEnforcementEpoch = enforcementEpoch;
        next.mutation.targetEnforcementEpoch = enforcementEpoch + 1;
        next.mutation.snapshotTopologyRevision = topologyRevision;
        next.mutation.snapshotInventorySha256 = ingress.inventorySnapshotSha256;
        next.mutation.snapshotRoutingSha256 = ingress.routingEvidenceSnapshotSha256;
        next.mutation.requiredAckNodeUuids = new ArrayList<>(ingress.requiredAckNodeUuids);
        next.mutation.deferredNodeUuids = new ArrayList<>();
        next.mutation.state = OperationState.PREPARED;
        next.idempotency.put(idempotencyKey, new IdempotencyRecord(next.mutation));
        return next;
    }

    /** Commits ENFORCING only after every frozen ingress durably ACKs its local pending file. */
    public MassDbLicenseState commitEnforcementActivation(String operationId,
            List<ActivationAckEvidence> ackEvidence, long now) {
        requirePrepared(operationId, now);
        Mutation pending = mutation;
        if (pending.kind != MutationKind.ENFORCEMENT
                || !"ACTIVATE_ENFORCEMENT".equals(pending.action)
                || pending.snapshotActiveSha256 == null
                || pending.snapshotActiveExpiresAt == null
                || pending.snapshotEnforcementEpoch == null
                || pending.targetEnforcementEpoch == null
                || pending.snapshotTopologyRevision == null
                || pending.snapshotInventorySha256 == null
                || pending.snapshotRoutingSha256 == null
                || pending.requiredAckNodeUuids == null
                || pending.deferredNodeUuids == null
                || !pending.deferredNodeUuids.isEmpty()) {
            fail("MASSDB_LICENSE_OPERATION_RECOVERY_FAILED",
                    "prepared enforcement activation缺少CAS快照");
        }
        if (enforcementMode != EnforcementMode.OBSERVE || activeLicense == null
                || now >= activeLicense.expiresAt) {
            fail(activeLicense != null && now >= activeLicense.expiresAt
                            ? "MASSDB_LICENSE_EXPIRED"
                            : "MASSDB_LICENSE_ENFORCEMENT_MODE_INVALID",
                    "提交激活前OBSERVE状态或active License已变化");
        }
        rejectWhenChallengeActive(MutationKind.ENFORCEMENT, now);
        MassDbLicenseIngressInventory.Evaluation ingress = getIngressInventory().evaluate(
                activeLicense, enforcementEpoch, now, false);
        if (enforcementEpoch != pending.snapshotEnforcementEpoch
                || pending.targetEnforcementEpoch != enforcementEpoch + 1
                || topologyRevision != pending.snapshotTopologyRevision
                || !activeLicense.sha256.equals(pending.snapshotActiveSha256)
                || activeLicense.expiresAt != pending.snapshotActiveExpiresAt
                || !pending.snapshotInventorySha256.equals(ingress.inventorySnapshotSha256)
                || !pending.snapshotRoutingSha256.equals(ingress.routingEvidenceSnapshotSha256)
                || !pending.requiredAckNodeUuids.equals(ingress.requiredAckNodeUuids)
                || ingress.expectedIngressNodes <= 0
                || ingress.liveIngressNodes != ingress.expectedIngressNodes
                || ingress.coveredIngressNodes != ingress.expectedIngressNodes
                || !"FRESH".equals(ingress.coverageFreshness)
                || !ingress.blockers.isEmpty()) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "active、epoch、topology、入口覆盖或路由快照已变化");
        }
        if (ackEvidence == null) {
            fail("MASSDB_LICENSE_ENFORCEMENT_ACK_INCOMPLETE", "入口ACK不能为空");
        }
        Map<String, ActivationAckEvidence> evidenceByNode = new LinkedHashMap<>();
        for (ActivationAckEvidence evidence : ackEvidence) {
            if (evidence == null) {
                fail("MASSDB_LICENSE_ENFORCEMENT_ACK_INVALID", "入口ACK不能为空");
            }
            requireText(evidence.nodeUuid, "nodeUuid");
            requireSha256(evidence.activeLicenseSha256);
            requireSha256(evidence.pendingSnapshotSha256);
            if (!operationId.equals(evidence.operationId)
                    || evidence.targetEnforcementEpoch != pending.targetEnforcementEpoch
                    || !pending.snapshotActiveSha256.equals(
                            evidence.activeLicenseSha256.toLowerCase())
                    || evidenceByNode.put(evidence.nodeUuid, evidence) != null) {
                fail("MASSDB_LICENSE_ENFORCEMENT_ACK_INVALID",
                        "入口ACK与operation、epoch或active License不匹配");
            }
        }
        if (evidenceByNode.size() != pending.requiredAckNodeUuids.size()
                || !evidenceByNode.keySet().containsAll(pending.requiredAckNodeUuids)) {
            fail("MASSDB_LICENSE_ENFORCEMENT_ACK_INCOMPLETE", "必须收到全部冻结入口的唯一ACK");
        }
        MassDbLicenseState next = copy();
        for (String nodeUuid : pending.requiredAckNodeUuids) {
            next.ingressInventory = next.ingressInventory.acknowledgeActive(
                    nodeUuid, activeLicense.sha256, activeLicense.expiresAt,
                    pending.targetEnforcementEpoch);
        }
        next.enforcementMode = EnforcementMode.ENFORCING;
        next.enforcementEpoch = pending.targetEnforcementEpoch;
        Mutation committed = next.mutation;
        committed.state = OperationState.SUCCEEDED;
        IdempotencyRecord succeeded = next.idempotency.get(committed.idempotencyKey);
        succeeded.state = OperationState.SUCCEEDED;
        succeeded.updatedAt = now;
        succeeded.action = committed.action;
        next.lastOperation = committed;
        next.mutation = null;
        return next;
    }

    /** Final CAS and exact role-ACK barrier for keyset and recovery-bundle control changes. */
    public MassDbLicenseState commitKeysetControl(String operationId,
            List<KeysetAckEvidence> ackEvidence, long now) {
        requirePrepared(operationId, now);
        Mutation pending = mutation;
        if (pending.candidateKeyset == null
                || pending.kind != MutationKind.ADDITIVE_KEYSET
                        && pending.kind != MutationKind.RESTRICTIVE_KEYSET
                        && pending.kind != MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE) {
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND",
                    "没有匹配的prepared keyset control");
        }
        if (ackEvidence == null) {
            fail("MASSDB_LICENSE_KEYSET_ACK_INCOMPLETE", "keyset ACK不能为空");
        }
        Map<String, KeysetAckEvidence> evidenceByNode = new LinkedHashMap<>();
        for (KeysetAckEvidence evidence : ackEvidence) {
            if (evidence == null) {
                fail("MASSDB_LICENSE_KEYSET_ACK_INVALID", "keyset ACK不能为空");
            }
            requireText(evidence.nodeUuid, "nodeUuid");
            requireSha256(evidence.keysetSha256);
            requireSha256(evidence.pendingSnapshotSha256);
            boolean bundle = pending.kind
                    == MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE;
            if (!operationId.equals(evidence.operationId)
                    || evidence.keysetVersion != pending.candidateKeyset.version
                    || !pending.candidateKeyset.sha256.equals(evidence.keysetSha256)
                    || bundle && (pending.candidateLicense == null
                            || !pending.candidateLicense.sha256.equals(
                                    evidence.licenseSha256)
                            || pending.candidateLicense.expiresAt
                                    != evidence.licenseExpiresAt)
                    || !bundle && (evidence.licenseSha256 != null
                            || evidence.licenseExpiresAt != 0)
                    || evidenceByNode.put(evidence.nodeUuid, evidence) != null) {
                fail("MASSDB_LICENSE_KEYSET_ACK_INVALID",
                        "keyset ACK与operation或候选工件不匹配");
            }
        }
        if (evidenceByNode.size() != pending.requiredAckNodeUuids.size()
                || !evidenceByNode.keySet().containsAll(pending.requiredAckNodeUuids)) {
            fail("MASSDB_LICENSE_KEYSET_ACK_INCOMPLETE",
                    "必须收到全部冻结入口的唯一keyset ACK");
        }
        return commitInternal(operationId, now, true);
    }

    public MassDbLicenseState commit(String operationId, long now) {
        return commitInternal(operationId, now, false);
    }

    private MassDbLicenseState commitInternal(String operationId, long now,
            boolean keysetAckVerified) {
        requirePrepared(operationId, now);
        if (mutation.kind == MutationKind.ENFORCEMENT) {
            fail("MASSDB_LICENSE_ENFORCEMENT_ACK_REQUIRED",
                    "enforcement activation必须通过专用ACK提交路径");
        }
        MassDbLicenseState next = copy();
        Mutation committed = next.mutation;
        if (committed.kind == MutationKind.LICENSE) {
            if (committed.intent == ImportIntent.REPLACE_WITH_SHORTER) {
                next.licenseCorrectionBarriers.add(new CorrectionBarrier(next.activeLicense,
                        committed.candidateLicense, committed.operationId, now));
                CorrectionProposal consumed = next.correctionProposals.get(
                        committed.correctionProposalId);
                if (consumed == null || consumed.state != CorrectionProposalState.APPROVED) {
                    fail("MASSDB_LICENSE_CORRECTION_PROPOSAL_MISMATCH",
                            "提交时correction proposal不存在或未批准");
                }
                consumed.state = CorrectionProposalState.CONSUMED;
                consumed.consumedAt = now;
            }
            next.activeLicense = committed.candidateLicense;
        } else if (committed.kind == MutationKind.ADDITIVE_KEYSET
                || committed.kind == MutationKind.RESTRICTIVE_KEYSET
                || committed.kind == MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE) {
            if (committed.candidateKeyset == null) {
                fail("MASSDB_LICENSE_FILE_INVALID", "prepared mutation缺少keyset工件");
            }
            boolean allowDeferred = committed.kind == MutationKind.ADDITIVE_KEYSET;
            boolean initialBootstrapKeyset = "INITIAL_KEYSET".equals(committed.action)
                    && next.activeKeyset == null && next.activeLicense == null;
            if (!initialBootstrapKeyset && !keysetAckVerified) {
                fail("MASSDB_LICENSE_KEYSET_ACK_REQUIRED",
                        "keyset控制变更必须通过角色ACK提交路径");
            }
            MassDbLicenseIngressInventory.Evaluation currentIngress =
                    next.getIngressInventory().evaluate(next.activeLicense,
                            next.enforcementEpoch, now, allowDeferred);
            if (!equalsText(committed.snapshotActiveSha256,
                            next.activeLicense == null ? null : next.activeLicense.sha256)
                    || !equalsLong(committed.snapshotActiveExpiresAt,
                            next.activeLicense == null ? null : next.activeLicense.expiresAt)
                    || committed.snapshotEnforcementEpoch == null
                    || committed.snapshotEnforcementEpoch != next.enforcementEpoch
                    || committed.snapshotTopologyRevision == null
                    || committed.snapshotTopologyRevision != next.topologyRevision
                    || !equalsText(committed.snapshotInventorySha256,
                            currentIngress.inventorySnapshotSha256)
                    || !equalsText(committed.snapshotRoutingSha256,
                            currentIngress.routingEvidenceSnapshotSha256)
                    || !committed.requiredAckNodeUuids.equals(
                            currentIngress.requiredAckNodeUuids)
                    || !committed.deferredNodeUuids.equals(
                            currentIngress.deferredNodeUuids)
                    || !initialBootstrapKeyset && !currentIngress.isReadyForImport()
                    || !allowDeferred
                            && !initialBootstrapKeyset
                            && currentIngress.liveIngressNodes
                                    != currentIngress.expectedIngressNodes) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                        "keyset提交前active、topology或入口快照已变化");
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
                String invalidatedChallengeId = next.clockChallenge.challengeId;
                next.clockChallenge.state = ClockChallengeState.INVALIDATED_BY_KEYSET_RECOVERY;
                next.clockChallenge.invalidatedAt = now;
                try {
                    next = next.appendDiagnosticEvent(new DiagnosticEventInput(
                            "CRITICAL",
                            "CLOCK_RECOVERY_CHALLENGE_INVALIDATED_BY_KEYSET_RECOVERY",
                            "MASSDB_LICENSE_CLOCK_RECOVERY_CHALLENGE_INVALIDATED_BY_KEYSET_RECOVERY",
                            "", committed.operationId,
                            diagnosticOpaqueSubject(invalidatedChallengeId),
                            committed.candidateKeyset.sha256.substring(0, 16),
                            "", "", true), now);
                } catch (MassDbLicenseException diagnosticFailure) {
                    // A diagnostic-capacity problem must never delay emergency trust-root recovery.
                }
            }
        } else if (committed.kind == MutationKind.INGRESS) {
            if (committed.candidateIngressInventory == null) {
                fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID", "prepared mutation缺少入口清单");
            }
            MassDbLicenseIngressInventory before = next.getIngressInventory();
            MassDbLicenseIngressInventory.Evaluation current = before.evaluate(
                    next.activeLicense, next.enforcementEpoch, now, true);
            if (!equalsText(committed.snapshotActiveSha256,
                            next.activeLicense == null ? null : next.activeLicense.sha256)
                    || !equalsLong(committed.snapshotActiveExpiresAt,
                            next.activeLicense == null ? null : next.activeLicense.expiresAt)
                    || committed.snapshotEnforcementEpoch == null
                    || committed.snapshotEnforcementEpoch != next.enforcementEpoch
                    || committed.snapshotTopologyRevision == null
                    || committed.snapshotTopologyRevision != next.topologyRevision
                    || !equalsText(committed.snapshotInventorySha256,
                            current.inventorySnapshotSha256)
                    || !equalsText(committed.snapshotRoutingSha256,
                            current.routingEvidenceSnapshotSha256)) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                        "入口提交前active、epoch、topology或路由快照已变化");
            }
            next.ingressInventory = before.applyControlCandidate(
                    committed.candidateIngressInventory);
            if (!before.semanticDigest().equals(next.ingressInventory.semanticDigest())) {
                next.topologyRevision = incrementRevision(next.topologyRevision);
            }
        } else if (committed.kind == MutationKind.CLOCK_RECOVERY) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_ACK_REQUIRED",
                    "clock recovery必须走专用原子提交路径");
        }
        committed.state = OperationState.SUCCEEDED;
        IdempotencyRecord succeeded = next.idempotency.get(committed.idempotencyKey);
        succeeded.state = OperationState.SUCCEEDED;
        succeeded.updatedAt = now;
        succeeded.action = committed.action;
        committed.candidateLicense = null;
        committed.candidateKeyset = null;
        committed.candidateIngressInventory = null;
        committed.candidateClockRecovery = null;
        next.lastOperation = committed;
        next.mutation = null;
        return next;
    }

    public MassDbLicenseState abort(String operationId) {
        return abort(operationId, mutation == null ? 0 : mutation.preparedAt);
    }

    public MassDbLicenseState abort(String operationId, long now) {
        if (mutation == null) {
            OperationView existing = findOperation(operationId);
            if (existing != null && existing.state == OperationState.ABORTED) {
                return copy();
            }
            if (existing != null) {
                fail("MASSDB_LICENSE_OPERATION_NOT_ABORTABLE", "operation已经进入终态");
            }
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的operation");
        }
        if (!equalsText(mutation.operationId, operationId)) {
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的active mutation");
        }
        MassDbLicenseState next = copy();
        next.mutation.state = OperationState.ABORTED;
        IdempotencyRecord aborted = next.idempotency.get(next.mutation.idempotencyKey);
        aborted.state = OperationState.ABORTED;
        aborted.updatedAt = now;
        Mutation terminal = next.mutation;
        terminal.candidateLicense = null;
        terminal.candidateKeyset = null;
        terminal.candidateIngressInventory = null;
        next.lastOperation = terminal;
        next.mutation = null;
        return next;
    }

    /** Releases an expired prepared slot into a stable FAILED tombstone. */
    public MassDbLicenseState recoverOrExpireMutation(long now) {
        requireInitialized();
        if (mutation == null || now < mutation.deadlineAt) {
            return copy();
        }
        return failOperation(mutation.operationId,
                "MASSDB_LICENSE_OPERATION_DEADLINE_EXCEEDED", now);
    }

    /**
     * Converts the active prepared mutation into a durable FAILED result and releases the slot.
     * This is used only after the component has proved that redrive cannot safely continue.
     */
    public MassDbLicenseState failOperation(String operationId, String errorCode, long now) {
        requireInitialized();
        requireText(operationId, "operationId");
        requireFailureCode(errorCode);
        if (mutation == null) {
            OperationView existing = findOperation(operationId);
            if (existing != null && existing.state == OperationState.FAILED
                    && equalsText(existing.errorCode, errorCode)) {
                return copy();
            }
            if (existing != null) {
                fail("MASSDB_LICENSE_OPERATION_NOT_ABORTABLE", "operation已经进入其他终态");
            }
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的operation");
        }
        if (!equalsText(mutation.operationId, operationId)) {
            fail("MASSDB_LICENSE_OPERATION_NOT_FOUND", "没有匹配的active mutation");
        }
        MassDbLicenseState next = copy();
        next.mutation.state = OperationState.FAILED;
        IdempotencyRecord failed = next.idempotency.get(next.mutation.idempotencyKey);
        failed.state = OperationState.FAILED;
        failed.updatedAt = now;
        failed.errorCode = errorCode;
        Mutation terminal = next.mutation;
        terminal.candidateLicense = null;
        terminal.candidateKeyset = null;
        terminal.candidateIngressInventory = null;
        next.lastOperation = terminal;
        next.mutation = null;
        try {
            next = next.appendDiagnosticEvent(new DiagnosticEventInput(
                    "ERROR", "OPERATION_FAILED", errorCode, "", operationId,
                    diagnosticOpaqueSubject(operationId), "", "", "", false), now);
        } catch (MassDbLicenseException diagnosticFailure) {
            // Releasing the global mutation slot is more important than best-effort diagnostics.
        }
        return next;
    }

    private static void requireFailureCode(String errorCode) {
        requireText(errorCode, "errorCode");
        if (!errorCode.matches("MASSDB_LICENSE_[A-Z0-9_]{1,96}")) {
            fail("MASSDB_LICENSE_FILE_INVALID", "operation失败码格式错误");
        }
    }

    public MassDbLicenseState createClockChallenge(String challengeId, String challengeHex,
            long now, long expiresAt) {
        requireInitialized();
        requireNoMutation();
        if (clockChallenge != null && clockChallenge.isActive(now)) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_CHALLENGE_ACTIVE", "已有未消费时钟恢复challenge");
        }
        MassDbLicenseState next = copy();
        if (next.clockChallenge != null
                && next.clockChallenge.getState()
                        == ClockChallengeState.INVALIDATED_BY_KEYSET_RECOVERY) {
            try {
                next = next.resolveDiagnosticEvent(
                        "CLOCK_RECOVERY_CHALLENGE_INVALIDATED_BY_KEYSET_RECOVERY", "",
                        diagnosticOpaqueSubject(next.clockChallenge.challengeId), now,
                        DIAGNOSTIC_EVENT_RETENTION_SECONDS);
            } catch (MassDbLicenseException diagnosticFailure) {
                // A missing historical event does not prevent creating a fresh recovery challenge.
            }
        }
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

    public MassDbLicenseState createClockChallengeOperation(String operationId,
            String idempotencyKey, String requestHash, String challengeId,
            String challengeHex, long now, long expiresAt) {
        requireOperation(operationId, idempotencyKey, requestHash, now, expiresAt);
        MassDbLicenseState replay = replayIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        MassDbLicenseState next = createClockChallenge(
                challengeId, challengeHex, now, expiresAt);
        return next.recordImmediateOperation(operationId, idempotencyKey, requestHash,
                MutationKind.CLOCK_RECOVERY, "CREATE_CHALLENGE", "", now);
    }

    public MassDbLicenseState cancelClockChallengeOperation(String operationId,
            String idempotencyKey, String requestHash, String challengeId, long now) {
        requireOperation(operationId, idempotencyKey, requestHash, now, saturatedAdd(now, 1));
        MassDbLicenseState replay = replayIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        MassDbLicenseState next = cancelClockChallenge(challengeId, now);
        return next.recordImmediateOperation(operationId, idempotencyKey, requestHash,
                MutationKind.CLOCK_RECOVERY, "CANCEL_CHALLENGE", "", now);
    }

    public MassDbLicenseState prepareClockRecovery(String operationId,
            String idempotencyKey, String requestHash, StagedClockRecovery candidate,
            long now, long deadlineAt) {
        requireInitialized();
        requireOperation(operationId, idempotencyKey, requestHash, now, deadlineAt);
        MassDbLicenseState replay = replayIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            return replay;
        }
        requireNoMutation();
        if (candidate == null || activeLicense == null || clockChallenge == null
                || !clockChallenge.isActive(now)
                || !clockChallenge.challengeId.equals(candidate.challengeId)
                || candidate.observedMaxSeenWallClock != maxSeenWallClock
                || candidate.recoverySequence <= maxAcceptedRecoverySequence
                || now < candidate.artifactIssuedAt || now > candidate.artifactExpiresAt) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_CONTEXT_MISMATCH",
                    "clock recovery候选与当前challenge、时钟或sequence不匹配");
        }
        MassDbLicenseIngressInventory.Evaluation ingress = getIngressInventory().evaluate(
                activeLicense, enforcementEpoch, now, true);
        if (!ingress.isReadyForImport()) {
            fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE",
                    "clock recovery存在不安全的desired入口");
        }
        MassDbLicenseState next = copy();
        next.mutation = new Mutation();
        next.mutation.operationId = operationId;
        next.mutation.kind = MutationKind.CLOCK_RECOVERY;
        next.mutation.idempotencyKey = idempotencyKey;
        next.mutation.requestHash = requestHash;
        next.mutation.preparedAt = now;
        next.mutation.deadlineAt = deadlineAt;
        next.mutation.action = "RECOVER_CLOCK";
        next.mutation.candidateClockRecovery = candidate;
        next.mutation.snapshotActiveSha256 = activeLicense.sha256;
        next.mutation.snapshotActiveExpiresAt = activeLicense.expiresAt;
        next.mutation.snapshotEnforcementEpoch = enforcementEpoch;
        next.mutation.snapshotTopologyRevision = topologyRevision;
        next.mutation.snapshotInventorySha256 = ingress.inventorySnapshotSha256;
        next.mutation.snapshotRoutingSha256 = ingress.routingEvidenceSnapshotSha256;
        next.mutation.requiredAckNodeUuids = new ArrayList<>(ingress.requiredAckNodeUuids);
        next.mutation.deferredNodeUuids = new ArrayList<>(ingress.deferredNodeUuids);
        next.mutation.state = OperationState.PREPARED;
        next.idempotency.put(idempotencyKey, new IdempotencyRecord(next.mutation));
        return next;
    }

    /** Commits the signed clock reset; all role guards then require the new recovery epoch. */
    public MassDbLicenseState commitClockRecovery(String operationId, long now) {
        requirePrepared(operationId, now);
        Mutation pending = mutation;
        StagedClockRecovery candidate = pending.candidateClockRecovery;
        if (pending.kind != MutationKind.CLOCK_RECOVERY || candidate == null
                || activeLicense == null || clockChallenge == null
                || !clockChallenge.isActive(now)
                || !clockChallenge.challengeId.equals(candidate.challengeId)
                || !activeLicense.sha256.equals(pending.snapshotActiveSha256)
                || activeLicense.expiresAt != pending.snapshotActiveExpiresAt
                || enforcementEpoch != pending.snapshotEnforcementEpoch
                || topologyRevision != pending.snapshotTopologyRevision
                || maxSeenWallClock != candidate.observedMaxSeenWallClock
                || maxAcceptedRecoverySequence >= candidate.recoverySequence
                || now < candidate.artifactIssuedAt || now > candidate.artifactExpiresAt) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_CONTEXT_MISMATCH",
                    "clock recovery提交前权威上下文已变化");
        }
        MassDbLicenseIngressInventory.Evaluation ingress = getIngressInventory().evaluate(
                activeLicense, enforcementEpoch, now, true);
        if (!pending.snapshotInventorySha256.equals(ingress.inventorySnapshotSha256)
                || !pending.snapshotRoutingSha256.equals(ingress.routingEvidenceSnapshotSha256)
                || !pending.requiredAckNodeUuids.equals(ingress.requiredAckNodeUuids)
                || !pending.deferredNodeUuids.equals(ingress.deferredNodeUuids)
                || !ingress.isReadyForImport()) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "clock recovery入口或路由快照已变化");
        }
        if (clockRecoveryEpoch == Long.MAX_VALUE) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_EPOCH_EXHAUSTED", "clock recovery epoch已耗尽");
        }
        MassDbLicenseState next = copy();
        next.maxSeenWallClock = candidate.resetMaxSeenWallClockTo;
        next.maxAcceptedRecoverySequence = candidate.recoverySequence;
        next.clockRecoveryEpoch++;
        next.clockChallenge.state = ClockChallengeState.CONSUMED;
        next.clockChallenge.invalidatedAt = now;
        Mutation committed = next.mutation;
        committed.state = OperationState.SUCCEEDED;
        IdempotencyRecord succeeded = next.idempotency.get(committed.idempotencyKey);
        succeeded.state = OperationState.SUCCEEDED;
        succeeded.updatedAt = now;
        succeeded.action = committed.action;
        committed.candidateClockRecovery = null;
        next.lastOperation = committed;
        next.mutation = null;
        return next;
    }

    private MassDbLicenseState recordImmediateOperation(String operationId,
            String idempotencyKey, String requestHash, MutationKind kind,
            String action, String contentSha256, long now) {
        MassDbLicenseState next = copy();
        Mutation terminal = new Mutation();
        terminal.operationId = operationId;
        terminal.kind = kind;
        terminal.idempotencyKey = idempotencyKey;
        terminal.requestHash = requestHash;
        terminal.action = action;
        terminal.preparedAt = now;
        terminal.deadlineAt = now;
        terminal.state = OperationState.SUCCEEDED;
        IdempotencyRecord record = new IdempotencyRecord(terminal);
        record.contentSha256 = contentSha256;
        record.updatedAt = now;
        next.idempotency.put(idempotencyKey, record);
        next.lastOperation = terminal;
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

    public byte[] getPreconditionHmacKey() {
        return preconditionHmacKey == null ? null : preconditionHmacKey.clone();
    }

    public ActiveLicense getActiveLicense() {
        return activeLicense;
    }

    public long getEnforcementEpoch() {
        return enforcementEpoch;
    }

    public long getTopologyRevision() {
        return topologyRevision;
    }

    public long getControlPlaneRevision() {
        return controlPlaneRevision;
    }

    public long getMaxSeenWallClock() {
        return maxSeenWallClock;
    }

    /** Advances the replicated wall-clock floor; callers decide the bounded persistence cadence. */
    public MassDbLicenseState advanceMaxSeenWallClock(long observedAt) {
        requireInitialized();
        if (observedAt <= 0) {
            fail("MASSDB_LICENSE_CLOCK_INVALID", "可信墙钟时间必须大于0");
        }
        MassDbLicenseState next = copy();
        next.maxSeenWallClock = Math.max(next.maxSeenWallClock, observedAt);
        return next;
    }

    public long getClockRecoveryEpoch() {
        return clockRecoveryEpoch;
    }

    public long getMaxAcceptedRecoverySequence() {
        return maxAcceptedRecoverySequence;
    }

    public MassDbLicenseIngressInventory getIngressInventory() {
        if (ingressInventory == null) {
            return MassDbLicenseIngressInventory.empty();
        }
        return ingressInventory.copy();
    }

    public boolean hasActiveClockChallenge(long now) {
        return clockChallenge != null && clockChallenge.isActive(now);
    }

    public MassDbLicenseState recordIngressHeartbeat(String nodeUuid, boolean guardReady,
            long observedAt, long leaseExpiresAt) {
        requireInitialized();
        MassDbLicenseState next = copy();
        next.ingressInventory = getIngressInventory().heartbeat(
                nodeUuid, guardReady, observedAt, leaseExpiresAt);
        return next;
    }

    /** Persists an authenticated FE role report without trusting it to create conflict authority. */
    public MassDbLicenseState recordIngressRoleStatus(String nodeUuid, boolean guardReady,
            boolean reportedIdentityConflict, MassDbLicenseFeRoleProtocol.RoleStatus status,
            long observedAt, long leaseExpiresAt) {
        requireInitialized();
        if (status == null) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "FE角色状态不能为空");
        }
        MassDbLicenseState next = copy();
        next.maxSeenWallClock = Math.max(next.maxSeenWallClock, observedAt);
        long reportedAuthorityRevision = next.controlPlaneRevision == 0
                ? 0 : next.controlPlaneRevision - 1;
        boolean authorityMatches = status.controlPlaneRevision == reportedAuthorityRevision
                && status.enforcementMode == next.enforcementMode
                && status.enforcementEpoch == next.enforcementEpoch
                && status.clockRecoveryEpoch == next.clockRecoveryEpoch
                && status.recoverySequence == next.maxAcceptedRecoverySequence
                && activeAuthorityMatches(status, next.activeLicense)
                && keysetAuthorityMatches(status, next.activeKeyset);
        next.ingressInventory = getIngressInventory().roleStatus(
                nodeUuid, guardReady, reportedIdentityConflict, status,
                authorityMatches, observedAt, leaseExpiresAt);
        return next;
    }

    private static boolean activeAuthorityMatches(
            MassDbLicenseFeRoleProtocol.RoleStatus status, ActiveLicense active) {
        return active == null
                ? status.activeLicenseSha256 == null && status.activeLicenseExpiresAt == null
                : active.sha256.equals(status.activeLicenseSha256)
                        && status.activeLicenseExpiresAt != null
                        && active.expiresAt == status.activeLicenseExpiresAt;
    }

    private static boolean keysetAuthorityMatches(
            MassDbLicenseFeRoleProtocol.RoleStatus status, ActiveKeyset keyset) {
        return keyset == null
                ? status.keysetVersion == 0 && status.keysetSha256 == null
                : keyset.version == status.keysetVersion
                        && keyset.sha256.equals(status.keysetSha256);
    }

    /** Only the Leader-side authenticated multi-session registry calls this transition. */
    public MassDbLicenseState recordIngressIdentityConflict(
            String nodeUuid, boolean active, long observedAt) {
        requireInitialized();
        if (controlPlaneRevision <= 0) {
            fail("MASSDB_LICENSE_CONTROL_PLANE_REVISION_INVALID",
                    "重复node UUID状态必须绑定已持久化控制面revision");
        }
        MassDbLicenseState next = copy();
        next.ingressInventory = getIngressInventory().identityConflict(
                nodeUuid, active, controlPlaneRevision, observedAt,
                DEFAULT_ROLE_LIVE_LEASE_SECONDS);
        return next;
    }

    public MassDbLicenseState recordRoutingEvidence(String nodeUuid,
            MassDbLicenseIngressInventory.RoutingState routingState,
            MassDbLicenseIngressInventory.EvidenceSource source,
            long observedAt, long expiresAt) {
        requireInitialized();
        MassDbLicenseIngressInventory before = getIngressInventory();
        MassDbLicenseIngressInventory after = before.observeRouting(
                nodeUuid, routingState, source, observedAt, expiresAt);
        MassDbLicenseState next = copy();
        next.ingressInventory = after;
        if (!routingSemanticDigest(before).equals(routingSemanticDigest(after))) {
            next.topologyRevision = incrementRevision(next.topologyRevision);
        }
        return next;
    }

    /** Independent authenticated adapter channel; it never occupies the global mutation slot. */
    public MassDbLicenseState recordMachineRoutingEvidence(String nodeUuid,
            MassDbLicenseIngressInventory.RoutingState routingState,
            String objectIdentity, long objectRevision, String evidenceDigest,
            long observedAt, long expiresAt) {
        requireInitialized();
        MassDbLicenseIngressInventory before = getIngressInventory();
        MassDbLicenseIngressInventory after = before.observeMachineRouting(
                nodeUuid, routingState, objectIdentity, objectRevision,
                evidenceDigest, observedAt, expiresAt);
        MassDbLicenseState next = copy();
        next.ingressInventory = after;
        if (!before.semanticDigest().equals(after.semanticDigest())) {
            next.topologyRevision = incrementRevision(next.topologyRevision);
        }
        return next;
    }

    public MassDbLicenseState recordTrustedRejoin(String nodeUuid, String activeSha256,
            long enforcementEpoch, long expiresAt) {
        requireInitialized();
        MassDbLicenseState next = copy();
        next.ingressInventory = getIngressInventory().trustRejoin(
                nodeUuid, activeSha256, enforcementEpoch, expiresAt);
        return next;
    }

    public MassDbLicenseState recordIngressActiveAck(String nodeUuid, String licenseSha256,
            long licenseExpiresAt, long enforcementEpoch) {
        requireInitialized();
        MassDbLicenseState next = copy();
        next.ingressInventory = getIngressInventory().acknowledgeActive(
                nodeUuid, licenseSha256, licenseExpiresAt, enforcementEpoch);
        return next;
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

    /** Called by MassDbLicenseManager before a journaled transition is evaluated. */
    MassDbLicenseState advanceControlPlaneRevision() {
        MassDbLicenseState next = copy();
        if (next.controlPlaneRevision == Long.MAX_VALUE) {
            fail("MASSDB_LICENSE_CONTROL_PLANE_REVISION_EXHAUSTED",
                    "控制面revision已耗尽");
        }
        next.controlPlaneRevision++;
        return next;
    }

    public List<CorrectionBarrier> getLicenseCorrectionBarriers() {
        return Collections.unmodifiableList(licenseCorrectionBarriers);
    }

    public long getBootstrapSealGeneration() {
        return bootstrapSealGeneration;
    }

    public String getBootstrapPhase() {
        return bootstrapPhase;
    }

    public String getBootstrapPlanSha256() {
        return bootstrapPlanSha256;
    }

    public String getBootstrapMarkerId() {
        return bootstrapMarkerId;
    }

    public long getBootstrapMarkerCreatedAt() {
        return bootstrapMarkerCreatedAt;
    }

    public long getBootstrapMarkerConsumedAt() {
        return bootstrapMarkerConsumedAt;
    }

    public String getBootstrapOperationId() {
        return bootstrapOperationId;
    }

    public String getInitializationSource() {
        return initializationSource;
    }

    public String getMinimumEnforcementVersion() {
        return minimumEnforcementVersion;
    }

    public String getUpgradeAttestationSha256() {
        return upgradeAttestationSha256;
    }

    public long getDiagnosticSequence() {
        return diagnosticSequence;
    }

    public List<DiagnosticEvent> getDiagnosticEvents() {
        return Collections.unmodifiableList(diagnosticEvents == null
                ? Collections.emptyList() : diagnosticEvents);
    }

    /**
     * Appends a payload-free event to the replicated License-only diagnostic ledger.
     * Critical first causes coalesce by node, kind and opaque subject and remain pinned while active.
     */
    public MassDbLicenseState appendDiagnosticEvent(DiagnosticEventInput input, long now) {
        requireInitialized();
        validateDiagnosticEventInput(input, now);
        MassDbLicenseState next = copy();
        next.normalizeDiagnosticEvents();
        next.incrementDiagnosticSequence();
        if (input.critical) {
            String key = diagnosticFirstCauseKey(input.nodeUuid, input.eventKind, input.subjectKey);
            for (DiagnosticEvent event : next.diagnosticEvents) {
                if (event.active && key.equals(diagnosticFirstCauseKey(
                        event.nodeUuid, event.eventKind, event.subjectKey))) {
                    event.sequence = next.diagnosticSequence;
                    event.lastSeenAt = now;
                    if (event.count != Long.MAX_VALUE) {
                        event.count++;
                    }
                    event.severity = input.severity;
                    event.errorCode = input.errorCode;
                    event.operationId = input.operationId;
                    event.digestPrefix = input.digestPrefix;
                    event.enforcementEpoch = next.enforcementEpoch;
                    event.clockRecoveryEpoch = next.clockRecoveryEpoch;
                    event.keysetVersion = next.getKeysetVersion();
                    event.guardState = input.guardState;
                    event.routingState = input.routingState;
                    next.pruneDiagnosticEvents(now);
                    return next;
                }
            }
        }
        next.diagnosticEvents.add(new DiagnosticEvent(input, next, now));
        next.pruneDiagnosticEvents(now);
        return next;
    }

    public MassDbLicenseState resolveDiagnosticEvent(String eventKind, String nodeUuid,
            String subjectKey, long now) {
        return resolveDiagnosticEvent(eventKind, nodeUuid, subjectKey, now,
                DEFAULT_CONTROL_PLANE_STALENESS_SECONDS);
    }

    private MassDbLicenseState resolveDiagnosticEvent(String eventKind, String nodeUuid,
            String subjectKey, long now, long pinSeconds) {
        DiagnosticEventInput probe = new DiagnosticEventInput("INFO", eventKind,
                "MASSDB_LICENSE_DIAGNOSTIC_RESOLVED", nodeUuid, "", subjectKey,
                "", "", "", true);
        requireInitialized();
        validateDiagnosticEventInput(probe, now);
        MassDbLicenseState next = copy();
        next.normalizeDiagnosticEvents();
        String key = diagnosticFirstCauseKey(probe.nodeUuid, probe.eventKind, probe.subjectKey);
        for (DiagnosticEvent event : next.diagnosticEvents) {
            if (!key.equals(diagnosticFirstCauseKey(
                    event.nodeUuid, event.eventKind, event.subjectKey))) {
                continue;
            }
            if (!event.active) {
                return next;
            }
            next.incrementDiagnosticSequence();
            event.sequence = next.diagnosticSequence;
            event.lastSeenAt = now;
            event.active = false;
            event.resolvedAt = now;
            event.pinnedUntil = saturatedAdd(now, pinSeconds);
            next.pruneDiagnosticEvents(now);
            return next;
        }
        fail("MASSDB_LICENSE_DIAGNOSTIC_EVENT_NOT_FOUND",
                "没有匹配的active License诊断首因事件");
        return null;
    }

    public DiagnosticEventPage diagnosticEventPage(long afterSequence, int pageSize, long now) {
        requireInitialized();
        if (afterSequence < 0 || pageSize <= 0 || pageSize > MAX_DIAGNOSTIC_EVENT_PAGE_SIZE) {
            fail("MASSDB_LICENSE_DIAGNOSTIC_PAGE_INVALID", "分页参数必须为非负sequence及1至200条");
        }
        MassDbLicenseState snapshot = copy();
        snapshot.normalizeDiagnosticEvents();
        snapshot.pruneDiagnosticEvents(now);
        List<DiagnosticEvent> ordered = new ArrayList<>(snapshot.diagnosticEvents);
        ordered.sort(Comparator.comparingLong(event -> event.sequence));
        List<DiagnosticEvent> items = new ArrayList<>();
        long nextSequence = afterSequence;
        boolean hasMore = false;
        for (DiagnosticEvent event : ordered) {
            if (event.sequence <= afterSequence) {
                continue;
            }
            if (items.size() == pageSize) {
                hasMore = true;
                break;
            }
            items.add(event);
            nextSequence = event.sequence;
        }
        return new DiagnosticEventPage(items, nextSequence, hasMore, pageSize);
    }

    public static String diagnosticOpaqueSubject(String value) {
        byte[] bytes = nullToEmpty(value).getBytes(StandardCharsets.UTF_8);
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder encoded = new StringBuilder("sha256-");
            for (int index = 0; index < 8; index++) {
                encoded.append(String.format("%02x", digest[index]));
            }
            return encoded.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static String requestDigest(String value) {
        byte[] bytes = nullToEmpty(value).getBytes(StandardCharsets.UTF_8);
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder encoded = new StringBuilder(64);
            for (byte item : digest) {
                encoded.append(String.format("%02x", item & 0xff));
            }
            return encoded.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private void incrementDiagnosticSequence() {
        if (diagnosticSequence == Long.MAX_VALUE) {
            fail("MASSDB_LICENSE_DIAGNOSTIC_SEQUENCE_EXHAUSTED",
                    "License诊断事件sequence已耗尽");
        }
        diagnosticSequence++;
    }

    private void normalizeDiagnosticEvents() {
        if (diagnosticEvents == null) {
            diagnosticEvents = new ArrayList<>();
        }
    }

    private void pruneDiagnosticEvents(long now) {
        List<DiagnosticEvent> kept = new ArrayList<>();
        for (DiagnosticEvent event : diagnosticEvents) {
            boolean retentionExpired = now >= saturatedAdd(
                    event.lastSeenAt, DIAGNOSTIC_EVENT_RETENTION_SECONDS);
            boolean pinned = event.active
                    || event.pinnedUntil != null && now < event.pinnedUntil;
            if (!retentionExpired || pinned) {
                kept.add(event);
            }
        }
        kept.sort(Comparator.comparingLong(event -> event.sequence));
        while (kept.size() > DEFAULT_DIAGNOSTIC_EVENT_CAPACITY
                || diagnosticEventsSize(kept) > MAX_DIAGNOSTIC_EVENT_STATE_BYTES) {
            int removable = -1;
            for (int index = 0; index < kept.size(); index++) {
                DiagnosticEvent event = kept.get(index);
                if (!event.active
                        && (event.pinnedUntil == null || now >= event.pinnedUntil)) {
                    removable = index;
                    break;
                }
            }
            if (removable < 0) {
                break;
            }
            kept.remove(removable);
        }
        diagnosticEvents = kept;
    }

    private static int diagnosticEventsSize(List<DiagnosticEvent> events) {
        return GsonUtils.GSON.toJson(events).getBytes(StandardCharsets.UTF_8).length;
    }

    private static void validateDiagnosticEventInput(DiagnosticEventInput input, long now) {
        if (input == null || now <= 0
                || !DIAGNOSTIC_EVENT_KIND.matcher(input.eventKind).matches()
                || !DIAGNOSTIC_ERROR_CODE.matcher(input.errorCode).matches()
                || !("INFO".equals(input.severity) || "WARNING".equals(input.severity)
                        || "ERROR".equals(input.severity) || "CRITICAL".equals(input.severity))) {
            fail("MASSDB_LICENSE_DIAGNOSTIC_EVENT_INVALID",
                    "License诊断事件时间、kind、severity或稳定错误码非法");
        }
        if (!input.nodeUuid.isEmpty() && !isCanonicalUuidV4(input.nodeUuid)) {
            fail("MASSDB_LICENSE_DIAGNOSTIC_EVENT_INVALID", "License诊断事件nodeUuid非法");
        }
        if (input.operationId.length() > 128
                || !diagnosticSafeToken(input.subjectKey, 128)
                || !diagnosticSafeToken(input.guardState, 64)
                || !diagnosticSafeToken(input.routingState, 64)) {
            fail("MASSDB_LICENSE_DIAGNOSTIC_EVENT_INVALID", "License诊断事件字段非法");
        }
        if (!input.digestPrefix.isEmpty()
                && (input.digestPrefix.length() < 8 || input.digestPrefix.length() > 16
                        || !DIAGNOSTIC_HEX.matcher(input.digestPrefix).matches())) {
            fail("MASSDB_LICENSE_DIAGNOSTIC_EVENT_INVALID", "License诊断摘要前缀非法");
        }
    }

    private static boolean diagnosticSafeToken(String value, int maximum) {
        if (value == null || value.length() > maximum) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < 0x21 || character > 0x7e) {
                return false;
            }
        }
        return true;
    }

    private static String diagnosticFirstCauseKey(
            String nodeUuid, String eventKind, String subjectKey) {
        return nullToEmpty(nodeUuid) + '\0' + nullToEmpty(eventKind) + '\0'
                + nullToEmpty(subjectKey);
    }

    private static void validatePersistedDiagnosticEvents(MassDbLicenseState state)
            throws IOException {
        Set<Long> sequences = new HashSet<>();
        Set<String> ids = new HashSet<>();
        long maximum = 0;
        for (DiagnosticEvent event : state.diagnosticEvents) {
            DiagnosticEventInput input = new DiagnosticEventInput(event.severity,
                    event.eventKind, event.errorCode, event.nodeUuid, event.operationId,
                    event.subjectKey, event.digestPrefix, event.guardState,
                    event.routingState, event.active);
            try {
                validateDiagnosticEventInput(input, event.lastSeenAt);
            } catch (MassDbLicenseException failure) {
                throw new IOException("persisted MassDB License diagnostic event is invalid",
                        failure);
            }
            if (event.sequence <= 0 || event.sequence > state.diagnosticSequence
                    || event.occurredAt <= 0 || event.lastSeenAt < event.occurredAt
                    || event.count <= 0 || !isCanonicalUuidV4(event.eventId)
                    || !sequences.add(event.sequence) || !ids.add(event.eventId)
                    || event.active && (event.resolvedAt != null || event.pinnedUntil != null)
                    || event.resolvedAt != null && (event.resolvedAt < event.lastSeenAt
                            || event.pinnedUntil == null
                            || event.pinnedUntil < event.resolvedAt)) {
                throw new IOException("persisted MassDB License diagnostic event is invalid");
            }
            maximum = Math.max(maximum, event.sequence);
        }
        if (maximum > state.diagnosticSequence
                || diagnosticEventsSize(state.diagnosticEvents)
                        > MAX_DIAGNOSTIC_EVENT_STATE_BYTES) {
            throw new IOException("MassDB License diagnostic sequence or size is invalid");
        }
    }

    private void validateNormal(ActiveLicense candidate) {
        if (activeLicense != null && !candidate.sha256.equals(activeLicense.sha256)
                && candidate.expiresAt <= activeLicense.expiresAt) {
            fail("MASSDB_LICENSE_EXPIRY_NOT_EXTENDED", "NORMAL续期必须严格延长到期时间");
        }
        for (CorrectionBarrier barrier : licenseCorrectionBarriers) {
            long correctedExpiresAt = barrier.correctedExpiresAt == 0
                    ? barrier.supersededExpiresAt : barrier.correctedExpiresAt;
            if (candidate.expiresAt > correctedExpiresAt
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
                || candidate.sha256.equals(activeLicense.sha256)
                || candidate.licenseId.equals(activeLicense.licenseId)
                || candidate.issuedAt < activeLicense.issuedAt) {
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
        if (now >= mutation.deadlineAt) {
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

    private IdempotencyRecord findIdempotencyByOperation(String operationId) {
        for (IdempotencyRecord record : idempotency.values()) {
            if (operationId.equals(record.operationId)) {
                return record;
            }
        }
        return null;
    }

    private static IdempotencyRecord copyIdempotency(IdempotencyRecord value) {
        return GsonUtils.GSON.fromJson(
                GsonUtils.GSON.toJson(value), IdempotencyRecord.class);
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

    private static void requireUuidV4(String value, String field) {
        requireText(value, field);
        try {
            UUID parsed = UUID.fromString(value);
            if (parsed.version() != 4 || !parsed.toString().equals(value)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", field + "必须是canonical UUIDv4");
            }
        } catch (IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", field + "必须是canonical UUIDv4");
        }
    }

    private static boolean equalsText(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static boolean equalsLong(Long left, Long right) {
        return left == null ? right == null : left.equals(right);
    }

    private static String operationApiState(IdempotencyRecord record) {
        if (record.state == OperationState.PREPARED) {
            return record.kind == MutationKind.LICENSE || record.kind == MutationKind.ENFORCEMENT
                    ? "AWAITING_ACK" : "VALIDATING";
        }
        if (record.state == OperationState.SUCCEEDED) {
            if (record.kind == MutationKind.BOOTSTRAP_CONTROL) {
                return "SEALED";
            }
            return "ACTIVE";
        }
        return record.state.name();
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static long incrementRevision(long value) {
        if (value == Long.MAX_VALUE) {
            fail("MASSDB_LICENSE_TOPOLOGY_REVISION_EXHAUSTED", "topology revision已耗尽");
        }
        return value + 1;
    }

    private static String routingSemanticDigest(MassDbLicenseIngressInventory inventory) {
        return inventory.evaluate(null, 0, 0, false).routingEvidenceSnapshotSha256;
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
        if (state.correctionProposals == null) {
            state.correctionProposals = new LinkedHashMap<>();
        }
        if (state.diagnosticEvents == null) {
            state.diagnosticEvents = new ArrayList<>();
        }
        if (state.ingressInventory == null) {
            state.ingressInventory = MassDbLicenseIngressInventory.empty();
        } else {
            state.ingressInventory = state.ingressInventory.copy();
        }
        if (state.isInitialized()
                && (state.preconditionHmacKey == null || state.preconditionHmacKey.length != 32)) {
            throw new IOException("MassDB License precondition HMAC key is missing or invalid");
        }
        if (state.controlPlaneRevision < 0 || state.maxSeenWallClock < 0) {
            throw new IOException("MassDB License control-plane revision or clock is invalid");
        }
        if (state.diagnosticSequence < 0) {
            throw new IOException("MassDB License diagnostic sequence is invalid");
        }
        validatePersistedDiagnosticEvents(state);
        if (state.isInitialized()) {
            if (!isCanonicalUuidV4(state.licenseControlDeploymentUuid)
                    || state.bootstrapPlanSha256 == null
                    || !state.bootstrapPlanSha256.matches("[0-9a-f]{64}")) {
                throw new IOException("MassDB License deployment identity or bootstrap digest is invalid");
            }
            if ("OPEN".equals(state.bootstrapPhase)) {
                if (state.bootstrapSealGeneration != 0
                        || !isCanonicalUuidV4(state.bootstrapMarkerId)
                        || state.bootstrapMarkerCreatedAt <= 0
                        || state.bootstrapMarkerConsumedAt != 0
                        || state.bootstrapOperationId != null
                        || state.bootstrapRequestHash != null
                        || state.activeKeyset != null
                        || state.activeLicense != null
                        || state.mutation != null
                        || state.lastOperation != null
                        || !state.idempotency.isEmpty()
                        || !state.licenseCorrectionBarriers.isEmpty()
                        || !state.correctionProposals.isEmpty()
                        || state.diagnosticSequence != 0 || !state.diagnosticEvents.isEmpty()
                        || state.clockChallenge != null
                        || state.enforcementMode != EnforcementMode.ENFORCING
                        || state.enforcementEpoch != 0
                        || state.topologyRevision != 0
                        || state.clockRecoveryEpoch != 0
                        || state.maxAcceptedRecoverySequence != 0
                        || !state.getIngressInventory().getNodes().isEmpty()) {
                    throw new IOException("MassDB License OPEN bootstrap state is invalid");
                }
            } else if (!"SEALED".equals(state.bootstrapPhase)
                    || state.bootstrapSealGeneration != 1) {
                throw new IOException("MassDB License bootstrap phase or seal generation is invalid");
            } else if (state.bootstrapMarkerId != null
                    && (!isCanonicalUuidV4(state.bootstrapMarkerId)
                            || state.bootstrapMarkerCreatedAt <= 0
                            || state.bootstrapMarkerConsumedAt <= 0
                            || state.bootstrapOperationId == null
                            || state.bootstrapOperationId.trim().isEmpty()
                            || state.bootstrapRequestHash == null
                            || !state.bootstrapRequestHash.matches("[0-9a-f]{64}"))) {
                throw new IOException("MassDB License SEALED bootstrap attestation is invalid");
            }
            boolean upgraded = "EXISTING_UPGRADE".equals(state.initializationSource);
            if (upgraded && (state.enforcementMode != EnforcementMode.OBSERVE
                    && state.enforcementMode != EnforcementMode.ENFORCING
                    || state.minimumEnforcementVersion == null
                    || state.minimumEnforcementVersion.trim().isEmpty()
                    || state.upgradeAttestationSha256 == null
                    || !state.upgradeAttestationSha256.matches("[0-9a-f]{64}"))) {
                throw new IOException("MassDB License existing-cluster upgrade evidence is invalid");
            }
            if (!upgraded && (state.initializationSource != null
                    || state.minimumEnforcementVersion != null
                    || state.upgradeAttestationSha256 != null)) {
                throw new IOException("MassDB License initialization evidence is inconsistent");
            }
        } else if (!"UNINITIALIZED".equals(state.bootstrapPhase)
                || state.bootstrapSealGeneration != 0
                || state.bootstrapPlanSha256 != null || state.bootstrapMarkerId != null
                || state.bootstrapMarkerCreatedAt != 0 || state.bootstrapMarkerConsumedAt != 0
                || state.bootstrapOperationId != null || state.bootstrapRequestHash != null
                || state.initializationSource != null
                || state.minimumEnforcementVersion != null
                || state.upgradeAttestationSha256 != null
                || state.licenseControlDeploymentUuid != null || state.preconditionHmacKey != null
                || state.activeKeyset != null || state.activeLicense != null
                || state.mutation != null || state.lastOperation != null
                || !state.idempotency.isEmpty() || !state.licenseCorrectionBarriers.isEmpty()
                || !state.correctionProposals.isEmpty()
                || state.diagnosticSequence != 0 || !state.diagnosticEvents.isEmpty()
                || state.clockChallenge != null || state.enforcementEpoch != 0
                || state.topologyRevision != 0 || state.maxSeenWallClock != 0
                || state.clockRecoveryEpoch != 0 || state.maxAcceptedRecoverySequence != 0
                || !state.getIngressInventory().getNodes().isEmpty()) {
            throw new IOException("uninitialized MassDB License state contains control data");
        }
        return state;
    }

    private static boolean isCanonicalUuidV4(String value) {
        try {
            UUID parsed = UUID.fromString(value);
            return parsed.version() == 4 && parsed.toString().equals(value);
        } catch (NullPointerException | IllegalArgumentException failure) {
            return false;
        }
    }
}
