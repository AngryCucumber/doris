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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Wire DTOs for the FE role-to-Leader License mTLS exchange. */
public final class MassDbLicenseFeRoleProtocol {
    public static final int VERSION = 1;
    public static final String PATH = "/api/massdb/license/internal/v1/fe-role/exchange";
    public static final String COMMAND_NORMAL = "NORMAL";
    public static final String COMMAND_ENFORCEMENT = "ACTIVATE_ENFORCEMENT";
    public static final String COMMAND_KEYSET = "PREPARE_KEYSET";

    public enum ClockState {
        UNINITIALIZED,
        NORMAL,
        SKEW_WARNING,
        ROLLBACK,
        RECOVERY_PENDING
    }

    public enum VerificationState {
        MISSING,
        UNVERIFIED,
        VERIFIED,
        CORRUPT,
        MISMATCH
    }

    private static final ObjectMapper WIRE_MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);

    private MassDbLicenseFeRoleProtocol() {
    }

    public static byte[] encode(Object value) throws IOException {
        return WIRE_MAPPER.writeValueAsBytes(value);
    }

    public static <T> T decode(byte[] value, Class<T> type) throws IOException {
        if (value == null || value.length == 0) {
            throw new IOException("empty MassDB License role payload");
        }
        return WIRE_MAPPER.readValue(value, type);
    }

    public static final class ExchangeRequest {
        public int protocolVersion;
        public String deploymentUuid;
        public String nodeUuid;
        public String processInstanceUuid;
        public RoleStatus status;
        public ActivationAck activationAck;
        public LicenseAck licenseAck;
        public ControlAck controlAck;

        public ExchangeRequest() {
        }

        ExchangeRequest(String deploymentUuid, String nodeUuid, String processInstanceUuid,
                RoleStatus status,
                ActivationAck activationAck, LicenseAck licenseAck) {
            this(deploymentUuid, nodeUuid, processInstanceUuid, status,
                    activationAck, licenseAck, null);
        }

        ExchangeRequest(String deploymentUuid, String nodeUuid, String processInstanceUuid,
                RoleStatus status, ActivationAck activationAck, LicenseAck licenseAck,
                ControlAck controlAck) {
            this.protocolVersion = VERSION;
            this.deploymentUuid = deploymentUuid;
            this.nodeUuid = nodeUuid;
            this.processInstanceUuid = processInstanceUuid;
            this.status = status;
            this.activationAck = activationAck;
            this.licenseAck = licenseAck;
            this.controlAck = controlAck;
        }
    }

    public static final class ExchangeResponse {
        public int protocolVersion;
        public String deploymentUuid;
        public long serverTime;
        public IdentityConflict identityConflict;
        public ControlPlaneSync controlPlaneSync;
        public List<Command> commands = new ArrayList<>();
        public List<Decision> decisions = new ArrayList<>();

        public ExchangeResponse() {
        }

        ExchangeResponse(String deploymentUuid, long serverTime,
                List<Command> commands, List<Decision> decisions) {
            this(deploymentUuid, serverTime, null, commands, decisions);
        }

        ExchangeResponse(String deploymentUuid, long serverTime,
                IdentityConflict identityConflict,
                List<Command> commands, List<Decision> decisions) {
            this(deploymentUuid, serverTime, identityConflict, null, commands, decisions);
        }

        ExchangeResponse(String deploymentUuid, long serverTime,
                IdentityConflict identityConflict, ControlPlaneSync controlPlaneSync,
                List<Command> commands, List<Decision> decisions) {
            this.protocolVersion = VERSION;
            this.deploymentUuid = deploymentUuid;
            this.serverTime = serverTime;
            this.identityConflict = identityConflict;
            this.controlPlaneSync = controlPlaneSync;
            this.commands = commands == null ? new ArrayList<>() : new ArrayList<>(commands);
            this.decisions = decisions == null ? new ArrayList<>() : new ArrayList<>(decisions);
        }
    }

    public static final class RoleStatus {
        public long reportSequence;
        public boolean identityConflict;
        public long identityConflictRevision;
        public boolean guardReady;
        public boolean licenseQueryAllowed;
        public String localStateErrorCode;
        public String activeLicenseSha256;
        public Long activeLicenseExpiresAt;
        public Long effectiveNow;
        public Long remainingSecondsAtCheck;
        public long observedWallClock;
        public Boolean licenseExpiredUnderEffectiveNow;
        public boolean licenseExpiredAtObservedWallClock;
        public ClockState clockState = ClockState.UNINITIALIZED;
        public long clockRecoveryEpoch;
        public long recoverySequence;
        public long keysetVersion;
        public String keysetSha256;
        public long controlPlaneRevision;
        public MassDbLicenseState.EnforcementMode enforcementMode =
                MassDbLicenseState.EnforcementMode.UNINITIALIZED;
        public long enforcementEpoch;
        public VerificationState verificationState = VerificationState.MISSING;
        public long lastAuthenticatedControlPlaneAt;
        public String controlPlaneFreshness = "MISSING";
        public Long controlPlaneStalenessRemainingSeconds;
        public String activationPendingOperationId;
        public String licensePendingOperationId;
        public String controlPendingOperationId;

        public RoleStatus() {
        }
    }

    /** Complete public authority snapshot returned by the chain-authenticated FE Master. */
    public static final class ControlPlaneSync {
        public long reportSequence;
        public long controlPlaneRevision;
        public String deploymentUuid;
        public long leaderObservedAt;
        public long maxSeenWallClock;
        public long maxControlPlaneStalenessSeconds;
        public MassDbLicenseState.EnforcementMode enforcementMode;
        public long enforcementEpoch;
        public long clockRecoveryEpoch;
        public long recoverySequence;
        public long activeKeysetVersion;
        public String activeKeysetSha256;
        public byte[] activeKeysetArtifact;
        public String activeLicenseSha256;
        public Long activeLicenseExpiresAt;
        public byte[] activeLicenseArtifact;

        public ControlPlaneSync() {
        }

        static ControlPlaneSync from(MassDbLicenseState state,
                long reportSequence, long leaderObservedAt) {
            if (state == null || !state.isInitialized()
                    || state.getControlPlaneRevision() <= 0
                    || reportSequence <= 0 || leaderObservedAt <= 0
                    || state.getActiveLicense() != null && state.getActiveKeyset() == null) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_PROTOCOL_INVALID",
                        "Leader控制面权威状态不完整");
            }
            ControlPlaneSync result = new ControlPlaneSync();
            result.reportSequence = reportSequence;
            result.controlPlaneRevision = state.getControlPlaneRevision();
            result.deploymentUuid = state.getLicenseControlDeploymentUuid();
            result.leaderObservedAt = leaderObservedAt;
            result.maxSeenWallClock = state.getMaxSeenWallClock();
            result.maxControlPlaneStalenessSeconds =
                    MassDbLicenseState.DEFAULT_CONTROL_PLANE_STALENESS_SECONDS;
            result.enforcementMode = state.getEnforcementMode();
            result.enforcementEpoch = state.getEnforcementEpoch();
            result.clockRecoveryEpoch = state.getClockRecoveryEpoch();
            result.recoverySequence = state.getMaxAcceptedRecoverySequence();
            MassDbLicenseState.ActiveKeyset keyset = state.getActiveKeyset();
            if (keyset != null) {
                result.activeKeysetVersion = keyset.getVersion();
                result.activeKeysetSha256 = keyset.getSha256();
                result.activeKeysetArtifact = keyset.getArtifact();
            }
            MassDbLicenseState.ActiveLicense license = state.getActiveLicense();
            if (license != null) {
                result.activeLicenseSha256 = license.getSha256();
                result.activeLicenseExpiresAt = license.getExpiresAt();
                result.activeLicenseArtifact = license.getArtifact();
            }
            return result;
        }
    }

    public static final class IdentityConflict {
        public boolean active;
        public long controlPlaneRevision;
        public String deploymentUuid;
        public long detectedAt;
        public long lastObservedAt;
        public long clearEligibleAt;
        public long resolvedAt;

        public IdentityConflict() {
        }

        IdentityConflict(boolean active, long controlPlaneRevision, String deploymentUuid,
                long detectedAt, long lastObservedAt, long clearEligibleAt, long resolvedAt) {
            this.active = active;
            this.controlPlaneRevision = controlPlaneRevision;
            this.deploymentUuid = deploymentUuid;
            this.detectedAt = detectedAt;
            this.lastObservedAt = lastObservedAt;
            this.clearEligibleAt = clearEligibleAt;
            this.resolvedAt = resolvedAt;
        }

        IdentityConflict copy() {
            return new IdentityConflict(active, controlPlaneRevision, deploymentUuid,
                    detectedAt, lastObservedAt, clearEligibleAt, resolvedAt);
        }
    }

    public static final class ActivationAck {
        public String nodeUuid;
        public String operationId;
        public long targetEnforcementEpoch;
        public String activeLicenseSha256;
        public String pendingSnapshotSha256;

        public ActivationAck() {
        }

        static ActivationAck from(MassDbLicenseLocalSnapshotStore.ActivationAck source) {
            if (source == null) {
                return null;
            }
            ActivationAck result = new ActivationAck();
            result.nodeUuid = source.nodeUuid;
            result.operationId = source.operationId;
            result.targetEnforcementEpoch = source.targetEnforcementEpoch;
            result.activeLicenseSha256 = source.activeSha256;
            result.pendingSnapshotSha256 = source.pendingSnapshotSha256;
            return result;
        }
    }

    public static final class LicenseAck {
        public String nodeUuid;
        public String operationId;
        public String contentSha256;
        public long licenseExpiresAt;
        public long enforcementEpoch;
        public String pendingSnapshotSha256;

        public LicenseAck() {
        }

        static LicenseAck from(MassDbLicenseLocalSnapshotStore.LicenseAck source) {
            if (source == null) {
                return null;
            }
            LicenseAck result = new LicenseAck();
            result.nodeUuid = source.nodeUuid;
            result.operationId = source.operationId;
            result.contentSha256 = source.contentSha256;
            result.licenseExpiresAt = source.licenseExpiresAt;
            result.enforcementEpoch = source.enforcementEpoch;
            result.pendingSnapshotSha256 = source.pendingSnapshotSha256;
            return result;
        }
    }

    public static final class ControlAck {
        public String nodeUuid;
        public String operationId;
        public String keysetSha256;
        public long keysetVersion;
        public String licenseSha256;
        public long licenseExpiresAt;
        public String pendingSnapshotSha256;

        public ControlAck() {
        }

        static ControlAck from(MassDbLicenseLocalSnapshotStore.ControlAck source) {
            if (source == null) {
                return null;
            }
            ControlAck result = new ControlAck();
            result.nodeUuid = source.nodeUuid;
            result.operationId = source.operationId;
            result.keysetSha256 = source.keysetSha256;
            result.keysetVersion = source.keysetVersion;
            result.licenseSha256 = source.licenseSha256;
            result.licenseExpiresAt = source.licenseExpiresAt;
            result.pendingSnapshotSha256 = source.pendingSnapshotSha256;
            return result;
        }
    }

    public static final class Command {
        public String type;
        public String operationId;
        public String contentSha256;
        public Long licenseExpiresAt;
        public long currentEnforcementEpoch;
        public Long targetEnforcementEpoch;
        public Long topologyRevision;
        public String inventorySnapshotSha256;
        public String routingSnapshotSha256;
        public long createdAt;
        public long deadlineAt;
        public byte[] artifact;
        public String keysetKind;
        public String keysetSha256;
        public Long keysetVersion;
        public byte[] licenseArtifact;
        public String licenseSha256;
        public List<String> requiredAckNodeUuids = new ArrayList<>();
        public List<String> deferredNodeUuids = new ArrayList<>();

        public Command() {
        }

        static Command normal(MassDbLicenseImportCore.RecoveryPlan plan) {
            Command result = new Command();
            result.type = COMMAND_NORMAL;
            result.operationId = plan.operationId;
            result.contentSha256 = plan.contentSha256;
            result.licenseExpiresAt = plan.licenseExpiresAt;
            result.currentEnforcementEpoch = plan.enforcementEpoch;
            result.createdAt = plan.stagedCreatedAt;
            result.deadlineAt = plan.deadlineAt;
            result.artifact = plan.artifact.clone();
            result.requiredAckNodeUuids = new ArrayList<>(plan.requiredAckNodeUuids);
            result.deferredNodeUuids = new ArrayList<>(plan.deferredNodeUuids);
            return result;
        }

        static Command enforcement(MassDbLicenseEnforcementCore.RecoveryPlan plan) {
            Command result = new Command();
            result.type = COMMAND_ENFORCEMENT;
            result.operationId = plan.operationId;
            result.contentSha256 = plan.activeLicenseSha256;
            result.licenseExpiresAt = plan.activeLicenseExpiresAt;
            result.currentEnforcementEpoch = plan.currentEnforcementEpoch;
            result.targetEnforcementEpoch = plan.targetEnforcementEpoch;
            result.topologyRevision = plan.topologyRevision;
            result.inventorySnapshotSha256 = plan.inventorySnapshotSha256;
            result.routingSnapshotSha256 = plan.routingSnapshotSha256;
            result.createdAt = plan.activationCreatedAt;
            result.deadlineAt = plan.deadlineAt;
            result.requiredAckNodeUuids = new ArrayList<>(plan.requiredAckNodeUuids);
            return result;
        }

        static Command keyset(MassDbLicenseKeysetControlCore.RecoveryPlan plan) {
            Command result = new Command();
            result.type = COMMAND_KEYSET;
            result.operationId = plan.operationId;
            result.keysetKind = plan.kind.name();
            result.keysetSha256 = plan.keysetSha256;
            result.keysetVersion = plan.keysetVersion;
            result.artifact = plan.keysetArtifact.clone();
            result.licenseArtifact = plan.licenseArtifact.clone();
            result.licenseSha256 = plan.licenseSha256;
            result.licenseExpiresAt = plan.licenseExpiresAt == 0
                    ? null : plan.licenseExpiresAt;
            result.currentEnforcementEpoch = plan.enforcementEpoch;
            result.createdAt = plan.stagedCreatedAt;
            result.deadlineAt = plan.deadlineAt;
            result.requiredAckNodeUuids = new ArrayList<>(plan.requiredAckNodeUuids);
            result.deferredNodeUuids = new ArrayList<>(plan.deferredNodeUuids);
            return result;
        }

        boolean samePayload(Command other) {
            return other != null && equalsText(type, other.type)
                    && equalsText(operationId, other.operationId)
                    && equalsText(contentSha256, other.contentSha256)
                    && equalsLong(licenseExpiresAt, other.licenseExpiresAt)
                    && currentEnforcementEpoch == other.currentEnforcementEpoch
                    && equalsLong(targetEnforcementEpoch, other.targetEnforcementEpoch)
                    && equalsLong(topologyRevision, other.topologyRevision)
                    && equalsText(inventorySnapshotSha256, other.inventorySnapshotSha256)
                    && equalsText(routingSnapshotSha256, other.routingSnapshotSha256)
                    && createdAt == other.createdAt && deadlineAt == other.deadlineAt
                    && Arrays.equals(artifact, other.artifact)
                    && equalsText(keysetKind, other.keysetKind)
                    && equalsText(keysetSha256, other.keysetSha256)
                    && equalsLong(keysetVersion, other.keysetVersion)
                    && Arrays.equals(licenseArtifact, other.licenseArtifact)
                    && equalsText(licenseSha256, other.licenseSha256)
                    && safeList(requiredAckNodeUuids).equals(safeList(other.requiredAckNodeUuids))
                    && safeList(deferredNodeUuids).equals(safeList(other.deferredNodeUuids));
        }

        Command copy() {
            Command result = new Command();
            result.type = type;
            result.operationId = operationId;
            result.contentSha256 = contentSha256;
            result.licenseExpiresAt = licenseExpiresAt;
            result.currentEnforcementEpoch = currentEnforcementEpoch;
            result.targetEnforcementEpoch = targetEnforcementEpoch;
            result.topologyRevision = topologyRevision;
            result.inventorySnapshotSha256 = inventorySnapshotSha256;
            result.routingSnapshotSha256 = routingSnapshotSha256;
            result.createdAt = createdAt;
            result.deadlineAt = deadlineAt;
            result.artifact = artifact == null ? null : artifact.clone();
            result.keysetKind = keysetKind;
            result.keysetSha256 = keysetSha256;
            result.keysetVersion = keysetVersion;
            result.licenseArtifact = licenseArtifact == null
                    ? null : licenseArtifact.clone();
            result.licenseSha256 = licenseSha256;
            result.requiredAckNodeUuids = new ArrayList<>(safeList(requiredAckNodeUuids));
            result.deferredNodeUuids = new ArrayList<>(safeList(deferredNodeUuids));
            return result;
        }
    }

    public static final class Decision {
        public String operationId;
        public String kind;
        public String state;
        public String action;
        public String contentSha256;
        public Long targetLicenseExpiresAt;
        public Long targetEnforcementEpoch;
        public String errorCode;

        public Decision() {
        }

        static Decision from(MassDbLicenseState.OperationView source) {
            Decision result = new Decision();
            result.operationId = source.operationId;
            result.kind = source.kind.name();
            result.state = source.state.name();
            result.action = source.action;
            result.contentSha256 = source.contentSha256;
            result.targetLicenseExpiresAt = source.targetLicenseExpiresAt;
            result.targetEnforcementEpoch = source.targetEnforcementEpoch;
            result.errorCode = source.errorCode;
            return result;
        }

        boolean succeeded() {
            return MassDbLicenseState.OperationState.SUCCEEDED.name().equals(state);
        }

        boolean failedOrAborted() {
            return MassDbLicenseState.OperationState.FAILED.name().equals(state)
                    || MassDbLicenseState.OperationState.ABORTED.name().equals(state);
        }
    }

    private static List<String> safeList(List<String> value) {
        return value == null ? Collections.emptyList() : value;
    }

    private static boolean equalsText(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static boolean equalsLong(Long left, Long right) {
        return left == null ? right == null : left.equals(right);
    }
}
