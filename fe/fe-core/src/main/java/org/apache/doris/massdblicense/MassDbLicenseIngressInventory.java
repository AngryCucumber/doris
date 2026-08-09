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

import org.apache.doris.persist.gson.GsonUtils;

import com.google.gson.annotations.SerializedName;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Durable configured ingress inventory, live lease, routing evidence and License ACK state. */
public final class MassDbLicenseIngressInventory {
    public enum RoutingState {
        IN_SERVICE,
        REMOVED,
        UNKNOWN
    }

    public enum EvidenceSource {
        MACHINE,
        MANUAL,
        NONE
    }

    public static final class IngressNode {
        @SerializedName("nodeUuid")
        private String nodeUuid;
        @SerializedName("endpoint")
        private String endpoint;
        @SerializedName("desired")
        private boolean desired;
        @SerializedName("identityConflict")
        private boolean identityConflict;
        @SerializedName("identityConflictRevision")
        private long identityConflictRevision;
        @SerializedName("identityConflictDetectedAt")
        private long identityConflictDetectedAt;
        @SerializedName("identityConflictLastObservedAt")
        private long identityConflictLastObservedAt;
        @SerializedName("identityConflictResolvedAt")
        private long identityConflictResolvedAt;
        @SerializedName("reportedIdentityConflict")
        private boolean reportedIdentityConflict;
        @SerializedName("guardReady")
        private boolean guardReady;
        @SerializedName("liveLeaseExpiresAt")
        private long liveLeaseExpiresAt;
        @SerializedName("lastRoleStatusObservedAt")
        private long lastRoleStatusObservedAt;
        @SerializedName("reportedRoleSequence")
        private long reportedRoleSequence;
        @SerializedName("reportedLicenseQueryAllowed")
        private boolean reportedLicenseQueryAllowed;
        @SerializedName("reportedLocalStateErrorCode")
        private String reportedLocalStateErrorCode;
        @SerializedName("reportedActiveLicenseSha256")
        private String reportedActiveLicenseSha256;
        @SerializedName("reportedActiveLicenseExpiresAt")
        private Long reportedActiveLicenseExpiresAt;
        @SerializedName("reportedEffectiveNow")
        private Long reportedEffectiveNow;
        @SerializedName("reportedRemainingSecondsAtCheck")
        private Long reportedRemainingSecondsAtCheck;
        @SerializedName("reportedObservedWallClock")
        private long reportedObservedWallClock;
        @SerializedName("reportedLicenseExpiredUnderEffectiveNow")
        private Boolean reportedLicenseExpiredUnderEffectiveNow;
        @SerializedName("reportedLicenseExpiredAtObservedWallClock")
        private boolean reportedLicenseExpiredAtObservedWallClock;
        @SerializedName("reportedClockState")
        private MassDbLicenseFeRoleProtocol.ClockState reportedClockState =
                MassDbLicenseFeRoleProtocol.ClockState.UNINITIALIZED;
        @SerializedName("reportedClockRecoveryEpoch")
        private long reportedClockRecoveryEpoch;
        @SerializedName("reportedRecoverySequence")
        private long reportedRecoverySequence;
        @SerializedName("reportedKeysetVersion")
        private long reportedKeysetVersion;
        @SerializedName("reportedKeysetSha256")
        private String reportedKeysetSha256;
        @SerializedName("reportedControlPlaneRevision")
        private long reportedControlPlaneRevision;
        @SerializedName("reportedEnforcementMode")
        private MassDbLicenseState.EnforcementMode reportedEnforcementMode =
                MassDbLicenseState.EnforcementMode.UNINITIALIZED;
        @SerializedName("reportedEnforcementEpoch")
        private long reportedEnforcementEpoch;
        @SerializedName("reportedVerificationState")
        private MassDbLicenseFeRoleProtocol.VerificationState reportedVerificationState =
                MassDbLicenseFeRoleProtocol.VerificationState.MISSING;
        @SerializedName("reportedLastAuthenticatedControlPlaneAt")
        private long reportedLastAuthenticatedControlPlaneAt;
        @SerializedName("reportedControlPlaneFreshness")
        private String reportedControlPlaneFreshness = "MISSING";
        @SerializedName("reportedControlPlaneStalenessRemainingSeconds")
        private Long reportedControlPlaneStalenessRemainingSeconds;
        @SerializedName("lastVerifiedClockEpoch")
        private long lastVerifiedClockEpoch;
        @SerializedName("lastVerifiedEffectiveNow")
        private long lastVerifiedEffectiveNow;
        @SerializedName("trustedTimePersistedAt")
        private long trustedTimePersistedAt;
        @SerializedName("routingState")
        private RoutingState routingState = RoutingState.UNKNOWN;
        @SerializedName("routingEvidenceSource")
        private EvidenceSource routingEvidenceSource = EvidenceSource.NONE;
        @SerializedName("routingEvidenceRevision")
        private long routingEvidenceRevision;
        @SerializedName("routingVerifiedAt")
        private long routingVerifiedAt;
        @SerializedName("routingExpiresAt")
        private long routingExpiresAt;
        @SerializedName("routingObjectIdentity")
        private String routingObjectIdentity;
        @SerializedName("routingObjectRevision")
        private long routingObjectRevision;
        @SerializedName("routingEvidenceDigest")
        private String routingEvidenceDigest;
        @SerializedName("trustedRejoinActiveSha256")
        private String trustedRejoinActiveSha256;
        @SerializedName("trustedRejoinEnforcementEpoch")
        private long trustedRejoinEnforcementEpoch;
        @SerializedName("trustedRejoinExpiresAt")
        private long trustedRejoinExpiresAt;
        @SerializedName("ackLicenseSha256")
        private String ackLicenseSha256;
        @SerializedName("ackLicenseExpiresAt")
        private Long ackLicenseExpiresAt;
        @SerializedName("ackEnforcementEpoch")
        private long ackEnforcementEpoch;

        public IngressNode() {
        }

        public IngressNode(String nodeUuid, String endpoint, boolean desired) {
            requireAtom(nodeUuid, "nodeUuid");
            requireEndpoint(endpoint);
            this.nodeUuid = nodeUuid;
            this.endpoint = endpoint;
            this.desired = desired;
        }

        public String getNodeUuid() {
            return nodeUuid;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public boolean isDesired() {
            return desired;
        }

        public boolean isGuardReady() {
            return guardReady;
        }

        public boolean isIdentityConflicted() {
            return identityConflict || reportedIdentityConflict;
        }

        public boolean isAuthoritativeIdentityConflict() {
            return identityConflict;
        }

        public long getIdentityConflictRevision() {
            return identityConflictRevision;
        }

        public long getIdentityConflictDetectedAt() {
            return identityConflictDetectedAt;
        }

        public long getIdentityConflictLastObservedAt() {
            return identityConflictLastObservedAt;
        }

        public long getIdentityConflictResolvedAt() {
            return identityConflictResolvedAt;
        }

        public boolean isReportedIdentityConflict() {
            return reportedIdentityConflict;
        }

        public long getLiveLeaseExpiresAt() {
            return liveLeaseExpiresAt;
        }

        public long getLastRoleStatusObservedAt() {
            return lastRoleStatusObservedAt;
        }

        public boolean isReportedLicenseQueryAllowed() {
            return reportedLicenseQueryAllowed;
        }

        public String getReportedLocalStateErrorCode() {
            return reportedLocalStateErrorCode;
        }

        public String getReportedActiveLicenseSha256() {
            return reportedActiveLicenseSha256;
        }

        public MassDbLicenseFeRoleProtocol.ClockState getReportedClockState() {
            return reportedClockState;
        }

        public MassDbLicenseFeRoleProtocol.VerificationState getReportedVerificationState() {
            return reportedVerificationState;
        }

        public String getReportedControlPlaneFreshness() {
            return reportedControlPlaneFreshness;
        }

        public Long getReportedControlPlaneStalenessRemainingSeconds() {
            return reportedControlPlaneStalenessRemainingSeconds;
        }

        public long getReportedControlPlaneRevision() {
            return reportedControlPlaneRevision;
        }

        public long getLastVerifiedEffectiveNow() {
            return lastVerifiedEffectiveNow;
        }

        public RoutingState getRoutingState() {
            return routingState == null ? RoutingState.UNKNOWN : routingState;
        }

        public long getRoutingEvidenceRevision() {
            return routingEvidenceRevision;
        }

        public EvidenceSource getRoutingEvidenceSource() {
            return routingEvidenceSource == null ? EvidenceSource.NONE : routingEvidenceSource;
        }

        public long getRoutingVerifiedAt() {
            return routingVerifiedAt;
        }

        public long getRoutingExpiresAt() {
            return routingExpiresAt;
        }

        public String getRoutingObjectIdentity() {
            return routingObjectIdentity;
        }

        public long getRoutingObjectRevision() {
            return routingObjectRevision;
        }

        public String getRoutingEvidenceDigest() {
            return routingEvidenceDigest;
        }

        public String getAckLicenseSha256() {
            return ackLicenseSha256;
        }

        public Long getAckLicenseExpiresAt() {
            return ackLicenseExpiresAt;
        }

        public long getAckEnforcementEpoch() {
            return ackEnforcementEpoch;
        }

        public boolean isLive(long now) {
            return now >= 0 && now < liveLeaseExpiresAt;
        }

        public boolean hasFreshRoutingEvidence(long now) {
            return routingEvidenceSource != null && routingEvidenceSource != EvidenceSource.NONE
                    && now >= 0 && now < routingExpiresAt;
        }

        private boolean hasTrustedRejoin(String activeSha256, long enforcementEpoch, long now) {
            return !isIdentityConflicted() && now >= 0 && now < trustedRejoinExpiresAt
                    && equalsText(normalizeActiveSha(activeSha256), trustedRejoinActiveSha256)
                    && trustedRejoinEnforcementEpoch == enforcementEpoch;
        }

        private boolean hasActiveAck(MassDbLicenseState.ActiveLicense active, long enforcementEpoch) {
            return active != null && !isIdentityConflicted() && guardReady
                    && equalsText(active.getSha256(), ackLicenseSha256)
                    && ackLicenseExpiresAt != null && ackLicenseExpiresAt == active.getExpiresAt()
                    && ackEnforcementEpoch == enforcementEpoch;
        }

        private String inventoryLine(long now, String activeSha256, long enforcementEpoch) {
            return nodeUuid + "\t" + endpoint + "\t" + desired + "\t" + isLive(now) + "\t"
                    + guardReady + "\t" + hasTrustedRejoin(activeSha256, enforcementEpoch, now);
        }

        private String routingLine() {
            return nodeUuid + "\t" + getRoutingState().name() + "\t" + routingEvidenceRevision;
        }
    }

    public static final class Evaluation {
        public final int expectedIngressNodes;
        public final int liveIngressNodes;
        public final int coveredIngressNodes;
        public final int deferredOfflineIngressNodes;
        public final String coverageFreshness;
        public final String inventorySnapshotSha256;
        public final String routingEvidenceSnapshotSha256;
        public final List<String> requiredAckNodeUuids;
        public final List<String> deferredNodeUuids;
        public final List<String> blockers;
        public final List<String> warnings;

        private Evaluation(int expected, int live, int covered, int deferred,
                String freshness, String inventoryDigest, String routingDigest,
                List<String> requiredAckNodeUuids, List<String> deferredNodeUuids,
                List<String> blockers, List<String> warnings) {
            this.expectedIngressNodes = expected;
            this.liveIngressNodes = live;
            this.coveredIngressNodes = covered;
            this.deferredOfflineIngressNodes = deferred;
            this.coverageFreshness = freshness;
            this.inventorySnapshotSha256 = inventoryDigest;
            this.routingEvidenceSnapshotSha256 = routingDigest;
            this.requiredAckNodeUuids = Collections.unmodifiableList(
                    new ArrayList<>(requiredAckNodeUuids));
            this.deferredNodeUuids = Collections.unmodifiableList(
                    new ArrayList<>(deferredNodeUuids));
            this.blockers = Collections.unmodifiableList(new ArrayList<>(blockers));
            this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
        }

        public boolean isReadyForImport() {
            return expectedIngressNodes > 0 && blockers.isEmpty();
        }
    }

    @SerializedName("nodes")
    private Map<String, IngressNode> nodes = new LinkedHashMap<>();

    public MassDbLicenseIngressInventory() {
    }

    public static MassDbLicenseIngressInventory empty() {
        return new MassDbLicenseIngressInventory();
    }

    public MassDbLicenseIngressInventory copy() {
        MassDbLicenseIngressInventory result = GsonUtils.GSON.fromJson(
                GsonUtils.GSON.toJson(this), MassDbLicenseIngressInventory.class);
        result.normalizeAndValidate();
        return result;
    }

    public MassDbLicenseIngressInventory upsertConfigured(
            String nodeUuid, String endpoint, boolean desired) {
        requireAtom(nodeUuid, "nodeUuid");
        requireEndpoint(endpoint);
        MassDbLicenseIngressInventory next = copy();
        for (IngressNode existing : next.nodes.values()) {
            if (!existing.nodeUuid.equals(nodeUuid) && existing.endpoint.equals(endpoint)) {
                fail("MASSDB_LICENSE_INGRESS_DUPLICATE", "同一endpoint不能绑定不同nodeUuid");
            }
        }
        IngressNode node = next.nodes.get(nodeUuid);
        if (node == null) {
            node = new IngressNode(nodeUuid, endpoint, desired);
            next.nodes.put(nodeUuid, node);
        } else {
            node.endpoint = endpoint;
            node.desired = desired;
        }
        return next;
    }

    /** Applies only configured fields and preserves all Leader/role-owned runtime evidence. */
    public MassDbLicenseIngressInventory applyConfiguredSnapshot(
            MassDbLicenseIngressInventory candidate) {
        if (candidate == null) {
            fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID", "候选入口清单不能为空");
        }
        MassDbLicenseIngressInventory current = copy();
        MassDbLicenseIngressInventory configured = candidate.copy();
        for (IngressNode existing : current.nodes.values()) {
            if (!configured.nodes.containsKey(existing.nodeUuid)
                    && existing.isIdentityConflicted()) {
                fail("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                        "重复node UUID未解除，不能从configured inventory移除");
            }
        }
        MassDbLicenseIngressInventory result = empty();
        for (IngressNode requested : configured.nodes.values()) {
            IngressNode existing = current.nodes.get(requested.nodeUuid);
            IngressNode merged = existing == null
                    ? new IngressNode(requested.nodeUuid, requested.endpoint, requested.desired)
                    : GsonUtils.GSON.fromJson(
                            GsonUtils.GSON.toJson(existing), IngressNode.class);
            merged.endpoint = requested.endpoint;
            merged.desired = requested.desired;
            result.nodes.put(merged.nodeUuid, merged);
        }
        result.normalizeAndValidate();
        return result;
    }

    /** Applies controller-owned configured and routing fields while preserving role authority. */
    public MassDbLicenseIngressInventory applyControlCandidate(
            MassDbLicenseIngressInventory candidate) {
        MassDbLicenseIngressInventory configured = applyConfiguredSnapshot(candidate);
        MassDbLicenseIngressInventory requested = candidate.copy();
        for (IngressNode requestedNode : requested.nodes.values()) {
            IngressNode target = configured.nodes.get(requestedNode.nodeUuid);
            target.routingState = requestedNode.getRoutingState();
            target.routingEvidenceSource = requestedNode.getRoutingEvidenceSource();
            target.routingEvidenceRevision = requestedNode.routingEvidenceRevision;
            target.routingVerifiedAt = requestedNode.routingVerifiedAt;
            target.routingExpiresAt = requestedNode.routingExpiresAt;
            target.routingObjectIdentity = requestedNode.routingObjectIdentity;
            target.routingObjectRevision = requestedNode.routingObjectRevision;
            target.routingEvidenceDigest = requestedNode.routingEvidenceDigest;
        }
        configured.normalizeAndValidate();
        return configured;
    }

    public MassDbLicenseIngressInventory heartbeat(String nodeUuid, boolean guardReady,
            long observedAt, long leaseExpiresAt) {
        if (observedAt < 0 || leaseExpiresAt <= observedAt) {
            fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE", "入口live lease时间错误");
        }
        MassDbLicenseIngressInventory next = copy();
        IngressNode node = next.requireNode(nodeUuid);
        node.guardReady = guardReady && !node.isIdentityConflicted();
        node.liveLeaseExpiresAt = leaseExpiresAt;
        return next;
    }

    /** Persists one authenticated FE status without allowing the role to create authority facts. */
    public MassDbLicenseIngressInventory roleStatus(String nodeUuid, boolean guardReady,
            boolean reportedIdentityConflict, MassDbLicenseFeRoleProtocol.RoleStatus status,
            boolean authorityMatches, long observedAt, long leaseExpiresAt) {
        if (observedAt <= 0 || leaseExpiresAt <= observedAt) {
            fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE", "FE角色live lease时间错误");
        }
        MassDbLicenseIngressInventory next = copy();
        IngressNode node = next.requireNode(nodeUuid);
        node.reportedIdentityConflict = reportedIdentityConflict;
        node.guardReady = guardReady && !node.isIdentityConflicted();
        node.liveLeaseExpiresAt = leaseExpiresAt;
        node.lastRoleStatusObservedAt = observedAt;
        node.reportedRoleSequence = status.reportSequence;
        node.reportedLicenseQueryAllowed = status.licenseQueryAllowed;
        node.reportedLocalStateErrorCode = status.localStateErrorCode;
        node.reportedActiveLicenseSha256 = status.activeLicenseSha256;
        node.reportedActiveLicenseExpiresAt = status.activeLicenseExpiresAt;
        node.reportedEffectiveNow = status.effectiveNow;
        node.reportedRemainingSecondsAtCheck = status.remainingSecondsAtCheck;
        node.reportedObservedWallClock = status.observedWallClock;
        node.reportedLicenseExpiredUnderEffectiveNow =
                status.licenseExpiredUnderEffectiveNow;
        node.reportedLicenseExpiredAtObservedWallClock =
                status.licenseExpiredAtObservedWallClock;
        node.reportedClockState = status.clockState;
        node.reportedClockRecoveryEpoch = status.clockRecoveryEpoch;
        node.reportedRecoverySequence = status.recoverySequence;
        node.reportedKeysetVersion = status.keysetVersion;
        node.reportedKeysetSha256 = status.keysetSha256;
        node.reportedControlPlaneRevision = status.controlPlaneRevision;
        node.reportedEnforcementMode = status.enforcementMode;
        node.reportedEnforcementEpoch = status.enforcementEpoch;
        node.reportedVerificationState = status.verificationState;
        node.reportedLastAuthenticatedControlPlaneAt =
                status.lastAuthenticatedControlPlaneAt;
        node.reportedControlPlaneFreshness = status.controlPlaneFreshness;
        node.reportedControlPlaneStalenessRemainingSeconds =
                status.controlPlaneStalenessRemainingSeconds;
        if (authorityMatches && !node.isIdentityConflicted()
                && status.verificationState
                        == MassDbLicenseFeRoleProtocol.VerificationState.VERIFIED
                && "FRESH".equals(status.controlPlaneFreshness)
                && (status.clockState == MassDbLicenseFeRoleProtocol.ClockState.NORMAL
                        || status.clockState
                                == MassDbLicenseFeRoleProtocol.ClockState.SKEW_WARNING)) {
            node.ackLicenseSha256 = status.activeLicenseSha256;
            node.ackLicenseExpiresAt = status.activeLicenseExpiresAt;
            node.ackEnforcementEpoch = status.enforcementEpoch;
            boolean due = node.lastVerifiedEffectiveNow == 0
                    || node.lastVerifiedClockEpoch != status.clockRecoveryEpoch
                    || observedAt >= saturatedAdd(node.trustedTimePersistedAt,
                            MassDbLicenseState.DEFAULT_CLOCK_PERSISTENCE_SECONDS);
            if (due && status.effectiveNow != null) {
                node.lastVerifiedClockEpoch = status.clockRecoveryEpoch;
                node.lastVerifiedEffectiveNow = Math.max(
                        node.lastVerifiedEffectiveNow, status.effectiveNow);
                node.trustedTimePersistedAt = observedAt;
            }
        }
        return next;
    }

    /** Only the Leader's authenticated multi-session registry may change this authority state. */
    public MassDbLicenseIngressInventory identityConflict(String nodeUuid, boolean active,
            long controlPlaneRevision, long observedAt, long liveLeaseSeconds) {
        if (controlPlaneRevision <= 0 || observedAt <= 0 || liveLeaseSeconds <= 0) {
            fail("MASSDB_LICENSE_DUPLICATE_NODE_UUID", "重复node UUID权威观测字段无效");
        }
        MassDbLicenseIngressInventory next = copy();
        IngressNode node = next.requireNode(nodeUuid);
        if (active) {
            if (!node.identityConflict || node.identityConflictDetectedAt == 0) {
                node.identityConflictDetectedAt = observedAt;
            }
            node.identityConflictLastObservedAt = Math.max(
                    node.identityConflictLastObservedAt, observedAt);
            node.identityConflict = true;
            node.identityConflictResolvedAt = 0;
        } else {
            if (!node.identityConflict) {
                return next;
            }
            long clearEligibleAt = saturatedAdd(
                    node.identityConflictLastObservedAt, liveLeaseSeconds);
            if (observedAt < clearEligibleAt) {
                fail("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                        "单一FE实例尚未稳定满一个live lease窗口");
            }
            node.identityConflict = false;
            node.identityConflictResolvedAt = observedAt;
        }
        node.identityConflictRevision = controlPlaneRevision;
        node.guardReady = false;
        next.normalizeAndValidate();
        return next;
    }

    public MassDbLicenseIngressInventory observeRouting(String nodeUuid, RoutingState routingState,
            EvidenceSource source, long observedAt, long expiresAt) {
        if (routingState == null || source == null || source == EvidenceSource.NONE
                || observedAt < 0 || expiresAt <= observedAt) {
            fail("MASSDB_LICENSE_ROUTING_EVIDENCE_INVALID", "路由证据字段错误");
        }
        MassDbLicenseIngressInventory next = copy();
        IngressNode node = next.requireNode(nodeUuid);
        boolean semanticChanged = node.getRoutingState() != routingState
                || node.routingEvidenceSource != source;
        node.routingState = routingState;
        node.routingEvidenceSource = source;
        node.routingObjectIdentity = null;
        node.routingObjectRevision = 0;
        node.routingEvidenceDigest = null;
        if (semanticChanged) {
            node.routingEvidenceRevision = increment(node.routingEvidenceRevision);
        }
        node.routingVerifiedAt = observedAt;
        node.routingExpiresAt = expiresAt;
        return next;
    }

    /** Applies authenticated machine evidence with an object-scoped monotonic revision. */
    public MassDbLicenseIngressInventory observeMachineRouting(String nodeUuid,
            RoutingState routingState, String objectIdentity, long objectRevision,
            String evidenceDigest, long observedAt, long expiresAt) {
        if (routingState == null || objectIdentity == null || objectIdentity.trim().isEmpty()
                || objectIdentity.length() > 256 || containsControl(objectIdentity)
                || objectRevision <= 0 || evidenceDigest == null
                || !evidenceDigest.matches("[0-9a-fA-F]{64}")
                || observedAt < 0 || expiresAt <= observedAt) {
            fail("MASSDB_LICENSE_ROUTING_EVIDENCE_INVALID", "机器路由证据字段错误");
        }
        MassDbLicenseIngressInventory next = copy();
        IngressNode node = next.requireNode(nodeUuid);
        String normalizedIdentity = objectIdentity.trim();
        String normalizedDigest = evidenceDigest.toLowerCase();
        boolean sameObject = normalizedIdentity.equals(node.routingObjectIdentity);
        if (node.getRoutingEvidenceSource() == EvidenceSource.MACHINE && sameObject) {
            if (objectRevision < node.routingObjectRevision) {
                fail("MASSDB_LICENSE_ROUTING_EVIDENCE_STALE", "机器路由对象revision发生回退");
            }
            if (objectRevision == node.routingObjectRevision) {
                if (node.getRoutingState() != routingState
                        || !equalsText(node.routingEvidenceDigest, normalizedDigest)) {
                    fail("MASSDB_LICENSE_ROUTING_EVIDENCE_CONFLICT",
                            "同一机器路由对象revision对应不同证据");
                }
                return next;
            }
        }
        boolean semanticChanged = node.getRoutingState() != routingState
                || node.getRoutingEvidenceSource() != EvidenceSource.MACHINE
                || !sameObject;
        node.routingState = routingState;
        node.routingEvidenceSource = EvidenceSource.MACHINE;
        if (semanticChanged) {
            node.routingEvidenceRevision = increment(node.routingEvidenceRevision);
        }
        node.routingVerifiedAt = observedAt;
        node.routingExpiresAt = expiresAt;
        node.routingObjectIdentity = normalizedIdentity;
        node.routingObjectRevision = objectRevision;
        node.routingEvidenceDigest = normalizedDigest;
        return next;
    }

    public MassDbLicenseIngressInventory trustRejoin(String nodeUuid, String activeSha256,
            long enforcementEpoch, long expiresAt) {
        if (enforcementEpoch < 0 || expiresAt <= 0) {
            fail("MASSDB_LICENSE_TRUSTED_REJOIN_INVALID", "trusted rejoin字段错误");
        }
        if (activeSha256 != null) {
            requireSha256(activeSha256);
        }
        MassDbLicenseIngressInventory next = copy();
        IngressNode node = next.requireNode(nodeUuid);
        if (node.isIdentityConflicted()) {
            fail("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                    "重复node UUID未解除，不能建立可信重加入证据");
        }
        node.trustedRejoinActiveSha256 = normalizeActiveSha(activeSha256);
        node.trustedRejoinEnforcementEpoch = enforcementEpoch;
        node.trustedRejoinExpiresAt = expiresAt;
        return next;
    }

    public MassDbLicenseIngressInventory acknowledgeActive(String nodeUuid,
            String licenseSha256, long licenseExpiresAt, long enforcementEpoch) {
        requireSha256(licenseSha256);
        if (licenseExpiresAt <= 0 || enforcementEpoch < 0) {
            fail("MASSDB_LICENSE_INGRESS_ACK_INVALID", "入口ACK字段错误");
        }
        MassDbLicenseIngressInventory next = copy();
        IngressNode node = next.requireNode(nodeUuid);
        if (node.isIdentityConflicted()) {
            fail("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                    "重复node UUID未解除，不能记录active ACK");
        }
        node.ackLicenseSha256 = licenseSha256.toLowerCase();
        node.ackLicenseExpiresAt = licenseExpiresAt;
        node.ackEnforcementEpoch = enforcementEpoch;
        return next;
    }

    public Evaluation evaluate(MassDbLicenseState.ActiveLicense active,
            long enforcementEpoch, long now, boolean allowDeferredOffline) {
        normalizeAndValidate();
        String activeSha = active == null ? null : active.getSha256();
        int expected = 0;
        int live = 0;
        int covered = 0;
        int deferred = 0;
        boolean allControlPlaneFresh = true;
        List<String> blockers = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        List<String> requiredAcks = new ArrayList<>();
        List<String> deferredNodes = new ArrayList<>();
        StringBuilder inventoryCanonical = new StringBuilder();
        StringBuilder routingCanonical = new StringBuilder();
        for (IngressNode node : new TreeMap<>(nodes).values()) {
            if (!node.desired) {
                continue;
            }
            expected++;
            inventoryCanonical.append(node.inventoryLine(now, activeSha, enforcementEpoch)).append('\n');
            routingCanonical.append(node.routingLine()).append('\n');
            boolean isLive = node.isLive(now);
            boolean routingFresh = node.hasFreshRoutingEvidence(now);
            if (node.hasActiveAck(active, enforcementEpoch)) {
                covered++;
            }
            if (isLive) {
                live++;
                requiredAcks.add(node.nodeUuid);
                if (node.isIdentityConflicted()) {
                    blockers.add("MASSDB_LICENSE_DUPLICATE_NODE_UUID:" + node.nodeUuid);
                }
                if (!node.guardReady) {
                    blockers.add("MASSDB_LICENSE_INGRESS_GUARD_NOT_READY:" + node.nodeUuid);
                }
                if (node.reportedControlPlaneRevision > 0
                        && !"FRESH".equals(node.reportedControlPlaneFreshness)) {
                    allControlPlaneFresh = false;
                    blockers.add("MASSDB_LICENSE_CONTROL_PLANE_STALE:" + node.nodeUuid);
                }
                if (!routingFresh || node.getRoutingState() != RoutingState.IN_SERVICE) {
                    blockers.add("MASSDB_LICENSE_ROUTING_EVIDENCE_REQUIRED:" + node.nodeUuid);
                }
            } else {
                allControlPlaneFresh = false;
                boolean safeDeferred = allowDeferredOffline && !node.isIdentityConflicted()
                        && node.getRoutingState() == RoutingState.REMOVED
                        && node.hasTrustedRejoin(activeSha, enforcementEpoch, now);
                if (safeDeferred) {
                    deferred++;
                    deferredNodes.add(node.nodeUuid);
                    warnings.add("MASSDB_LICENSE_INGRESS_DEFERRED:" + node.nodeUuid);
                    if (!routingFresh) {
                        warnings.add("MASSDB_LICENSE_ROUTING_EVIDENCE_RECONFIRM_REQUIRED:"
                                + node.nodeUuid);
                    }
                } else {
                    blockers.add("MASSDB_LICENSE_INGRESS_UNAVAILABLE:" + node.nodeUuid);
                }
            }
        }
        if (expected == 0) {
            blockers.add("MASSDB_LICENSE_INGRESS_INVENTORY_EMPTY");
        }
        String freshness = expected > 0 && allControlPlaneFresh ? "FRESH" : "STALE";
        return new Evaluation(expected, live, covered, deferred, freshness,
                digest(inventoryCanonical.toString()), digest(routingCanonical.toString()),
                requiredAcks, deferredNodes, blockers, warnings);
    }

    /** Applies trusted internal node ACK results to the same snapshot used by an import operation. */
    public MassDbLicenseIngressInventory applyImportAcks(List<String> requiredNodeUuids,
            List<String> deferredNodeUuids, List<String> ackedNodeUuids,
            MassDbLicenseState.ActiveLicense currentActive,
            MassDbLicenseState.ActiveLicense candidate, long enforcementEpoch, long now) {
        if (requiredNodeUuids == null || deferredNodeUuids == null || ackedNodeUuids == null
                || candidate == null) {
            fail("MASSDB_LICENSE_INGRESS_ACK_INVALID", "入口ACK参数不能为空");
        }
        MassDbLicenseIngressInventory next = copy();
        if (!sameUniqueSet(requiredNodeUuids, ackedNodeUuids)) {
            fail("MASSDB_LICENSE_INGRESS_ACK_INCOMPLETE", "必须收到全部当次在线入口ACK");
        }
        for (String nodeUuid : requiredNodeUuids) {
            IngressNode node = next.requireNode(nodeUuid);
            if (node.isIdentityConflicted()) {
                fail("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                        "重复node UUID未解除，不能应用入口ACK:" + nodeUuid);
            }
            if (!node.desired || !node.isLive(now) || !node.guardReady
                    || !node.hasFreshRoutingEvidence(now)
                    || node.getRoutingState() != RoutingState.IN_SERVICE) {
                fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE", "入口ACK时已不可用:" + nodeUuid);
            }
            node.ackLicenseSha256 = candidate.getSha256();
            node.ackLicenseExpiresAt = candidate.getExpiresAt();
            node.ackEnforcementEpoch = enforcementEpoch;
        }
        for (String nodeUuid : deferredNodeUuids) {
            IngressNode node = next.requireNode(nodeUuid);
            String currentSha = currentActive == null ? null : currentActive.getSha256();
            if (node.isIdentityConflicted()) {
                fail("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                        "重复node UUID未解除，不能迁移可信重加入证据:" + nodeUuid);
            }
            if (!node.desired || node.isLive(now)
                    || node.getRoutingState() != RoutingState.REMOVED
                    || !node.hasTrustedRejoin(currentSha, enforcementEpoch, now)) {
                fail("MASSDB_LICENSE_INGRESS_UNAVAILABLE", "延迟入口证据已变化:" + nodeUuid);
            }
            // A non-reducing import preserves the fail-closed rejoin promise while retargeting
            // the artifact that must be synchronized before this offline node may query again.
            node.trustedRejoinActiveSha256 = candidate.getSha256();
        }
        return next;
    }

    public Map<String, IngressNode> getNodes() {
        normalizeAndValidate();
        return Collections.unmodifiableMap(new LinkedHashMap<>(nodes));
    }

    public String configuredDigest() {
        normalizeAndValidate();
        StringBuilder value = new StringBuilder();
        for (IngressNode node : new TreeMap<>(nodes).values()) {
            value.append(node.nodeUuid).append('\t').append(node.endpoint).append('\t')
                    .append(node.desired).append('\n');
        }
        return digest(value.toString());
    }

    /** Digest of desired/endpoint and routing semantics; evidence renewal timestamps are excluded. */
    public String semanticDigest() {
        normalizeAndValidate();
        StringBuilder value = new StringBuilder();
        for (IngressNode node : new TreeMap<>(nodes).values()) {
            value.append(node.nodeUuid).append('\t').append(node.endpoint).append('\t')
                    .append(node.desired).append('\t').append(node.getRoutingState().name())
                    .append('\t').append(node.getRoutingEvidenceSource().name()).append('\t')
                    .append(node.routingEvidenceRevision).append('\t')
                    .append(nullToEmpty(node.routingObjectIdentity)).append('\n');
        }
        return digest(value.toString());
    }

    /** Digest of every mutable routing/configuration evidence field used for durable no-op checks. */
    public String fullDigest() {
        normalizeAndValidate();
        StringBuilder value = new StringBuilder();
        for (IngressNode node : new TreeMap<>(nodes).values()) {
            value.append(node.nodeUuid).append('\t').append(node.endpoint).append('\t')
                    .append(node.desired).append('\t').append(node.getRoutingState().name())
                    .append('\t').append(node.getRoutingEvidenceSource().name()).append('\t')
                    .append(node.routingEvidenceRevision).append('\t')
                    .append(node.routingVerifiedAt).append('\t').append(node.routingExpiresAt)
                    .append('\t').append(nullToEmpty(node.routingObjectIdentity)).append('\t')
                    .append(node.routingObjectRevision).append('\t')
                    .append(nullToEmpty(node.routingEvidenceDigest)).append('\n');
        }
        return digest(value.toString());
    }

    private IngressNode requireNode(String nodeUuid) {
        requireAtom(nodeUuid, "nodeUuid");
        IngressNode node = nodes.get(nodeUuid);
        if (node == null) {
            fail("MASSDB_LICENSE_INGRESS_NOT_FOUND", "入口不在configured inventory中");
        }
        return node;
    }

    private static boolean sameUniqueSet(List<String> expected, List<String> actual) {
        java.util.LinkedHashSet<String> expectedSet = new java.util.LinkedHashSet<>(expected);
        java.util.LinkedHashSet<String> actualSet = new java.util.LinkedHashSet<>(actual);
        return expectedSet.size() == expected.size() && actualSet.size() == actual.size()
                && expectedSet.equals(actualSet);
    }

    private void normalizeAndValidate() {
        if (nodes == null) {
            nodes = new LinkedHashMap<>();
        }
        for (Map.Entry<String, IngressNode> entry : nodes.entrySet()) {
            IngressNode node = entry.getValue();
            if (node == null || !entry.getKey().equals(node.nodeUuid)) {
                fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID", "入口map key与nodeUuid不一致");
            }
            requireAtom(node.nodeUuid, "nodeUuid");
            requireEndpoint(node.endpoint);
            boolean activeConflictValid = node.identityConflict
                    && node.identityConflictRevision > 0
                    && node.identityConflictDetectedAt > 0
                    && node.identityConflictLastObservedAt >= node.identityConflictDetectedAt
                    && node.identityConflictResolvedAt == 0;
            boolean resolvedConflictValid = !node.identityConflict
                    && node.identityConflictRevision > 0
                    && node.identityConflictDetectedAt > 0
                    && node.identityConflictLastObservedAt >= node.identityConflictDetectedAt
                    && node.identityConflictResolvedAt >= saturatedAdd(
                            node.identityConflictLastObservedAt,
                            MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS);
            boolean noConflictHistory = !node.identityConflict
                    && node.identityConflictRevision == 0
                    && node.identityConflictDetectedAt == 0
                    && node.identityConflictLastObservedAt == 0
                    && node.identityConflictResolvedAt == 0;
            if (!activeConflictValid && !resolvedConflictValid && !noConflictHistory) {
                fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID",
                        "重复node UUID权威状态字段不一致");
            }
            if (node.routingState == null) {
                node.routingState = RoutingState.UNKNOWN;
            }
            if (node.routingEvidenceSource == null) {
                node.routingEvidenceSource = EvidenceSource.NONE;
            }
            if (node.routingObjectRevision < 0
                    || node.routingObjectRevision > 0
                            && (node.routingEvidenceSource != EvidenceSource.MACHINE
                                    || node.routingObjectIdentity == null
                                    || node.routingEvidenceDigest == null
                                    || !node.routingEvidenceDigest.matches("[0-9a-f]{64}"))) {
                fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID",
                        "机器路由证据对象字段不一致");
            }
            if (node.reportedClockState == null) {
                node.reportedClockState =
                        MassDbLicenseFeRoleProtocol.ClockState.UNINITIALIZED;
            }
            if (node.reportedVerificationState == null) {
                node.reportedVerificationState =
                        MassDbLicenseFeRoleProtocol.VerificationState.MISSING;
            }
            if (node.reportedEnforcementMode == null) {
                node.reportedEnforcementMode =
                        MassDbLicenseState.EnforcementMode.UNINITIALIZED;
            }
            if (node.reportedControlPlaneFreshness == null) {
                node.reportedControlPlaneFreshness = "MISSING";
            }
            if (node.lastRoleStatusObservedAt < 0 || node.reportedRoleSequence < 0
                    || node.reportedObservedWallClock < 0
                    || node.reportedControlPlaneRevision < 0
                    || node.lastVerifiedEffectiveNow < 0 || node.trustedTimePersistedAt < 0
                    || (node.reportedActiveLicenseSha256 == null)
                            != (node.reportedActiveLicenseExpiresAt == null)
                    || (node.reportedKeysetVersion == 0)
                            != (node.reportedKeysetSha256 == null)) {
                fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID",
                        "FE角色持久状态字段不一致");
            }
        }
    }

    private static String normalizeActiveSha(String activeSha256) {
        return activeSha256 == null ? "-" : activeSha256.toLowerCase();
    }

    private static long increment(long value) {
        if (value == Long.MAX_VALUE) {
            fail("MASSDB_LICENSE_TOPOLOGY_REVISION_EXHAUSTED", "revision已耗尽");
        }
        return value + 1;
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static String digest(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(64);
            for (byte item : bytes) {
                result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
                result.append(Character.forDigit(item & 0x0f, 16));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    private static void requireAtom(String value, String field) {
        if (value == null || value.length() == 0 || value.length() > 128) {
            fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID", field + "为空或过长");
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (item < 0x21 || item > 0x7e || item == '\t') {
                fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID", field + "不是安全ASCII atom");
            }
        }
    }

    private static void requireEndpoint(String value) {
        if (value == null || value.length() == 0 || value.length() > 512
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\t') >= 0) {
            fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID", "endpoint为空、过长或含控制字符");
        }
    }

    private static void requireSha256(String value) {
        if (value == null || !value.matches("[0-9a-fA-F]{64}")) {
            fail("MASSDB_LICENSE_INGRESS_INVENTORY_INVALID", "SHA-256格式错误");
        }
    }

    private static boolean equalsText(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static boolean containsControl(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) {
                return true;
            }
        }
        return false;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }
}
