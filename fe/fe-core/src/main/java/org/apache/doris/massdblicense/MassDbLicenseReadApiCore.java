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

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Read-only application core for capability, status and License validation.
 *
 * <p>A precondition token is issued only when the durable configured ingress inventory and
 * current live/routing snapshot are safe for import.</p>
 */
public final class MassDbLicenseReadApiCore {
    public static final String CAPABILITY_VERSION = "1";
    public static final String COMPONENT_TYPE = "massdb-sql";
    public static final long MAX_CONTROL_PLANE_STALENESS_SECONDS = 604_800;
    public static final long MANUAL_ROUTING_EVIDENCE_TTL_SECONDS = 7_776_000;
    public static final long MAX_MANUAL_ROUTING_EVIDENCE_TTL_SECONDS = 15_552_000;
    public static final long MACHINE_ROUTING_EVIDENCE_POLL_SECONDS = 300;
    public static final long MACHINE_ROUTING_EVIDENCE_STALE_SECONDS = 900;
    public static final long DIAGNOSTIC_EVENT_RETENTION_SECONDS = 1_209_600;

    private final String componentVersion;
    private final long maxLicenseTermSeconds;
    private final Map<String, PublicKey> rootKeys;

    public MassDbLicenseReadApiCore(String componentVersion, long maxLicenseTermSeconds,
            Map<String, PublicKey> rootKeys) {
        if (componentVersion == null || componentVersion.trim().isEmpty()
                || maxLicenseTermSeconds <= 0 || rootKeys == null || rootKeys.isEmpty()) {
            throw new IllegalArgumentException("componentVersion、maxLicenseTermSeconds和rootKeys必须配置");
        }
        this.componentVersion = componentVersion;
        this.maxLicenseTermSeconds = maxLicenseTermSeconds;
        this.rootKeys = Collections.unmodifiableMap(new LinkedHashMap<>(rootKeys));
    }

    public Capability capability(MassDbLicenseState state) {
        boolean initialized = state != null && state.isInitialized();
        return new Capability(componentVersion,
                initialized ? state.getLicenseControlDeploymentUuid() : null,
                initialized ? state.getEnforcementMode().name() : "UNINITIALIZED",
                maxLicenseTermSeconds);
    }

    public Status status(MassDbLicenseState state, long effectiveNow, long observedWallClock) {
        requireInitialized(state);
        effectiveNow = Math.max(effectiveNow, state.getMaxSeenWallClock());
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        String licenseState = "MISSING";
        String invalidReason = null;
        MassDbLicenseIngressInventory.Evaluation ingress = state.getIngressInventory().evaluate(
                active, state.getEnforcementEpoch(), effectiveNow, true);
        if (active != null) {
            try {
                verifyActiveState(state, effectiveNow);
            } catch (MassDbLicenseException error) {
                licenseState = "INVALID";
                invalidReason = "MASSDB_LICENSE_KEYSET_INVALID".equals(error.getCode())
                        ? "KEYSET_INVALID" : "ACTIVE_FILE_CORRUPT";
            }
            if (!"INVALID".equals(licenseState)) {
                boolean clockRollback = observedWallClock <= Long.MAX_VALUE - 120
                        && observedWallClock + 120 < state.getMaxSeenWallClock();
                for (MassDbLicenseIngressInventory.IngressNode node
                        : state.getIngressInventory().getNodes().values()) {
                    if (!node.isDesired() || !node.isLive(observedWallClock)) {
                        continue;
                    }
                    MassDbLicenseFeRoleProtocol.ClockState nodeClock =
                            node.getReportedClockState();
                    if (nodeClock == MassDbLicenseFeRoleProtocol.ClockState.ROLLBACK
                            || nodeClock
                                    == MassDbLicenseFeRoleProtocol.ClockState.RECOVERY_PENDING) {
                        clockRollback = true;
                    }
                }
                long remaining = Math.max(0, active.getExpiresAt() - effectiveNow);
                if (clockRollback) {
                    licenseState = "CLOCK_ROLLBACK";
                } else if (effectiveNow >= active.getExpiresAt()) {
                    licenseState = "EXPIRED";
                } else if (!ingress.blockers.isEmpty()) {
                    licenseState = "PARTIAL_COVERAGE";
                } else if (remaining <= 30L * 24 * 60 * 60) {
                    licenseState = "EXPIRING";
                } else {
                    licenseState = "VALID";
                }
            }
        }
        Long remaining = active == null ? null : Math.max(0, active.getExpiresAt() - effectiveNow);
        return new Status(componentVersion, state, licenseState, invalidReason,
                effectiveNow, observedWallClock, remaining, ingress);
    }

    public ValidateResult validateNormal(MassDbLicenseState state, byte[] artifact, long effectiveNow) {
        requireInitialized(state);
        MassDbLicenseProtocolV1.VerifiedKeyset keyset = verifyActiveKeyset(state, effectiveNow);
        MassDbLicenseProtocolV1.VerifiedLicense verified = MassDbLicenseProtocolV1.verifyLicense(
                artifact, keyset, effectiveNow, maxLicenseTermSeconds, null);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        for (MassDbLicenseState.CorrectionBarrier barrier : state.getLicenseCorrectionBarriers()) {
            long correctedExpiresAt = barrier.getCorrectedExpiresAt() == 0
                    ? barrier.getSupersededExpiresAt() : barrier.getCorrectedExpiresAt();
            if (verified.getPayload().getExpiresAt() > correctedExpiresAt
                    && verified.getPayload().getIssuedAt() <= barrier.getSupersededIssuedAtCutoff()) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_SUPERSEDED", "候选License会撤销已批准的到期更正");
            }
        }
        String action;
        if (active != null && active.getSha256().equals(verified.getSha256())) {
            try {
                verifyActiveState(state, effectiveNow);
                action = "ALREADY_ACTIVE";
            } catch (MassDbLicenseException error) {
                action = "REPAIR";
            }
        } else {
            if (active != null && verified.getPayload().getExpiresAt() <= active.getExpiresAt()) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_EXPIRY_NOT_EXTENDED", "NORMAL续期必须严格延长");
            }
            action = "ACTIVATE";
        }
        MassDbLicenseIngressInventory.Evaluation ingress = state.getIngressInventory().evaluate(
                active, state.getEnforcementEpoch(), effectiveNow, true);
        if ("ALREADY_ACTIVE".equals(action)
                && (ingress.coveredIngressNodes != ingress.expectedIngressNodes
                || !"FRESH".equals(ingress.coverageFreshness))) {
            action = "REPAIR";
        }
        List<String> warnings = new ArrayList<>(ingress.warnings);
        warnings.addAll(ingress.blockers);
        boolean readyForImport = ingress.isReadyForImport();
        if (state.getMutation() != null) {
            readyForImport = false;
            warnings.add("MASSDB_LICENSE_MUTATION_IN_PROGRESS");
        }
        if (state.hasActiveClockChallenge(effectiveNow)) {
            readyForImport = false;
            warnings.add("MASSDB_LICENSE_CLOCK_RECOVERY_CHALLENGE_ACTIVE");
        }
        String preconditionToken = null;
        if (readyForImport) {
            long tokenExpiresAt = Math.min(verified.getPayload().getExpiresAt(),
                    saturatedAdd(effectiveNow, MassDbLicensePreconditionToken.MAX_TTL_SECONDS));
            MassDbLicensePreconditionToken.Claims claims = new MassDbLicensePreconditionToken.Claims(
                    "LICENSE_IMPORT", action,
                    active == null ? null : active.getSha256(),
                    active == null ? null : active.getExpiresAt(),
                    state.getEnforcementEpoch(), state.getTopologyRevision(),
                    ingress.inventorySnapshotSha256, ingress.routingEvidenceSnapshotSha256,
                    verified.getSha256(), verified.getPayload().getIssuedAt(),
                    verified.getPayload().getExpiresAt(), effectiveNow, tokenExpiresAt,
                    UUID.randomUUID().toString());
            preconditionToken = MassDbLicensePreconditionToken.issue(
                    state.getPreconditionHmacKey(), claims);
        }
        return new ValidateResult(action, verified, active, state.getTopologyRevision(),
                ingress, readyForImport, preconditionToken, warnings);
    }

    private MassDbLicenseProtocolV1.VerifiedKeyset verifyActiveKeyset(
            MassDbLicenseState state, long effectiveNow) {
        MassDbLicenseState.ActiveKeyset activeKeyset = state.getActiveKeyset();
        if (activeKeyset == null) {
            throw new MassDbLicenseException("MASSDB_LICENSE_KEYSET_INVALID", "尚未安装trusted keyset");
        }
        MassDbLicenseProtocolV1.VerifiedKeyset verified = MassDbLicenseProtocolV1.verifyKeyset(
                activeKeyset.getArtifact(), rootKeys, effectiveNow, null);
        if (verified.getPayload().getKeysetVersion() != activeKeyset.getVersion()
                || !verified.getSha256().equals(activeKeyset.getSha256())) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_KEYSET_INVALID", "持久keyset元数据与工件不一致");
        }
        return verified;
    }

    private void verifyActiveState(MassDbLicenseState state, long effectiveNow) {
        MassDbLicenseProtocolV1.VerifiedKeyset keyset = verifyActiveKeyset(state, effectiveNow);
        MassDbLicenseState.ActiveLicense active = state.getActiveLicense();
        if (active.getExpiresAt() <= 0) {
            throw new MassDbLicenseException("MASSDB_LICENSE_FILE_INVALID", "active到期时间错误");
        }
        long artifactValidationNow = Math.min(effectiveNow, active.getExpiresAt() - 1);
        MassDbLicenseProtocolV1.VerifiedLicense verified = MassDbLicenseProtocolV1.verifyLicense(
                active.getArtifact(), keyset, artifactValidationNow, maxLicenseTermSeconds, null);
        if (!verified.getSha256().equals(active.getSha256())
                || !verified.getKid().equals(active.getKid())
                || !verified.getPayload().getLicenseId().equals(active.getLicenseId())
                || verified.getPayload().getIssuedAt() != active.getIssuedAt()
                || verified.getPayload().getExpiresAt() != active.getExpiresAt()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_FILE_INVALID", "持久active License元数据与工件不一致");
        }
    }

    private static void requireInitialized(MassDbLicenseState state) {
        if (state == null || !state.isInitialized()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_BOOTSTRAP_REQUIRED", "License一致性状态尚未bootstrap");
        }
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    public static final class Capability {
        public final boolean supported = true;
        public final String capabilityVersion = CAPABILITY_VERSION;
        public final String componentType = COMPONENT_TYPE;
        public final String componentVersion;
        public final String licenseControlDeploymentUuid;
        public final String enforcementMode;
        public final long maxLicenseTermSeconds;
        public final long maxControlPlaneStalenessSeconds = MAX_CONTROL_PLANE_STALENESS_SECONDS;
        public final long manualRoutingEvidenceTtlSeconds = MANUAL_ROUTING_EVIDENCE_TTL_SECONDS;
        public final long maxManualRoutingEvidenceTtlSeconds = MAX_MANUAL_ROUTING_EVIDENCE_TTL_SECONDS;
        public final long machineRoutingEvidencePollSeconds = MACHINE_ROUTING_EVIDENCE_POLL_SECONDS;
        public final long machineRoutingEvidenceStaleSeconds = MACHINE_ROUTING_EVIDENCE_STALE_SECONDS;
        public final long diagnosticEventRetentionSeconds = DIAGNOSTIC_EVENT_RETENTION_SECONDS;
        public final int diagnosticEventCapacity =
                MassDbLicenseState.DEFAULT_DIAGNOSTIC_EVENT_CAPACITY;

        private Capability(String componentVersion, String deploymentUuid,
                String enforcementMode, long maxLicenseTermSeconds) {
            this.componentVersion = componentVersion;
            this.licenseControlDeploymentUuid = deploymentUuid;
            this.enforcementMode = enforcementMode;
            this.maxLicenseTermSeconds = maxLicenseTermSeconds;
        }
    }

    public static final class Status {
        public final String capabilityVersion = CAPABILITY_VERSION;
        public final String componentType = COMPONENT_TYPE;
        public final String componentVersion;
        public final String licenseControlDeploymentUuid;
        public final String enforcementMode;
        public final long enforcementEpoch;
        public final String state;
        public final String invalidReason;
        public final String licenseId;
        public final String issuerKeyId;
        public final String contentSha256;
        public final Long issuedAt;
        public final Long licenseExpiresAt;
        public final String stagedOperationId;
        public final String stagedContentSha256;
        public final Long stagedLicenseExpiresAt;
        public final String pendingEnforcementOperationId;
        public final Long pendingEnforcementEpoch;
        public final long keysetVersion;
        public final long lastClockRecoverySequence;
        public final long clockRecoveryEpoch;
        public final int expectedIngressNodes;
        public final int liveIngressNodes;
        public final int coveredIngressNodes;
        public final String coverageFreshness;
        public final long topologyRevision;
        public final long checkedAt;
        public final long effectiveNow;
        public final long observedWallClock;
        public final Long remainingSecondsAtCheck;
        public final boolean licenseExpiredUnderEffectiveNow;
        public final boolean licenseExpiredAtObservedWallClock;
        public final long diagnosticEventRetentionSeconds = DIAGNOSTIC_EVENT_RETENTION_SECONDS;
        public final int diagnosticEventCapacity =
                MassDbLicenseState.DEFAULT_DIAGNOSTIC_EVENT_CAPACITY;

        private Status(String componentVersion, MassDbLicenseState source, String state,
                String invalidReason, long effectiveNow, long observedWallClock, Long remaining,
                MassDbLicenseIngressInventory.Evaluation ingress) {
            MassDbLicenseState.ActiveLicense active = source.getActiveLicense();
            this.componentVersion = componentVersion;
            this.licenseControlDeploymentUuid = source.getLicenseControlDeploymentUuid();
            this.enforcementMode = source.getEnforcementMode().name();
            this.enforcementEpoch = source.getEnforcementEpoch();
            this.state = state;
            this.invalidReason = invalidReason;
            this.licenseId = active == null ? null : active.getLicenseId();
            this.issuerKeyId = active == null ? null : active.getKid();
            this.contentSha256 = active == null ? null : active.getSha256();
            this.issuedAt = active == null ? null : active.getIssuedAt();
            this.licenseExpiresAt = active == null ? null : active.getExpiresAt();
            MassDbLicenseState.Mutation mutation = source.getMutation();
            MassDbLicenseState.ActiveLicense staged = mutation == null
                    ? null : mutation.getCandidateLicense();
            this.stagedOperationId = staged == null ? null : mutation.getOperationId();
            this.stagedContentSha256 = staged == null ? null : staged.getSha256();
            this.stagedLicenseExpiresAt = staged == null ? null : staged.getExpiresAt();
            boolean enforcementPending = mutation != null
                    && mutation.getKind() == MassDbLicenseState.MutationKind.ENFORCEMENT;
            this.pendingEnforcementOperationId = enforcementPending
                    ? mutation.getOperationId() : null;
            this.pendingEnforcementEpoch = enforcementPending
                    ? mutation.getTargetEnforcementEpoch() : null;
            this.keysetVersion = source.getKeysetVersion();
            this.lastClockRecoverySequence = source.getMaxAcceptedRecoverySequence();
            this.clockRecoveryEpoch = source.getClockRecoveryEpoch();
            this.expectedIngressNodes = ingress.expectedIngressNodes;
            this.liveIngressNodes = ingress.liveIngressNodes;
            this.coveredIngressNodes = ingress.coveredIngressNodes;
            this.coverageFreshness = ingress.coverageFreshness;
            this.topologyRevision = source.getTopologyRevision();
            this.checkedAt = observedWallClock;
            this.effectiveNow = effectiveNow;
            this.observedWallClock = observedWallClock;
            this.remainingSecondsAtCheck = remaining;
            this.licenseExpiredUnderEffectiveNow = active != null && effectiveNow >= active.getExpiresAt();
            this.licenseExpiredAtObservedWallClock =
                    active != null && observedWallClock >= active.getExpiresAt();
        }
    }

    public static final class ValidateResult {
        public final boolean valid = true;
        public final boolean readyForImport;
        public final Boolean workflowCreatable = null;
        public final String action;
        public final String licenseId;
        public final long issuedAt;
        public final long licenseExpiresAt;
        public final Long currentLicenseExpiresAt;
        public final long topologyRevision;
        public final int expectedIngressNodes;
        public final int liveIngressNodes;
        public final int deferredOfflineIngressNodes;
        public final String contentSha256;
        public final String preconditionToken;
        public final List<String> warnings;

        private ValidateResult(String action, MassDbLicenseProtocolV1.VerifiedLicense verified,
                MassDbLicenseState.ActiveLicense active, long topologyRevision,
                MassDbLicenseIngressInventory.Evaluation ingress, boolean readyForImport,
                String preconditionToken, List<String> warnings) {
            this.readyForImport = readyForImport;
            this.action = action;
            this.licenseId = verified.getPayload().getLicenseId();
            this.issuedAt = verified.getPayload().getIssuedAt();
            this.licenseExpiresAt = verified.getPayload().getExpiresAt();
            this.currentLicenseExpiresAt = active == null ? null : active.getExpiresAt();
            this.topologyRevision = topologyRevision;
            this.expectedIngressNodes = ingress.expectedIngressNodes;
            this.liveIngressNodes = ingress.liveIngressNodes;
            this.deferredOfflineIngressNodes = ingress.deferredOfflineIngressNodes;
            this.contentSha256 = verified.getSha256();
            this.preconditionToken = preconditionToken;
            this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
        }
    }
}
