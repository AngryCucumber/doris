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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Leader-side FE role transport.
 *
 * <p>Commands and ACKs are deliberately memory-only. The journaled mutation is the authority and
 * recreates a command after Leader failover; every role recreates its ACK from durable local
 * pending bytes. A transport restart therefore cannot commit or lose a License operation.</p>
 */
public final class MassDbLicenseFeRoleTransport
        implements MassDbLicenseLeaderReconciler.TrustedRoleTransport {
    private final MassDbLicenseManager manager;
    private final boolean available;
    private final Map<String, CommandState> commands = new LinkedHashMap<>();
    private final Map<String, Map<String, SessionView>> sessions = new LinkedHashMap<>();

    public MassDbLicenseFeRoleTransport(MassDbLicenseManager manager, boolean available) {
        this.manager = Objects.requireNonNull(manager, "manager");
        this.available = available;
    }

    @Override
    public boolean isAvailable() {
        return available;
    }

    @Override
    public synchronized List<MassDbLicenseLeaderReconciler.AuthenticatedActivationAck>
            prepareEnforcement(MassDbLicenseEnforcementCore.RecoveryPlan plan) {
        requireAvailable();
        CommandState state = ensureCommand(
                MassDbLicenseFeRoleProtocol.Command.enforcement(plan));
        List<MassDbLicenseLeaderReconciler.AuthenticatedActivationAck> result = new ArrayList<>();
        for (String nodeUuid : plan.requiredAckNodeUuids) {
            MassDbLicenseLeaderReconciler.AuthenticatedActivationAck ack =
                    state.activationAcks.get(nodeUuid);
            if (ack != null && !identityConflicted(nodeUuid)) {
                result.add(ack);
            }
        }
        return result;
    }

    @Override
    public synchronized List<MassDbLicenseLeaderReconciler.AuthenticatedLicenseAck>
            prepareNormal(MassDbLicenseImportCore.RecoveryPlan plan) {
        requireAvailable();
        CommandState state = ensureCommand(MassDbLicenseFeRoleProtocol.Command.normal(plan));
        List<MassDbLicenseLeaderReconciler.AuthenticatedLicenseAck> result = new ArrayList<>();
        for (String nodeUuid : plan.requiredAckNodeUuids) {
            MassDbLicenseLeaderReconciler.AuthenticatedLicenseAck ack =
                    state.licenseAcks.get(nodeUuid);
            if (ack != null && !identityConflicted(nodeUuid)) {
                result.add(ack);
            }
        }
        return result;
    }

    @Override
    public synchronized List<MassDbLicenseLeaderReconciler.AuthenticatedKeysetAck>
            prepareKeyset(MassDbLicenseKeysetControlCore.RecoveryPlan plan) {
        requireAvailable();
        CommandState state = ensureCommand(MassDbLicenseFeRoleProtocol.Command.keyset(plan));
        List<MassDbLicenseLeaderReconciler.AuthenticatedKeysetAck> result = new ArrayList<>();
        for (String nodeUuid : plan.requiredAckNodeUuids) {
            MassDbLicenseLeaderReconciler.AuthenticatedKeysetAck ack =
                    state.keysetAcks.get(nodeUuid);
            if (ack != null && !identityConflicted(nodeUuid)) {
                result.add(ack);
            }
        }
        return result;
    }

    @Override
    public synchronized void publishAuthoritativeDecision(String operationId,
            MassDbLicenseState.OperationView operation) {
        if (operation == null || !operation.terminal
                || !operationId.equals(operation.operationId)) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "Leader终态决议无效");
        }
        commands.remove(operationId);
    }

    /** Called only after the servlet container has chain-verified the peer certificate. */
    public synchronized MassDbLicenseFeRoleProtocol.ExchangeResponse exchange(
            MassDbLicenseSpiffeIdentity.Identity identity,
            MassDbLicenseFeRoleProtocol.ExchangeRequest request, long now) {
        requireAvailable();
        if (now <= 0) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "Leader接收时间无效");
        }
        MassDbLicenseState snapshot = manager.snapshot();
        String deploymentUuid = snapshot.getLicenseControlDeploymentUuid();
        if (!snapshot.isInitialized() || deploymentUuid == null) {
            fail("MASSDB_LICENSE_NOT_INITIALIZED", "License bootstrap尚未完成");
        }
        validateIdentity(identity, request, deploymentUuid);
        validateStatus(request.status);
        SessionObservation observation = observeSession(identity.nodeUuid,
                request.processInstanceUuid, request.status, now);

        MassDbLicenseIngressInventory.IngressNode node = findNode(snapshot, identity.nodeUuid);
        if (observation.conflicted) {
            clearAcksForNode(identity.nodeUuid);
            snapshot = persistIdentityConflictIfDue(identity.nodeUuid, true, now, snapshot);
        } else if (node != null && node.isAuthoritativeIdentityConflict()
                && clearEligible(node, observation.uniqueSince, now)) {
            snapshot = persistIdentityConflictIfDue(identity.nodeUuid, false, now, snapshot);
        }
        node = findNode(snapshot, identity.nodeUuid);
        boolean authoritativeConflict = node != null
                && node.isAuthoritativeIdentityConflict();
        boolean identityBlocked = observation.conflicted || authoritativeConflict
                || request.status.identityConflict;
        if (identityBlocked) {
            clearAcksForNode(identity.nodeUuid);
        }
        snapshot = persistRoleStatusIfDue(identity.nodeUuid, request.status,
                identityBlocked, now, snapshot);
        snapshot = persistClockFloorIfDue(now, snapshot);

        if (!identityBlocked) {
            acceptActivationAck(identity.nodeUuid, request.activationAck);
            acceptLicenseAck(identity.nodeUuid, request.licenseAck);
            acceptControlAck(identity.nodeUuid, request.controlAck);
        }

        List<MassDbLicenseFeRoleProtocol.Decision> decisions = new ArrayList<>();
        appendTerminalDecision(snapshot, request.status.activationPendingOperationId, decisions);
        appendTerminalDecision(snapshot, request.status.licensePendingOperationId, decisions);
        appendTerminalDecision(snapshot, request.status.controlPendingOperationId, decisions);

        List<MassDbLicenseFeRoleProtocol.Command> responseCommands = new ArrayList<>();
        MassDbLicenseState.Mutation mutation = snapshot.getMutation();
        if (!identityBlocked && mutation != null) {
            CommandState command = commands.get(mutation.getOperationId());
            if (command != null && command.command.requiredAckNodeUuids.contains(identity.nodeUuid)) {
                responseCommands.add(command.command.copy());
            }
        }
        MassDbLicenseFeRoleProtocol.IdentityConflict identityConflict =
                identityConflictCommand(request.status, snapshot, identity.nodeUuid);
        MassDbLicenseFeRoleProtocol.ControlPlaneSync controlPlaneSync =
                MassDbLicenseFeRoleProtocol.ControlPlaneSync.from(
                        snapshot, request.status.reportSequence, now);
        return new MassDbLicenseFeRoleProtocol.ExchangeResponse(
                deploymentUuid, now, identityConflict, controlPlaneSync,
                responseCommands, decisions);
    }

    synchronized SessionView findSession(String nodeUuid) {
        Map<String, SessionView> bucket = sessions.get(nodeUuid);
        if (bucket == null || bucket.size() != 1) {
            return null;
        }
        return bucket.values().iterator().next();
    }

    private SessionObservation observeSession(String nodeUuid, String processInstanceUuid,
            MassDbLicenseFeRoleProtocol.RoleStatus status, long now) {
        pruneExpiredSessions(now);
        Map<String, SessionView> bucket = sessions.computeIfAbsent(
                nodeUuid, ignored -> new LinkedHashMap<>());
        SessionView previous = bucket.get(processInstanceUuid);
        if (previous != null && now < previous.lastSeenAt) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "FE角色会话时间发生回退");
        }
        if (previous != null && status.reportSequence <= previous.reportSequence) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "FE角色report sequence未递增");
        }
        long uniqueSince = previous == null ? now : previous.uniqueSince;
        SessionView current = new SessionView(nodeUuid, processInstanceUuid, now, uniqueSince,
                status.reportSequence,
                status.activeLicenseSha256, status.activeLicenseExpiresAt,
                status.enforcementEpoch, status.activationPendingOperationId,
                status.licensePendingOperationId, status.controlPendingOperationId);
        bucket.put(processInstanceUuid, current);
        boolean conflicted = bucket.size() > 1;
        if (conflicted) {
            for (SessionView session : bucket.values()) {
                session.uniqueSince = 0;
            }
            return new SessionObservation(true, 0);
        }
        if (current.uniqueSince == 0) {
            current.uniqueSince = now;
        }
        return new SessionObservation(false, current.uniqueSince);
    }

    private void pruneExpiredSessions(long now) {
        Iterator<Map.Entry<String, Map<String, SessionView>>> nodeIterator =
                sessions.entrySet().iterator();
        while (nodeIterator.hasNext()) {
            Map<String, SessionView> bucket = nodeIterator.next().getValue();
            Iterator<Map.Entry<String, SessionView>> sessionIterator =
                    bucket.entrySet().iterator();
            while (sessionIterator.hasNext()) {
                SessionView session = sessionIterator.next().getValue();
                if (now >= saturatedAdd(session.lastSeenAt,
                        MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS)) {
                    sessionIterator.remove();
                }
            }
            if (bucket.isEmpty()) {
                nodeIterator.remove();
            }
        }
    }

    private MassDbLicenseState persistIdentityConflictIfDue(String nodeUuid, boolean active,
            long now, MassDbLicenseState snapshot) {
        MassDbLicenseIngressInventory.IngressNode node = findNode(snapshot, nodeUuid);
        if (node == null) {
            return snapshot;
        }
        if (active && node.isAuthoritativeIdentityConflict()
                && now < saturatedAdd(node.getIdentityConflictLastObservedAt(),
                        MassDbLicenseState.DEFAULT_ROLE_STATUS_INTERVAL_SECONDS)) {
            return snapshot;
        }
        if (!active && !node.isAuthoritativeIdentityConflict()) {
            return snapshot;
        }
        return manager.transition(current -> current.recordIngressIdentityConflict(
                nodeUuid, active, now));
    }

    private MassDbLicenseState persistRoleStatusIfDue(String nodeUuid,
            MassDbLicenseFeRoleProtocol.RoleStatus status,
            boolean identityBlocked, long now, MassDbLicenseState snapshot) {
        MassDbLicenseIngressInventory.IngressNode node = findNode(snapshot, nodeUuid);
        if (node == null) {
            // Valid mTLS roles may connect before configured inventory is committed.
            return snapshot;
        }
        boolean reportedConflict = identityBlocked || status.identityConflict;
        boolean guardReady = status.guardReady && !reportedConflict;
        boolean criticalChange = node.getLastRoleStatusObservedAt() == 0
                || node.isReportedLicenseQueryAllowed() != status.licenseQueryAllowed
                || !equalsText(node.getReportedLocalStateErrorCode(),
                        status.localStateErrorCode)
                || !equalsText(node.getReportedActiveLicenseSha256(),
                        status.activeLicenseSha256)
                || node.getReportedClockState() != status.clockState
                || node.getReportedVerificationState() != status.verificationState
                || !equalsText(node.getReportedControlPlaneFreshness(),
                        status.controlPlaneFreshness);
        long renewThreshold = saturatedAdd(now,
                MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS
                        - MassDbLicenseState.DEFAULT_ROLE_STATUS_INTERVAL_SECONDS);
        if (node.getLiveLeaseExpiresAt() > renewThreshold
                && node.isGuardReady() == guardReady
                && node.isReportedIdentityConflict() == reportedConflict
                && !criticalChange) {
            return snapshot;
        }
        long leaseExpiresAt = saturatedAdd(
                now, MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS);
        return manager.transition(current -> current.recordIngressRoleStatus(
                nodeUuid, guardReady, reportedConflict, status, now, leaseExpiresAt));
    }

    private MassDbLicenseState persistClockFloorIfDue(
            long now, MassDbLicenseState snapshot) {
        long current = snapshot.getMaxSeenWallClock();
        if (now <= current || current != 0 && now - current
                < MassDbLicenseState.DEFAULT_CLOCK_PERSISTENCE_SECONDS) {
            return snapshot;
        }
        return manager.transition(state -> state.advanceMaxSeenWallClock(now));
    }

    private MassDbLicenseFeRoleProtocol.IdentityConflict identityConflictCommand(
            MassDbLicenseFeRoleProtocol.RoleStatus status,
            MassDbLicenseState snapshot, String nodeUuid) {
        MassDbLicenseIngressInventory.IngressNode node = findNode(snapshot, nodeUuid);
        if (node == null || node.getIdentityConflictRevision() <= 0) {
            return null;
        }
        boolean active = node.isAuthoritativeIdentityConflict();
        if (status.identityConflict == active
                && status.identityConflictRevision == node.getIdentityConflictRevision()) {
            return null;
        }
        long clearEligibleAt = saturatedAdd(node.getIdentityConflictLastObservedAt(),
                MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS);
        return new MassDbLicenseFeRoleProtocol.IdentityConflict(active,
                node.getIdentityConflictRevision(), snapshot.getLicenseControlDeploymentUuid(),
                node.getIdentityConflictDetectedAt(), node.getIdentityConflictLastObservedAt(),
                clearEligibleAt, node.getIdentityConflictResolvedAt());
    }

    private boolean identityConflicted(String nodeUuid) {
        Map<String, SessionView> bucket = sessions.get(nodeUuid);
        if (bucket != null && bucket.size() > 1) {
            return true;
        }
        MassDbLicenseIngressInventory.IngressNode node =
                findNode(manager.snapshot(), nodeUuid);
        return node != null && node.isIdentityConflicted();
    }

    private static boolean clearEligible(MassDbLicenseIngressInventory.IngressNode node,
            long uniqueSince, long now) {
        return uniqueSince > 0
                && now >= saturatedAdd(uniqueSince,
                        MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS)
                && now >= saturatedAdd(node.getIdentityConflictLastObservedAt(),
                        MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS);
    }

    private static MassDbLicenseIngressInventory.IngressNode findNode(
            MassDbLicenseState snapshot, String nodeUuid) {
        return snapshot.getIngressInventory().getNodes().get(nodeUuid);
    }

    private void clearAcksForNode(String nodeUuid) {
        for (CommandState command : commands.values()) {
            command.activationAcks.remove(nodeUuid);
            command.licenseAcks.remove(nodeUuid);
            command.keysetAcks.remove(nodeUuid);
        }
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private CommandState ensureCommand(MassDbLicenseFeRoleProtocol.Command candidate) {
        if (candidate.operationId == null || !candidate.requiredAckNodeUuids.isEmpty()
                && candidate.requiredAckNodeUuids.contains(null)) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "Leader角色计划无效");
        }
        CommandState existing = commands.get(candidate.operationId);
        if (existing != null) {
            if (!existing.command.samePayload(candidate)) {
                fail("MASSDB_LICENSE_ROLE_COMMAND_CONFLICT", "operation的角色命令发生冲突");
            }
            return existing;
        }
        commands.clear();
        CommandState created = new CommandState(candidate.copy());
        commands.put(candidate.operationId, created);
        return created;
    }

    private void acceptActivationAck(String authenticatedNodeUuid,
            MassDbLicenseFeRoleProtocol.ActivationAck wire) {
        if (wire == null) {
            return;
        }
        if (!authenticatedNodeUuid.equals(wire.nodeUuid)
                || wire.operationId == null || !validOperationId(wire.operationId)
                || !isSha256(wire.activeLicenseSha256)
                || !isSha256(wire.pendingSnapshotSha256)
                || wire.targetEnforcementEpoch <= 0) {
            fail("MASSDB_LICENSE_ROLE_ACK_INVALID", "activation ACK基本字段无效");
        }
        CommandState state = commands.get(wire.operationId);
        if (state == null) {
            // A new Leader may receive the durable ACK before its first reconciler pass.
            return;
        }
        if (!MassDbLicenseFeRoleProtocol.COMMAND_ENFORCEMENT.equals(state.command.type)
                || !state.command.requiredAckNodeUuids.contains(authenticatedNodeUuid)
                || state.command.targetEnforcementEpoch == null
                || state.command.targetEnforcementEpoch != wire.targetEnforcementEpoch
                || !equalsText(state.command.contentSha256, wire.activeLicenseSha256)
                || !isSha256(wire.pendingSnapshotSha256)) {
            fail("MASSDB_LICENSE_ROLE_ACK_INVALID", "activation ACK与mTLS身份或命令不匹配");
        }
        MassDbLicenseState.ActivationAckEvidence evidence =
                new MassDbLicenseState.ActivationAckEvidence(
                        authenticatedNodeUuid, wire.operationId,
                        wire.targetEnforcementEpoch, wire.activeLicenseSha256,
                        wire.pendingSnapshotSha256);
        state.activationAcks.put(authenticatedNodeUuid,
                new MassDbLicenseLeaderReconciler.AuthenticatedActivationAck(
                        authenticatedNodeUuid, evidence));
    }

    private void acceptLicenseAck(String authenticatedNodeUuid,
            MassDbLicenseFeRoleProtocol.LicenseAck wire) {
        if (wire == null) {
            return;
        }
        if (!authenticatedNodeUuid.equals(wire.nodeUuid)
                || wire.operationId == null || !validOperationId(wire.operationId)
                || !isSha256(wire.contentSha256)
                || !isSha256(wire.pendingSnapshotSha256)
                || wire.licenseExpiresAt <= 0 || wire.enforcementEpoch < 0) {
            fail("MASSDB_LICENSE_ROLE_ACK_INVALID", "NORMAL ACK基本字段无效");
        }
        CommandState state = commands.get(wire.operationId);
        if (state == null) {
            // The next poll resends this durable ACK after the journal recreates the command.
            return;
        }
        if (!MassDbLicenseFeRoleProtocol.COMMAND_NORMAL.equals(state.command.type)
                || !state.command.requiredAckNodeUuids.contains(authenticatedNodeUuid)
                || state.command.licenseExpiresAt == null
                || state.command.licenseExpiresAt != wire.licenseExpiresAt
                || state.command.currentEnforcementEpoch != wire.enforcementEpoch
                || !equalsText(state.command.contentSha256, wire.contentSha256)
                || !isSha256(wire.pendingSnapshotSha256)) {
            fail("MASSDB_LICENSE_ROLE_ACK_INVALID", "NORMAL ACK与mTLS身份或命令不匹配");
        }
        MassDbLicenseLeaderReconciler.LicenseAckEvidence evidence =
                new MassDbLicenseLeaderReconciler.LicenseAckEvidence(
                        authenticatedNodeUuid, wire.operationId, wire.contentSha256,
                        wire.licenseExpiresAt, wire.enforcementEpoch,
                        wire.pendingSnapshotSha256);
        state.licenseAcks.put(authenticatedNodeUuid,
                new MassDbLicenseLeaderReconciler.AuthenticatedLicenseAck(
                        authenticatedNodeUuid, evidence));
    }

    private void acceptControlAck(String authenticatedNodeUuid,
            MassDbLicenseFeRoleProtocol.ControlAck wire) {
        if (wire == null) {
            return;
        }
        boolean licenseAbsent = wire.licenseSha256 == null && wire.licenseExpiresAt == 0;
        if (!authenticatedNodeUuid.equals(wire.nodeUuid)
                || wire.operationId == null || !validOperationId(wire.operationId)
                || !isSha256(wire.keysetSha256) || wire.keysetVersion <= 0
                || !isSha256(wire.pendingSnapshotSha256)
                || !licenseAbsent && (!isSha256(wire.licenseSha256)
                        || wire.licenseExpiresAt <= 0)) {
            fail("MASSDB_LICENSE_ROLE_ACK_INVALID", "keyset ACK基本字段无效");
        }
        CommandState state = commands.get(wire.operationId);
        if (state == null) {
            return;
        }
        boolean bundle = MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE
                .name().equals(state.command.keysetKind);
        if (!MassDbLicenseFeRoleProtocol.COMMAND_KEYSET.equals(state.command.type)
                || !state.command.requiredAckNodeUuids.contains(authenticatedNodeUuid)
                || state.command.keysetVersion == null
                || state.command.keysetVersion != wire.keysetVersion
                || !equalsText(state.command.keysetSha256, wire.keysetSha256)
                || bundle && (state.command.licenseExpiresAt == null
                        || state.command.licenseExpiresAt != wire.licenseExpiresAt
                        || !equalsText(state.command.licenseSha256, wire.licenseSha256))
                || !bundle && !licenseAbsent) {
            fail("MASSDB_LICENSE_ROLE_ACK_INVALID", "keyset ACK与mTLS身份或命令不匹配");
        }
        MassDbLicenseState.KeysetAckEvidence evidence =
                new MassDbLicenseState.KeysetAckEvidence(authenticatedNodeUuid,
                        wire.operationId, wire.keysetSha256, wire.keysetVersion,
                        wire.licenseSha256, wire.licenseExpiresAt,
                        wire.pendingSnapshotSha256);
        state.keysetAcks.put(authenticatedNodeUuid,
                new MassDbLicenseLeaderReconciler.AuthenticatedKeysetAck(
                        authenticatedNodeUuid, evidence));
    }

    private static void validateIdentity(MassDbLicenseSpiffeIdentity.Identity identity,
            MassDbLicenseFeRoleProtocol.ExchangeRequest request, String deploymentUuid) {
        if (identity == null || request == null
                || request.protocolVersion != MassDbLicenseFeRoleProtocol.VERSION
                || request.status == null
                || !"massdb-sql".equals(identity.component)
                || !"fe".equals(identity.role)
                || !deploymentUuid.equals(identity.deploymentUuid)
                || !deploymentUuid.equals(request.deploymentUuid)
                || !identity.nodeUuid.equals(request.nodeUuid)) {
            fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                    "FE角色请求与mTLS URI SAN、部署或协议不匹配");
        }
        if (!isCanonicalVersion4Uuid(request.processInstanceUuid)) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "FE进程实例UUID格式无效");
        }
    }

    private static void validateStatus(MassDbLicenseFeRoleProtocol.RoleStatus status) {
        if (status.reportSequence <= 0 || status.observedWallClock <= 0
                || status.enforcementEpoch < 0
                || status.identityConflictRevision < 0
                || status.localStateErrorCode != null
                        && !status.localStateErrorCode.matches(
                                "MASSDB_LICENSE_[A-Z0-9_]{1,96}")
                || status.clockState == null || status.verificationState == null
                || status.enforcementMode == null
                || status.activeLicenseSha256 != null && !isSha256(status.activeLicenseSha256)
                || (status.activeLicenseSha256 == null) != (status.activeLicenseExpiresAt == null)
                || status.activeLicenseExpiresAt != null && status.activeLicenseExpiresAt <= 0
                || (status.keysetVersion == 0) != (status.keysetSha256 == null)
                || status.keysetSha256 != null && !isSha256(status.keysetSha256)
                || !validOperationId(status.activationPendingOperationId)
                || !validOperationId(status.licensePendingOperationId)
                || !validOperationId(status.controlPendingOperationId)
                || status.activationPendingOperationId != null
                        && (status.licensePendingOperationId != null
                                || status.controlPendingOperationId != null)
                || status.licensePendingOperationId != null
                        && status.controlPendingOperationId != null) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "FE角色状态无效");
        }
        if (status.identityConflict && (status.guardReady || status.licenseQueryAllowed
                || !"MASSDB_LICENSE_DUPLICATE_NODE_UUID".equals(
                        status.localStateErrorCode))
                || !status.identityConflict && "MASSDB_LICENSE_DUPLICATE_NODE_UUID".equals(
                        status.localStateErrorCode)) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "重复node UUID状态必须失败关闭");
        }
        if (status.clockState == MassDbLicenseFeRoleProtocol.ClockState.UNINITIALIZED) {
            if (status.effectiveNow != null || status.remainingSecondsAtCheck != null
                    || status.licenseExpiredUnderEffectiveNow != null
                    || status.clockRecoveryEpoch != 0 || status.recoverySequence != 0) {
                fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "未初始化时钟携带权威时间");
            }
        } else if (status.effectiveNow == null || status.effectiveNow <= 0
                || status.licenseExpiredUnderEffectiveNow == null) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "已初始化时钟缺少权威时间");
        } else if (status.activeLicenseSha256 == null) {
            if (status.remainingSecondsAtCheck != null
                    || status.licenseExpiredUnderEffectiveNow) {
                fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "无active的时间裁决非法");
            }
        } else {
            long expectedRemaining = status.effectiveNow < status.activeLicenseExpiresAt
                    ? status.activeLicenseExpiresAt - status.effectiveNow : 0;
            if (status.remainingSecondsAtCheck == null
                    || status.remainingSecondsAtCheck != expectedRemaining
                    || status.licenseExpiredUnderEffectiveNow
                            != (status.effectiveNow >= status.activeLicenseExpiresAt)) {
                fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "License权威剩余时间不一致");
            }
        }
        if (status.licenseExpiredAtObservedWallClock
                != (status.activeLicenseSha256 != null
                        && status.observedWallClock >= status.activeLicenseExpiresAt)) {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "License墙钟到期诊断不一致");
        }
        if ("MISSING".equals(status.controlPlaneFreshness)) {
            if (status.lastAuthenticatedControlPlaneAt != 0
                    || status.controlPlaneRevision != 0
                    || status.controlPlaneStalenessRemainingSeconds != null
                    || status.enforcementMode
                            != MassDbLicenseState.EnforcementMode.UNINITIALIZED) {
                fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "缺少控制面却携带认证字段");
            }
        } else if ("FRESH".equals(status.controlPlaneFreshness)) {
            if (status.lastAuthenticatedControlPlaneAt <= 0
                    || status.controlPlaneRevision <= 0
                    || status.controlPlaneStalenessRemainingSeconds == null
                    || status.controlPlaneStalenessRemainingSeconds < 0
                    || status.controlPlaneStalenessRemainingSeconds
                            > MassDbLicenseState.DEFAULT_CONTROL_PLANE_STALENESS_SECONDS
                    || status.enforcementMode
                            == MassDbLicenseState.EnforcementMode.UNINITIALIZED) {
                fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "新鲜控制面状态无效");
            }
        } else if ("STALE".equals(status.controlPlaneFreshness)) {
            if (status.lastAuthenticatedControlPlaneAt <= 0
                    || status.controlPlaneRevision <= 0
                    || status.controlPlaneStalenessRemainingSeconds == null
                    || status.controlPlaneStalenessRemainingSeconds != 0
                    || status.enforcementMode
                            == MassDbLicenseState.EnforcementMode.UNINITIALIZED) {
                fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "陈旧控制面状态无效");
            }
        } else {
            fail("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", "控制面新鲜度枚举无效");
        }
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

    private static void appendTerminalDecision(MassDbLicenseState snapshot,
            String operationId, List<MassDbLicenseFeRoleProtocol.Decision> result) {
        if (operationId == null) {
            return;
        }
        MassDbLicenseState.OperationView operation = snapshot.findOperation(operationId);
        if (operation != null && operation.terminal) {
            result.add(MassDbLicenseFeRoleProtocol.Decision.from(operation));
        }
    }

    private void requireAvailable() {
        if (!available) {
            fail("MASSDB_LICENSE_ROLE_TRANSPORT_UNAVAILABLE", "FE角色mTLS通道未启用");
        }
    }

    private static boolean validOperationId(String value) {
        if (value == null) {
            return true;
        }
        if (value.isEmpty() || value.length() > MassDbLicenseState.MAX_IDEMPOTENCY_KEY_BYTES) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (item < 0x21 || item > 0x7e) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSha256(String value) {
        return value != null && value.matches("[0-9a-f]{64}");
    }

    private static boolean equalsText(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    private static final class CommandState {
        private final MassDbLicenseFeRoleProtocol.Command command;
        private final Map<String, MassDbLicenseLeaderReconciler.AuthenticatedActivationAck>
                activationAcks = new LinkedHashMap<>();
        private final Map<String, MassDbLicenseLeaderReconciler.AuthenticatedLicenseAck>
                licenseAcks = new LinkedHashMap<>();
        private final Map<String, MassDbLicenseLeaderReconciler.AuthenticatedKeysetAck>
                keysetAcks = new LinkedHashMap<>();

        private CommandState(MassDbLicenseFeRoleProtocol.Command command) {
            this.command = command;
        }
    }

    static final class SessionView {
        final String nodeUuid;
        final String processInstanceUuid;
        final long lastSeenAt;
        long uniqueSince;
        final long reportSequence;
        final String activeLicenseSha256;
        final Long activeLicenseExpiresAt;
        final long enforcementEpoch;
        final String activationPendingOperationId;
        final String licensePendingOperationId;
        final String controlPendingOperationId;

        private SessionView(String nodeUuid, String processInstanceUuid,
                long lastSeenAt, long uniqueSince, long reportSequence,
                String activeLicenseSha256,
                Long activeLicenseExpiresAt, long enforcementEpoch,
                String activationPendingOperationId, String licensePendingOperationId,
                String controlPendingOperationId) {
            this.nodeUuid = nodeUuid;
            this.processInstanceUuid = processInstanceUuid;
            this.lastSeenAt = lastSeenAt;
            this.uniqueSince = uniqueSince;
            this.reportSequence = reportSequence;
            this.activeLicenseSha256 = activeLicenseSha256;
            this.activeLicenseExpiresAt = activeLicenseExpiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.activationPendingOperationId = activationPendingOperationId;
            this.licensePendingOperationId = licensePendingOperationId;
            this.controlPendingOperationId = controlPendingOperationId;
        }
    }

    private static final class SessionObservation {
        private final boolean conflicted;
        private final long uniqueSince;

        private SessionObservation(boolean conflicted, long uniqueSince) {
            this.conflicted = conflicted;
            this.uniqueSince = uniqueSince;
        }
    }
}
