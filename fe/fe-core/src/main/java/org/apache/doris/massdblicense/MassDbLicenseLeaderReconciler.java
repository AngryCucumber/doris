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

import org.apache.doris.catalog.Env;
import org.apache.doris.common.util.MasterDaemon;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * FE-master lifecycle reconciler for durable License operations.
 *
 * <p>A recovery failure or deadline is journaled before role dispatch stops. A valid enforcement
 * plan is already represented by the durable PREPARED journal state; only then may the reconciler
 * call a component-internal trusted transport. ACK fields alone are never trusted: every ACK is
 * paired with the node UUID authenticated by the internal connection.</p>
 */
public final class MassDbLicenseLeaderReconciler extends MasterDaemon {
    private static final Logger LOG = LogManager.getLogger(MassDbLicenseLeaderReconciler.class);
    private static final long DEFAULT_INTERVAL_MILLIS = 1_000L;

    public enum Outcome {
        IDLE,
        WAITING_FOR_SUPPORTED_OPERATION,
        WAITING_FOR_ROLE_TRANSPORT,
        WAITING_FOR_ACKS,
        UNTRUSTED_ACK,
        COMMITTED,
        TERMINAL_PERSISTED,
        CLOCK_FLOOR_PERSISTED,
        STATE_CHANGED
    }

    /** Implementations must bind authenticatedNodeUuid from component-internal mTLS/RPC identity. */
    public interface TrustedRoleTransport {
        boolean isAvailable();

        List<AuthenticatedActivationAck> prepareEnforcement(
                MassDbLicenseEnforcementCore.RecoveryPlan plan) throws Exception;

        List<AuthenticatedLicenseAck> prepareNormal(
                MassDbLicenseImportCore.RecoveryPlan plan) throws Exception;

        default List<AuthenticatedKeysetAck> prepareKeyset(
                MassDbLicenseKeysetControlCore.RecoveryPlan plan) throws Exception {
            return Collections.emptyList();
        }

        void publishAuthoritativeDecision(String operationId,
                MassDbLicenseState.OperationView operation) throws Exception;
    }

    public static final class AuthenticatedActivationAck {
        public final String authenticatedNodeUuid;
        public final MassDbLicenseState.ActivationAckEvidence evidence;

        public AuthenticatedActivationAck(String authenticatedNodeUuid,
                MassDbLicenseState.ActivationAckEvidence evidence) {
            this.authenticatedNodeUuid = Objects.requireNonNull(
                    authenticatedNodeUuid, "authenticatedNodeUuid");
            this.evidence = Objects.requireNonNull(evidence, "evidence");
        }
    }

    /** NORMAL ACK is trusted only after the role persisted and read back license.pending. */
    public static final class LicenseAckEvidence {
        public final String nodeUuid;
        public final String operationId;
        public final String contentSha256;
        public final long licenseExpiresAt;
        public final long enforcementEpoch;
        public final String pendingSnapshotSha256;

        public LicenseAckEvidence(String nodeUuid, String operationId,
                String contentSha256, long licenseExpiresAt, long enforcementEpoch,
                String pendingSnapshotSha256) {
            this.nodeUuid = Objects.requireNonNull(nodeUuid, "nodeUuid");
            this.operationId = Objects.requireNonNull(operationId, "operationId");
            this.contentSha256 = Objects.requireNonNull(contentSha256, "contentSha256");
            this.licenseExpiresAt = licenseExpiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.pendingSnapshotSha256 = Objects.requireNonNull(
                    pendingSnapshotSha256, "pendingSnapshotSha256");
        }
    }

    /** authenticatedNodeUuid must come from component-internal mTLS/RPC identity. */
    public static final class AuthenticatedLicenseAck {
        public final String authenticatedNodeUuid;
        public final LicenseAckEvidence evidence;

        public AuthenticatedLicenseAck(String authenticatedNodeUuid,
                LicenseAckEvidence evidence) {
            this.authenticatedNodeUuid = Objects.requireNonNull(
                    authenticatedNodeUuid, "authenticatedNodeUuid");
            this.evidence = Objects.requireNonNull(evidence, "evidence");
        }
    }

    /** authenticatedNodeUuid must come from component-internal mTLS/RPC identity. */
    public static final class AuthenticatedKeysetAck {
        public final String authenticatedNodeUuid;
        public final MassDbLicenseState.KeysetAckEvidence evidence;

        public AuthenticatedKeysetAck(String authenticatedNodeUuid,
                MassDbLicenseState.KeysetAckEvidence evidence) {
            this.authenticatedNodeUuid = Objects.requireNonNull(
                    authenticatedNodeUuid, "authenticatedNodeUuid");
            this.evidence = Objects.requireNonNull(evidence, "evidence");
        }
    }

    interface NormalOperationCoordinator {
        MassDbLicenseImportCore.RedriveResult recover(
                MassDbLicenseState state, String operationId, long effectiveNow);

        MassDbLicenseState commit(MassDbLicenseState state, String operationId,
                List<String> ackedNodeUuids, long effectiveNow);
    }

    private interface StateTransition {
        MassDbLicenseState apply(MassDbLicenseState state);
    }

    private static final TrustedRoleTransport UNAVAILABLE_TRANSPORT =
            new TrustedRoleTransport() {
                @Override
                public boolean isAvailable() {
                    return false;
                }

                @Override
                public List<AuthenticatedActivationAck> prepareEnforcement(
                        MassDbLicenseEnforcementCore.RecoveryPlan plan) {
                    return Collections.emptyList();
                }

                @Override
                public List<AuthenticatedLicenseAck> prepareNormal(
                        MassDbLicenseImportCore.RecoveryPlan plan) {
                    return Collections.emptyList();
                }

                @Override
                public void publishAuthoritativeDecision(String operationId,
                        MassDbLicenseState.OperationView operation) {
                    // A role with pending state queries the authoritative operation after restart.
                }
            };

    private final MassDbLicenseManager manager;
    private final MassDbLicenseEnforcementCore enforcementCore;
    private final AtomicReference<TrustedRoleTransport> transport =
            new AtomicReference<>(UNAVAILABLE_TRANSPORT);
    private final AtomicReference<NormalOperationCoordinator> normalCoordinator =
            new AtomicReference<>();
    private final AtomicReference<NormalOperationCoordinator> controlledCoordinator =
            new AtomicReference<>();
    private final AtomicReference<MassDbLicenseClockRecoveryCore> clockRecoveryCore =
            new AtomicReference<>();
    private final AtomicReference<MassDbLicenseKeysetControlCore> keysetControlCore =
            new AtomicReference<>();

    public MassDbLicenseLeaderReconciler(MassDbLicenseManager manager) {
        this(manager, new MassDbLicenseEnforcementCore(), DEFAULT_INTERVAL_MILLIS);
    }

    MassDbLicenseLeaderReconciler(MassDbLicenseManager manager,
            MassDbLicenseEnforcementCore enforcementCore, long intervalMillis) {
        super("massdb-license-leader-reconciler", intervalMillis);
        this.manager = Objects.requireNonNull(manager, "manager");
        this.enforcementCore = Objects.requireNonNull(enforcementCore, "enforcementCore");
    }

    public void setTrustedRoleTransport(TrustedRoleTransport trustedTransport) {
        transport.set(trustedTransport == null ? UNAVAILABLE_TRANSPORT : trustedTransport);
    }

    /** Installed only after the component root trust configuration has been loaded. */
    public void setNormalImportCore(MassDbLicenseImportCore importCore) {
        normalCoordinator.set(importCore == null ? null : new NormalOperationCoordinator() {
            @Override
            public MassDbLicenseImportCore.RedriveResult recover(
                    MassDbLicenseState state, String operationId, long effectiveNow) {
                return importCore.recoverNormal(state, operationId, effectiveNow);
            }

            @Override
            public MassDbLicenseState commit(MassDbLicenseState state, String operationId,
                    List<String> ackedNodeUuids, long effectiveNow) {
                return importCore.commitNormal(
                        state, operationId, ackedNodeUuids, effectiveNow).state;
            }
        });
    }

    public void setControlledImportCore(MassDbLicenseCorrectionCore correctionCore) {
        controlledCoordinator.set(correctionCore == null ? null
                : new NormalOperationCoordinator() {
                    @Override
                    public MassDbLicenseImportCore.RedriveResult recover(
                            MassDbLicenseState state, String operationId,
                            long effectiveNow) {
                        return correctionCore.recoverForDistribution(
                                state, operationId, effectiveNow);
                    }

                    @Override
                    public MassDbLicenseState commit(MassDbLicenseState state,
                            String operationId, List<String> ackedNodeUuids,
                            long effectiveNow) {
                        return correctionCore.commitDistributed(
                                state, operationId, ackedNodeUuids, effectiveNow);
                    }
                });
    }

    public void setClockRecoveryCore(MassDbLicenseClockRecoveryCore core) {
        clockRecoveryCore.set(core);
    }

    public void setKeysetControlCore(MassDbLicenseKeysetControlCore core) {
        keysetControlCore.set(core);
    }

    void setNormalOperationCoordinator(NormalOperationCoordinator coordinator) {
        normalCoordinator.set(coordinator);
    }

    @Override
    protected void runAfterCatalogReady() {
        if (!Env.getServingEnv().isMaster()) {
            return;
        }
        try {
            reconcileOnce(Instant.now().getEpochSecond());
        } catch (Throwable error) {
            LOG.warn("MassDB License Leader reconcile失败，保持prepared并等待下一轮", error);
        }
    }

    public Outcome reconcileOnce(long effectiveNow) {
        MassDbLicenseState initial = manager.snapshot();
        boolean clockFloorPersisted = shouldPersistClockFloor(initial, effectiveNow);
        if (clockFloorPersisted) {
            initial = manager.transition(current -> current.advanceMaxSeenWallClock(effectiveNow));
        }
        MassDbLicenseState.Mutation mutation = initial.getMutation();
        if (mutation == null) {
            return clockFloorPersisted ? Outcome.CLOCK_FLOOR_PERSISTED : Outcome.IDLE;
        }
        String operationId = mutation.getOperationId();
        if (mutation.getKind() == MassDbLicenseState.MutationKind.LICENSE) {
            NormalOperationCoordinator coordinator = mutation.getIntent()
                    == MassDbLicenseState.ImportIntent.NORMAL
                    ? normalCoordinator.get() : controlledCoordinator.get();
            return reconcileLicense(initial, operationId, effectiveNow, coordinator);
        }
        if (mutation.getKind() == MassDbLicenseState.MutationKind.CLOCK_RECOVERY) {
            MassDbLicenseClockRecoveryCore core = clockRecoveryCore.get();
            if (core == null) {
                return Outcome.WAITING_FOR_SUPPORTED_OPERATION;
            }
            return reconcileImmediate(operationId, effectiveNow,
                    current -> core.recover(current, operationId, effectiveNow).state);
        }
        if (mutation.getKind() == MassDbLicenseState.MutationKind.ADDITIVE_KEYSET
                || mutation.getKind() == MassDbLicenseState.MutationKind.RESTRICTIVE_KEYSET
                || mutation.getKind()
                        == MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE) {
            MassDbLicenseKeysetControlCore core = keysetControlCore.get();
            if (core == null) {
                return Outcome.WAITING_FOR_SUPPORTED_OPERATION;
            }
            return reconcileKeyset(initial, operationId, effectiveNow, core);
        }
        if (mutation.getKind() != MassDbLicenseState.MutationKind.ENFORCEMENT) {
            MassDbLicenseState recovered = initial.recoverOrExpireMutation(effectiveNow);
            MassDbLicenseState.OperationView recoveredView = recovered.findOperation(operationId);
            if (recoveredView != null && recoveredView.terminal) {
                return persistTerminal(operationId, effectiveNow);
            }
            return Outcome.WAITING_FOR_SUPPORTED_OPERATION;
        }

        MassDbLicenseEnforcementCore.RedriveResult redrive =
                enforcementCore.recover(initial, operationId, effectiveNow);
        if (redrive.terminal) {
            return persistTerminal(operationId, effectiveNow);
        }
        TrustedRoleTransport trustedTransport = transport.get();
        if (!trustedTransport.isAvailable()) {
            return Outcome.WAITING_FOR_ROLE_TRANSPORT;
        }

        List<AuthenticatedActivationAck> authenticated;
        try {
            authenticated = trustedTransport.prepareEnforcement(redrive.plan);
        } catch (Exception error) {
            LOG.warn("MassDB License角色分发暂时不可用，operation={}", operationId, error);
            return Outcome.WAITING_FOR_ROLE_TRANSPORT;
        }
        AckValidation validation = validateAcks(redrive.plan, authenticated);
        if (validation.outcome != null) {
            return validation.outcome;
        }

        MassDbLicenseState committed;
        try {
            committed = manager.transition(current -> current.commitEnforcementActivation(
                    operationId, validation.evidence, effectiveNow));
        } catch (MassDbLicenseException error) {
            LOG.warn("MassDB License提交前状态已变化，operation={} code={}",
                    operationId, error.getCode());
            return persistFailureIfProved(operationId, effectiveNow);
        }
        publishDecision(trustedTransport, operationId, committed.findOperation(operationId));
        return Outcome.COMMITTED;
    }

    private static boolean shouldPersistClockFloor(MassDbLicenseState state, long effectiveNow) {
        if (!state.isInitialized() || effectiveNow <= 0
                || effectiveNow <= state.getMaxSeenWallClock()) {
            return false;
        }
        long current = state.getMaxSeenWallClock();
        return current == 0 || effectiveNow - current
                >= MassDbLicenseState.DEFAULT_CLOCK_PERSISTENCE_SECONDS;
    }

    private Outcome reconcileLicense(MassDbLicenseState initial,
            String operationId, long effectiveNow,
            NormalOperationCoordinator coordinator) {
        if (coordinator == null) {
            MassDbLicenseState recovered = initial.recoverOrExpireMutation(effectiveNow);
            MassDbLicenseState.OperationView view = recovered.findOperation(operationId);
            return view != null && view.terminal
                    ? persistTerminal(operationId, effectiveNow)
                    : Outcome.WAITING_FOR_SUPPORTED_OPERATION;
        }
        MassDbLicenseImportCore.RedriveResult redrive;
        try {
            redrive = coordinator.recover(initial, operationId, effectiveNow);
        } catch (MassDbLicenseException error) {
            LOG.warn("MassDB License NORMAL恢复时状态已变化，operation={} code={}",
                    operationId, error.getCode());
            return Outcome.STATE_CHANGED;
        }
        if (redrive.terminal) {
            return persistNormalTerminal(coordinator, operationId, effectiveNow);
        }
        TrustedRoleTransport trustedTransport = transport.get();
        if (!trustedTransport.isAvailable()) {
            return Outcome.WAITING_FOR_ROLE_TRANSPORT;
        }
        List<AuthenticatedLicenseAck> authenticated;
        try {
            authenticated = trustedTransport.prepareNormal(redrive.plan);
        } catch (Exception error) {
            LOG.warn("MassDB License NORMAL角色分发暂时不可用，operation={}",
                    operationId, error);
            return Outcome.WAITING_FOR_ROLE_TRANSPORT;
        }
        NormalAckValidation validation = validateNormalAcks(redrive.plan, authenticated);
        if (validation.outcome != null) {
            return validation.outcome;
        }
        MassDbLicenseState committed;
        try {
            committed = manager.transition(current -> coordinator.commit(
                    current, operationId, validation.nodeUuids, effectiveNow));
        } catch (MassDbLicenseException error) {
            LOG.warn("MassDB License NORMAL提交前状态已变化，operation={} code={}",
                    operationId, error.getCode());
            return persistNormalFailureIfProved(coordinator, operationId, effectiveNow);
        }
        publishDecision(trustedTransport, operationId, committed.findOperation(operationId));
        return Outcome.COMMITTED;
    }

    private Outcome reconcileKeyset(MassDbLicenseState initial, String operationId,
            long effectiveNow, MassDbLicenseKeysetControlCore core) {
        MassDbLicenseKeysetControlCore.RedriveResult redrive;
        try {
            redrive = core.recover(initial, operationId, effectiveNow);
        } catch (MassDbLicenseException error) {
            LOG.warn("MassDB License keyset恢复时状态已变化，operation={} code={}",
                    operationId, error.getCode());
            return Outcome.STATE_CHANGED;
        }
        if (redrive.terminal) {
            MassDbLicenseState terminal = manager.transition(current ->
                    core.recover(current, operationId, effectiveNow).state);
            MassDbLicenseState.OperationView view = terminal.findOperation(operationId);
            if (view == null || !view.terminal) {
                return Outcome.STATE_CHANGED;
            }
            publishDecision(transport.get(), operationId, view);
            return Outcome.TERMINAL_PERSISTED;
        }
        TrustedRoleTransport trustedTransport = transport.get();
        if (!trustedTransport.isAvailable()) {
            return Outcome.WAITING_FOR_ROLE_TRANSPORT;
        }
        List<AuthenticatedKeysetAck> authenticated;
        try {
            authenticated = trustedTransport.prepareKeyset(redrive.plan);
        } catch (Exception error) {
            LOG.warn("MassDB License keyset角色分发暂时不可用，operation={}",
                    operationId, error);
            return Outcome.WAITING_FOR_ROLE_TRANSPORT;
        }
        KeysetAckValidation validation = validateKeysetAcks(
                redrive.plan, authenticated);
        if (validation.outcome != null) {
            return validation.outcome;
        }
        MassDbLicenseState committed;
        try {
            committed = manager.transition(current -> core.commit(current, operationId,
                    validation.evidence, effectiveNow));
        } catch (MassDbLicenseException error) {
            LOG.warn("MassDB License keyset提交前状态已变化，operation={} code={}",
                    operationId, error.getCode());
            return Outcome.STATE_CHANGED;
        }
        publishDecision(trustedTransport, operationId, committed.findOperation(operationId));
        return Outcome.COMMITTED;
    }

    private Outcome reconcileImmediate(String operationId, long effectiveNow,
            StateTransition transition) {
        try {
            MassDbLicenseState terminal = manager.transition(transition::apply);
            MassDbLicenseState.OperationView view = terminal.findOperation(operationId);
            if (view == null || !view.terminal) {
                return Outcome.WAITING_FOR_ACKS;
            }
            publishDecision(transport.get(), operationId, view);
            return view.state == MassDbLicenseState.OperationState.SUCCEEDED
                    ? Outcome.COMMITTED : Outcome.TERMINAL_PERSISTED;
        } catch (MassDbLicenseException error) {
            LOG.warn("MassDB License即时恢复操作未能收敛，operation={} code={}",
                    operationId, error.getCode());
            return Outcome.STATE_CHANGED;
        }
    }

    private Outcome persistNormalFailureIfProved(NormalOperationCoordinator coordinator,
            String operationId, long effectiveNow) {
        MassDbLicenseState current = manager.snapshot();
        MassDbLicenseState.OperationView view = current.findOperation(operationId);
        if (view == null || view.terminal || current.getMutation() == null
                || !operationId.equals(current.getMutation().getOperationId())) {
            return Outcome.STATE_CHANGED;
        }
        try {
            MassDbLicenseImportCore.RedriveResult retry =
                    coordinator.recover(current, operationId, effectiveNow);
            return retry.terminal
                    ? persistNormalTerminal(coordinator, operationId, effectiveNow)
                    : Outcome.STATE_CHANGED;
        } catch (MassDbLicenseException error) {
            return Outcome.STATE_CHANGED;
        }
    }

    private Outcome persistNormalTerminal(NormalOperationCoordinator coordinator,
            String operationId, long effectiveNow) {
        MassDbLicenseState terminal = manager.transition(current -> {
            MassDbLicenseState.OperationView view = current.findOperation(operationId);
            if (view == null || view.terminal) {
                return current;
            }
            MassDbLicenseImportCore.RedriveResult recovered =
                    coordinator.recover(current, operationId, effectiveNow);
            if (!recovered.terminal) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_PRECONDITION_FAILED", "NORMAL operation尚未终结");
            }
            return recovered.state;
        });
        MassDbLicenseState.OperationView view = terminal.findOperation(operationId);
        if (view == null || !view.terminal) {
            return Outcome.STATE_CHANGED;
        }
        publishDecision(transport.get(), operationId, view);
        return Outcome.TERMINAL_PERSISTED;
    }

    private Outcome persistFailureIfProved(String operationId, long effectiveNow) {
        MassDbLicenseState current = manager.snapshot();
        MassDbLicenseState.OperationView view = current.findOperation(operationId);
        if (view == null || view.terminal || current.getMutation() == null
                || !operationId.equals(current.getMutation().getOperationId())) {
            return Outcome.STATE_CHANGED;
        }
        MassDbLicenseEnforcementCore.RedriveResult retry =
                enforcementCore.recover(current, operationId, effectiveNow);
        return retry.terminal ? persistTerminal(operationId, effectiveNow) : Outcome.STATE_CHANGED;
    }

    private Outcome persistTerminal(String operationId, long effectiveNow) {
        MassDbLicenseState terminal = manager.transition(current -> {
            MassDbLicenseState.OperationView view = current.findOperation(operationId);
            if (view == null || view.terminal) {
                return current;
            }
            if (current.getMutation() == null
                    || !operationId.equals(current.getMutation().getOperationId())) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_PRECONDITION_FAILED", "operation已被其他状态替换");
            }
            if (current.getMutation().getKind()
                    == MassDbLicenseState.MutationKind.ENFORCEMENT) {
                return enforcementCore.recover(current, operationId, effectiveNow).state;
            }
            return current.recoverOrExpireMutation(effectiveNow);
        });
        MassDbLicenseState.OperationView view = terminal.findOperation(operationId);
        if (view == null || !view.terminal) {
            return Outcome.STATE_CHANGED;
        }
        publishDecision(transport.get(), operationId, view);
        return Outcome.TERMINAL_PERSISTED;
    }

    private void publishDecision(TrustedRoleTransport trustedTransport, String operationId,
            MassDbLicenseState.OperationView operation) {
        if (operation == null || !operation.terminal || !trustedTransport.isAvailable()) {
            return;
        }
        try {
            trustedTransport.publishAuthoritativeDecision(operationId, operation);
        } catch (Exception error) {
            LOG.warn("MassDB License终态广播失败，入口将通过operation查回，operation={}",
                    operationId, error);
        }
    }

    private static AckValidation validateAcks(
            MassDbLicenseEnforcementCore.RecoveryPlan plan,
            List<AuthenticatedActivationAck> authenticated) {
        if (authenticated == null
                || authenticated.size() != plan.requiredAckNodeUuids.size()) {
            return AckValidation.outcome(Outcome.WAITING_FOR_ACKS);
        }
        Map<String, MassDbLicenseState.ActivationAckEvidence> byNode = new HashMap<>();
        for (AuthenticatedActivationAck item : authenticated) {
            if (item == null || item.evidence == null
                    || !item.authenticatedNodeUuid.equals(item.evidence.nodeUuid)
                    || !plan.requiredAckNodeUuids.contains(item.authenticatedNodeUuid)
                    || !plan.operationId.equals(item.evidence.operationId)
                    || plan.targetEnforcementEpoch != item.evidence.targetEnforcementEpoch
                    || !plan.activeLicenseSha256.equals(item.evidence.activeLicenseSha256)
                    || byNode.put(item.authenticatedNodeUuid, item.evidence) != null) {
                return AckValidation.outcome(Outcome.UNTRUSTED_ACK);
            }
        }
        List<MassDbLicenseState.ActivationAckEvidence> evidence = new ArrayList<>();
        for (String nodeUuid : plan.requiredAckNodeUuids) {
            MassDbLicenseState.ActivationAckEvidence item = byNode.get(nodeUuid);
            if (item == null) {
                return AckValidation.outcome(Outcome.WAITING_FOR_ACKS);
            }
            evidence.add(item);
        }
        return AckValidation.evidence(evidence);
    }

    private static NormalAckValidation validateNormalAcks(
            MassDbLicenseImportCore.RecoveryPlan plan,
            List<AuthenticatedLicenseAck> authenticated) {
        if (authenticated == null
                || authenticated.size() != plan.requiredAckNodeUuids.size()) {
            return NormalAckValidation.outcome(Outcome.WAITING_FOR_ACKS);
        }
        Map<String, String> byNode = new HashMap<>();
        for (AuthenticatedLicenseAck item : authenticated) {
            if (item == null || item.evidence == null
                    || !item.authenticatedNodeUuid.equals(item.evidence.nodeUuid)
                    || !plan.requiredAckNodeUuids.contains(item.authenticatedNodeUuid)
                    || !plan.operationId.equals(item.evidence.operationId)
                    || !plan.contentSha256.equals(item.evidence.contentSha256)
                    || plan.licenseExpiresAt != item.evidence.licenseExpiresAt
                    || plan.enforcementEpoch != item.evidence.enforcementEpoch
                    || !isSha256(item.evidence.pendingSnapshotSha256)
                    || byNode.put(item.authenticatedNodeUuid,
                            item.evidence.pendingSnapshotSha256) != null) {
                return NormalAckValidation.outcome(Outcome.UNTRUSTED_ACK);
            }
        }
        List<String> ordered = new ArrayList<>();
        for (String nodeUuid : plan.requiredAckNodeUuids) {
            if (!byNode.containsKey(nodeUuid)) {
                return NormalAckValidation.outcome(Outcome.WAITING_FOR_ACKS);
            }
            ordered.add(nodeUuid);
        }
        return NormalAckValidation.nodes(ordered);
    }

    private static KeysetAckValidation validateKeysetAcks(
            MassDbLicenseKeysetControlCore.RecoveryPlan plan,
            List<AuthenticatedKeysetAck> authenticated) {
        if (authenticated == null
                || authenticated.size() != plan.requiredAckNodeUuids.size()) {
            return KeysetAckValidation.outcome(Outcome.WAITING_FOR_ACKS);
        }
        Map<String, MassDbLicenseState.KeysetAckEvidence> byNode = new HashMap<>();
        boolean bundle = plan.kind
                == MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE;
        for (AuthenticatedKeysetAck item : authenticated) {
            if (item == null || item.evidence == null
                    || !item.authenticatedNodeUuid.equals(item.evidence.nodeUuid)
                    || !plan.requiredAckNodeUuids.contains(item.authenticatedNodeUuid)
                    || !plan.operationId.equals(item.evidence.operationId)
                    || !plan.keysetSha256.equals(item.evidence.keysetSha256)
                    || plan.keysetVersion != item.evidence.keysetVersion
                    || !isSha256(item.evidence.pendingSnapshotSha256)
                    || bundle && (!plan.licenseSha256.equals(item.evidence.licenseSha256)
                            || plan.licenseExpiresAt != item.evidence.licenseExpiresAt)
                    || !bundle && (item.evidence.licenseSha256 != null
                            || item.evidence.licenseExpiresAt != 0)
                    || byNode.put(item.authenticatedNodeUuid, item.evidence) != null) {
                return KeysetAckValidation.outcome(Outcome.UNTRUSTED_ACK);
            }
        }
        List<MassDbLicenseState.KeysetAckEvidence> ordered = new ArrayList<>();
        for (String nodeUuid : plan.requiredAckNodeUuids) {
            MassDbLicenseState.KeysetAckEvidence evidence = byNode.get(nodeUuid);
            if (evidence == null) {
                return KeysetAckValidation.outcome(Outcome.WAITING_FOR_ACKS);
            }
            ordered.add(evidence);
        }
        return KeysetAckValidation.evidence(ordered);
    }

    private static boolean isSha256(String value) {
        return value != null && value.matches("[0-9a-f]{64}");
    }

    private static final class AckValidation {
        private final Outcome outcome;
        private final List<MassDbLicenseState.ActivationAckEvidence> evidence;

        private AckValidation(Outcome outcome,
                List<MassDbLicenseState.ActivationAckEvidence> evidence) {
            this.outcome = outcome;
            this.evidence = evidence;
        }

        private static AckValidation outcome(Outcome outcome) {
            return new AckValidation(outcome, Collections.emptyList());
        }

        private static AckValidation evidence(
                List<MassDbLicenseState.ActivationAckEvidence> evidence) {
            return new AckValidation(null, evidence);
        }
    }

    private static final class NormalAckValidation {
        private final Outcome outcome;
        private final List<String> nodeUuids;

        private NormalAckValidation(Outcome outcome, List<String> nodeUuids) {
            this.outcome = outcome;
            this.nodeUuids = nodeUuids;
        }

        private static NormalAckValidation outcome(Outcome outcome) {
            return new NormalAckValidation(outcome, Collections.emptyList());
        }

        private static NormalAckValidation nodes(List<String> nodeUuids) {
            return new NormalAckValidation(null, nodeUuids);
        }
    }

    private static final class KeysetAckValidation {
        private final Outcome outcome;
        private final List<MassDbLicenseState.KeysetAckEvidence> evidence;

        private KeysetAckValidation(Outcome outcome,
                List<MassDbLicenseState.KeysetAckEvidence> evidence) {
            this.outcome = outcome;
            this.evidence = evidence;
        }

        private static KeysetAckValidation outcome(Outcome outcome) {
            return new KeysetAckValidation(outcome, Collections.emptyList());
        }

        private static KeysetAckValidation evidence(
                List<MassDbLicenseState.KeysetAckEvidence> evidence) {
            return new KeysetAckValidation(null, evidence);
        }
    }
}
