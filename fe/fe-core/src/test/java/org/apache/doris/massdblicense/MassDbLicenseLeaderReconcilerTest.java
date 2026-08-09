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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class MassDbLicenseLeaderReconcilerTest {
    @Test
    void commitsOnlyAfterCompleteIdentityBoundAckSet() {
        List<MassDbLicenseState> journal = new ArrayList<>();
        MassDbLicenseState prepared = readyObserveState().prepareEnforcementActivation(
                "enforce", "enforce-idem", repeat('7'), 300, 500);
        MassDbLicenseManager manager = new MassDbLicenseManager(prepared, journal::add);
        MassDbLicenseLeaderReconciler reconciler = new MassDbLicenseLeaderReconciler(
                manager, new MassDbLicenseEnforcementCore(), 1_000);
        RecordingTransport transport = new RecordingTransport();
        transport.mode = RecordingTransport.Mode.COMPLETE;
        reconciler.setTrustedRoleTransport(transport);

        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.COMMITTED,
                reconciler.reconcileOnce(301));
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.ENFORCING,
                manager.snapshot().getEnforcementMode());
        Assertions.assertEquals(1, manager.snapshot().getEnforcementEpoch());
        Assertions.assertEquals(2, journal.size());
        Assertions.assertEquals(301, manager.snapshot().getMaxSeenWallClock());
        Assertions.assertEquals(1, transport.publishCount);
    }

    @Test
    void incompleteOrUntrustedAckNeverCommits() {
        MassDbLicenseState prepared = readyObserveState().prepareEnforcementActivation(
                "enforce", "enforce-idem", repeat('6'), 300, 500);
        List<MassDbLicenseState> journal = new ArrayList<>();
        MassDbLicenseManager manager = new MassDbLicenseManager(prepared, journal::add);
        MassDbLicenseLeaderReconciler reconciler = new MassDbLicenseLeaderReconciler(
                manager, new MassDbLicenseEnforcementCore(), 1_000);
        RecordingTransport transport = new RecordingTransport();
        reconciler.setTrustedRoleTransport(transport);

        transport.mode = RecordingTransport.Mode.INCOMPLETE;
        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.WAITING_FOR_ACKS,
                reconciler.reconcileOnce(301));
        transport.mode = RecordingTransport.Mode.IDENTITY_MISMATCH;
        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.UNTRUSTED_ACK,
                reconciler.reconcileOnce(302));
        Assertions.assertEquals(MassDbLicenseState.OperationState.PREPARED,
                manager.snapshot().findOperation("enforce").state);
        Assertions.assertEquals(1, journal.size());
        Assertions.assertEquals(301, journal.get(0).getMaxSeenWallClock());
    }

    @Test
    void deadlineIsJournaledBeforeTransportCanRun() {
        MassDbLicenseState prepared = readyObserveState().prepareEnforcementActivation(
                "enforce", "enforce-idem", repeat('5'), 300, 305);
        List<MassDbLicenseState> journal = new ArrayList<>();
        MassDbLicenseManager manager = new MassDbLicenseManager(prepared, journal::add);
        MassDbLicenseLeaderReconciler reconciler = new MassDbLicenseLeaderReconciler(
                manager, new MassDbLicenseEnforcementCore(), 1_000);
        RecordingTransport transport = new RecordingTransport();
        transport.mode = RecordingTransport.Mode.COMPLETE;
        reconciler.setTrustedRoleTransport(transport);

        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.TERMINAL_PERSISTED,
                reconciler.reconcileOnce(305));
        MassDbLicenseState.OperationView operation = manager.snapshot().findOperation("enforce");
        Assertions.assertEquals(MassDbLicenseState.OperationState.FAILED, operation.state);
        Assertions.assertEquals("MASSDB_LICENSE_OPERATION_DEADLINE_EXCEEDED",
                operation.errorCode);
        Assertions.assertEquals(0, transport.prepareCount);
        Assertions.assertEquals(1, transport.publishCount);
        Assertions.assertEquals(2, journal.size());
        Assertions.assertEquals(305, manager.snapshot().getMaxSeenWallClock());
    }

    @Test
    void missingInternalTransportLeavesPreparedUntouched() {
        MassDbLicenseState prepared = readyObserveState().prepareEnforcementActivation(
                "enforce", "enforce-idem", repeat('4'), 300, 500);
        List<MassDbLicenseState> journal = new ArrayList<>();
        MassDbLicenseManager manager = new MassDbLicenseManager(prepared, journal::add);
        MassDbLicenseLeaderReconciler reconciler = new MassDbLicenseLeaderReconciler(
                manager, new MassDbLicenseEnforcementCore(), 1_000);

        Assertions.assertEquals(
                MassDbLicenseLeaderReconciler.Outcome.WAITING_FOR_ROLE_TRANSPORT,
                reconciler.reconcileOnce(301));
        Assertions.assertEquals(MassDbLicenseState.OperationState.PREPARED,
                manager.snapshot().findOperation("enforce").state);
        Assertions.assertEquals(1, journal.size());
        Assertions.assertEquals(301, manager.snapshot().getMaxSeenWallClock());
    }

    @Test
    void normalImportRedriveRequiresIdentityBoundPendingAck() {
        MassDbLicenseState prepared = preparedNormalState();
        List<MassDbLicenseState> journal = new ArrayList<>();
        MassDbLicenseManager manager = new MassDbLicenseManager(prepared, journal::add);
        MassDbLicenseLeaderReconciler reconciler = new MassDbLicenseLeaderReconciler(
                manager, new MassDbLicenseEnforcementCore(), 1_000);
        reconciler.setNormalOperationCoordinator(new FakeNormalCoordinator());
        RecordingTransport transport = new RecordingTransport();
        transport.mode = RecordingTransport.Mode.IDENTITY_MISMATCH;
        reconciler.setTrustedRoleTransport(transport);

        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.UNTRUSTED_ACK,
                reconciler.reconcileOnce(301));
        Assertions.assertNotNull(manager.snapshot().getMutation());
        Assertions.assertEquals(1, journal.size());

        transport.mode = RecordingTransport.Mode.COMPLETE;
        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.COMMITTED,
                reconciler.reconcileOnce(302));
        Assertions.assertEquals(repeat('e'),
                manager.snapshot().getActiveLicense().getSha256());
        Assertions.assertEquals(MassDbLicenseState.OperationState.SUCCEEDED,
                manager.snapshot().findOperation("normal").state);
        Assertions.assertEquals(2, journal.size());
        Assertions.assertEquals(1, transport.publishCount);
    }

    private static final class FakeNormalCoordinator
            implements MassDbLicenseLeaderReconciler.NormalOperationCoordinator {
        @Override
        public MassDbLicenseImportCore.RedriveResult recover(
                MassDbLicenseState state, String operationId, long effectiveNow) {
            MassDbLicenseState recovered = state.recoverOrExpireMutation(effectiveNow);
            MassDbLicenseState.OperationView view = recovered.findOperation(operationId);
            if (view != null && view.terminal) {
                return new MassDbLicenseImportCore.RedriveResult(
                        recovered, null, true, view.errorCode);
            }
            MassDbLicenseState.Mutation mutation = recovered.getMutation();
            MassDbLicenseState.ActiveLicense candidate = mutation.getCandidateLicense();
            MassDbLicenseImportCore.RecoveryPlan plan =
                    new MassDbLicenseImportCore.RecoveryPlan(
                            operationId, candidate.getSha256(), candidate.getExpiresAt(),
                            recovered.getEnforcementEpoch(), mutation.getPreparedAt(),
                            candidate.getArtifact(), mutation.getRequiredAckNodeUuids(),
                            mutation.getDeferredNodeUuids(), mutation.getDeadlineAt());
            return new MassDbLicenseImportCore.RedriveResult(
                    recovered, plan, false, null);
        }

        @Override
        public MassDbLicenseState commit(MassDbLicenseState state, String operationId,
                List<String> ackedNodeUuids, long effectiveNow) {
            return state.commitNormalLicenseImport(
                    operationId, ackedNodeUuids, effectiveNow);
        }
    }

    private static final class RecordingTransport
            implements MassDbLicenseLeaderReconciler.TrustedRoleTransport {
        enum Mode {
            COMPLETE,
            INCOMPLETE,
            IDENTITY_MISMATCH
        }

        private Mode mode = Mode.INCOMPLETE;
        private int prepareCount;
        private int publishCount;

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public List<MassDbLicenseLeaderReconciler.AuthenticatedActivationAck>
                prepareEnforcement(MassDbLicenseEnforcementCore.RecoveryPlan plan) {
            prepareCount++;
            if (mode == Mode.INCOMPLETE) {
                return Collections.emptyList();
            }
            MassDbLicenseState.ActivationAckEvidence evidence =
                    new MassDbLicenseState.ActivationAckEvidence(
                            "fe-1", plan.operationId, plan.targetEnforcementEpoch,
                            plan.activeLicenseSha256, repeat('d'));
            String authenticated = mode == Mode.IDENTITY_MISMATCH ? "fe-attacker" : "fe-1";
            return Collections.singletonList(
                    new MassDbLicenseLeaderReconciler.AuthenticatedActivationAck(
                            authenticated, evidence));
        }

        @Override
        public List<MassDbLicenseLeaderReconciler.AuthenticatedLicenseAck>
                prepareNormal(MassDbLicenseImportCore.RecoveryPlan plan) {
            prepareCount++;
            if (mode == Mode.INCOMPLETE) {
                return Collections.emptyList();
            }
            MassDbLicenseLeaderReconciler.LicenseAckEvidence evidence =
                    new MassDbLicenseLeaderReconciler.LicenseAckEvidence(
                            "fe-1", plan.operationId, plan.contentSha256,
                            plan.licenseExpiresAt, plan.enforcementEpoch, repeat('f'));
            String authenticated = mode == Mode.IDENTITY_MISMATCH ? "fe-attacker" : "fe-1";
            return Collections.singletonList(
                    new MassDbLicenseLeaderReconciler.AuthenticatedLicenseAck(
                            authenticated, evidence));
        }

        @Override
        public void publishAuthoritativeDecision(String operationId,
                MassDbLicenseState.OperationView operation) {
            publishCount++;
        }
    }

    private static MassDbLicenseState readyObserveState() {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, repeat('a'));
        MassDbLicenseState.ActiveLicense active = new MassDbLicenseState.ActiveLicense(
                "initial", activeSha256(), "kid", 100, 2_000, new byte[] {1, 2, 3});
        state = state.prepareLicense("license", "license-idem", repeat('b'),
                MassDbLicenseState.ImportIntent.NORMAL, active,
                "admin", null, 200, 250).commit("license", 201);
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured("fe-1", "https://fe-1:8050", true);
        state = state.prepareIngressInventory("ingress", "ingress-idem", repeat('c'),
                inventory, 210, 250).commit("ingress", 211)
                .recordIngressHeartbeat("fe-1", true, 220, 1_000)
                .recordRoutingEvidence("fe-1",
                        MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                        MassDbLicenseIngressInventory.EvidenceSource.MACHINE, 220, 1_000);
        return state.recordIngressActiveAck("fe-1", activeSha256(), 2_000, 0);
    }

    private static MassDbLicenseState preparedNormalState() {
        MassDbLicenseState state = readyObserveState();
        MassDbLicenseIngressInventory.Evaluation ingress =
                state.getIngressInventory().evaluate(
                        state.getActiveLicense(), state.getEnforcementEpoch(), 300, true);
        MassDbLicenseState.ActiveLicense candidate = new MassDbLicenseState.ActiveLicense(
                "renewed", repeat('e'), "kid", 250, 3_000, new byte[] {4, 5, 6});
        return state.prepareNormalLicenseImport(
                "normal", "normal-idem", repeat('8'), candidate, "admin", "ACTIVATE",
                state.getTopologyRevision(), ingress.inventorySnapshotSha256,
                ingress.routingEvidenceSnapshotSha256, ingress.requiredAckNodeUuids,
                ingress.deferredNodeUuids, 300, 500);
    }

    private static String activeSha256() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(new byte[] {1, 2, 3});
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
                result.append(Character.forDigit(item & 0x0f, 16));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    private static String repeat(char value) {
        StringBuilder result = new StringBuilder(64);
        for (int index = 0; index < 64; index++) {
            result.append(value);
        }
        return result.toString();
    }
}
