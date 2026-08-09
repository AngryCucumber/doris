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

import org.apache.doris.common.io.DataInputBuffer;
import org.apache.doris.common.io.DataOutputBuffer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

class MassDbLicenseStateTest {
    private static final String PLAN_SHA = repeat('a');
    private static final String REQUEST_SHA = repeat('b');

    @Test
    void newAndExistingClustersChooseDifferentSafeDefaults() {
        MassDbLicenseState fresh = MassDbLicenseState.empty().bootstrap(false, PLAN_SHA);
        MassDbLicenseState upgraded = MassDbLicenseState.empty().bootstrap(true, PLAN_SHA);

        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.ENFORCING,
                fresh.getEnforcementMode());
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.OBSERVE,
                upgraded.getEnforcementMode());
        Assertions.assertNotNull(fresh.getLicenseControlDeploymentUuid());
        Assertions.assertEquals(32, fresh.getPreconditionHmacKey().length);
        Assertions.assertEquals(1, fresh.getBootstrapSealGeneration());

        MassDbLicenseState replayed = fresh.bootstrap(false, PLAN_SHA);
        Assertions.assertArrayEquals(fresh.getPreconditionHmacKey(), replayed.getPreconditionHmacKey());
    }

    @Test
    void correctionBarrierBlocksAnyPreCorrectionEquivalentFile() {
        MassDbLicenseState state = initializedWithLicense(2_000);
        MassDbLicenseState.ActiveLicense shorter = license("short", repeat('c'), 200, 1_500);
        String proposalId = "00000000-0000-4000-8000-000000000021";
        state = state.createCorrectionProposal(proposalId, shorter,
                        "requester", 390, 900)
                .approveCorrectionProposal(proposalId, "different-approver", 395)
                .prepareControlledLicenseImport("op-2", "key-2", repeat('d'),
                        MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER, shorter,
                        "requester", "different-approver", proposalId, 400, 500)
                .commitControlledLicenseImport("op-2",
                        Collections.singletonList("fe-1"), 401);

        Assertions.assertEquals(1, state.getLicenseCorrectionBarriers().size());
        final MassDbLicenseState corrected = state;
        MassDbLicenseException blocked = Assertions.assertThrows(MassDbLicenseException.class,
                () -> corrected.prepareLicense("op-3", "key-3", repeat('e'),
                        MassDbLicenseState.ImportIntent.NORMAL,
                        license("alternate-old-file", repeat('f'), 300, 2_000),
                        "tenant-admin", null, 410, 500));
        Assertions.assertEquals("MASSDB_LICENSE_SUPERSEDED", blocked.getCode());

        MassDbLicenseException between = Assertions.assertThrows(MassDbLicenseException.class,
                () -> corrected.prepareLicense("op-between", "key-between", repeat('8'),
                        MassDbLicenseState.ImportIntent.NORMAL,
                        license("alternate-between", repeat('9'), 300, 1_800),
                        "tenant-admin", null, 410, 500));
        Assertions.assertEquals("MASSDB_LICENSE_SUPERSEDED", between.getCode());

        long allowedIssuedAt = state.getLicenseCorrectionBarriers().get(0)
                .getSupersededIssuedAtCutoff() + 1;
        MassDbLicenseState allowed = state.prepareLicense("op-4", "key-4", repeat('1'),
                MassDbLicenseState.ImportIntent.NORMAL,
                license("newly-signed", repeat('2'), allowedIssuedAt, 2_000),
                "tenant-admin", null, 410, 500);
        Assertions.assertNotNull(allowed.getMutation());
    }

    @Test
    void ingressInventoryUsesMutationAndOnlySemanticRoutingChangesAdvanceTopology() {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(false, PLAN_SHA);
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured("fe-1", "https://fe-1:8050", true);
        state = state.prepareIngressInventory("ingress", "ingress-idem", repeat('e'),
                inventory, 100, 200).commit("ingress", 101);
        Assertions.assertEquals(1, state.getTopologyRevision());
        state = state.recordIngressHeartbeat("fe-1", true, 110, 300);
        state = state.recordRoutingEvidence("fe-1",
                MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                MassDbLicenseIngressInventory.EvidenceSource.MACHINE, 110, 300);
        Assertions.assertEquals(2, state.getTopologyRevision());
        state = state.recordRoutingEvidence("fe-1",
                MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                MassDbLicenseIngressInventory.EvidenceSource.MACHINE, 120, 400);
        Assertions.assertEquals(2, state.getTopologyRevision());
        Assertions.assertTrue(state.getIngressInventory()
                .evaluate(null, state.getEnforcementEpoch(), 130, true).isReadyForImport());
    }

    @Test
    void restrictiveKeysetPreemptsClockChallengeOnlyAfterCommit() {
        MassDbLicenseState state = initializedWithLicense(2_000)
                .createClockChallenge("challenge", repeat('3'), 300, 900);
        final MassDbLicenseState challenged = state;

        MassDbLicenseException blocked = Assertions.assertThrows(MassDbLicenseException.class,
                () -> challenged.prepareKeyset("add", "key-add", repeat('4'),
                        MassDbLicenseState.MutationKind.ADDITIVE_KEYSET,
                        keyset(2, '4'), 301, 500));
        Assertions.assertEquals("MASSDB_LICENSE_CLOCK_RECOVERY_CHALLENGE_ACTIVE", blocked.getCode());

        MassDbLicenseState prepared = state.prepareKeyset("recover", "key-recover", repeat('5'),
                MassDbLicenseState.MutationKind.RESTRICTIVE_KEYSET,
                keyset(2, '5'), 301, 500);
        Assertions.assertEquals(MassDbLicenseState.ClockChallengeState.ACTIVE,
                prepared.getClockChallenge().getState());
        MassDbLicenseState committed = commitKeyset(prepared, "recover", 302);
        Assertions.assertEquals(MassDbLicenseState.ClockChallengeState.INVALIDATED_BY_KEYSET_RECOVERY,
                committed.getClockChallenge().getState());
        Assertions.assertEquals(2, committed.getKeysetVersion());
    }

    @Test
    void recoveryBundleAtomicallyCommitsKeysetAndLicense() {
        MassDbLicenseState challenged = initializedWithLicense(2_000)
                .createClockChallenge("challenge", repeat('3'), 300, 900);
        MassDbLicenseState.ActiveLicense replacement =
                license("replacement", repeat('a'), 250, 2_500);

        MassDbLicenseState prepared = challenged.prepareRecoveryBundle(
                "bundle", "key-bundle", repeat('f'), keyset(3, 'e'), replacement, 301, 500);
        MassDbLicenseState aborted = prepared.abort("bundle");
        Assertions.assertEquals(0, aborted.getKeysetVersion());
        Assertions.assertEquals("initial", aborted.getActiveLicense().getLicenseId());
        Assertions.assertEquals(MassDbLicenseState.ClockChallengeState.ACTIVE,
                aborted.getClockChallenge().getState());

        MassDbLicenseState bundlePrepared = challenged.prepareRecoveryBundle(
                "bundle-2", "key-bundle-2", repeat('9'), keyset(3, 'd'), replacement, 301, 500);
        MassDbLicenseState committed = commitKeyset(bundlePrepared, "bundle-2", 302);
        Assertions.assertEquals(3, committed.getKeysetVersion());
        Assertions.assertEquals("replacement", committed.getActiveLicense().getLicenseId());
        Assertions.assertEquals(MassDbLicenseState.ClockChallengeState.INVALIDATED_BY_KEYSET_RECOVERY,
                committed.getClockChallenge().getState());
    }

    @Test
    void sameIdempotencyKeyReplaysAndDifferentHashConflicts() {
        MassDbLicenseState state = initializedWithLicense(2_000);
        MassDbLicenseState prepared = state.prepareLicense("op-idem", "idem", REQUEST_SHA,
                MassDbLicenseState.ImportIntent.NORMAL,
                license("next", repeat('6'), 200, 3_000), "admin", null, 300, 500);
        MassDbLicenseState replayed = prepared.prepareLicense("ignored", "idem", REQUEST_SHA,
                MassDbLicenseState.ImportIntent.NORMAL,
                license("other", repeat('7'), 200, 4_000), "admin", null, 301, 501);
        Assertions.assertEquals("op-idem", replayed.getMutation().getOperationId());

        MassDbLicenseException conflict = Assertions.assertThrows(MassDbLicenseException.class,
                () -> prepared.prepareLicense("new", "idem", repeat('8'),
                        MassDbLicenseState.ImportIntent.NORMAL,
                        license("other", repeat('9'), 200, 4_000), "admin", null, 301, 501));
        Assertions.assertEquals("MASSDB_LICENSE_IDEMPOTENCY_CONFLICT", conflict.getCode());
    }

    @Test
    void journalSnapshotRoundTripKeepsPermanentBarrier() throws IOException {
        MassDbLicenseState state = initializedWithLicense(2_000);
        String proposalId = "00000000-0000-4000-8000-000000000022";
        MassDbLicenseState.ActiveLicense shorter =
                license("short", repeat('d'), 200, 1_500);
        state = state.createCorrectionProposal(proposalId, shorter,
                        "requester", 390, 900)
                .approveCorrectionProposal(proposalId, "approver", 395)
                .prepareControlledLicenseImport("op-2", "key-2", repeat('c'),
                        MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER,
                        shorter, "requester", "approver", proposalId, 400, 500)
                .commitControlledLicenseImport("op-2",
                        Collections.singletonList("fe-1"), 401);

        DataOutputBuffer output = new DataOutputBuffer(1024);
        state.write(output);
        DataInputBuffer input = new DataInputBuffer();
        input.reset(output.getData(), output.getLength());
        MassDbLicenseState restored = MassDbLicenseState.read(input);

        Assertions.assertEquals(1, restored.getLicenseCorrectionBarriers().size());
        Assertions.assertEquals(2_000,
                restored.getLicenseCorrectionBarriers().get(0).getSupersededExpiresAt());
    }

    @Test
    void journalRoundTripKeepsOpenBootstrapAttestation() throws IOException {
        String markerId = "00000000-0000-4000-8000-000000000071";
        String deploymentId = "00000000-0000-4000-8000-000000000072";
        MassDbLicenseException nonCanonical = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseState.empty().openBootstrap(
                        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
                        deploymentId, PLAN_SHA, 100));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID",
                nonCanonical.getCode());
        MassDbLicenseState open = MassDbLicenseState.empty().openBootstrap(
                markerId, deploymentId, PLAN_SHA, 100);
        DataOutputBuffer output = new DataOutputBuffer(1024);
        open.write(output);
        DataInputBuffer input = new DataInputBuffer();
        input.reset(output.getData(), output.getLength());
        MassDbLicenseState restored = MassDbLicenseState.read(input);

        Assertions.assertEquals("OPEN", restored.getBootstrapPhase());
        Assertions.assertEquals(0, restored.getBootstrapSealGeneration());
        Assertions.assertEquals(markerId, restored.getBootstrapMarkerId());
        Assertions.assertEquals(deploymentId, restored.getLicenseControlDeploymentUuid());
        Assertions.assertArrayEquals(open.getPreconditionHmacKey(),
                restored.getPreconditionHmacKey());

        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured("00000000-0000-4000-8000-000000000073",
                        "https://fe-1.example:8050", true);
        MassDbLicenseState sealed = open.sealBootstrap(
                "bootstrap-operation", "bootstrap-idempotency", REQUEST_SHA,
                markerId, PLAN_SHA, keyset(1, 'c'), inventory, 101);
        output = new DataOutputBuffer(1024);
        sealed.write(output);
        input = new DataInputBuffer();
        input.reset(output.getData(), output.getLength());
        MassDbLicenseState restoredSealed = MassDbLicenseState.read(input);
        Assertions.assertEquals("SEALED", restoredSealed.getBootstrapPhase());
        Assertions.assertEquals(101, restoredSealed.getBootstrapMarkerConsumedAt());
        Assertions.assertEquals("bootstrap-operation",
                restoredSealed.findOperation("bootstrap-operation").operationId);
    }

    @Test
    void managerJournalsBeforePublishingState() {
        AtomicInteger journals = new AtomicInteger();
        MassDbLicenseManager manager = new MassDbLicenseManager(
                MassDbLicenseState.empty(), ignored -> journals.incrementAndGet());
        manager.transition(state -> state.bootstrap(false, PLAN_SHA));
        Assertions.assertEquals(1, journals.get());
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.ENFORCING,
                manager.snapshot().getEnforcementMode());
        Assertions.assertEquals(1, manager.snapshot().getControlPlaneRevision());
    }

    @Test
    void duplicateNodeIdentityIsJournaledAndBlocksEveryCoverageProof() throws IOException {
        String nodeUuid = "00000000-0000-4000-8000-000000000031";
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, PLAN_SHA);
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured(nodeUuid, "https://fe-1:8050", true);
        state = state.prepareIngressInventory("ingress-conflict", "ingress-conflict-idem",
                repeat('3'), inventory, 100, 200).commit("ingress-conflict", 101)
                .recordIngressHeartbeat(nodeUuid, true, 110, 1_000)
                .recordRoutingEvidence(nodeUuid,
                        MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                        MassDbLicenseIngressInventory.EvidenceSource.MACHINE,
                        110, 1_000)
                .recordTrustedRejoin(nodeUuid, repeat('4'), 0, 1_000)
                .recordIngressActiveAck(nodeUuid, repeat('4'), 2_000, 0);
        AtomicInteger journals = new AtomicInteger();
        MassDbLicenseManager manager = new MassDbLicenseManager(
                state, ignored -> journals.incrementAndGet());

        MassDbLicenseState conflicted = manager.transition(current ->
                current.recordIngressIdentityConflict(nodeUuid, true, 200));
        MassDbLicenseIngressInventory.IngressNode node = conflicted.getIngressInventory()
                .getNodes().get(nodeUuid);
        Assertions.assertTrue(node.isAuthoritativeIdentityConflict());
        Assertions.assertFalse(node.isGuardReady());
        Assertions.assertEquals(200, node.getIdentityConflictDetectedAt());
        Assertions.assertEquals(conflicted.getControlPlaneRevision(),
                node.getIdentityConflictRevision());
        Assertions.assertTrue(conflicted.getIngressInventory().evaluate(
                null, 0, 201, true).blockers.contains(
                        "MASSDB_LICENSE_DUPLICATE_NODE_UUID:" + nodeUuid));

        MassDbLicenseException rejoin = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> conflicted.recordTrustedRejoin(nodeUuid, repeat('4'), 0, 1_100));
        Assertions.assertEquals("MASSDB_LICENSE_DUPLICATE_NODE_UUID", rejoin.getCode());
        MassDbLicenseException ack = Assertions.assertThrows(MassDbLicenseException.class,
                () -> conflicted.recordIngressActiveAck(nodeUuid, repeat('4'), 2_000, 0));
        Assertions.assertEquals("MASSDB_LICENSE_DUPLICATE_NODE_UUID", ack.getCode());
        long revisionBeforeEarlyClear = manager.snapshot().getControlPlaneRevision();
        MassDbLicenseException early = Assertions.assertThrows(MassDbLicenseException.class,
                () -> manager.transition(current ->
                        current.recordIngressIdentityConflict(nodeUuid, false, 289)));
        Assertions.assertEquals("MASSDB_LICENSE_DUPLICATE_NODE_UUID", early.getCode());
        Assertions.assertEquals(revisionBeforeEarlyClear,
                manager.snapshot().getControlPlaneRevision());

        MassDbLicenseState resolved = manager.transition(current ->
                current.recordIngressIdentityConflict(nodeUuid, false, 290));
        node = resolved.getIngressInventory().getNodes().get(nodeUuid);
        Assertions.assertFalse(node.isAuthoritativeIdentityConflict());
        Assertions.assertEquals(290, node.getIdentityConflictResolvedAt());
        Assertions.assertFalse(node.isGuardReady());
        Assertions.assertEquals(2, journals.get());

        DataOutputBuffer output = new DataOutputBuffer(1024);
        resolved.write(output);
        DataInputBuffer input = new DataInputBuffer();
        input.reset(output.getData(), output.getLength());
        MassDbLicenseState restored = MassDbLicenseState.read(input);
        MassDbLicenseIngressInventory.IngressNode restoredNode = restored.getIngressInventory()
                .getNodes().get(nodeUuid);
        Assertions.assertEquals(290, restoredNode.getIdentityConflictResolvedAt());
        Assertions.assertEquals(resolved.getControlPlaneRevision(),
                restored.getControlPlaneRevision());
    }

    @Test
    void configuredInventoryCannotEraseOrInjectDuplicateIdentityAuthority() {
        String nodeUuid = "00000000-0000-4000-8000-000000000032";
        MassDbLicenseIngressInventory initial = MassDbLicenseIngressInventory.empty()
                .upsertConfigured(nodeUuid, "https://fe-original:8050", true);
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, PLAN_SHA)
                .prepareIngressInventory("ingress-original", "ingress-original-idem",
                        repeat('5'), initial, 100, 200)
                .commit("ingress-original", 101)
                .advanceControlPlaneRevision()
                .recordIngressIdentityConflict(nodeUuid, true, 200);

        MassDbLicenseIngressInventory reconfigured = MassDbLicenseIngressInventory.empty()
                .upsertConfigured(nodeUuid, "https://fe-reconfigured:8050", false);
        MassDbLicenseState updated = state.prepareIngressInventory(
                "ingress-update", "ingress-update-idem", repeat('6'),
                reconfigured, 201, 300).commit("ingress-update", 202);
        MassDbLicenseIngressInventory.IngressNode preserved = updated.getIngressInventory()
                .getNodes().get(nodeUuid);
        Assertions.assertEquals("https://fe-reconfigured:8050", preserved.getEndpoint());
        Assertions.assertFalse(preserved.isDesired());
        Assertions.assertTrue(preserved.isAuthoritativeIdentityConflict());
        Assertions.assertEquals(200, preserved.getIdentityConflictDetectedAt());

        MassDbLicenseState removing = state.prepareIngressInventory(
                "ingress-remove", "ingress-remove-idem", repeat('7'),
                MassDbLicenseIngressInventory.empty(), 201, 300);
        MassDbLicenseException blocked = Assertions.assertThrows(MassDbLicenseException.class,
                () -> removing.commit("ingress-remove", 202));
        Assertions.assertEquals("MASSDB_LICENSE_DUPLICATE_NODE_UUID", blocked.getCode());
    }

    @Test
    void enforcementActivationRequiresDurableBoundAckFromEveryIngress() {
        MassDbLicenseState state = readyObserveState();
        MassDbLicenseState prepared = state.prepareEnforcementActivation(
                "enforce-1", "enforce-idem", repeat('7'), 300, 500);

        Assertions.assertEquals(MassDbLicenseState.MutationKind.ENFORCEMENT,
                prepared.getMutation().getKind());
        Assertions.assertEquals(1L, prepared.getMutation().getTargetEnforcementEpoch());
        Assertions.assertEquals("AWAITING_ACK",
                prepared.findOperation("enforce-1").apiState);
        Assertions.assertEquals(1L,
                prepared.findOperation("enforce-1").targetEnforcementEpoch);

        MassDbLicenseException bypass = Assertions.assertThrows(MassDbLicenseException.class,
                () -> prepared.commit("enforce-1", 301));
        Assertions.assertEquals("MASSDB_LICENSE_ENFORCEMENT_ACK_REQUIRED", bypass.getCode());

        MassDbLicenseException incomplete = Assertions.assertThrows(MassDbLicenseException.class,
                () -> prepared.commitEnforcementActivation(
                        "enforce-1", Collections.emptyList(), 301));
        Assertions.assertEquals("MASSDB_LICENSE_ENFORCEMENT_ACK_INCOMPLETE", incomplete.getCode());

        MassDbLicenseState.ActivationAckEvidence wrong =
                new MassDbLicenseState.ActivationAckEvidence(
                        "fe-1", "different-operation", 1, repeat('0'), repeat('8'));
        MassDbLicenseException invalid = Assertions.assertThrows(MassDbLicenseException.class,
                () -> prepared.commitEnforcementActivation(
                        "enforce-1", Collections.singletonList(wrong), 301));
        Assertions.assertEquals("MASSDB_LICENSE_ENFORCEMENT_ACK_INVALID", invalid.getCode());

        MassDbLicenseState.ActivationAckEvidence ack =
                new MassDbLicenseState.ActivationAckEvidence(
                        "fe-1", "enforce-1", 1, repeat('0'), repeat('8'));
        MassDbLicenseState enforcing = prepared.commitEnforcementActivation(
                "enforce-1", Collections.singletonList(ack), 301);
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.ENFORCING,
                enforcing.getEnforcementMode());
        Assertions.assertEquals(1, enforcing.getEnforcementEpoch());
        Assertions.assertNull(enforcing.getMutation());
        Assertions.assertEquals("ACTIVE", enforcing.findOperation("enforce-1").apiState);
        Assertions.assertEquals(1, enforcing.getIngressInventory().evaluate(
                enforcing.getActiveLicense(), 1, 302, false).coveredIngressNodes);
    }

    @Test
    void enforcementActivationRejectsIncompleteCoverageAndChangedSnapshot() {
        MassDbLicenseState uncovered = readyObserveStateWithoutAck();
        MassDbLicenseException notReady = Assertions.assertThrows(MassDbLicenseException.class,
                () -> uncovered.prepareEnforcementActivation(
                        "enforce-unready", "enforce-unready-idem", repeat('6'), 300, 500));
        Assertions.assertEquals("MASSDB_LICENSE_ENFORCEMENT_NOT_READY", notReady.getCode());

        MassDbLicenseState prepared = readyObserveState().prepareEnforcementActivation(
                "enforce-change", "enforce-change-idem", repeat('5'), 300, 500);
        MassDbLicenseState changed = prepared.recordRoutingEvidence("fe-1",
                MassDbLicenseIngressInventory.RoutingState.REMOVED,
                MassDbLicenseIngressInventory.EvidenceSource.MACHINE, 301, 500);
        MassDbLicenseState.ActivationAckEvidence ack =
                new MassDbLicenseState.ActivationAckEvidence(
                        "fe-1", "enforce-change", 1, repeat('0'), repeat('4'));
        MassDbLicenseException staleSnapshot = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> changed.commitEnforcementActivation(
                        "enforce-change", Collections.singletonList(ack), 302));
        Assertions.assertEquals("MASSDB_LICENSE_PRECONDITION_FAILED", staleSnapshot.getCode());

        MassDbLicenseState aborted = prepared.abort("enforce-change", 302);
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.OBSERVE,
                aborted.getEnforcementMode());
        Assertions.assertEquals("ABORTED", aborted.findOperation("enforce-change").apiState);
    }

    @Test
    void confirmedOfflineIngressOnlyWarnsAfterRoutingEvidenceExpires() {
        MassDbLicenseState state = readyObserveState()
                .recordRoutingEvidence("fe-1",
                        MassDbLicenseIngressInventory.RoutingState.REMOVED,
                        MassDbLicenseIngressInventory.EvidenceSource.MACHINE,
                        900, 950)
                .recordTrustedRejoin("fe-1", repeat('0'), 0, 2_000);

        MassDbLicenseIngressInventory.Evaluation evaluation =
                state.getIngressInventory().evaluate(
                        state.getActiveLicense(), state.getEnforcementEpoch(), 1_001, true);
        Assertions.assertEquals(1, evaluation.deferredOfflineIngressNodes);
        Assertions.assertEquals(1, evaluation.coveredIngressNodes);
        Assertions.assertEquals("STALE", evaluation.coverageFreshness);
        Assertions.assertTrue(evaluation.blockers.isEmpty());
        Assertions.assertTrue(evaluation.warnings.contains(
                "MASSDB_LICENSE_ROUTING_EVIDENCE_RECONFIRM_REQUIRED:fe-1"));
        Assertions.assertEquals(Collections.singletonList("fe-1"),
                evaluation.deferredNodeUuids);
    }

    @Test
    void diagnosticCriticalFirstCauseCoalescesPinsAndSurvivesJournalRoundTrip()
            throws IOException {
        long firstSeen = 1_000;
        String nodeUuid = "00000000-0000-4000-8000-000000000031";
        MassDbLicenseState.DiagnosticEventInput input =
                new MassDbLicenseState.DiagnosticEventInput(
                        "CRITICAL", "CONTROL_PLANE_STALE",
                        "MASSDB_LICENSE_CONTROL_PLANE_STALE", nodeUuid, "",
                        MassDbLicenseState.diagnosticOpaqueSubject(nodeUuid), "",
                        "ENFORCING", "IN_SERVICE", true);
        MassDbLicenseState state = initializedWithLicense(4_000)
                .appendDiagnosticEvent(input, firstSeen)
                .appendDiagnosticEvent(input,
                        firstSeen + MassDbLicenseState.DIAGNOSTIC_EVENT_RETENTION_SECONDS + 1);
        Assertions.assertEquals(1, state.getDiagnosticEvents().size());
        Assertions.assertEquals(2, state.getDiagnosticEvents().get(0).count);
        Assertions.assertEquals(firstSeen, state.getDiagnosticEvents().get(0).occurredAt);

        long resolvedAt = firstSeen
                + MassDbLicenseState.DIAGNOSTIC_EVENT_RETENTION_SECONDS + 2;
        state = state.resolveDiagnosticEvent(input.eventKind, nodeUuid,
                input.subjectKey, resolvedAt);
        Assertions.assertFalse(state.getDiagnosticEvents().get(0).active);
        Assertions.assertEquals(resolvedAt
                        + MassDbLicenseState.DEFAULT_CONTROL_PLANE_STALENESS_SECONDS,
                state.getDiagnosticEvents().get(0).pinnedUntil);

        DataOutputBuffer output = new DataOutputBuffer();
        state.write(output);
        DataInputBuffer inputBuffer = new DataInputBuffer();
        inputBuffer.reset(output.getData(), output.getLength());
        MassDbLicenseState restored = MassDbLicenseState.read(inputBuffer);
        MassDbLicenseState.DiagnosticEventPage page = restored.diagnosticEventPage(
                0, 1, resolvedAt + 1);
        Assertions.assertEquals(1, page.items.size());
        Assertions.assertEquals(restored.getDiagnosticSequence(), page.nextSequence);
        Assertions.assertEquals(MassDbLicenseState.DIAGNOSTIC_EVENT_RETENTION_SECONDS,
                page.retentionSeconds);
    }

    @Test
    void operationFailureAndEmergencyKeysetRecoveryEmitSafeDiagnostics() {
        MassDbLicenseState failed = initializedWithLicense(4_000)
                .prepareLicense("failure-op", "failure-key", repeat('6'),
                        MassDbLicenseState.ImportIntent.NORMAL,
                        license("next", repeat('7'), 200, 5_000),
                        "admin", null, 300, 500)
                .failOperation("failure-op", "MASSDB_LICENSE_INGRESS_UNAVAILABLE", 301);
        Assertions.assertEquals("OPERATION_FAILED",
                failed.getDiagnosticEvents().get(0).eventKind);
        Assertions.assertTrue(failed.getDiagnosticEvents().get(0).subjectKey
                .startsWith("sha256-"));

        MassDbLicenseState prepared = failed
                .createClockChallenge("challenge", repeat('3'), 400, 900)
                .prepareKeyset("restrictive", "restrictive-key", repeat('8'),
                        MassDbLicenseState.MutationKind.RESTRICTIVE_KEYSET,
                        keyset(2, '9'), 401, 500);
        MassDbLicenseState recovered = commitKeyset(prepared, "restrictive", 402);
        Assertions.assertEquals(2, recovered.getDiagnosticEvents().size());
        Assertions.assertEquals(
                "CLOCK_RECOVERY_CHALLENGE_INVALIDATED_BY_KEYSET_RECOVERY",
                recovered.getDiagnosticEvents().get(1).eventKind);
        Assertions.assertTrue(recovered.getDiagnosticEvents().get(1).active);
    }

    private static MassDbLicenseState initializedWithLicense(long expiresAt) {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(false, PLAN_SHA);
        state = state.prepareLicense("op-1", "key-1", REQUEST_SHA,
                MassDbLicenseState.ImportIntent.NORMAL,
                license("initial", repeat('0'), 100, expiresAt),
                "admin", null, 200, 300);
        state = state.commit("op-1", 201);
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured("fe-1", "https://fe-1:8050", true);
        state = state.prepareIngressInventory("base-ingress", "base-ingress-idem",
                        repeat('a'), inventory, 202, 300)
                .commit("base-ingress", 203)
                .recordIngressHeartbeat("fe-1", true, 204, 1_000)
                .recordRoutingEvidence("fe-1",
                        MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                        MassDbLicenseIngressInventory.EvidenceSource.MACHINE, 204, 1_000);
        return state.recordIngressActiveAck("fe-1",
                state.getActiveLicense().getSha256(),
                state.getActiveLicense().getExpiresAt(), state.getEnforcementEpoch());
    }

    private static MassDbLicenseState readyObserveState() {
        MassDbLicenseState state = readyObserveStateWithoutAck();
        return state.recordIngressActiveAck(
                "fe-1", state.getActiveLicense().getSha256(),
                state.getActiveLicense().getExpiresAt(), state.getEnforcementEpoch());
    }

    private static MassDbLicenseState readyObserveStateWithoutAck() {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, PLAN_SHA);
        state = state.prepareLicense("observe-license", "observe-license-idem", REQUEST_SHA,
                MassDbLicenseState.ImportIntent.NORMAL,
                license("initial", repeat('0'), 100, 2_000),
                "admin", null, 200, 250).commit("observe-license", 201);
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured("fe-1", "https://fe-1:8050", true);
        state = state.prepareIngressInventory("observe-ingress", "observe-ingress-idem", repeat('3'),
                inventory, 210, 250).commit("observe-ingress", 211);
        state = state.recordIngressHeartbeat("fe-1", true, 220, 1_000);
        return state.recordRoutingEvidence("fe-1",
                MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                MassDbLicenseIngressInventory.EvidenceSource.MACHINE, 220, 1_000);
    }

    private static MassDbLicenseState.ActiveLicense license(
            String id, String sha, long issuedAt, long expiresAt) {
        return new MassDbLicenseState.ActiveLicense(
                id, sha, "license-kid", issuedAt, expiresAt, new byte[] {1, 2, 3});
    }

    private static MassDbLicenseState.ActiveKeyset keyset(long version, char shaCharacter) {
        return new MassDbLicenseState.ActiveKeyset(
                version, repeat(shaCharacter), new byte[] {4, 5, 6});
    }

    private static MassDbLicenseState commitKeyset(MassDbLicenseState prepared,
            String operationId, long now) {
        MassDbLicenseState.Mutation mutation = prepared.getMutation();
        MassDbLicenseState.ActiveLicense replacement = mutation.getCandidateLicense();
        List<MassDbLicenseState.KeysetAckEvidence> evidence = new java.util.ArrayList<>();
        for (String nodeUuid : mutation.getRequiredAckNodeUuids()) {
            evidence.add(new MassDbLicenseState.KeysetAckEvidence(nodeUuid, operationId,
                    mutation.getCandidateKeyset().getSha256(),
                    mutation.getCandidateKeyset().getVersion(),
                    replacement == null ? null : replacement.getSha256(),
                    replacement == null ? 0 : replacement.getExpiresAt(), repeat('b')));
        }
        return prepared.commitKeysetControl(operationId, evidence, now);
    }

    private static String repeat(char value) {
        StringBuilder result = new StringBuilder(64);
        for (int index = 0; index < 64; index++) {
            result.append(value);
        }
        return result.toString();
    }
}
