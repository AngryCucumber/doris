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

import org.apache.doris.common.Config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

class MassDbLicenseFeRoleTransportTest {
    private static final long NOW = 1_767_225_600L;
    private static final long MAX_TERM = 31_536_000L;
    private static final String LICENSE_SHA =
            "b3f71e8f014c7eaf0f81db83a13803b34648617d3baf2e38b3e44ef0700e1745";
    private static final AtomicLong ROLE_SEQUENCE = new AtomicLong();

    @TempDir
    Path temporaryDirectory;

    @Test
    void uninitializedExistingClusterPreservesLegacyQueryBehavior() throws Exception {
        MassDbLicenseManager manager = new MassDbLicenseManager(
                MassDbLicenseState.empty(), ignored -> { });
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("legacy-uninitialized"));
        MassDbLicenseSpiffeIdentity.Identity identity = identity(
                "00000000-0000-4000-8000-000000000011", store.getNodeUuid());
        MassDbLicenseFeRoleClient client = roleClient(
                manager, new MassDbLicenseImportCore(MAX_TERM, roots()), store,
                (host, port, request, snapshot) -> {
                    throw new AssertionError("UNINITIALIZED不应请求Leader");
                }, identity);

        Assertions.assertTrue(client.evaluateLocalQuery().allowed);
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.NOT_INITIALIZED,
                client.cycle(NOW));
        Assertions.assertTrue(client.evaluateLocalQuery().allowed);
    }

    @Test
    void diskKeyStoreTransportRequiresExplicitDevelopmentDebugGate() {
        boolean previousDebug = Config.enable_debug_points;
        boolean previousDevelopment =
                Config.massdb_license_role_mtls_development_keystore_enabled;
        try {
            Config.enable_debug_points = false;
            Config.massdb_license_role_mtls_development_keystore_enabled = true;
            MassDbLicenseException withoutDebug = Assertions.assertThrows(
                    MassDbLicenseException.class,
                    MassDbLicenseFeRoleClient::requireDevelopmentKeyStoreAllowed);
            Assertions.assertEquals("MASSDB_LICENSE_ROLE_MTLS_CONFIG_INVALID",
                    withoutDebug.getCode());

            Config.enable_debug_points = true;
            Config.massdb_license_role_mtls_development_keystore_enabled = false;
            Assertions.assertThrows(MassDbLicenseException.class,
                    MassDbLicenseFeRoleClient::requireDevelopmentKeyStoreAllowed);

            Config.massdb_license_role_mtls_development_keystore_enabled = true;
            Assertions.assertDoesNotThrow(
                    MassDbLicenseFeRoleClient::requireDevelopmentKeyStoreAllowed);
        } finally {
            Config.enable_debug_points = previousDebug;
            Config.massdb_license_role_mtls_development_keystore_enabled =
                    previousDevelopment;
        }
    }

    @Test
    void normalImportSurvivesLeaderAndRoleRestartBeforeTerminalLookup() throws Exception {
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("role"));
        String nodeUuid = store.getNodeUuid();
        Map<String, PublicKey> roots = roots();
        byte[] keysetBytes = MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.KEYSET);
        byte[] licenseBytes = MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.VALID_LICENSE);
        MassDbLicenseProtocolV1.VerifiedKeyset keyset =
                MassDbLicenseProtocolV1.verifyKeyset(keysetBytes, roots, NOW, null);
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(false, repeat('a'))
                .prepareKeyset("keyset", "keyset-idem", repeat('b'),
                        MassDbLicenseState.MutationKind.ADDITIVE_KEYSET,
                        new MassDbLicenseState.ActiveKeyset(
                                keyset.getPayload().getKeysetVersion(),
                                keyset.getSha256(), keysetBytes), NOW, NOW + 60)
                .commit("keyset", NOW);
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured(nodeUuid, "https://fe-1:8050", true);
        state = state.prepareIngressInventory("ingress", "ingress-idem", repeat('c'),
                inventory, NOW, NOW + 60).commit("ingress", NOW)
                .recordIngressHeartbeat(nodeUuid, true, NOW, NOW + 120)
                .recordRoutingEvidence(nodeUuid,
                        MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                        MassDbLicenseIngressInventory.EvidenceSource.MACHINE,
                        NOW, NOW + 120);
        MassDbLicenseReadApiCore readCore = new MassDbLicenseReadApiCore(
                "4.0.5", MAX_TERM, roots);
        MassDbLicenseReadApiCore.ValidateResult validation =
                readCore.validateNormal(state, licenseBytes, NOW);
        MassDbLicenseImportCore importCore = new MassDbLicenseImportCore(MAX_TERM, roots);
        MassDbLicenseImportCore.Result prepared = importCore.prepareNormal(
                state, licenseBytes, LICENSE_SHA, validation.preconditionToken,
                "normal-idem", "normal-op", "admin-cert", NOW, NOW + 300);

        List<MassDbLicenseState> journal = new ArrayList<>();
        MassDbLicenseManager manager = new MassDbLicenseManager(prepared.state, journal::add);
        MassDbLicenseLeaderReconciler reconciler = new MassDbLicenseLeaderReconciler(
                manager, new MassDbLicenseEnforcementCore(), 1_000);
        reconciler.setNormalImportCore(importCore);
        AtomicReference<MassDbLicenseFeRoleTransport> leaderTransport =
                new AtomicReference<>(new MassDbLicenseFeRoleTransport(manager, true));
        reconciler.setTrustedRoleTransport(leaderTransport.get());
        String deploymentUuid = manager.snapshot().getLicenseControlDeploymentUuid();
        MassDbLicenseSpiffeIdentity.Identity identity = identity(deploymentUuid, nodeUuid);
        MassDbLicenseFeRoleClient.ExchangeClient exchange =
                new MassDbLicenseFeRoleClient.ExchangeClient() {
                    @Override
                    public MassDbLicenseFeRoleProtocol.ExchangeResponse exchange(
                            String host, int port,
                            MassDbLicenseFeRoleProtocol.ExchangeRequest request,
                            MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot) {
                        return leaderTransport.get().exchange(identity, request, NOW + 1);
                    }
                };

        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.WAITING_FOR_ACKS,
                reconciler.reconcileOnce(NOW + 1));
        MassDbLicenseFeRoleClient firstRole = roleClient(
                manager, importCore, store, exchange, identity);
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.PREPARED_ACK,
                firstRole.cycle(NOW + 1));
        Assertions.assertNotNull(store.loadLicensePending());
        Assertions.assertNull(store.loadActive());

        MassDbLicenseFeRoleTransport promoted =
                new MassDbLicenseFeRoleTransport(manager, true);
        leaderTransport.set(promoted);
        reconciler.setTrustedRoleTransport(promoted);
        MassDbLicenseLocalSnapshotStore restartedStore = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("role"));
        Assertions.assertEquals(nodeUuid, restartedStore.getNodeUuid());
        MassDbLicenseFeRoleClient restartedRole = roleClient(
                manager, importCore, restartedStore, exchange, identity);
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.EXCHANGED,
                restartedRole.cycle(NOW + 1));
        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.WAITING_FOR_ACKS,
                reconciler.reconcileOnce(NOW + 1));
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.PREPARED_ACK,
                restartedRole.cycle(NOW + 1));
        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.COMMITTED,
                reconciler.reconcileOnce(NOW + 2));
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.APPLIED_DECISION,
                restartedRole.cycle(NOW + 3));

        Assertions.assertNull(restartedStore.loadLicensePending());
        Assertions.assertEquals(LICENSE_SHA, restartedStore.loadActive().sha256);
        Assertions.assertEquals(MassDbLicenseState.OperationState.SUCCEEDED,
                manager.snapshot().findOperation("normal-op").state);
        Assertions.assertFalse(journal.isEmpty());
        Assertions.assertEquals(MassDbLicenseState.OperationState.SUCCEEDED,
                journal.get(journal.size() - 1).findOperation("normal-op").state);
        Assertions.assertEquals(nodeUuid, promoted.findSession(nodeUuid).nodeUuid);
    }

    @Test
    void rejectsPayloadIdentityThatDoesNotMatchAuthenticatedSpiffeNode() {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, repeat('d'));
        MassDbLicenseManager manager = new MassDbLicenseManager(state, ignored -> { });
        MassDbLicenseFeRoleTransport transport =
                new MassDbLicenseFeRoleTransport(manager, true);
        String deploymentUuid = state.getLicenseControlDeploymentUuid();
        String authenticatedNode = "00000000-0000-4000-8000-000000000011";
        MassDbLicenseFeRoleProtocol.ExchangeRequest request =
                new MassDbLicenseFeRoleProtocol.ExchangeRequest(
                        deploymentUuid, "00000000-0000-4000-8000-000000000012",
                        "00000000-0000-4000-8000-000000000013",
                        new MassDbLicenseFeRoleProtocol.RoleStatus(), null, null);

        MassDbLicenseException error = Assertions.assertThrows(MassDbLicenseException.class,
                () -> transport.exchange(identity(deploymentUuid, authenticatedNode),
                        request, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH", error.getCode());
    }

    @Test
    void distinctProcessInstancesCreateDurableConflictAndRequireDualLeaseClear() {
        String nodeUuid = "00000000-0000-4000-8000-000000000021";
        String firstProcess = "00000000-0000-4000-8000-000000000022";
        String secondProcess = "00000000-0000-4000-8000-000000000023";
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, repeat('7'));
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured(nodeUuid, "https://fe-conflict:8050", true);
        state = state.prepareIngressInventory("conflict-ingress", "conflict-ingress-idem",
                repeat('8'), inventory, NOW - 10, NOW + 300)
                .commit("conflict-ingress", NOW - 9);
        List<MassDbLicenseState> journal = new ArrayList<>();
        MassDbLicenseManager manager = new MassDbLicenseManager(state, journal::add);
        MassDbLicenseFeRoleTransport transport =
                new MassDbLicenseFeRoleTransport(manager, true);
        String deploymentUuid = state.getLicenseControlDeploymentUuid();
        MassDbLicenseSpiffeIdentity.Identity identity = identity(deploymentUuid, nodeUuid);

        MassDbLicenseFeRoleProtocol.ExchangeResponse first = transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess, false, 0, true), NOW);
        Assertions.assertNull(first.identityConflict);
        Assertions.assertEquals(firstProcess,
                transport.findSession(nodeUuid).processInstanceUuid);
        transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess, false, 0, true), NOW + 1);

        MassDbLicenseFeRoleProtocol.ExchangeResponse conflicted = transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, secondProcess, false, 0, true), NOW + 2);
        Assertions.assertNotNull(conflicted.identityConflict);
        Assertions.assertTrue(conflicted.identityConflict.active);
        Assertions.assertNull(transport.findSession(nodeUuid));
        MassDbLicenseIngressInventory.IngressNode node = manager.snapshot()
                .getIngressInventory().getNodes().get(nodeUuid);
        Assertions.assertTrue(node.isAuthoritativeIdentityConflict());
        Assertions.assertTrue(node.isReportedIdentityConflict());
        Assertions.assertFalse(node.isGuardReady());

        long conflictRevision = conflicted.identityConflict.controlPlaneRevision;
        transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess,
                        true, conflictRevision, false), NOW + 3);
        transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess,
                        true, conflictRevision, false), NOW + 92);
        node = manager.snapshot().getIngressInventory().getNodes().get(nodeUuid);
        Assertions.assertTrue(node.isAuthoritativeIdentityConflict(),
                "单一实例刚出现时不能立即解除冲突");
        transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess,
                        true, conflictRevision, false), NOW + 181);
        MassDbLicenseFeRoleProtocol.ExchangeResponse resolved = transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess,
                        true, conflictRevision, false), NOW + 182);
        Assertions.assertNotNull(resolved.identityConflict);
        Assertions.assertFalse(resolved.identityConflict.active);
        Assertions.assertTrue(resolved.identityConflict.controlPlaneRevision > conflictRevision);

        long resolvedRevision = resolved.identityConflict.controlPlaneRevision;
        MassDbLicenseFeRoleProtocol.ExchangeResponse confirmed = transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess,
                        false, resolvedRevision, true), NOW + 183);
        Assertions.assertNull(confirmed.identityConflict);
        node = manager.snapshot().getIngressInventory().getNodes().get(nodeUuid);
        Assertions.assertFalse(node.isIdentityConflicted());
        Assertions.assertTrue(node.isGuardReady());
        Assertions.assertTrue(node.isLive(NOW + 183));
        Assertions.assertFalse(journal.isEmpty());
    }

    @Test
    void expiredSessionsArePrunedAcrossNodeBuckets() {
        String firstNode = "00000000-0000-4000-8000-000000000025";
        String secondNode = "00000000-0000-4000-8000-000000000026";
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, repeat('7'));
        MassDbLicenseManager manager = new MassDbLicenseManager(state, ignored -> { });
        MassDbLicenseFeRoleTransport transport =
                new MassDbLicenseFeRoleTransport(manager, true);
        String deploymentUuid = state.getLicenseControlDeploymentUuid();

        transport.exchange(identity(deploymentUuid, firstNode),
                roleRequest(deploymentUuid, firstNode,
                        "00000000-0000-4000-8000-000000000027", false, 0, false), NOW);
        Assertions.assertNotNull(transport.findSession(firstNode));

        transport.exchange(identity(deploymentUuid, secondNode),
                roleRequest(deploymentUuid, secondNode,
                        "00000000-0000-4000-8000-000000000028", false, 0, false),
                NOW + MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS);
        Assertions.assertNull(transport.findSession(firstNode),
                "其他节点的认证交换也必须清除全局过期会话");
        Assertions.assertNotNull(transport.findSession(secondNode));
    }

    @Test
    void rejectsReplayedReportSequenceWithinOneProcessSession() {
        String nodeUuid = "00000000-0000-4000-8000-000000000029";
        String processUuid = "00000000-0000-4000-8000-000000000030";
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, repeat('7'));
        MassDbLicenseManager manager = new MassDbLicenseManager(state, ignored -> { });
        MassDbLicenseFeRoleTransport transport =
                new MassDbLicenseFeRoleTransport(manager, true);
        String deploymentUuid = state.getLicenseControlDeploymentUuid();
        MassDbLicenseFeRoleProtocol.ExchangeRequest request = roleRequest(
                deploymentUuid, nodeUuid, processUuid, false, 0, false);

        transport.exchange(identity(deploymentUuid, nodeUuid), request, NOW);
        MassDbLicenseException replay = Assertions.assertThrows(MassDbLicenseException.class,
                () -> transport.exchange(
                        identity(deploymentUuid, nodeUuid), request, NOW + 1));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", replay.getCode());
    }

    @Test
    void roleClientPersistsLeaderConflictMarkerBeforeReturningFromExchange() throws Exception {
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("conflict-role-client"));
        String nodeUuid = store.getNodeUuid();
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, repeat('9'));
        MassDbLicenseManager manager = new MassDbLicenseManager(state, ignored -> { });
        manager.transition(current -> current.advanceMaxSeenWallClock(NOW));
        String deploymentUuid = state.getLicenseControlDeploymentUuid();
        MassDbLicenseSpiffeIdentity.Identity identity = identity(deploymentUuid, nodeUuid);
        MassDbLicenseFeRoleClient role = roleClient(manager,
                new MassDbLicenseImportCore(MAX_TERM, roots()), store,
                new MassDbLicenseFeRoleClient.ExchangeClient() {
                    @Override
                    public MassDbLicenseFeRoleProtocol.ExchangeResponse exchange(
                            String host, int port,
                            MassDbLicenseFeRoleProtocol.ExchangeRequest request,
                            MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot) {
                        MassDbLicenseFeRoleProtocol.IdentityConflict marker =
                                new MassDbLicenseFeRoleProtocol.IdentityConflict(
                                        true, 1, deploymentUuid, NOW, NOW,
                                        NOW + MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS,
                                        0);
                        return new MassDbLicenseFeRoleProtocol.ExchangeResponse(
                                deploymentUuid, NOW, marker,
                                MassDbLicenseFeRoleProtocol.ControlPlaneSync.from(
                                        manager.snapshot(), request.status.reportSequence, NOW),
                                Collections.emptyList(), Collections.emptyList());
                    }
                }, identity);

        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.EXCHANGED,
                role.cycle(NOW));
        Assertions.assertTrue(store.loadIdentityConflict().active);
        Assertions.assertEquals("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                store.evaluateQuery(MassDbLicenseState.EnforcementMode.OBSERVE, NOW).errorCode);
        Assertions.assertEquals(role.getProcessInstanceUuid(), role.getProcessInstanceUuid());
    }

    @Test
    void conflictDiscardsAcceptedAckAndResolvedSessionMustResendIt() throws Exception {
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("conflict-clears-ack"));
        String nodeUuid = store.getNodeUuid();
        byte[] artifact = MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.VALID_LICENSE);
        long expiresAt = goldenLicense().getPayload().getExpiresAt();
        store.writeActive(new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                artifact, LICENSE_SHA, expiresAt, 0, NOW - 1));
        MassDbLicenseState state = readyObserveState(nodeUuid, artifact)
                .prepareEnforcementActivation(
                        "conflict-ack-op", "conflict-ack-idem", repeat('6'),
                        NOW, NOW + 300);
        MassDbLicenseManager manager = new MassDbLicenseManager(state, ignored -> { });
        MassDbLicenseEnforcementCore enforcementCore = new MassDbLicenseEnforcementCore();
        MassDbLicenseEnforcementCore.RedriveResult recovered = enforcementCore.recover(
                state, "conflict-ack-op", NOW + 1);
        Assertions.assertNotNull(recovered.plan);
        MassDbLicenseFeRoleTransport transport =
                new MassDbLicenseFeRoleTransport(manager, true);
        Assertions.assertTrue(transport.prepareEnforcement(recovered.plan).isEmpty());
        String deploymentUuid = state.getLicenseControlDeploymentUuid();
        MassDbLicenseSpiffeIdentity.Identity identity = identity(deploymentUuid, nodeUuid);
        MassDbLicenseFeRoleClient role = roleClient(manager,
                new MassDbLicenseImportCore(MAX_TERM, roots()), store,
                new MassDbLicenseFeRoleClient.ExchangeClient() {
                    @Override
                    public MassDbLicenseFeRoleProtocol.ExchangeResponse exchange(
                            String host, int port,
                            MassDbLicenseFeRoleProtocol.ExchangeRequest request,
                            MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot) {
                        return transport.exchange(identity, request, NOW + 1);
                    }
                }, identity);
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.PREPARED_ACK,
                role.cycle(NOW + 1));
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.PREPARED_ACK,
                role.cycle(NOW + 1));
        Assertions.assertEquals(1, transport.prepareEnforcement(recovered.plan).size());
        MassDbLicenseIngressInventory.IngressNode trusted = manager.snapshot()
                .getIngressInventory().getNodes().get(nodeUuid);
        Assertions.assertEquals(MassDbLicenseFeRoleProtocol.VerificationState.VERIFIED,
                trusted.getReportedVerificationState());
        Assertions.assertEquals("FRESH", trusted.getReportedControlPlaneFreshness());
        Assertions.assertTrue(trusted.getLastVerifiedEffectiveNow() >= NOW + 1);

        String cloneProcess = "00000000-0000-4000-8000-000000000024";
        MassDbLicenseFeRoleProtocol.ExchangeResponse conflicted = transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, cloneProcess, false, 0, true), NOW + 2);
        Assertions.assertTrue(conflicted.identityConflict.active);
        Assertions.assertTrue(transport.prepareEnforcement(recovered.plan).isEmpty());

        String firstProcess = role.getProcessInstanceUuid();
        long conflictRevision = conflicted.identityConflict.controlPlaneRevision;
        transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess,
                        true, conflictRevision, false), NOW + 92);
        transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess,
                        true, conflictRevision, false), NOW + 181);
        MassDbLicenseFeRoleProtocol.ExchangeResponse resolved = transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess,
                        true, conflictRevision, false), NOW + 182);
        Assertions.assertNotNull(resolved.identityConflict);
        Assertions.assertFalse(resolved.identityConflict.active);
        transport.exchange(identity,
                roleRequest(deploymentUuid, nodeUuid, firstProcess, false,
                        resolved.identityConflict.controlPlaneRevision, true), NOW + 183);

        Assertions.assertTrue(transport.prepareEnforcement(recovered.plan).isEmpty(),
                "冲突前ACK不能在解除后复用，唯一FE必须从本地pending重新发送");
    }

    @Test
    void enforcementCommandCommitsOnlyAfterDurableRoleAck() throws Exception {
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("enforcement-role"));
        String nodeUuid = store.getNodeUuid();
        byte[] artifact = MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.VALID_LICENSE);
        long expiresAt = goldenLicense().getPayload().getExpiresAt();
        store.writeActive(new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                artifact, LICENSE_SHA, expiresAt, 0, NOW - 1));
        MassDbLicenseState state = readyObserveState(nodeUuid, artifact)
                .prepareEnforcementActivation(
                        "enforce-op", "enforce-idem", repeat('e'), NOW, NOW + 300);
        MassDbLicenseManager manager = new MassDbLicenseManager(state, ignored -> { });
        MassDbLicenseLeaderReconciler reconciler = new MassDbLicenseLeaderReconciler(
                manager, new MassDbLicenseEnforcementCore(), 1_000);
        MassDbLicenseFeRoleTransport transport =
                new MassDbLicenseFeRoleTransport(manager, true);
        reconciler.setTrustedRoleTransport(transport);
        String deploymentUuid = state.getLicenseControlDeploymentUuid();
        MassDbLicenseSpiffeIdentity.Identity identity = identity(deploymentUuid, nodeUuid);
        MassDbLicenseFeRoleClient role = roleClient(
                manager, new MassDbLicenseImportCore(MAX_TERM, roots()), store,
                new MassDbLicenseFeRoleClient.ExchangeClient() {
                    @Override
                    public MassDbLicenseFeRoleProtocol.ExchangeResponse exchange(
                            String host, int port,
                            MassDbLicenseFeRoleProtocol.ExchangeRequest request,
                            MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot) {
                        return transport.exchange(identity, request, NOW + 1);
                    }
                }, identity);

        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.WAITING_FOR_ACKS,
                reconciler.reconcileOnce(NOW + 1));
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.PREPARED_ACK,
                role.cycle(NOW + 1));
        Assertions.assertNotNull(store.loadPending());
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.PREPARED_ACK,
                role.cycle(NOW + 1));
        Assertions.assertEquals(MassDbLicenseLeaderReconciler.Outcome.COMMITTED,
                reconciler.reconcileOnce(NOW + 2));
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.APPLIED_DECISION,
                role.cycle(NOW + 3));
        Assertions.assertNull(store.loadPending());
        Assertions.assertEquals(1, store.loadActive().enforcementEpoch);
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.ENFORCING,
                manager.snapshot().getEnforcementMode());
    }

    private static MassDbLicenseFeRoleClient roleClient(
            MassDbLicenseManager manager, MassDbLicenseImportCore importCore,
            MassDbLicenseLocalSnapshotStore store,
            MassDbLicenseFeRoleClient.ExchangeClient exchange,
            MassDbLicenseSpiffeIdentity.Identity identity) {
        MassDbLicenseFeRoleClient client = new MassDbLicenseFeRoleClient(
                manager, importCore, store, new MassDbLicenseEnforcementCore(),
                new MassDbLicenseFeRoleClient.EndpointProvider() {
                    @Override
                    public String masterHost() {
                        return "leader.example";
                    }

                    @Override
                    public int httpsPort() {
                        return 8050;
                    }
                }, exchange, new MassDbLicenseFeRoleIdentityProvider.Rotating(
                        identitySnapshot(identity)), 1_000);
        client.markQueryGuardInstalled();
        return client;
    }

    private static MassDbLicenseFeRoleIdentityProvider.Snapshot identitySnapshot(
            MassDbLicenseSpiffeIdentity.Identity identity) {
        try {
            return new MassDbLicenseFeRoleIdentityProvider.Snapshot(
                    1L, javax.net.ssl.SSLContext.getDefault(), identity,
                    NOW - 60, NOW + 3_600);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    private static MassDbLicenseSpiffeIdentity.Identity identity(
            String deploymentUuid, String nodeUuid) {
        return MassDbLicenseSpiffeIdentity.parseUnique(Collections.singletonList(
                "spiffe://massdb.internal/license/component/massdb-sql/"
                        + deploymentUuid + "/fe/" + nodeUuid));
    }

    private static MassDbLicenseFeRoleProtocol.ExchangeRequest roleRequest(
            String deploymentUuid, String nodeUuid, String processInstanceUuid,
            boolean identityConflict, long identityConflictRevision, boolean guardReady) {
        MassDbLicenseFeRoleProtocol.RoleStatus status =
                new MassDbLicenseFeRoleProtocol.RoleStatus();
        status.reportSequence = ROLE_SEQUENCE.incrementAndGet();
        status.observedWallClock = NOW;
        status.identityConflict = identityConflict;
        status.identityConflictRevision = identityConflictRevision;
        status.guardReady = guardReady;
        status.localStateErrorCode = identityConflict
                ? "MASSDB_LICENSE_DUPLICATE_NODE_UUID" : null;
        return new MassDbLicenseFeRoleProtocol.ExchangeRequest(
                deploymentUuid, nodeUuid, processInstanceUuid, status, null, null);
    }

    private static Map<String, PublicKey> roots() {
        return Collections.singletonMap("massdb-test-root-1",
                MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.decode(
                                MassDbLicenseProtocolV1Test.ROOT_PUBLIC)));
    }

    private static MassDbLicenseState readyObserveState(String nodeUuid, byte[] artifact) {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, repeat('f'));
        byte[] keysetArtifact = MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.KEYSET);
        MassDbLicenseProtocolV1.VerifiedKeyset keyset = goldenKeyset();
        state = state.prepareKeyset("fixture-keyset", "fixture-keyset-idem", repeat('3'),
                MassDbLicenseState.MutationKind.ADDITIVE_KEYSET,
                new MassDbLicenseState.ActiveKeyset(
                        keyset.getPayload().getKeysetVersion(), keyset.getSha256(),
                        keysetArtifact), NOW - 200, NOW - 150)
                .commit("fixture-keyset", NOW - 199);
        MassDbLicenseProtocolV1.VerifiedLicense verified = goldenLicense();
        MassDbLicenseState.ActiveLicense active = new MassDbLicenseState.ActiveLicense(
                verified.getPayload().getLicenseId(), verified.getSha256(), verified.getKid(),
                verified.getPayload().getIssuedAt(), verified.getPayload().getExpiresAt(),
                artifact);
        state = state.prepareLicense("license", "license-idem", repeat('1'),
                MassDbLicenseState.ImportIntent.NORMAL, active,
                "admin", null, NOW - 50, NOW - 40).commit("license", NOW - 49);
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured(nodeUuid, "https://fe-1:8050", true);
        state = state.prepareIngressInventory("ingress", "ingress-idem", repeat('2'),
                inventory, NOW - 40, NOW - 30).commit("ingress", NOW - 39)
                .recordIngressHeartbeat(nodeUuid, true, NOW - 10, NOW + 120)
                .recordRoutingEvidence(nodeUuid,
                        MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                        MassDbLicenseIngressInventory.EvidenceSource.MACHINE,
                        NOW - 10, NOW + 120);
        return state.recordIngressActiveAck(nodeUuid, verified.getSha256(),
                verified.getPayload().getExpiresAt(), 0);
    }

    private static MassDbLicenseProtocolV1.VerifiedKeyset goldenKeyset() {
        return MassDbLicenseProtocolV1.verifyKeyset(
                MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.KEYSET),
                roots(), NOW, null);
    }

    private static MassDbLicenseProtocolV1.VerifiedLicense goldenLicense() {
        return MassDbLicenseProtocolV1.verifyLicense(
                MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.VALID_LICENSE),
                goldenKeyset(), NOW, MAX_TERM, null);
    }

    private static String repeat(char value) {
        return String.join("", Collections.nCopies(64, String.valueOf(value)));
    }
}
