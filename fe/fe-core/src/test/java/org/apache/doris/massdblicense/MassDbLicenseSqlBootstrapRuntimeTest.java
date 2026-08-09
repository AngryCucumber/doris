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

import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.BackendMember;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.FrontendMember;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.IngestAccount;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.InstallationHealth;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.InstallationPlan;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

class MassDbLicenseSqlBootstrapRuntimeTest {
    private static final long NOW = 1_767_225_600L;
    private static final long MAX_TERM = 31_536_000L;
    private static final String MARKER_ID = "00000000-0000-4000-8000-000000000051";
    private static final String DEPLOYMENT_ID = "00000000-0000-4000-8000-000000000052";
    private static final String MASTER_NODE_ID = "00000000-0000-4000-8000-000000000053";
    private static final String FOLLOWER_NODE_ID = "00000000-0000-4000-8000-000000000054";
    private static final String BACKEND_NODE_ID = "00000000-0000-4000-8000-000000000055";

    @Test
    void reconcilesMissingMembersAndAccountIdempotently() {
        InstallationPlan plan = installationPlan();
        FakeControl control = new FakeControl();
        MassDbLicenseSqlBootstrapRuntime runtime =
                new MassDbLicenseSqlBootstrapRuntime(control);

        runtime.requireCompatible(plan, NOW);
        InstallationHealth first = runtime.reconcileAndRequireHealthy(plan, NOW);
        Assertions.assertEquals(2, first.plannedFrontends);
        Assertions.assertEquals(2, first.aliveFrontends);
        Assertions.assertEquals(1, first.plannedBackends);
        Assertions.assertEquals(1, first.aliveBackends);
        Assertions.assertEquals(1, first.readyIngestRoutes);
        Assertions.assertTrue(first.ingestAccountReady);
        Assertions.assertEquals(1, control.addedFrontends);
        Assertions.assertEquals(1, control.addedBackends);
        Assertions.assertEquals(1, control.ensuredAccounts);

        InstallationHealth replay = runtime.reconcileAndRequireHealthy(plan, NOW + 1);
        Assertions.assertEquals(2, replay.aliveFrontends);
        Assertions.assertEquals(1, replay.aliveBackends);
        Assertions.assertTrue(replay.ingestAccountReady);
        Assertions.assertEquals(1, control.addedFrontends);
        Assertions.assertEquals(1, control.addedBackends);
        Assertions.assertEquals(2, control.ensuredAccounts);
    }

    @Test
    void rejectsBusinessMetadataAndUnplannedTopologyBeforeMutation() {
        InstallationPlan plan = installationPlan();
        FakeControl metadata = new FakeControl();
        metadata.databaseNames.add("customer_data");
        MassDbLicenseException notFresh = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> new MassDbLicenseSqlBootstrapRuntime(metadata)
                        .reconcileAndRequireHealthy(plan, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH", notFresh.getCode());
        Assertions.assertEquals(0, metadata.addedFrontends);
        Assertions.assertEquals(0, metadata.addedBackends);

        FakeControl topology = new FakeControl();
        topology.backends.add(new MassDbLicenseSqlBootstrapRuntime.BackendStatus(
                "be-outside.example", 9050, 9060, 8040, 8060, true));
        MassDbLicenseException conflict = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> new MassDbLicenseSqlBootstrapRuntime(topology)
                        .reconcileAndRequireHealthy(plan, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_TOPOLOGY_CONFLICT",
                conflict.getCode());
        Assertions.assertEquals(0, topology.addedFrontends);
        Assertions.assertEquals(0, topology.addedBackends);
    }

    @Test
    void returnsOnlySealedMinimalTopologyAndDoesNotTreatHeartbeatAsIdentity() {
        FakeControl control = new FakeControl();
        control.frontends.add(new MassDbLicenseSqlBootstrapRuntime.FrontendStatus(
                "FOLLOWER", "fe-2.example", 9010, 9030, true,
                control.buildVersion));
        control.backends.add(new MassDbLicenseSqlBootstrapRuntime.BackendStatus(
                "be-1.example", 9050, 9060, 8040, 8060, true));
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured(MASTER_NODE_ID,
                        "https://fe-1.example:8050", true)
                .upsertConfigured(FOLLOWER_NODE_ID,
                        "https://fe-2.example:8050", true);
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(false, repeat('a', 64));
        state = state.prepareIngressInventory("inventory-operation", "inventory-idem",
                repeat('b', 64), inventory, NOW, NOW + 60)
                .commit("inventory-operation", NOW)
                .recordIngressHeartbeat(MASTER_NODE_ID, true, NOW, NOW + 120);

        MassDbLicenseSqlBootstrapRuntime.MinimalTopology topology =
                new MassDbLicenseSqlBootstrapRuntime(control).minimalTopology(state, NOW);

        Assertions.assertEquals("massdb-sql", topology.componentType);
        Assertions.assertEquals("SEALED", topology.bootstrapPhase);
        Assertions.assertEquals(2, topology.summary.actualFrontendCount);
        Assertions.assertEquals(1, topology.summary.actualBackendCount);
        Assertions.assertEquals(2, topology.summary.desiredIngressCount);
        Assertions.assertEquals(1, topology.summary.liveDesiredIngressCount);
        Assertions.assertEquals("UNSEEN", topology.ingressNodes.get(0).identityStatus);
        Assertions.assertEquals("UNSEEN", topology.ingressNodes.get(1).identityStatus);
        String json = org.apache.doris.persist.gson.GsonUtils.GSON.toJson(topology);
        Assertions.assertFalse(json.contains("buildVersion"));
        Assertions.assertFalse(json.contains("businessDatabase"));
        Assertions.assertFalse(json.contains("licenseId"));

        MassDbLicenseException uninitialized = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> new MassDbLicenseSqlBootstrapRuntime(control)
                        .minimalTopology(MassDbLicenseState.empty(), NOW));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_REQUIRED",
                uninitialized.getCode());
    }

    @Test
    void existingClusterPreflightNeverAuthorizesObserveFromOrdinaryHeartbeat() {
        FakeControl control = new FakeControl();
        control.databaseNames.add("customer_data");
        control.frontends.clear();
        control.frontends.add(new MassDbLicenseSqlBootstrapRuntime.FrontendStatus(
                "MASTER", "fe-1.example", 9010, 9030, true,
                control.buildVersion));
        control.frontends.add(new MassDbLicenseSqlBootstrapRuntime.FrontendStatus(
                "FOLLOWER", "fe-2.example", 9010, 9030, true,
                control.buildVersion));
        MassDbLicenseState state = MassDbLicenseState.empty();

        MassDbLicenseSqlBootstrapRuntime.ObserveUpgradePreflight preflight =
                new MassDbLicenseSqlBootstrapRuntime(control)
                        .observeUpgradePreflight(state, NOW);

        Assertions.assertTrue(preflight.compatibilityHintReady);
        Assertions.assertFalse(preflight.trustedNodeAttestationReady);
        Assertions.assertFalse(preflight.safeToInitializeObserve);
        Assertions.assertEquals("COMPATIBILITY_HINT_ONLY", preflight.evidenceClass);
        Assertions.assertEquals(Collections.singletonList(
                "MASSDB_LICENSE_UPGRADE_TRUSTED_ATTESTATION_REQUIRED"),
                preflight.blockers);
        Assertions.assertFalse(state.isInitialized());

        control.frontends.set(1, new MassDbLicenseSqlBootstrapRuntime.FrontendStatus(
                "FOLLOWER", "fe-2.example", 9010, 9030, false, "old-build"));
        MassDbLicenseSqlBootstrapRuntime.ObserveUpgradePreflight blocked =
                new MassDbLicenseSqlBootstrapRuntime(control)
                        .observeUpgradePreflight(state, NOW);
        Assertions.assertFalse(blocked.compatibilityHintReady);
        Assertions.assertTrue(blocked.blockers.stream()
                .anyMatch(value -> value.startsWith("MASSDB_LICENSE_UPGRADE_FE_OFFLINE:")));
        Assertions.assertTrue(blocked.blockers.stream()
                .anyMatch(value -> value.startsWith(
                        "MASSDB_LICENSE_UPGRADE_BUILD_ID_MISMATCH:")));
    }

    private static InstallationPlan installationPlan() {
        byte[] planBytes = fullPlan();
        MassDbLicenseBootstrapCore.PlanSummary summary =
                MassDbLicenseBootstrapCore.summarize(planBytes);
        MassDbLicenseState open = MassDbLicenseState.empty().openBootstrap(
                MARKER_ID, DEPLOYMENT_ID, summary.planSha256, NOW - 60);
        AtomicReference<InstallationPlan> captured = new AtomicReference<>();
        MassDbLicenseBootstrapCore.WriteHealth capture =
                new MassDbLicenseBootstrapCore.WriteHealth() {
                    @Override
                    public String requireLocalFeIdentity(String deploymentUuid, long now) {
                        return MASTER_NODE_ID;
                    }

                    @Override
                    public void requireFullPlanCompatible(InstallationPlan plan, long now) {
                        captured.set(plan);
                    }
                };
        new MassDbLicenseBootstrapCore(importCore()).validate(
                open, planBytes, capture, NOW);
        return captured.get();
    }

    private static MassDbLicenseImportCore importCore() {
        PublicKey root = MassDbLicenseProtocolV1.parsePublicKeyPem(
                MassDbLicenseProtocolV1Test.rootPublicBytes());
        Map<String, PublicKey> roots = Collections.singletonMap("massdb-test-root-1", root);
        return new MassDbLicenseImportCore(MAX_TERM, roots);
    }

    private static byte[] fullPlan() {
        String keyset = Base64.getEncoder().encodeToString(
                MassDbLicenseProtocolV1Test.keysetBytes());
        String passwordHash = Base64.getEncoder().encodeToString(
                ("*" + repeat('B', 40)).getBytes(StandardCharsets.US_ASCII));
        String json = "{\"formatVersion\":2,\"componentType\":\"massdb-sql\","
                + "\"targetPhase\":\"SEALED\",\"keysetArtifactBase64\":\"" + keyset
                + "\",\"ingressNodes\":[{\"nodeUuid\":\"" + MASTER_NODE_ID
                + "\",\"endpoint\":\"https://fe-1.example:8050\",\"desired\":true},"
                + "{\"nodeUuid\":\"" + FOLLOWER_NODE_ID
                + "\",\"endpoint\":\"https://fe-2.example:8050\",\"desired\":true}],"
                + "\"minimumWriteHealth\":\"ALL_PLANNED_MEMBERS_ALIVE_AND_INGEST_READY\","
                + "\"frontends\":[{\"nodeUuid\":\"" + MASTER_NODE_ID
                + "\",\"role\":\"MASTER\",\"host\":\"fe-1.example\","
                + "\"editLogPort\":9010,\"queryPort\":9030,\"httpsPort\":8050},"
                + "{\"nodeUuid\":\"" + FOLLOWER_NODE_ID
                + "\",\"role\":\"FOLLOWER\",\"host\":\"fe-2.example\","
                + "\"editLogPort\":9010,\"queryPort\":9030,\"httpsPort\":8050}],"
                + "\"backends\":[{\"nodeUuid\":\"" + BACKEND_NODE_ID
                + "\",\"host\":\"be-1.example\",\"heartbeatPort\":9050,"
                + "\"bePort\":9060,\"httpPort\":8040,\"brpcPort\":8060}],"
                + "\"ingestAccount\":{\"username\":\"massdb_ingest\","
                + "\"hostPattern\":\"10.%\",\"passwordHashBase64\":\"" + passwordHash
                + "\",\"privilege\":\"GLOBAL_LOAD_ONLY\"},"
                + "\"ingestRoutes\":[{\"kind\":\"STREAM_LOAD_HTTPS\","
                + "\"feNodeUuid\":\"" + MASTER_NODE_ID
                + "\",\"endpoint\":\"https://fe-1.example:8050\",\"desired\":true}]}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static String repeat(char value, int count) {
        StringBuilder result = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            result.append(value);
        }
        return result.toString();
    }

    private static final class FakeControl
            implements MassDbLicenseSqlBootstrapRuntime.ComponentControl {
        private final Set<String> databaseNames = new HashSet<>();
        private final List<MassDbLicenseSqlBootstrapRuntime.FrontendStatus> frontends =
                new ArrayList<>();
        private final List<MassDbLicenseSqlBootstrapRuntime.BackendStatus> backends =
                new ArrayList<>();
        private final String buildVersion = "massdb-sql-test-build";
        private boolean accountReady;
        private int addedFrontends;
        private int addedBackends;
        private int ensuredAccounts;

        private FakeControl() {
            frontends.add(new MassDbLicenseSqlBootstrapRuntime.FrontendStatus(
                    "MASTER", "fe-1.example", 9010, 9030, true, buildVersion));
        }

        @Override
        public boolean isClassicMode() {
            return true;
        }

        @Override
        public boolean isReadyMaster() {
            return true;
        }

        @Override
        public String selfHost() {
            return "fe-1.example";
        }

        @Override
        public int selfEditLogPort() {
            return 9010;
        }

        @Override
        public int localQueryPort() {
            return 9030;
        }

        @Override
        public int localHttpsPort() {
            return 8050;
        }

        @Override
        public String localBuildVersion() {
            return buildVersion;
        }

        @Override
        public Set<String> databaseNames() {
            return new HashSet<>(databaseNames);
        }

        @Override
        public List<MassDbLicenseSqlBootstrapRuntime.FrontendStatus> frontends() {
            return new ArrayList<>(frontends);
        }

        @Override
        public List<MassDbLicenseSqlBootstrapRuntime.BackendStatus> backends() {
            return new ArrayList<>(backends);
        }

        @Override
        public boolean canEnsureIngestAccount(IngestAccount account) {
            return true;
        }

        @Override
        public boolean isIngestAccountExact(IngestAccount account) {
            return accountReady;
        }

        @Override
        public void addFrontend(FrontendMember frontend) {
            addedFrontends++;
            frontends.add(new MassDbLicenseSqlBootstrapRuntime.FrontendStatus(
                    frontend.role, frontend.host, frontend.editLogPort,
                    frontend.queryPort, true, buildVersion));
        }

        @Override
        public void addBackend(BackendMember backend) {
            addedBackends++;
            backends.add(new MassDbLicenseSqlBootstrapRuntime.BackendStatus(
                    backend.host, backend.heartbeatPort, backend.bePort,
                    backend.httpPort, backend.brpcPort, true));
        }

        @Override
        public void ensureIngestAccount(IngestAccount account) {
            ensuredAccounts++;
            accountReady = true;
        }
    }
}
