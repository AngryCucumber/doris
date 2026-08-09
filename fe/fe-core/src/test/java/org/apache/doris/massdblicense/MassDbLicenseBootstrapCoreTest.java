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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

class MassDbLicenseBootstrapCoreTest {
    private static final long NOW = 1_767_225_600L;
    private static final long MAX_TERM = 31_536_000L;
    private static final String MARKER_ID = "00000000-0000-4000-8000-000000000041";
    private static final String DEPLOYMENT_ID = "00000000-0000-4000-8000-000000000042";
    private static final String NODE_ID = "00000000-0000-4000-8000-000000000043";
    private static final String FOLLOWER_NODE_ID = "00000000-0000-4000-8000-000000000044";
    private static final String BACKEND_NODE_ID = "00000000-0000-4000-8000-000000000045";

    @Test
    void validatesThenAtomicallySealsAndReplaysCanonicalOperation() {
        byte[] plan = plan("https://fe-1.example:8050");
        MassDbLicenseBootstrapCore.PlanSummary summary =
                MassDbLicenseBootstrapCore.summarize(plan);
        MassDbLicenseState open = MassDbLicenseState.empty().openBootstrap(
                MARKER_ID, DEPLOYMENT_ID, summary.planSha256, NOW - 60);
        MassDbLicenseBootstrapCore core = new MassDbLicenseBootstrapCore(importCore());
        MassDbLicenseBootstrapCore.WriteHealth health = (deployment, now) -> {
            Assertions.assertEquals(DEPLOYMENT_ID, deployment);
            return NODE_ID;
        };

        MassDbLicenseBootstrapCore.ValidateResult validation =
                core.validate(open, plan, health, NOW);
        Assertions.assertTrue(validation.readyForApply);
        Assertions.assertEquals("OPEN", validation.bootstrapPhase);
        Assertions.assertEquals(summary.planSha256, validation.bootstrapPlanSha256);
        MassDbLicenseBootstrapCore.ApplyResult applied = core.apply(open, plan,
                sha256(plan), validation.preconditionToken, "bootstrap-key-1",
                "bootstrap-operation-1", health, NOW);

        Assertions.assertFalse(applied.replayed);
        Assertions.assertEquals("SEALED", applied.state.getBootstrapPhase());
        Assertions.assertEquals(1, applied.state.getBootstrapSealGeneration());
        Assertions.assertEquals(NOW, applied.state.getBootstrapMarkerConsumedAt());
        Assertions.assertEquals(summary.inventorySha256,
                applied.state.getIngressInventory().configuredDigest());
        Assertions.assertEquals(validation.keysetVersion, applied.state.getKeysetVersion());
        Assertions.assertEquals("SEALED",
                applied.state.findOperation("bootstrap-operation-1").apiState);

        MassDbLicenseBootstrapCore.ApplyResult sameKey = core.apply(applied.state, plan,
                sha256(plan), "expired-token-is-ignored-for-terminal-replay",
                "bootstrap-key-1", "ignored-operation", health, NOW + 10_000);
        Assertions.assertTrue(sameKey.replayed);
        Assertions.assertEquals("bootstrap-operation-1", sameKey.operationId);

        MassDbLicenseBootstrapCore.ApplyResult alias = core.apply(applied.state, plan,
                sha256(plan), "terminal-alias-does-not-need-a-token",
                "bootstrap-key-2", "ignored-alias-operation", health, NOW + 20_000);
        Assertions.assertTrue(alias.replayed);
        Assertions.assertEquals("bootstrap-operation-1", alias.operationId);
        Assertions.assertEquals("bootstrap-operation-1",
                alias.state.findOperationByIdempotencyKey("bootstrap-key-2").operationId);
    }

    @Test
    void rejectsDifferentPlanMissingLocalIdentityAndTamperedToken() {
        byte[] plan = plan("https://fe-1.example:8050");
        MassDbLicenseBootstrapCore.PlanSummary summary =
                MassDbLicenseBootstrapCore.summarize(plan);
        MassDbLicenseState open = MassDbLicenseState.empty().openBootstrap(
                MARKER_ID, DEPLOYMENT_ID, summary.planSha256, NOW - 60);
        MassDbLicenseBootstrapCore core = new MassDbLicenseBootstrapCore(importCore());

        MassDbLicenseException identity = Assertions.assertThrows(MassDbLicenseException.class,
                () -> core.validate(open, plan,
                        (deployment, now) -> "00000000-0000-4000-8000-000000000099", NOW));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_IDENTITY_MISMATCH",
                identity.getCode());

        MassDbLicenseBootstrapCore.ValidateResult validation = core.validate(
                open, plan, (deployment, now) -> NODE_ID, NOW);
        MassDbLicenseException token = Assertions.assertThrows(MassDbLicenseException.class,
                () -> core.apply(open, plan, sha256(plan),
                        validation.preconditionToken + "x", "bootstrap-key",
                        "bootstrap-operation", (deployment, now) -> NODE_ID, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED",
                token.getCode());

        byte[] different = plan("https://fe-2.example:8050");
        MassDbLicenseException mismatch = Assertions.assertThrows(MassDbLicenseException.class,
                () -> core.validate(open, different, (deployment, now) -> NODE_ID, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_PLAN_MISMATCH", mismatch.getCode());

        MassDbLicenseException nullPlan = Assertions.assertThrows(MassDbLicenseException.class,
                () -> MassDbLicenseBootstrapCore.summarize("null".getBytes(StandardCharsets.UTF_8)));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", nullPlan.getCode());
        String nullIngress = new String(plan, StandardCharsets.UTF_8).replace(
                "{\"nodeUuid\":\"" + NODE_ID
                        + "\",\"endpoint\":\"https://fe-1.example:8050\",\"desired\":true}",
                "null");
        MassDbLicenseException nullNode = Assertions.assertThrows(MassDbLicenseException.class,
                () -> MassDbLicenseBootstrapCore.summarize(
                        nullIngress.getBytes(StandardCharsets.UTF_8)));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", nullNode.getCode());
    }

    @Test
    void fullPlanSealsOnlyAfterEveryMemberAccountAndRouteIsHealthy() {
        byte[] plan = fullPlan();
        MassDbLicenseBootstrapCore.PlanSummary summary =
                MassDbLicenseBootstrapCore.summarize(plan);
        MassDbLicenseState open = MassDbLicenseState.empty().openBootstrap(
                MARKER_ID, DEPLOYMENT_ID, summary.planSha256, NOW - 60);
        MassDbLicenseBootstrapCore core = new MassDbLicenseBootstrapCore(importCore());
        AtomicBoolean compatibilityChecked = new AtomicBoolean();
        MassDbLicenseBootstrapCore.WriteHealth incomplete =
                new MassDbLicenseBootstrapCore.WriteHealth() {
                    @Override
                    public String requireLocalFeIdentity(String deploymentUuid, long now) {
                        return NODE_ID;
                    }

                    @Override
                    public void requireFullPlanCompatible(
                            MassDbLicenseBootstrapCore.InstallationPlan installation,
                            long now) {
                        compatibilityChecked.set(true);
                        Assertions.assertEquals(2, installation.getFrontends().size());
                        Assertions.assertEquals(1, installation.getBackends().size());
                        Assertions.assertEquals("'massdb_ingest'@'10.%'",
                                installation.getIngestAccount().getQualifiedName());
                    }

                    @Override
                    public MassDbLicenseBootstrapCore.InstallationHealth
                            reconcileAndRequireFullHealth(
                                    MassDbLicenseBootstrapCore.InstallationPlan installation,
                                    long now) {
                        return new MassDbLicenseBootstrapCore.InstallationHealth(
                                2, 1, 1, 1, 1, true);
                    }
                };

        MassDbLicenseBootstrapCore.ValidateResult validation =
                core.validate(open, plan, incomplete, NOW);
        Assertions.assertTrue(compatibilityChecked.get());
        Assertions.assertEquals(2, validation.planFormatVersion);
        Assertions.assertEquals(MassDbLicenseBootstrapCore.FULL_MINIMUM_WRITE_HEALTH,
                validation.minimumWriteHealth);
        Assertions.assertEquals(2, validation.plannedFrontends);
        Assertions.assertEquals(1, validation.plannedBackends);
        Assertions.assertEquals(1, validation.plannedIngestRoutes);
        Assertions.assertEquals("'massdb_ingest'@'10.%'", validation.ingestAccount);

        MassDbLicenseException notReady = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> core.apply(open, plan, sha256(plan), validation.preconditionToken,
                        "bootstrap-full-incomplete", "bootstrap-full-operation-incomplete",
                        incomplete, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_NOT_READY", notReady.getCode());
        Assertions.assertEquals("OPEN", open.getBootstrapPhase());

        MassDbLicenseBootstrapCore.WriteHealth complete = fullPlanHealth(2, 2, 1, 1, 1, true);
        MassDbLicenseBootstrapCore.ApplyResult applied = core.apply(
                open, plan, sha256(plan), validation.preconditionToken,
                "bootstrap-full-complete", "bootstrap-full-operation-complete",
                complete, NOW);
        Assertions.assertEquals("SEALED", applied.state.getBootstrapPhase());
        Assertions.assertEquals(2, applied.state.getIngressInventory().getNodes().size());
    }

    @Test
    void fullPlanRejectsMissingRuntimeAndPrivilegeExpansion() {
        byte[] plan = fullPlan();
        MassDbLicenseBootstrapCore.PlanSummary summary =
                MassDbLicenseBootstrapCore.summarize(plan);
        MassDbLicenseState open = MassDbLicenseState.empty().openBootstrap(
                MARKER_ID, DEPLOYMENT_ID, summary.planSha256, NOW - 60);
        MassDbLicenseBootstrapCore core = new MassDbLicenseBootstrapCore(importCore());

        MassDbLicenseException unavailable = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> core.validate(open, plan,
                        (deploymentUuid, now) -> NODE_ID, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_RUNTIME_UNAVAILABLE",
                unavailable.getCode());

        String expanded = new String(plan, StandardCharsets.UTF_8)
                .replace("GLOBAL_LOAD_ONLY", "GLOBAL_LOAD_AND_SELECT");
        MassDbLicenseException privilege = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseBootstrapCore.summarize(
                        expanded.getBytes(StandardCharsets.UTF_8)));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                privilege.getCode());
    }

    private static MassDbLicenseImportCore importCore() {
        PublicKey root = MassDbLicenseProtocolV1.parsePublicKeyPem(
                MassDbLicenseProtocolV1Test.rootPublicBytes());
        Map<String, PublicKey> roots = Collections.singletonMap("massdb-test-root-1", root);
        return new MassDbLicenseImportCore(MAX_TERM, roots);
    }

    private static byte[] plan(String endpoint) {
        String keyset = Base64.getEncoder().encodeToString(
                MassDbLicenseProtocolV1Test.keysetBytes());
        String json = "{\"formatVersion\":1,\"componentType\":\"massdb-sql\","
                + "\"targetPhase\":\"SEALED\",\"keysetArtifactBase64\":\"" + keyset
                + "\",\"ingressNodes\":[{\"nodeUuid\":\"" + NODE_ID
                + "\",\"endpoint\":\"" + endpoint + "\",\"desired\":true}],"
                + "\"minimumWriteHealth\":\"FE_LEADER_READY\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] fullPlan() {
        String keyset = Base64.getEncoder().encodeToString(
                MassDbLicenseProtocolV1Test.keysetBytes());
        String passwordHash = Base64.getEncoder().encodeToString(
                ("*" + repeat('A', 40)).getBytes(StandardCharsets.US_ASCII));
        String json = "{\"formatVersion\":2,\"componentType\":\"massdb-sql\","
                + "\"targetPhase\":\"SEALED\",\"keysetArtifactBase64\":\"" + keyset
                + "\",\"ingressNodes\":[{\"nodeUuid\":\"" + NODE_ID
                + "\",\"endpoint\":\"https://fe-1.example:8050\",\"desired\":true},"
                + "{\"nodeUuid\":\"" + FOLLOWER_NODE_ID
                + "\",\"endpoint\":\"https://fe-2.example:8050\",\"desired\":true}],"
                + "\"minimumWriteHealth\":\"ALL_PLANNED_MEMBERS_ALIVE_AND_INGEST_READY\","
                + "\"frontends\":[{\"nodeUuid\":\"" + NODE_ID
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
                + "\"feNodeUuid\":\"" + NODE_ID
                + "\",\"endpoint\":\"https://fe-1.example:8050\",\"desired\":true}]}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static MassDbLicenseBootstrapCore.WriteHealth fullPlanHealth(
            int plannedFrontends, int aliveFrontends, int plannedBackends,
            int aliveBackends, int readyRoutes, boolean accountReady) {
        return new MassDbLicenseBootstrapCore.WriteHealth() {
            @Override
            public String requireLocalFeIdentity(String deploymentUuid, long now) {
                return NODE_ID;
            }

            @Override
            public void requireFullPlanCompatible(
                    MassDbLicenseBootstrapCore.InstallationPlan plan, long now) {
            }

            @Override
            public MassDbLicenseBootstrapCore.InstallationHealth
                    reconcileAndRequireFullHealth(
                            MassDbLicenseBootstrapCore.InstallationPlan plan, long now) {
                return new MassDbLicenseBootstrapCore.InstallationHealth(
                        plannedFrontends, aliveFrontends, plannedBackends,
                        aliveBackends, readyRoutes, accountReady);
            }
        };
    }

    private static String repeat(char value, int count) {
        StringBuilder result = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            result.append(value);
        }
        return result.toString();
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
