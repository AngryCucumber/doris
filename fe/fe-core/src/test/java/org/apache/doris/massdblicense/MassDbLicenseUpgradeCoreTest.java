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
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

class MassDbLicenseUpgradeCoreTest {
    private static final long NOW = 1_767_225_600L;
    private static final long MAX_TERM = 31_536_000L;
    private static final String SESSION_ID = "00000000-0000-4000-8000-000000000081";
    private static final String DEPLOYMENT_ID = "00000000-0000-4000-8000-000000000082";
    private static final String FOLLOWER_ID = "00000000-0000-4000-8000-000000000083";

    @TempDir
    Path temporaryDirectory;

    @Test
    void attestsEveryFrontendThenJournalsOneObserveInitializationAndReplays()
            throws Exception {
        Fixture fixture = fixture("success");
        MassDbLicenseState empty = MassDbLicenseState.empty();

        MassDbLicenseUpgradeCore.ValidateResult validation =
                fixture.core.validate(empty, fixture.plan, NOW);
        Assertions.assertTrue(validation.readyForApply);
        Assertions.assertEquals("INITIALIZE_OBSERVE", validation.action);
        Assertions.assertEquals(2, validation.requiredFrontends);
        Assertions.assertEquals(2, validation.attestedFrontends);
        Assertions.assertEquals(2, fixture.attestationCalls.get());
        MassDbLicenseUpgradeToken.Claims claims = MassDbLicenseUpgradeToken.verify(
                fixture.marker.preconditionHmacKey(), validation.preconditionToken, NOW);
        Assertions.assertEquals(validation.attestationSha256, claims.attestationSha256);

        MassDbLicenseUpgradeCore.PreparedApply prepared = fixture.core.prepareApply(
                empty, fixture.plan, sha256(fixture.plan), validation.preconditionToken,
                "upgrade-idempotency", NOW);
        Assertions.assertEquals(4, fixture.attestationCalls.get());
        List<MassDbLicenseState> journal = new ArrayList<>();
        MassDbLicenseManager manager = new MassDbLicenseManager(empty, journal::add);
        MassDbLicenseState initialized = manager.transition(current -> fixture.core.commit(
                current, prepared, "upgrade-idempotency", "upgrade-operation", NOW).state);

        Assertions.assertEquals(1, journal.size());
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.OBSERVE,
                initialized.getEnforcementMode());
        Assertions.assertEquals("EXISTING_UPGRADE", initialized.getInitializationSource());
        Assertions.assertEquals(fixture.build.componentVersion,
                initialized.getMinimumEnforcementVersion());
        String appliedAttestationSha256 = initialized.getUpgradeAttestationSha256();
        Assertions.assertTrue(appliedAttestationSha256.matches("[0-9a-f]{64}"));
        Assertions.assertNotEquals(validation.attestationSha256,
                appliedAttestationSha256);
        Assertions.assertEquals("SEALED", initialized.getBootstrapPhase());
        Assertions.assertEquals(1, initialized.getBootstrapSealGeneration());
        Assertions.assertEquals(SESSION_ID, initialized.getBootstrapMarkerId());
        Assertions.assertEquals(DEPLOYMENT_ID,
                initialized.getLicenseControlDeploymentUuid());
        Assertions.assertEquals(2, initialized.getIngressInventory().getNodes().size());
        Assertions.assertNotNull(initialized.getActiveKeyset());
        Assertions.assertEquals("SEALED",
                initialized.findOperation("upgrade-operation").apiState);

        DataOutputBuffer output = new DataOutputBuffer(1024);
        initialized.write(output);
        DataInputBuffer input = new DataInputBuffer();
        input.reset(output.getData(), output.getLength());
        MassDbLicenseState restored = MassDbLicenseState.read(input);
        Assertions.assertEquals("EXISTING_UPGRADE", restored.getInitializationSource());
        Assertions.assertEquals(appliedAttestationSha256,
                restored.getUpgradeAttestationSha256());

        MassDbLicenseUpgradeCore.PreparedApply replay = fixture.core.prepareApply(
                restored, fixture.plan, sha256(fixture.plan), "expired-token-is-ignored",
                "upgrade-idempotency", NOW + 100_000);
        Assertions.assertTrue(replay.isReplay());
        MassDbLicenseUpgradeCore.ApplyResult replayed = fixture.core.commit(
                restored, replay, "upgrade-idempotency", "ignored", NOW + 100_000);
        Assertions.assertTrue(replayed.replayed);
        Assertions.assertEquals("upgrade-operation", replayed.operationId);
        Assertions.assertEquals(4, fixture.attestationCalls.get());

        MassDbLicenseUpgradeCore restartedWithoutMarker = new MassDbLicenseUpgradeCore(
                importCore(), null, fixture.build, fixture.cluster,
                (frontend, request, now) -> {
                    throw new AssertionError("journal终态回放不应重新取远端证明");
                });
        MassDbLicenseException alreadyInitialized = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> restartedWithoutMarker.validate(restored, fixture.plan, NOW + 1));
        Assertions.assertEquals("MASSDB_LICENSE_UPGRADE_ALREADY_INITIALIZED",
                alreadyInitialized.getCode());
        MassDbLicenseUpgradeCore.PreparedApply markerlessReplay =
                restartedWithoutMarker.prepareApply(
                        restored, fixture.plan, sha256(fixture.plan), null,
                        "upgrade-idempotency", NOW + 100_000);
        Assertions.assertTrue(markerlessReplay.isReplay());
        Assertions.assertEquals("upgrade-operation",
                restartedWithoutMarker.commit(restored, markerlessReplay,
                        "upgrade-idempotency", "ignored", NOW + 100_000).operationId);

        String activeSha256 = repeat('d');
        long activeExpiresAt = NOW + 10_000;
        MassDbLicenseState enforcing = restored.prepareLicense(
                "license-operation", "license-idempotency", repeat('e'),
                MassDbLicenseState.ImportIntent.NORMAL,
                new MassDbLicenseState.ActiveLicense(
                        "license-after-upgrade", activeSha256, "license-kid",
                        NOW - 100, activeExpiresAt, new byte[] {1, 2, 3}),
                "admin", null, NOW + 1, NOW + 100)
                .commit("license-operation", NOW + 2);
        for (String nodeUuid : Arrays.asList(fixture.localNodeUuid, FOLLOWER_ID)) {
            enforcing = enforcing.recordIngressHeartbeat(
                    nodeUuid, true, NOW + 3, NOW + 1_000)
                    .recordRoutingEvidence(nodeUuid,
                            MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                            MassDbLicenseIngressInventory.EvidenceSource.MACHINE,
                            NOW + 3, NOW + 1_000)
                    .recordIngressActiveAck(nodeUuid, activeSha256, activeExpiresAt, 0);
        }
        enforcing = enforcing.prepareEnforcementActivation(
                "enforce-operation", "enforce-idempotency", repeat('f'),
                NOW + 4, NOW + 100);
        List<MassDbLicenseState.ActivationAckEvidence> evidence = Arrays.asList(
                new MassDbLicenseState.ActivationAckEvidence(
                        fixture.localNodeUuid, "enforce-operation", 1,
                        activeSha256, repeat('1')),
                new MassDbLicenseState.ActivationAckEvidence(
                        FOLLOWER_ID, "enforce-operation", 1,
                        activeSha256, repeat('2')));
        enforcing = enforcing.commitEnforcementActivation(
                "enforce-operation", evidence, NOW + 5);
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.ENFORCING,
                enforcing.getEnforcementMode());

        output = new DataOutputBuffer(1024);
        enforcing.write(output);
        input = new DataInputBuffer();
        input.reset(output.getData(), output.getLength());
        MassDbLicenseState restoredEnforcing = MassDbLicenseState.read(input);
        Assertions.assertEquals("EXISTING_UPGRADE",
                restoredEnforcing.getInitializationSource());
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.ENFORCING,
                restoredEnforcing.getEnforcementMode());
    }

    @Test
    void unavailableOrMismatchedAttestationNeverCreatesJournalState() throws Exception {
        Fixture fixture = fixture("attestation-failure");
        MassDbLicenseState empty = MassDbLicenseState.empty();
        MassDbLicenseUpgradeCore.ValidateResult validation =
                fixture.core.validate(empty, fixture.plan, NOW);

        fixture.failFollower.set(true);
        MassDbLicenseException unavailable = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> fixture.core.prepareApply(empty, fixture.plan,
                        sha256(fixture.plan), validation.preconditionToken,
                        "upgrade-unavailable", NOW));
        Assertions.assertEquals("MASSDB_LICENSE_UPGRADE_ATTESTATION_FAILED",
                unavailable.getCode());

        fixture.failFollower.set(false);
        fixture.corruptFollowerBuild.set(true);
        MassDbLicenseException mismatch = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> fixture.core.validate(empty, fixture.plan, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_UPGRADE_ATTESTATION_MISMATCH",
                mismatch.getCode());

        Assertions.assertFalse(empty.isInitialized());
    }

    @Test
    void membershipChangeAfterNetworkProofAbortsAtomicCommit() throws Exception {
        Fixture fixture = fixture("membership-change");
        MassDbLicenseState empty = MassDbLicenseState.empty();
        MassDbLicenseUpgradeCore.ValidateResult validation =
                fixture.core.validate(empty, fixture.plan, NOW);
        MassDbLicenseUpgradeCore.PreparedApply prepared = fixture.core.prepareApply(
                empty, fixture.plan, sha256(fixture.plan), validation.preconditionToken,
                "upgrade-membership", NOW);
        fixture.cluster.frontends.remove(1);

        List<MassDbLicenseState> journal = new ArrayList<>();
        MassDbLicenseManager manager = new MassDbLicenseManager(empty, journal::add);
        MassDbLicenseException changed = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> manager.transition(current -> fixture.core.commit(
                        current, prepared, "upgrade-membership",
                        "upgrade-membership-operation", NOW).state));
        Assertions.assertEquals("MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED",
                changed.getCode());
        Assertions.assertTrue(journal.isEmpty());
        Assertions.assertFalse(manager.snapshot().isInitialized());
    }

    @Test
    void localAttestationRequiresExactMtlsIdentityMarkerAndChallenge() throws Exception {
        Fixture fixture = fixture("local-attestation");
        String challenge = repeat('c');
        MassDbLicenseUpgradeProtocol.Request request =
                new MassDbLicenseUpgradeProtocol.Request(
                        SESSION_ID, DEPLOYMENT_ID, fixture.summary.planSha256,
                        fixture.summary.membershipSha256, fixture.localNodeUuid,
                        fixture.localNodeUuid, challenge, NOW);
        MassDbLicenseSpiffeIdentity.Identity identity =
                MassDbLicenseSpiffeIdentity.parseUnique(Collections.singletonList(
                        "spiffe://massdb.internal/license/component/massdb-sql/"
                                + DEPLOYMENT_ID + "/fe/" + fixture.localNodeUuid));

        MassDbLicenseUpgradeProtocol.Response response = fixture.core.attestLocal(
                MassDbLicenseState.empty(), identity, fixture.localNodeUuid, request, NOW);
        Assertions.assertEquals(fixture.localNodeUuid, response.nodeUuid);
        Assertions.assertEquals(challenge, response.challenge);
        Assertions.assertEquals(fixture.summary.membershipSha256,
                response.membershipSha256);

        MassDbLicenseSpiffeIdentity.Identity wrong =
                MassDbLicenseSpiffeIdentity.parseUnique(Collections.singletonList(
                        "spiffe://massdb.internal/license/component/massdb-sql/"
                                + DEPLOYMENT_ID + "/fe/" + FOLLOWER_ID));
        MassDbLicenseException rejected = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> fixture.core.attestLocal(MassDbLicenseState.empty(), wrong,
                        fixture.localNodeUuid, request, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                rejected.getCode());
    }

    private Fixture fixture(String name) throws IOException {
        Path meta = Files.createDirectories(temporaryDirectory.resolve(name).resolve("meta"));
        Files.createDirectory(meta.resolve("image"));
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                meta.resolve("massdb-license"));
        String localNodeUuid = store.getNodeUuid();
        MassDbLicenseBuildIdentity build = new MassDbLicenseBuildIdentity(
                "4.0.5-license-test", "1", MassDbLicenseState.FORMAT_VERSION,
                10_001, MassDbLicenseBuildIdentity.SNAPSHOT_FORMAT, repeat('a'));
        byte[] plan = plan(localNodeUuid, build);
        MassDbLicenseUpgradeCore.PlanSummary summary =
                MassDbLicenseUpgradeCore.summarize(plan);
        MassDbLicenseUpgradeMarker.Attestation marker =
                MassDbLicenseUpgradeMarker.create(
                        meta.resolve("license-upgrade.marker"), meta, summary, build,
                        SESSION_ID, DEPLOYMENT_ID, NOW - 100);
        MutableClusterView cluster = new MutableClusterView(localNodeUuid);
        AtomicBoolean failFollower = new AtomicBoolean();
        AtomicBoolean corruptFollowerBuild = new AtomicBoolean();
        AtomicInteger attestationCalls = new AtomicInteger();
        MassDbLicenseUpgradeCore.AttestationClient attestor = (frontend, request, now) -> {
            attestationCalls.incrementAndGet();
            if (failFollower.get() && FOLLOWER_ID.equals(frontend.nodeUuid)) {
                throw new IOException("follower unavailable");
            }
            MassDbLicenseUpgradeProtocol.Response response = response(
                    marker, frontend, request, build, now);
            if (corruptFollowerBuild.get() && FOLLOWER_ID.equals(frontend.nodeUuid)) {
                response.binarySha256 = repeat('b');
            }
            return response;
        };
        MassDbLicenseUpgradeCore core = new MassDbLicenseUpgradeCore(
                importCore(), marker, build, cluster, attestor);
        return new Fixture(localNodeUuid, build, plan, summary, marker, cluster, core,
                failFollower, corruptFollowerBuild, attestationCalls);
    }

    private static MassDbLicenseUpgradeProtocol.Response response(
            MassDbLicenseUpgradeMarker.Attestation marker,
            MassDbLicenseUpgradeCore.UpgradeFrontend frontend,
            MassDbLicenseUpgradeProtocol.Request request,
            MassDbLicenseBuildIdentity build, long now) {
        MassDbLicenseUpgradeProtocol.Response response =
                new MassDbLicenseUpgradeProtocol.Response();
        response.protocolVersion = MassDbLicenseUpgradeProtocol.VERSION;
        response.upgradeSessionId = marker.upgradeSessionId;
        response.deploymentUuid = marker.licenseControlDeploymentUuid;
        response.planSha256 = marker.upgradePlanSha256;
        response.membershipSha256 = request.membershipSha256;
        response.nodeUuid = frontend.nodeUuid;
        response.challenge = request.challenge;
        response.componentType = build.componentType;
        response.componentVersion = build.componentVersion;
        response.capabilityVersion = build.capabilityVersion;
        response.stateFormatVersion = build.stateFormatVersion;
        response.journalOperationType = build.journalOperationType;
        response.snapshotFormat = build.snapshotFormat;
        response.binarySha256 = build.binarySha256;
        response.observedAt = now;
        return response;
    }

    private static byte[] plan(String localNodeUuid, MassDbLicenseBuildIdentity build) {
        String keyset = Base64.getEncoder().encodeToString(
                MassDbLicenseProtocolV1Test.keysetBytes());
        String json = "{\"formatVersion\":1,\"componentType\":\"massdb-sql\","
                + "\"targetMode\":\"OBSERVE\",\"keysetArtifactBase64\":\""
                + keyset + "\",\"requiredBuild\":{"
                + "\"componentType\":\"massdb-sql\",\"componentVersion\":\""
                + build.componentVersion + "\",\"capabilityVersion\":\""
                + build.capabilityVersion + "\",\"stateFormatVersion\":"
                + build.stateFormatVersion + ",\"journalOperationType\":"
                + build.journalOperationType + ",\"snapshotFormat\":\""
                + build.snapshotFormat + "\",\"binarySha256\":\""
                + build.binarySha256 + "\"},\"frontends\":[{\"nodeUuid\":\""
                + localNodeUuid + "\",\"role\":\"VOTER\",\"host\":\"fe-1.example\","
                + "\"editLogPort\":9010,\"httpsEndpoint\":\"https://fe-1.example:8050\"},"
                + "{\"nodeUuid\":\"" + FOLLOWER_ID
                + "\",\"role\":\"OBSERVER\",\"host\":\"fe-2.example\","
                + "\"editLogPort\":9010,\"httpsEndpoint\":\"https://fe-2.example:8050\"}]}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static MassDbLicenseImportCore importCore() {
        PublicKey root = MassDbLicenseProtocolV1.parsePublicKeyPem(
                MassDbLicenseProtocolV1Test.rootPublicBytes());
        Map<String, PublicKey> roots = Collections.singletonMap("massdb-test-root-1", root);
        return new MassDbLicenseImportCore(MAX_TERM, roots);
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String repeat(char value) {
        return String.join("", Collections.nCopies(64, String.valueOf(value)));
    }

    private static final class MutableClusterView implements MassDbLicenseUpgradeCore.ClusterView {
        private final String localNodeUuid;
        private final List<MassDbLicenseUpgradeCore.PersistentFrontend> frontends =
                new ArrayList<>();

        private MutableClusterView(String localNodeUuid) {
            this.localNodeUuid = localNodeUuid;
            frontends.add(new MassDbLicenseUpgradeCore.PersistentFrontend(
                    "VOTER", "fe-1.example", 9010));
            frontends.add(new MassDbLicenseUpgradeCore.PersistentFrontend(
                    "OBSERVER", "fe-2.example", 9010));
        }

        @Override
        public boolean isReadyLeader() {
            return true;
        }

        @Override
        public boolean hasExistingBusinessMetadata() {
            return true;
        }

        @Override
        public String localNodeUuid() {
            return localNodeUuid;
        }

        @Override
        public List<MassDbLicenseUpgradeCore.PersistentFrontend> persistentFrontends() {
            return new ArrayList<>(frontends);
        }
    }

    private static final class Fixture {
        private final String localNodeUuid;
        private final MassDbLicenseBuildIdentity build;
        private final byte[] plan;
        private final MassDbLicenseUpgradeCore.PlanSummary summary;
        private final MassDbLicenseUpgradeMarker.Attestation marker;
        private final MutableClusterView cluster;
        private final MassDbLicenseUpgradeCore core;
        private final AtomicBoolean failFollower;
        private final AtomicBoolean corruptFollowerBuild;
        private final AtomicInteger attestationCalls;

        private Fixture(String localNodeUuid, MassDbLicenseBuildIdentity build,
                byte[] plan, MassDbLicenseUpgradeCore.PlanSummary summary,
                MassDbLicenseUpgradeMarker.Attestation marker,
                MutableClusterView cluster, MassDbLicenseUpgradeCore core,
                AtomicBoolean failFollower, AtomicBoolean corruptFollowerBuild,
                AtomicInteger attestationCalls) {
            this.localNodeUuid = localNodeUuid;
            this.build = build;
            this.plan = plan.clone();
            this.summary = summary;
            this.marker = marker;
            this.cluster = cluster;
            this.core = core;
            this.failFollower = failFollower;
            this.corruptFollowerBuild = corruptFollowerBuild;
            this.attestationCalls = attestationCalls;
        }
    }
}
