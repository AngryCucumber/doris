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
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

class MassDbLicenseFeRoleRuntimeTest {
    private static final long NOW = 1_767_225_600L;
    private static final long MAX_TERM = 31_536_000L;

    @TempDir
    Path temporaryDirectory;

    @Test
    void fullSyncSurvivesRestartAndUsesOnlyComponentRootTrust() throws Exception {
        Fixture fixture = fixture(false, "restart");
        apply(fixture, fixture.sync, NOW, NOW, 1);

        Assertions.assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(fixture.directory.resolve("control.snapshot")));
        MassDbLicenseLocalSnapshotStore restarted =
                new MassDbLicenseLocalSnapshotStore(fixture.directory);
        MassDbLicenseFeRoleRuntime.Evaluation evaluation = MassDbLicenseFeRoleRuntime.evaluate(
                restarted, fixture.importCore, fixture.deploymentUuid, NOW + 10, NOW + 10);

        Assertions.assertEquals(MassDbLicenseFeRoleProtocol.VerificationState.VERIFIED,
                evaluation.verificationState);
        Assertions.assertEquals(MassDbLicenseFeRoleProtocol.ClockState.NORMAL,
                evaluation.clockState);
        Assertions.assertEquals("FRESH", evaluation.controlPlaneFreshness);
        Assertions.assertTrue(evaluation.queryDecision.allowed);
        Assertions.assertEquals(fixture.sync.activeLicenseSha256,
                restarted.loadActive().sha256);
    }

    @Test
    void monotonicClockDistinguishesWallSkewFromRestartRollback() {
        Fixture fixture = fixture(false, "clock");
        apply(fixture, fixture.sync, NOW, NOW, 1);
        apply(fixture, fixture.sync, NOW - 1_000, NOW + 31, 1);
        MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint refreshed =
                fixture.store.loadControlPlaneCheckpoint();
        Assertions.assertEquals(NOW + 31, refreshed.lastVerifiedEffectiveNow);
        Assertions.assertEquals(NOW - 1_000, refreshed.authenticatedAtWallClock);

        MassDbLicenseFeRoleRuntime.Evaluation skew = MassDbLicenseFeRoleRuntime.evaluate(
                fixture.store, fixture.importCore, fixture.deploymentUuid,
                NOW - 1_000, NOW + 10);
        Assertions.assertEquals(MassDbLicenseFeRoleProtocol.ClockState.SKEW_WARNING,
                skew.clockState);
        Assertions.assertTrue(skew.queryDecision.allowed);

        MassDbLicenseFeRoleRuntime.Evaluation rollback = MassDbLicenseFeRoleRuntime.evaluate(
                fixture.store, fixture.importCore, fixture.deploymentUuid,
                NOW - 1_000, NOW - 1_000);
        Assertions.assertEquals(MassDbLicenseFeRoleProtocol.ClockState.ROLLBACK,
                rollback.clockState);
        Assertions.assertFalse(rollback.queryDecision.allowed);
        Assertions.assertEquals("MASSDB_LICENSE_CLOCK_ROLLBACK",
                rollback.queryDecision.errorCode);
    }

    @Test
    void enforcingBecomesStaleOnlyAfterFrozenSevenDayBoundary() {
        Fixture fixture = fixture(false, "stale-enforcing");
        apply(fixture, fixture.sync, NOW, NOW, 1);
        long boundary = NOW + MassDbLicenseState.DEFAULT_CONTROL_PLANE_STALENESS_SECONDS;

        MassDbLicenseFeRoleRuntime.Evaluation atBoundary = MassDbLicenseFeRoleRuntime.evaluate(
                fixture.store, fixture.importCore, fixture.deploymentUuid, boundary, boundary);
        Assertions.assertEquals("FRESH", atBoundary.controlPlaneFreshness);
        Assertions.assertEquals(0L, atBoundary.controlPlaneStalenessRemainingSeconds);
        Assertions.assertTrue(atBoundary.queryDecision.allowed);

        MassDbLicenseFeRoleRuntime.Evaluation stale = MassDbLicenseFeRoleRuntime.evaluate(
                fixture.store, fixture.importCore, fixture.deploymentUuid,
                boundary + 1, boundary + 1);
        Assertions.assertEquals("STALE", stale.controlPlaneFreshness);
        Assertions.assertFalse(stale.queryDecision.allowed);
        Assertions.assertEquals("MASSDB_LICENSE_CONTROL_PLANE_STALE",
                stale.queryDecision.errorCode);
    }

    @Test
    void observeKeepsReadsOpenWhenControlPlaneIsStale() {
        Fixture fixture = fixture(true, "stale-observe");
        apply(fixture, fixture.sync, NOW, NOW, 1);
        long staleAt = NOW + MassDbLicenseState.DEFAULT_CONTROL_PLANE_STALENESS_SECONDS + 1;

        MassDbLicenseFeRoleRuntime.Evaluation stale = MassDbLicenseFeRoleRuntime.evaluate(
                fixture.store, fixture.importCore, fixture.deploymentUuid, staleAt, staleAt);
        Assertions.assertEquals("STALE", stale.controlPlaneFreshness);
        Assertions.assertTrue(stale.queryDecision.allowed);
    }

    @Test
    void verifiedSyncRepairsCorruptManifestButPendingBlocksActiveReplacement()
            throws Exception {
        Fixture fixture = fixture(false, "repair");
        apply(fixture, fixture.sync, NOW, NOW, 1);
        Files.write(fixture.directory.resolve("control.snapshot"), new byte[] {1});
        MassDbLicenseFeRoleRuntime.Evaluation corrupt = MassDbLicenseFeRoleRuntime.evaluate(
                fixture.store, fixture.importCore, fixture.deploymentUuid, NOW + 1, NOW + 1);
        Assertions.assertEquals(MassDbLicenseFeRoleProtocol.VerificationState.CORRUPT,
                corrupt.verificationState);

        apply(fixture, fixture.sync, NOW + 1, NOW + 1, 1);
        Assertions.assertEquals(MassDbLicenseFeRoleProtocol.VerificationState.VERIFIED,
                MassDbLicenseFeRoleRuntime.evaluate(fixture.store, fixture.importCore,
                        fixture.deploymentUuid, NOW + 1, NOW + 1).verificationState);

        fixture.store.beginActivationPending(
                new MassDbLicenseLocalSnapshotStore.ActivationPending(
                        "pending", 1, fixture.sync.activeLicenseSha256, NOW + 2));
        MassDbLicenseFeRoleProtocol.ControlPlaneSync withoutLicense = copy(fixture.sync);
        withoutLicense.controlPlaneRevision++;
        withoutLicense.activeLicenseSha256 = null;
        withoutLicense.activeLicenseExpiresAt = null;
        withoutLicense.activeLicenseArtifact = null;
        MassDbLicenseException blocked = Assertions.assertThrows(MassDbLicenseException.class,
                () -> apply(fixture, withoutLicense, NOW + 2, NOW + 2, 1));
        Assertions.assertEquals("MASSDB_LICENSE_OPERATION_IN_PROGRESS", blocked.getCode());
        Assertions.assertNotNull(fixture.store.loadActive());
    }

    @Test
    void rejectsRevisionRollbackAndSameRevisionAuthorityConflict() {
        Fixture fixture = fixture(false, "revision");
        apply(fixture, fixture.sync, NOW, NOW, 1);
        MassDbLicenseFeRoleProtocol.ControlPlaneSync revisionTwo = copy(fixture.sync);
        revisionTwo.controlPlaneRevision = fixture.sync.controlPlaneRevision + 1;
        apply(fixture, revisionTwo, NOW + 31, NOW + 31, 1);

        MassDbLicenseException rollback = Assertions.assertThrows(MassDbLicenseException.class,
                () -> apply(fixture, fixture.sync, NOW + 32, NOW + 32, 1));
        Assertions.assertEquals("MASSDB_LICENSE_PRECONDITION_FAILED", rollback.getCode());

        MassDbLicenseFeRoleProtocol.ControlPlaneSync conflict = copy(revisionTwo);
        conflict.enforcementMode = MassDbLicenseState.EnforcementMode.OBSERVE;
        MassDbLicenseException mismatch = Assertions.assertThrows(MassDbLicenseException.class,
                () -> apply(fixture, conflict, NOW + 32, NOW + 32, 1));
        Assertions.assertEquals("MASSDB_LICENSE_PRECONDITION_FAILED", mismatch.getCode());
    }

    private Fixture fixture(boolean observe, String name) {
        Map<String, PublicKey> roots = roots();
        byte[] keysetArtifact = MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.KEYSET);
        byte[] licenseArtifact = MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.VALID_LICENSE);
        MassDbLicenseProtocolV1.VerifiedKeyset keyset =
                MassDbLicenseProtocolV1.verifyKeyset(keysetArtifact, roots, NOW, null);
        MassDbLicenseProtocolV1.VerifiedLicense license =
                MassDbLicenseProtocolV1.verifyLicense(
                        licenseArtifact, keyset, NOW, MAX_TERM, null);
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(observe, repeat('a'))
                .prepareKeyset("keyset", "keyset-idem", repeat('b'),
                        MassDbLicenseState.MutationKind.ADDITIVE_KEYSET,
                        new MassDbLicenseState.ActiveKeyset(
                                keyset.getPayload().getKeysetVersion(),
                                keyset.getSha256(), keysetArtifact), NOW - 100, NOW - 50)
                .commit("keyset", NOW - 99)
                .prepareLicense("license", "license-idem", repeat('c'),
                        MassDbLicenseState.ImportIntent.NORMAL,
                        new MassDbLicenseState.ActiveLicense(
                                license.getPayload().getLicenseId(), license.getSha256(),
                                license.getKid(), license.getPayload().getIssuedAt(),
                                license.getPayload().getExpiresAt(), licenseArtifact),
                        "admin", null, NOW - 40, NOW - 20)
                .commit("license", NOW - 39);
        MassDbLicenseManager manager = new MassDbLicenseManager(state, ignored -> { });
        state = manager.transition(current -> current.advanceMaxSeenWallClock(NOW));
        Path directory = temporaryDirectory.resolve(name);
        MassDbLicenseLocalSnapshotStore store =
                new MassDbLicenseLocalSnapshotStore(directory);
        return new Fixture(directory, store, new MassDbLicenseImportCore(MAX_TERM, roots),
                state.getLicenseControlDeploymentUuid(),
                MassDbLicenseFeRoleProtocol.ControlPlaneSync.from(state, 1, NOW));
    }

    private static void apply(Fixture fixture,
            MassDbLicenseFeRoleProtocol.ControlPlaneSync sync,
            long wallClock, long monotonicNow, long reportSequence) {
        MassDbLicenseFeRoleRuntime.applyControlPlaneSync(
                fixture.store, fixture.importCore, fixture.deploymentUuid,
                sync, wallClock, monotonicNow, reportSequence);
    }

    private static MassDbLicenseFeRoleProtocol.ControlPlaneSync copy(
            MassDbLicenseFeRoleProtocol.ControlPlaneSync source) {
        try {
            return MassDbLicenseFeRoleProtocol.decode(
                    MassDbLicenseFeRoleProtocol.encode(source),
                    MassDbLicenseFeRoleProtocol.ControlPlaneSync.class);
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private static Map<String, PublicKey> roots() {
        return Collections.singletonMap("massdb-test-root-1",
                MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.decode(
                                MassDbLicenseProtocolV1Test.ROOT_PUBLIC)));
    }

    private static String repeat(char value) {
        return String.join("", Collections.nCopies(64, String.valueOf(value)));
    }

    private static final class Fixture {
        private final Path directory;
        private final MassDbLicenseLocalSnapshotStore store;
        private final MassDbLicenseImportCore importCore;
        private final String deploymentUuid;
        private final MassDbLicenseFeRoleProtocol.ControlPlaneSync sync;

        private Fixture(Path directory, MassDbLicenseLocalSnapshotStore store,
                MassDbLicenseImportCore importCore, String deploymentUuid,
                MassDbLicenseFeRoleProtocol.ControlPlaneSync sync) {
            this.directory = directory;
            this.store = store;
            this.importCore = importCore;
            this.deploymentUuid = deploymentUuid;
            this.sync = sync;
        }
    }
}
