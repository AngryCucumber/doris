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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.Collections;

class MassDbLicenseUpgradeMarkerTest {
    private static final long NOW = 1_767_225_600L;
    private static final String SESSION_ID = "00000000-0000-4000-8000-000000000091";
    private static final String DEPLOYMENT_ID = "00000000-0000-4000-8000-000000000092";

    @TempDir
    Path temporaryDirectory;

    @Test
    void omittedIdentityRetryReturnsOriginalPrivateExistingClusterMarker()
            throws IOException {
        Fixture fixture = fixture("retry", true);
        Path markerPath = fixture.meta.resolve("license-upgrade.marker");
        MassDbLicenseUpgradeMarker.Attestation created =
                MassDbLicenseUpgradeMarker.create(markerPath, fixture.meta,
                        fixture.summary, fixture.build, null, null, NOW);
        MassDbLicenseUpgradeMarker.Attestation retried =
                MassDbLicenseUpgradeMarker.create(markerPath, fixture.meta,
                        fixture.summary, fixture.build, null, null, NOW + 1);

        Assertions.assertTrue(created.isEligible());
        Assertions.assertEquals(created.upgradeSessionId, retried.upgradeSessionId);
        Assertions.assertEquals(created.licenseControlDeploymentUuid,
                retried.licenseControlDeploymentUuid);
        Assertions.assertEquals(created.createdAt, retried.createdAt);
        Assertions.assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(markerPath));

        MassDbLicenseUpgradeMarker.Attestation explicitRetry =
                MassDbLicenseUpgradeMarker.create(markerPath, fixture.meta,
                        fixture.summary, fixture.build, created.upgradeSessionId,
                        created.licenseControlDeploymentUuid, NOW + 2);
        Assertions.assertEquals(created.upgradeSessionId, explicitRetry.upgradeSessionId);
    }

    @Test
    void rejectsFreshClusterDifferentPlanBuildAndExplicitIdentity() throws IOException {
        Fixture fresh = fixture("fresh", false);
        MassDbLicenseException noHistory = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseUpgradeMarker.create(
                        fresh.meta.resolve("license-upgrade.marker"), fresh.meta,
                        fresh.summary, fresh.build, SESSION_ID, DEPLOYMENT_ID, NOW));
        Assertions.assertEquals("MASSDB_LICENSE_UPGRADE_NOT_EXISTING_CLUSTER",
                noHistory.getCode());

        Fixture fixture = fixture("conflict", true);
        Path markerPath = fixture.meta.resolve("license-upgrade.marker");
        MassDbLicenseUpgradeMarker.create(markerPath, fixture.meta,
                fixture.summary, fixture.build, SESSION_ID, DEPLOYMENT_ID, NOW);

        MassDbLicenseException identity = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseUpgradeMarker.create(markerPath, fixture.meta,
                        fixture.summary, fixture.build,
                        "00000000-0000-4000-8000-000000000093",
                        DEPLOYMENT_ID, NOW + 1));
        Assertions.assertEquals("MASSDB_LICENSE_UPGRADE_MARKER_CONFLICT",
                identity.getCode());

        MassDbLicenseUpgradeCore.PlanSummary otherPlan =
                MassDbLicenseUpgradeCore.summarize(
                        plan(fixture.localNodeUuid, fixture.build, 8051));
        MassDbLicenseException plan = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseUpgradeMarker.create(markerPath, fixture.meta,
                        otherPlan, fixture.build, SESSION_ID, DEPLOYMENT_ID, NOW + 1));
        Assertions.assertEquals("MASSDB_LICENSE_UPGRADE_MARKER_CONFLICT", plan.getCode());

        MassDbLicenseBuildIdentity wrongBuild = new MassDbLicenseBuildIdentity(
                fixture.build.componentVersion, fixture.build.capabilityVersion,
                fixture.build.stateFormatVersion, fixture.build.journalOperationType,
                fixture.build.snapshotFormat, repeat('b'));
        MassDbLicenseUpgradeMarker.Attestation sealed = MassDbLicenseUpgradeMarker.inspect(
                markerPath, fixture.meta, wrongBuild, fixture.localNodeUuid, NOW + 1);
        Assertions.assertEquals(MassDbLicenseUpgradeMarker.Status.SEALED, sealed.status);
        Assertions.assertEquals("MASSDB_LICENSE_UPGRADE_MARKER_MISMATCH",
                sealed.reasonCode);
    }

    private Fixture fixture(String name, boolean existing) throws IOException {
        Path meta = Files.createDirectories(temporaryDirectory.resolve(name).resolve("meta"));
        if (existing) {
            Files.createDirectory(meta.resolve("image"));
        }
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                meta.resolve("massdb-license"));
        String localNodeUuid = store.getNodeUuid();
        MassDbLicenseBuildIdentity build = new MassDbLicenseBuildIdentity(
                "4.0.5-license-test", "1", MassDbLicenseState.FORMAT_VERSION,
                10_001, MassDbLicenseBuildIdentity.SNAPSHOT_FORMAT, repeat('a'));
        MassDbLicenseUpgradeCore.PlanSummary summary =
                MassDbLicenseUpgradeCore.summarize(plan(localNodeUuid, build, 8050));
        return new Fixture(meta, localNodeUuid, build, summary);
    }

    private static byte[] plan(String localNodeUuid,
            MassDbLicenseBuildIdentity build, int httpsPort) {
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
                + "\"editLogPort\":9010,\"httpsEndpoint\":\"https://fe-1.example:"
                + httpsPort + "\"}]}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static String repeat(char value) {
        return String.join("", Collections.nCopies(64, String.valueOf(value)));
    }

    private static final class Fixture {
        private final Path meta;
        private final String localNodeUuid;
        private final MassDbLicenseBuildIdentity build;
        private final MassDbLicenseUpgradeCore.PlanSummary summary;

        private Fixture(Path meta, String localNodeUuid,
                MassDbLicenseBuildIdentity build,
                MassDbLicenseUpgradeCore.PlanSummary summary) {
            this.meta = meta;
            this.localNodeUuid = localNodeUuid;
            this.build = build;
            this.summary = summary;
        }
    }
}
