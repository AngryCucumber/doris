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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

class MassDbLicenseBootstrapMarkerTest {
    @TempDir
    Path directory;

    @Test
    void createsOnceReplaysSamePlanAndFreshnessFailCloses() throws IOException {
        Path markerFile = directory.resolve("bootstrap-control.marker");
        String plan = repeat('a');
        MassDbLicenseBootstrapMarker.Attestation created =
                MassDbLicenseBootstrapMarker.create(markerFile, directory, plan, 100);
        Assertions.assertEquals(MassDbLicenseBootstrapMarker.Status.ELIGIBLE, created.status);
        Assertions.assertEquals(plan, created.bootstrapPlanSha256);
        Assertions.assertEquals(created.bootstrapMarkerId,
                MassDbLicenseBootstrapMarker.create(
                        markerFile, directory, plan, 200).bootstrapMarkerId);
        MassDbLicenseBootstrapMarker.Attestation claimed =
                MassDbLicenseBootstrapMarker.inspect(markerFile, directory);
        Assertions.assertTrue(claimed.isEligible());
        Assertions.assertEquals("CLAIMED", claimed.localClaimStatus);
        Assertions.assertNotNull(claimed.bootstrapClaimId);

        MassDbLicenseException mismatch = Assertions.assertThrows(MassDbLicenseException.class,
                () -> MassDbLicenseBootstrapMarker.create(
                        markerFile, directory, repeat('b'), 200));
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_PLAN_MISMATCH", mismatch.getCode());

        Files.createDirectory(directory.resolve("image"));
        Files.createDirectory(directory.resolve("bdb"));
        MassDbLicenseBootstrapMarker.Attestation recovered =
                MassDbLicenseBootstrapMarker.inspect(markerFile, directory);
        Assertions.assertTrue(recovered.isEligible());
        Assertions.assertEquals(claimed.bootstrapClaimId, recovered.bootstrapClaimId);

        MassDbLicenseBootstrapMarker.Attestation recorded =
                MassDbLicenseBootstrapMarker.markOpenRecorded(
                        markerFile, directory, recovered, 400);
        Assertions.assertEquals("OPEN_RECORDED", recorded.localClaimStatus);
        MassDbLicenseBootstrapMarker.Attestation sealed =
                MassDbLicenseBootstrapMarker.inspect(markerFile, directory);
        Assertions.assertEquals(MassDbLicenseBootstrapMarker.Status.SEALED, sealed.status);
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_CLAIM_ALREADY_OPENED",
                sealed.reasonCode);
    }

    @Test
    void absentMarkerNeverOpensAndMalformedMarkerFailsClosed() throws IOException {
        Path markerFile = directory.resolve("bootstrap-control.marker");
        Assertions.assertEquals(MassDbLicenseBootstrapMarker.Status.ABSENT,
                MassDbLicenseBootstrapMarker.inspect(markerFile, directory).status);

        Files.write(markerFile, "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MassDbLicenseBootstrapMarker.Attestation invalid =
                MassDbLicenseBootstrapMarker.inspect(markerFile, directory);
        Assertions.assertEquals(MassDbLicenseBootstrapMarker.Status.SEALED, invalid.status);
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", invalid.reasonCode);

        Path freshMeta = Files.createDirectory(directory.resolve("fresh-meta"));
        new MassDbLicenseLocalSnapshotStore(freshMeta.resolve("massdb-license"));
        Path freshMarker = freshMeta.resolve("bootstrap-control.marker");
        MassDbLicenseBootstrapMarker.create(freshMarker, freshMeta, repeat('c'), 300);
        Assertions.assertTrue(MassDbLicenseBootstrapMarker.inspect(
                freshMarker, freshMeta).isEligible());
        Files.write(freshMeta.resolve("massdb-license").resolve("active.snapshot"),
                new byte[] {1});
        MassDbLicenseBootstrapMarker.Attestation restoredRuntime =
                MassDbLicenseBootstrapMarker.inspect(freshMarker, freshMeta);
        Assertions.assertEquals(MassDbLicenseBootstrapMarker.Status.SEALED,
                restoredRuntime.status);
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH",
                restoredRuntime.reasonCode);
    }

    private static String repeat(char value) {
        return String.join("", Collections.nCopies(64, String.valueOf(value)));
    }
}
