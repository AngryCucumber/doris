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

import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

public class MassDbLicenseMetricsTest {
    @Test
    public void missingSnapshotUsesFrozenMetricNamesWithoutArtifactBytes() {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(false, repeat('a'));
        Map<String, PublicKey> roots = Collections.singletonMap(
                "massdb-test-root-1",
                MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.decode(
                                MassDbLicenseProtocolV1Test.ROOT_PUBLIC)));
        MassDbLicenseReadApiCore core = new MassDbLicenseReadApiCore(
                "4.0.0", 31_536_000L, roots);
        MassDbLicenseReadApiCore.Status status = core.status(state, 1_000, 1_000);
        String metrics = MassDbLicenseMetrics.render(status, state);
        Assertions.assertTrue(metrics.contains("massdb_license_state{state=\"MISSING\"} 1"));
        Assertions.assertTrue(metrics.contains("massdb_license_expiry_timestamp_seconds 0"));
        Assertions.assertTrue(metrics.contains("massdb_license_enforcement_enabled 1"));
        Assertions.assertFalse(metrics.contains("artifact"));
    }

    private static String repeat(char value) {
        return new String(new char[64]).replace('\0', value);
    }
}
