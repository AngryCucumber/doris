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

import org.apache.doris.catalog.Env;
import org.apache.doris.datasource.tvf.source.TVFScanNode;
import org.apache.doris.massdblicense.MassDbLicenseQueryGuard.QueryOrigin;
import org.apache.doris.nereids.parser.NereidsParser;
import org.apache.doris.nereids.trees.plans.logical.LogicalPlan;
import org.apache.doris.planner.GroupCommitScanNode;
import org.apache.doris.planner.ScanNode;
import org.apache.doris.qe.ConnectContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Collections;

class MassDbLicenseQueryGuardTest {
    private final NereidsParser parser = new NereidsParser();

    @BeforeEach
    void installConnectContext() {
        new ConnectContext().setThreadLocalInfo();
    }

    @AfterEach
    void clearConnectContext() {
        ConnectContext.remove();
    }

    @Test
    void parsedGateBlocksBusinessReadsButNotConstantQueries() {
        Assertions.assertTrue(isProtected("SELECT * FROM sales.orders"));
        Assertions.assertTrue(isProtected(
                "SELECT (SELECT MAX(id) FROM sales.orders)"));
        Assertions.assertTrue(isProtected(
                "WITH recent AS (SELECT * FROM sales.orders) SELECT * FROM recent"));
        Assertions.assertTrue(isProtected("SHOW TABLES"));
        Assertions.assertTrue(isProtected("EXPLAIN SELECT * FROM sales.orders"));
        Assertions.assertFalse(isProtected("SELECT 1"));
        Assertions.assertFalse(isProtected("EXPLAIN SELECT 1"));
    }

    @Test
    void parsedGateAllowsValuesIngestionAndBlocksReadBasedWrites() {
        Assertions.assertFalse(isProtected("INSERT INTO sales.orders VALUES (1)"));
        Assertions.assertTrue(isProtected(
                "INSERT INTO sales.archive SELECT * FROM sales.orders"));
        Assertions.assertTrue(isProtected("UPDATE sales.orders SET id = 2 WHERE id = 1"));
        Assertions.assertTrue(isProtected("DELETE FROM sales.orders WHERE id = 1"));
    }

    @Test
    void parsedGateDefaultsSchemaAndUnknownCommandsToDenied() {
        Assertions.assertTrue(isProtected("CREATE DATABASE sales"));
        Assertions.assertTrue(isProtected("CREATE TABLE sales.orders (id INT)"));
        Assertions.assertTrue(isProtected(
                "CREATE TABLE sales.archive AS SELECT * FROM sales.orders"));
    }

    @Test
    void onlyTrustedHttpLoadOriginMayReadHttpStreamTvf() {
        LogicalPlan httpStream = parser.parseSingle(
                "INSERT INTO sales.orders SELECT * FROM http_stream('format'='csv')");
        Assertions.assertFalse(MassDbLicenseQueryGuard.isProtectedParsedPlan(
                QueryOrigin.EXTERNAL_HTTP_LOAD, httpStream));
        Assertions.assertTrue(MassDbLicenseQueryGuard.isProtectedParsedPlan(
                QueryOrigin.EXTERNAL_MYSQL, httpStream));

        LogicalPlan externalFile = parser.parseSingle(
                "INSERT INTO sales.orders SELECT * FROM s3('uri'='s3://bucket/object')");
        Assertions.assertTrue(MassDbLicenseQueryGuard.isProtectedParsedPlan(
                QueryOrigin.EXTERNAL_HTTP_LOAD, externalFile));
    }

    @Test
    void analyzedGateAllowsOnlyDedicatedIngestionScans() {
        ScanNode ordinary = Mockito.mock(ScanNode.class);
        GroupCommitScanNode groupCommit = Mockito.mock(GroupCommitScanNode.class);
        TVFScanNode httpStream = Mockito.mock(TVFScanNode.class);

        Assertions.assertTrue(MassDbLicenseQueryGuard.isProtectedAnalyzedPlan(
                QueryOrigin.EXTERNAL_MYSQL, Collections.singletonList(ordinary), false));
        Assertions.assertFalse(MassDbLicenseQueryGuard.isProtectedAnalyzedPlan(
                QueryOrigin.EXTERNAL_MYSQL, Collections.singletonList(groupCommit), true));
        Assertions.assertFalse(MassDbLicenseQueryGuard.isProtectedAnalyzedPlan(
                QueryOrigin.EXTERNAL_HTTP_LOAD, Collections.singletonList(httpStream), true));
        Assertions.assertTrue(MassDbLicenseQueryGuard.isProtectedAnalyzedPlan(
                QueryOrigin.EXTERNAL_MYSQL, Collections.singletonList(httpStream), true));
    }

    @Test
    void internalOriginNeverDependsOnLicenseState() {
        Assertions.assertFalse(MassDbLicenseQueryGuard.isProtectedParsedPlan(
                QueryOrigin.INTERNAL, parser.parseSingle("SELECT * FROM sales.orders")));
        Assertions.assertFalse(MassDbLicenseQueryGuard.isProtectedAnalyzedPlan(
                QueryOrigin.INTERNAL,
                Collections.singletonList(Mockito.mock(ScanNode.class)), false));
    }

    @Test
    void localDenialKeepsStableComponentPublicCode() {
        Env env = Mockito.mock(Env.class);
        Mockito.when(env.evaluateMassDbLicenseLocalQuery()).thenReturn(
                MassDbLicenseLocalSnapshotStore.QueryDecision.deny("MASSDB_LICENSE_EXPIRED"));
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            MassDbLicenseQueryException error = Assertions.assertThrows(
                    MassDbLicenseQueryException.class,
                    () -> MassDbLicenseQueryGuard.enforceMetadataRead(
                            QueryOrigin.EXTERNAL_MYSQL));
            Assertions.assertEquals("MASSDB_LICENSE_EXPIRED", error.getLicenseErrorCode());
            Assertions.assertEquals(6001, error.getMysqlErrorCode().getCode());
            Assertions.assertTrue(error.getMessage().contains("MASSDB_LICENSE_EXPIRED"));
        }
    }

    @Test
    void absentComponentCapabilityPreservesOldClusterBehavior() {
        Env env = Mockito.mock(Env.class);
        Mockito.when(env.evaluateMassDbLicenseLocalQuery()).thenReturn(null);
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            Assertions.assertDoesNotThrow(() ->
                    MassDbLicenseQueryGuard.enforceMetadataRead(
                            QueryOrigin.EXTERNAL_MYSQL));
        }
    }

    private boolean isProtected(String sql) {
        return MassDbLicenseQueryGuard.isProtectedParsedPlan(
                QueryOrigin.EXTERNAL_MYSQL, parser.parseSingle(sql));
    }
}
