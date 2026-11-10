// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.nereids.rules.RuleType;
import org.apache.doris.planner.Planner;
import org.apache.doris.utframe.TestWithFeService;

import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Review L14: the CTAS, overwrite and EXPORT admission tests stub the check itself, so they never exercise the
 * real classification or status. These run the real guard on plans bound by a real FE; only the license status
 * is forced. External CTAS and overwrite need a reachable external catalog, so their shared external-write check
 * is driven directly with a real bound plan instead of through the command.
 */
class LicenseRealAdmissionTest extends TestWithFeService {
    private static volatile LicenseQueryStatus status = LicenseQueryStatus.EXPIRED;

    /** Forces the status itself. */
    @Override
    protected boolean validLicenseFixture() {
        return false;
    }

    @Override
    protected void runBeforeAll() throws Exception {
        createDatabase("lic");
        createTable("create table lic.t1(k1 int, v1 int) distributed by hash(k1) buckets 1 "
                + "properties('replication_num'='1')");
    }

    @Test
    void externalWriteCheckDeniesABoundBusinessTableAndAdmitsInformationSchema() throws Exception {
        // Plan under a valid license so binding records the real facts, then check as an expired one. Keep the
        // empty partition: a plan that provably reads nothing needs no license by design.
        connectContext.getSessionVariable().setDisableNereidsRules(RuleType.PRUNE_EMPTY_PARTITION.name());
        mockStatus();
        status = LicenseQueryStatus.VALID;
        Planner business = getSqlStmtExecutor("select k1, v1 from lic.t1").planner();
        Planner metadata = getSqlStmtExecutor("select table_name from information_schema.tables").planner();
        status = LicenseQueryStatus.EXPIRED;
        LicenseSqlException denied = Assertions.assertThrows(LicenseSqlException.class,
                () -> LicenseQueryGuard.checkExternalWrite(business));
        Assertions.assertTrue(denied.getMessage().contains("LICENSE_EXPIRED"), denied.getMessage());
        Assertions.assertDoesNotThrow(() -> LicenseQueryGuard.checkExternalWrite(metadata));
    }

    @Test
    void exportIsDeniedBeforeAJobIsRegisteredWhileShowExportIsServed() throws Exception {
        mockStatus();
        status = LicenseQueryStatus.EXPIRED;
        boolean previous = Config.enable_outfile_to_local;
        Config.enable_outfile_to_local = true;
        try {
            IllegalStateException denied = Assertions.assertThrows(IllegalStateException.class,
                    () -> executeSql("export table lic.t1 to \"file:///tmp/massdb-license-export-test/\""));
            Assertions.assertTrue(denied.getMessage().contains("LICENSE_EXPIRED"), denied.getMessage());
            Assertions.assertTrue(Env.getCurrentEnv().getExportMgr().getJobs().isEmpty());
            executeSql("show export from lic");
        } finally {
            Config.enable_outfile_to_local = previous;
        }
    }

    /** Only the status is forced; the guard, the classification and the commands stay real. */
    private static void mockStatus() {
        new MockUp<LicenseManager>() {
            @Mock
            public LicenseQueryStatus queryStatus() {
                return status;
            }
        };
    }
}
