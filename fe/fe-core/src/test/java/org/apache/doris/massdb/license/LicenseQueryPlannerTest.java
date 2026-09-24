// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.MaterializedIndexMeta;
import org.apache.doris.catalog.OlapTable;
import org.apache.doris.common.cache.NereidsSqlCacheManager;
import org.apache.doris.nereids.NereidsPlanner;
import org.apache.doris.nereids.SqlCacheContext;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.glue.LogicalPlanAdapter;
import org.apache.doris.nereids.parser.NereidsParser;
import org.apache.doris.nereids.properties.PhysicalProperties;
import org.apache.doris.nereids.trees.plans.Plan;
import org.apache.doris.nereids.trees.plans.commands.ExplainCommand.ExplainLevel;
import org.apache.doris.nereids.trees.plans.logical.LogicalPlan;
import org.apache.doris.nereids.trees.plans.logical.LogicalSqlCache;
import org.apache.doris.qe.OriginStatement;
import org.apache.doris.thrift.TUniqueId;
import org.apache.doris.utframe.TestWithFeService;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Optional;

/** Real binding/rewrite/cache tests; no BE execution or entitlement is simulated as an integration result. */
class LicenseQueryPlannerTest extends TestWithFeService {
    @Override
    protected void runBeforeAll() throws Exception {
        createDatabaseAndUse("license_query");
        connectContext.getSessionVariable().setDisableNereidsRules("PRUNE_EMPTY_PARTITION");
        connectContext.getSessionVariable().setParallelResultSink(false);
        createTable("create table t(k int, v int) duplicate key(k) distributed by hash(k) buckets 1 "
                + "properties('replication_num'='1')");
        createTable("create table pt(dt date, k int) duplicate key(dt) partition by range(dt) "
                + "(partition p2020 values [('2020-01-01'),('2021-01-01'))) "
                + "distributed by hash(k) buckets 1 properties('replication_num'='1')");
        createView("create view v_t as select * from t");
    }

    @Test
    void boundBusinessDependenciesSurviveOptimization() {
        for (String sql : new String[] {"select * from t", "select count(*) from t", "select sum(k) from t",
                "select distinct k from t", "select 1 from t where k=1", "select exists(select 1 from t)",
                "select a.k from t a join t b on a.k=b.k", "with a as (select * from t) select * from a",
                "select k from t union all select k from t", "select * from v_t",
                "select 1 from v_t limit 1",
                "select table_name from information_schema.tables where table_name in (select cast(k as string) from t)"}) {
            Assertions.assertTrue(plan(sql).getStatementContext().getLicenseQueryClassification()
                    .requiresLicense(false), sql);
        }
    }

    @Test
    void metadataConstantsAndStrictProbesKeepTheirOriginalMeaning() {
        for (String sql : new String[] {"select 1", "select now()", "select database()", "select @@version",
                "select table_name from information_schema.tables", "select * from numbers('number'='3')",
                "select * from backends()", "select 1 from t limit 1", "select 1 as alive from t limit 1 offset 0"}) {
            Assertions.assertFalse(plan(sql).getStatementContext().getLicenseQueryClassification()
                    .requiresLicense(false), sql);
        }
        for (String sql : new String[] {"select 1 from t where 1=1 limit 1",
                "select 1 from t order by 1 limit 1", "select cast(1 as int) from t limit 1",
                "select 1 from t limit 2", "select 1 from t limit 1 offset 1"}) {
            Assertions.assertTrue(plan(sql).getStatementContext().getLicenseQueryClassification()
                    .requiresLicense(false), sql);
        }
    }

    @Test
    void finalEmptyProofDiffersFromEmptyInputAndNonemptyUnion() {
        for (String sql : new String[] {"select * from t limit 0", "select * from t where 1=0",
                "select * from pt where dt='2099-01-01'"}) {
            LicenseQueryGuard.Classification classification = plan(sql).getStatementContext()
                    .getLicenseQueryClassification();
            Assertions.assertTrue(classification.isEmptyWithoutRead(), sql);
            Assertions.assertFalse(classification.requiresLicense(false), sql);
        }
        for (String sql : new String[] {"select count(*) from pt where dt='2099-01-01'",
                "select k from pt where dt='2099-01-01' union all select k from t",
                "select * from t where k=-1"}) {
            Assertions.assertTrue(plan(sql).getStatementContext().getLicenseQueryClassification()
                    .requiresLicense(false), sql);
        }
    }

    @Test
    void planWithLockPublishesFactsWithoutFullPlannerCallback() {
        String sql = "select * from t";
        StatementContext statement = new StatementContext(connectContext, new OriginStatement(sql, 0));
        connectContext.setStatementContext(statement);
        Plan physical = new NereidsPlanner(statement).planWithLock(new NereidsParser().parseSingle(sql),
                PhysicalProperties.ANY, ExplainLevel.NONE);
        Assertions.assertNotNull(statement.getLicenseQueryClassification());
        Assertions.assertTrue(LicenseQueryGuard.requiresLicense(statement, physical));
    }

    @Test
    void feCacheRetainsClassificationAndInvalidatesOnBaseSchemaChange() throws Exception {
        String sql = "select * from t where 1=0";
        NereidsPlanner planner = plan(sql);
        SqlCacheContext cache = planner.getStatementContext().getSqlCacheContext().get();
        LogicalPlan logical = new NereidsParser().parseSingle(sql);
        connectContext.setQueryId(new TUniqueId(1, 2));
        Assertions.assertTrue(planner.handleQueryInFe(LogicalPlanAdapter.of(logical)).isPresent());
        NereidsSqlCacheManager cacheManager = new NereidsSqlCacheManager();
        cacheManager.tryAddFeSqlCache(connectContext, sql);
        Assertions.assertEquals(1, cacheManager.getSqlCacheNum());
        connectContext.setStatementContext(new StatementContext(connectContext, new OriginStatement(sql, 0)));
        Optional<LogicalSqlCache> hit = cacheManager.tryParseSql(connectContext, sql);
        Assertions.assertTrue(hit.isPresent());
        Assertions.assertSame(cache.getLicenseQueryClassification(), hit.get().getLicenseQueryClassification());
        NereidsPlanner hitPlanner = new NereidsPlanner(connectContext.getStatementContext());
        hitPlanner.plan(LogicalPlanAdapter.of(hit.get()));
        Assertions.assertFalse(LicenseQueryGuard.requiresLicense(hitPlanner.getStatementContext(),
                hitPlanner.getPhysicalPlan()));

        LicenseQueryGuard.Classification known = cache.getLicenseQueryClassification();
        cache.setLicenseQueryClassification(null);
        connectContext.setStatementContext(new StatementContext(connectContext, new OriginStatement(sql, 0)));
        Optional<LogicalSqlCache> oldHit = cacheManager.tryParseSql(connectContext, sql);
        Assertions.assertTrue(oldHit.isPresent());
        NereidsPlanner oldPlanner = new NereidsPlanner(connectContext.getStatementContext());
        oldPlanner.plan(LogicalPlanAdapter.of(oldHit.get()));
        Assertions.assertTrue(LicenseQueryGuard.requiresLicense(oldPlanner.getStatementContext(),
                oldPlanner.getPhysicalPlan()));
        cache.setLicenseQueryClassification(known);

        OlapTable table = (OlapTable) Env.getCurrentInternalCatalog().getDbOrAnalysisException("license_query")
                .getTableOrAnalysisException("t");
        MaterializedIndexMeta meta = table.getIndexMetaByIndexId(table.getBaseIndexId());
        int originalVersion = meta.getSchemaVersion();
        try {
            meta.setSchemaVersion(originalVersion + 1);
            connectContext.setStatementContext(new StatementContext(connectContext, new OriginStatement(sql, 0)));
            Assertions.assertFalse(cacheManager.tryParseSql(connectContext, sql).isPresent());
            Assertions.assertEquals(0, cacheManager.getSqlCacheNum());
        } finally {
            meta.setSchemaVersion(originalVersion);
        }
    }

    private NereidsPlanner plan(String sql) {
        StatementContext statement = new StatementContext(connectContext, new OriginStatement(sql, 0));
        connectContext.setStatementContext(statement);
        NereidsPlanner planner = new NereidsPlanner(statement);
        planner.plan(LogicalPlanAdapter.of(new NereidsParser().parseSingle(sql)));
        Assertions.assertNotNull(statement.getLicenseQueryClassification(), sql);
        return planner;
    }
}
