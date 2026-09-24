// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.TableIf;
import org.apache.doris.common.ErrorCode;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.parser.NereidsParser;
import org.apache.doris.nereids.trees.expressions.functions.agg.AggregateParam;
import org.apache.doris.nereids.trees.expressions.functions.scalar.DictGet;
import org.apache.doris.nereids.trees.expressions.functions.scalar.DictGetMany;
import org.apache.doris.nereids.trees.expressions.literal.IntegerLiteral;
import org.apache.doris.nereids.trees.expressions.literal.StringLiteral;
import org.apache.doris.nereids.trees.plans.AggMode;
import org.apache.doris.nereids.trees.plans.AggPhase;
import org.apache.doris.nereids.trees.plans.Plan;
import org.apache.doris.nereids.trees.plans.RelationId;
import org.apache.doris.nereids.trees.plans.algebra.SetOperation.Qualifier;
import org.apache.doris.nereids.trees.plans.physical.PhysicalEmptyRelation;
import org.apache.doris.nereids.trees.plans.physical.PhysicalHashAggregate;
import org.apache.doris.nereids.trees.plans.physical.PhysicalOneRowRelation;
import org.apache.doris.nereids.trees.plans.physical.PhysicalResultSink;
import org.apache.doris.nereids.trees.plans.physical.PhysicalUnion;
import org.apache.doris.tablefunction.ExternalFileTableValuedFunction;
import org.apache.doris.tablefunction.MetadataTableValuedFunction;
import org.apache.doris.tablefunction.NumbersTableValuedFunction;
import org.apache.doris.tablefunction.QueryTableValueFunction;
import org.apache.doris.tablefunction.TableValuedFunctionIf;

import com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Optional;

class LicenseQueryGuardTest {
    private final Plan ordinaryPlan = Mockito.mock(Plan.class);

    @Test
    void exactOriginalTableProbeAllowsOnlyFrozenShape() {
        for (String sql : new String[] {
                "select 1 from t limit 1", "select 1 as alive from t limit 1 offset 0",
                "(select 1 from t limit 1)", "select 1 from external_catalog.db.t limit 1"}) {
            Assertions.assertTrue(LicenseQueryGuard.isOriginalTableProbe(parse(sql)), sql);
        }
        for (String sql : new String[] {
                "select 1 from t limit 1 offset 1", "select 1 from t limit 2", "select 1 from t",
                "select 1 from t where 1=1 limit 1", "select distinct 1 from t limit 1",
                "select 1 from t order by 1 limit 1", "select cast(1 as int) from t limit 1",
                "select abs(1) from t limit 1", "select 1 from t having 1=1 limit 1",
                "select 1 from t join u on t.k=u.k limit 1",
                "select 1 from (select * from t) a limit 1",
                "with a as (select * from t) select 1 from a limit 1",
                "select 1 from t union all select 1 from u limit 1",
                "select 1 from numbers('number'='1') limit 1", "select 1.0 from t limit 1",
                "select 1,1 from t limit 1", "select 1 from t tablesample(1 rows) limit 1"}) {
            Assertions.assertFalse(LicenseQueryGuard.isOriginalTableProbe(parse(sql)), sql);
        }
    }

    @Test
    void realTablesIncludeInternalSystemAndExternalTables() {
        for (TableIf.TableType type : new TableIf.TableType[] {TableIf.TableType.OLAP,
                TableIf.TableType.MATERIALIZED_VIEW, TableIf.TableType.HMS_EXTERNAL_TABLE,
                TableIf.TableType.JDBC_EXTERNAL_TABLE, TableIf.TableType.ICEBERG_EXTERNAL_TABLE}) {
            LicenseQueryGuard.Facts facts = facts("select * from t");
            facts.table(table(type), false);
            Assertions.assertTrue(facts.finish(ordinaryPlan).requiresLicense(false), type.name());
        }
    }

    @Test
    void metadataMixedWithBusinessRemainsProtected() {
        LicenseQueryGuard.Facts facts = facts("select * from information_schema.tables");
        facts.table(table(TableIf.TableType.SCHEMA), false);
        Assertions.assertFalse(facts.finish(ordinaryPlan).requiresLicense(false));
        facts.table(table(TableIf.TableType.OLAP), false);
        Assertions.assertTrue(facts.finish(ordinaryPlan).requiresLicense(false));
    }

    @Test
    void probeNeedsBoundRealTableAndIsNotAnExternalWriteExemption() {
        LicenseQueryGuard.Facts facts = facts("select 1 from t limit 1");
        facts.table(table(TableIf.TableType.OLAP), false);
        LicenseQueryGuard.Classification classification = facts.finish(ordinaryPlan);
        Assertions.assertTrue(classification.isTableProbe());
        Assertions.assertFalse(classification.requiresLicense(false));
        Assertions.assertTrue(classification.requiresLicense(true));
        // Binding a policy's additional data source must not inherit the original single-table exemption.
        facts.table(table(TableIf.TableType.OLAP), false);
        Assertions.assertTrue(facts.finish(ordinaryPlan).requiresLicense(false));
    }

    @Test
    void viewAndTvfCannotBorrowProbeShape() {
        LicenseQueryGuard.Facts view = facts("select 1 from v limit 1");
        view.table(table(TableIf.TableType.OLAP), false);
        view.table(table(TableIf.TableType.VIEW), true);
        Assertions.assertFalse(view.finish(ordinaryPlan).isTableProbe());
        Assertions.assertTrue(view.finish(ordinaryPlan).requiresLicense(false));
        LicenseQueryGuard.Facts tvf = facts("select 1 from t limit 1");
        tvf.tableFunction(Mockito.mock(ExternalFileTableValuedFunction.class));
        Assertions.assertFalse(tvf.finish(ordinaryPlan).isTableProbe());
        Assertions.assertTrue(tvf.finish(ordinaryPlan).requiresLicense(false));
    }

    @Test
    void tvfClassificationUsesBoundImplementationNotTextName() {
        for (Class<? extends TableValuedFunctionIf> type : ImmutableList.of(
                ExternalFileTableValuedFunction.class, QueryTableValueFunction.class)) {
            LicenseQueryGuard.Facts facts = facts("select 1");
            facts.tableFunction(Mockito.mock(type));
            Assertions.assertTrue(facts.finish(ordinaryPlan).requiresLicense(false));
        }
        for (Class<? extends TableValuedFunctionIf> type : ImmutableList.of(
                MetadataTableValuedFunction.class, NumbersTableValuedFunction.class)) {
            LicenseQueryGuard.Facts facts = facts("select 1");
            facts.tableFunction(Mockito.mock(type));
            Assertions.assertFalse(facts.finish(ordinaryPlan).requiresLicense(false));
        }
    }

    @Test
    void dictionarySourceSurvivesLiteralFoldingAndNoScanPlan() {
        LicenseQueryGuard.Facts single = facts("select 1");
        single.function(new DictGet(new StringLiteral("db.d"), new StringLiteral("v"), new IntegerLiteral(1)));
        Assertions.assertTrue(single.finish(ordinaryPlan).requiresLicense(false));
        LicenseQueryGuard.Facts many = facts("select 1");
        many.function(new DictGetMany(new StringLiteral("db.d"), new StringLiteral("v"), new IntegerLiteral(1)));
        Assertions.assertTrue(many.finish(ordinaryPlan).requiresLicense(false));
        LicenseQueryGuard.Facts constant = facts("select 1");
        constant.function(new IntegerLiteral(1));
        Assertions.assertFalse(constant.finish(ordinaryPlan).requiresLicense(false));
    }

    @Test
    void onlyCompleteEmptyWithoutReadProofAllowsProtectedSource() {
        LicenseQueryGuard.Facts facts = facts("select * from t where 1=0");
        facts.table(table(TableIf.TableType.OLAP), false);
        PhysicalEmptyRelation empty = empty();
        PhysicalResultSink<Plan> sink = new PhysicalResultSink<>(ImmutableList.of(), Optional.empty(), null, empty);
        Assertions.assertTrue(LicenseQueryGuard.emptyWithoutRead(sink));
        Assertions.assertFalse(facts.finish(sink).requiresLicense(false));
        Assertions.assertTrue(facts.finish(ordinaryPlan).requiresLicense(false));
        Assertions.assertFalse(LicenseQueryGuard.emptyWithoutRead(null));
    }

    @Test
    void emptyAggregateInputCannotProveScalarCountEmpty() {
        PhysicalHashAggregate<Plan> count = new PhysicalHashAggregate<>(ImmutableList.of(), ImmutableList.of(),
                new AggregateParam(AggPhase.GLOBAL, AggMode.INPUT_TO_RESULT), false, null, empty());
        Assertions.assertFalse(LicenseQueryGuard.emptyWithoutRead(count));
        PhysicalHashAggregate<Plan> grouped = new PhysicalHashAggregate<>(ImmutableList.of(new IntegerLiteral(1)),
                ImmutableList.of(), new AggregateParam(AggPhase.GLOBAL, AggMode.INPUT_TO_RESULT), false, null, empty());
        Assertions.assertTrue(LicenseQueryGuard.emptyWithoutRead(grouped));
    }

    @Test
    void emptyUnionBranchDoesNotProveWholeResultEmpty() {
        PhysicalUnion mixed = new PhysicalUnion(Qualifier.ALL, ImmutableList.of(), ImmutableList.of(), ImmutableList.of(),
                null, ImmutableList.of(empty(),
                        new PhysicalOneRowRelation(new RelationId(2), ImmutableList.of(), null)));
        Assertions.assertFalse(LicenseQueryGuard.emptyWithoutRead(mixed));
        PhysicalUnion allEmpty = new PhysicalUnion(Qualifier.ALL, ImmutableList.of(), ImmutableList.of(), ImmutableList.of(),
                null, ImmutableList.of(empty(), empty()));
        Assertions.assertTrue(LicenseQueryGuard.emptyWithoutRead(allEmpty));
    }

    @Test
    void everyDeniedStateUsesTypedReadErrorAndUnknownClassificationFailsClosed() throws Exception {
        for (LicenseQueryStatus status : LicenseQueryStatus.values()) {
            if (status.permitsNewQuery()) {
                LicenseQueryGuard.check(status, null, false);
            } else {
                LicenseSqlException failure = Assertions.assertThrows(LicenseSqlException.class,
                        () -> LicenseQueryGuard.check(status, null, false));
                Assertions.assertEquals(ErrorCode.ERR_LICENSE_QUERY_DENIED, failure.getMysqlErrorCode());
                Assertions.assertTrue(failure.getMessage().contains(LicenseQueryGuard.reason(status)));
            }
        }
        Assertions.assertTrue(LicenseQueryGuard.requiresLicense(null, ordinaryPlan));
        Assertions.assertTrue(LicenseQueryGuard.requiresLicense(new StatementContext(), ordinaryPlan));
    }

    @Test
    void cachedImmutableClassificationRetainsSourcesAndExactExceptions() {
        LicenseQueryGuard.Facts source = facts("select * from t");
        source.table(table(TableIf.TableType.OLAP), false);
        LicenseQueryGuard.Classification saved = source.finish(ordinaryPlan);
        StatementContext hit = new StatementContext();
        hit.setLicenseQueryClassification(saved);
        Assertions.assertTrue(LicenseQueryGuard.requiresLicense(hit, ordinaryPlan));
        LicenseQueryGuard.Facts probe = facts("select 1 from t limit 1");
        probe.table(table(TableIf.TableType.OLAP), false);
        hit.setLicenseQueryClassification(probe.finish(ordinaryPlan));
        Assertions.assertFalse(LicenseQueryGuard.requiresLicense(hit, ordinaryPlan));
        hit.setLicenseQueryClassification(null);
        Assertions.assertTrue(LicenseQueryGuard.requiresLicense(hit, ordinaryPlan));
    }

    private static Plan parse(String sql) {
        return new NereidsParser().parseSingle(sql);
    }

    private static LicenseQueryGuard.Facts facts(String sql) {
        LicenseQueryGuard.Facts facts = new LicenseQueryGuard.Facts();
        facts.begin(parse(sql));
        facts.analyzed();
        return facts;
    }

    private static TableIf table(TableIf.TableType type) {
        TableIf table = Mockito.mock(TableIf.class);
        Mockito.when(table.getType()).thenReturn(type);
        return table;
    }

    private static PhysicalEmptyRelation empty() {
        return new PhysicalEmptyRelation(new RelationId(1), ImmutableList.of(), null);
    }
}
