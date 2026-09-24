// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.nereids.trees.plans.commands.insert;

import org.apache.doris.analysis.StatementBase;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.OlapTable;
import org.apache.doris.catalog.TableIf;
import org.apache.doris.catalog.TableProperty;
import org.apache.doris.datasource.InternalCatalog;
import org.apache.doris.datasource.hive.HMSExternalTable;
import org.apache.doris.load.loadv2.LoadManager;
import org.apache.doris.massdb.license.LicenseManager;
import org.apache.doris.massdb.license.LicenseQueryGuard;
import org.apache.doris.massdb.license.LicenseQueryStatus;
import org.apache.doris.massdb.license.LicenseSqlException;
import org.apache.doris.nereids.CascadesContext;
import org.apache.doris.nereids.NereidsPlanner;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.properties.PhysicalProperties;
import org.apache.doris.nereids.trees.plans.commands.ExplainCommand.ExplainLevel;
import org.apache.doris.nereids.trees.plans.logical.LogicalPlan;
import org.apache.doris.nereids.trees.plans.physical.PhysicalHiveTableSink;
import org.apache.doris.nereids.trees.plans.physical.PhysicalOlapTableSink;
import org.apache.doris.nereids.trees.plans.physical.PhysicalSink;
import org.apache.doris.planner.PlanFragment;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.Coordinator;
import org.apache.doris.qe.StmtExecutor;
import org.apache.doris.system.SystemInfoService;
import org.apache.doris.thrift.TQueryOptions;
import org.apache.doris.thrift.TUniqueId;

import mockit.Invocation;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

class LicenseInsertAdmissionTest {
    @AfterEach
    void clearContext() {
        ConnectContext.remove();
    }

    @Test
    void protectedExternalInsertIsDeniedBeforeExecutorConstructionAndTransaction() throws Exception {
        verifyBoundary(true, true);
    }

    @Test
    void externalValuesStillConstructsAndStartsItsWriteTransactionWhileExpired() throws Exception {
        verifyBoundary(true, false);
    }

    @Test
    void internalInsertWithProtectedSourceStillStartsItsWriteTransactionWhileExpired() throws Exception {
        verifyBoundary(false, true);
    }

    private static void verifyBoundary(boolean external, boolean protectedSource) throws Exception {
        ConnectContext context = new ConnectContext();
        Env env = Mockito.mock(Env.class);
        LicenseManager license = Mockito.mock(LicenseManager.class);
        LoadManager loads = Mockito.mock(LoadManager.class);
        Mockito.when(env.getLicenseManager()).thenReturn(license);
        Mockito.when(env.getLoadManager()).thenReturn(loads);
        Mockito.when(license.queryStatus()).thenReturn(LicenseQueryStatus.EXPIRED);
        InternalCatalog catalog =
                Mockito.mock(InternalCatalog.class);
        Mockito.when(catalog.getName()).thenReturn("internal");
        Mockito.when(env.getInternalCatalog()).thenReturn(catalog);
        context.setEnv(env);
        context.setQueryId(new TUniqueId(1, 2));
        context.setStatementContext(new StatementContext(context, null));
        context.setThreadLocalInfo();
        LogicalPlan query = Mockito.mock(LogicalPlan.class);
        TableIf table = external ? Mockito.mock(HMSExternalTable.class) : Mockito.mock(OlapTable.class);
        PhysicalSink<?> sink = external ? Mockito.mock(PhysicalHiveTableSink.class)
                : Mockito.mock(PhysicalOlapTableSink.class);
        Mockito.doReturn(Collections.singleton(sink)).when(sink).collect(Mockito.any());
        if (!external) {
            Mockito.when(((OlapTable) table).getTableProperty()).thenReturn(Mockito.mock(TableProperty.class));
        }
        context.getStatementContext().getLicenseQueryFacts().begin(query);
        context.getStatementContext().getLicenseQueryFacts().analyzed();
        if (protectedSource) {
            TableIf source = Mockito.mock(TableIf.class);
            Mockito.when(source.getType()).thenReturn(TableIf.TableType.OLAP);
            context.getStatementContext().getLicenseQueryFacts().table(source, false);
        }
        StmtExecutor executor = Mockito.mock(StmtExecutor.class);
        Mockito.doAnswer(call -> {
            LicenseQueryGuard.checkExternalWrite(call.getArgument(0));
            return null;
        }).when(executor).checkLicenseExternalWrite(Mockito.any(NereidsPlanner.class));
        Coordinator coordinator = Mockito.mock(Coordinator.class);
        Mockito.when(coordinator.getQueryOptions()).thenReturn(new TQueryOptions());
        PlanFragment fragment = Mockito.mock(PlanFragment.class);
        CascadesContext cascades = Mockito.mock(CascadesContext.class);

        // The real command retains its factory selection, construction and transaction ordering.
        // Replace only planning/backend work with an already bound physical sink and source facts.
        new MockUp<NereidsPlanner>() {
            @Mock
            public void plan(Invocation invocation, StatementBase statement, TQueryOptions options) throws Exception {
                NereidsPlanner planner = invocation.getInvokedInstance();
                Field physicalPlan = NereidsPlanner.class.getDeclaredField("physicalPlan");
                physicalPlan.setAccessible(true);
                physicalPlan.set(planner, sink);
                planner.getFragments().add(fragment);
                Method distribute = planner.getClass().getDeclaredMethod("doDistribute", boolean.class,
                        ExplainLevel.class);
                distribute.setAccessible(true);
                distribute.invoke(planner, false, ExplainLevel.NONE);
            }
        };
        try (MockedStatic<Env> environment = Mockito.mockStatic(Env.class);
                MockedStatic<InsertUtils> inserts = Mockito.mockStatic(InsertUtils.class);
                MockedStatic<CascadesContext> contexts = Mockito.mockStatic(CascadesContext.class);
                MockedStatic<OlapGroupCommitInsertExecutor> groupCommit
                        = Mockito.mockStatic(OlapGroupCommitInsertExecutor.class);
                MockedConstruction<HiveInsertExecutor> hive = Mockito.mockConstruction(HiveInsertExecutor.class,
                        (insert, construction) -> Mockito.when(insert.getCoordinator()).thenReturn(coordinator));
                MockedConstruction<OlapInsertExecutor> olap = Mockito.mockConstruction(OlapInsertExecutor.class,
                        (insert, construction) -> Mockito.when(insert.getCoordinator()).thenReturn(coordinator))) {
            environment.when(Env::getCurrentEnv).thenReturn(env);
            environment.when(Env::getCurrentSystemInfo)
                    .thenReturn(Mockito.mock(SystemInfoService.class));
            inserts.when(() -> InsertUtils.getTargetTableQualified(query, context))
                    .thenReturn(Arrays.asList("catalog", "db", "target"));
            contexts.when(() -> CascadesContext.initContext(context.getStatementContext(), query,
                    PhysicalProperties.ANY)).thenReturn(cascades);
            InsertIntoTableCommand command = new TargetCommand(query, table);
            command.setJobId(123L); // A constructed executor would otherwise register an InsertLoadJob.
            if (external && protectedSource) {
                Throwable error = Assertions.assertThrows(IllegalStateException.class,
                        () -> command.initPlan(context, executor));
                Assertions.assertNotNull(LicenseSqlException.find(error));
                Assertions.assertTrue(hive.constructed().isEmpty());
                Assertions.assertTrue(olap.constructed().isEmpty());
                Mockito.verifyNoInteractions(loads, coordinator);
            } else {
                AbstractInsertExecutor result = command.initPlan(context, executor);
                List<? extends AbstractInsertExecutor> constructed = external ? hive.constructed() : olap.constructed();
                Assertions.assertEquals(1, constructed.size());
                Assertions.assertSame(constructed.get(0), result);
                Mockito.verify(result).beginTransaction();
                Mockito.verify(result).finalizeSink(fragment, null, sink);
                Mockito.verify(coordinator).setLicenseQueryExecutor(executor);
                Mockito.verify(executor, external ? Mockito.times(2) : Mockito.never())
                        .checkLicenseExternalWrite(Mockito.any(NereidsPlanner.class));
            }
        }
    }

    private static final class TargetCommand extends InsertIntoTableCommand {
        private final TableIf target;

        private TargetCommand(LogicalPlan query, TableIf target) {
            super(query, Optional.of("owned_insert"), Optional.empty(), Optional.empty(), false, Optional.empty());
            this.target = target;
        }

        @Override
        protected TableIf getTargetTableIf(ConnectContext context, List<String> name) {
            return target;
        }

        @Override
        protected boolean needAuthCheck(TableIf table) {
            return false;
        }
    }
}
