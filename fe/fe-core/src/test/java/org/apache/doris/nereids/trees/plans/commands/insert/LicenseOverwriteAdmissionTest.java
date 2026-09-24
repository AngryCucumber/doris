// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.nereids.trees.plans.commands.insert;

import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.TableIf;
import org.apache.doris.datasource.hive.HMSExternalTable;
import org.apache.doris.datasource.iceberg.IcebergExternalTable;
import org.apache.doris.insertoverwrite.InsertOverwriteManager;
import org.apache.doris.insertoverwrite.InsertOverwriteUtil;
import org.apache.doris.massdb.license.LicenseSqlException;
import org.apache.doris.nereids.CascadesContext;
import org.apache.doris.nereids.NereidsPlanner;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.properties.PhysicalProperties;
import org.apache.doris.nereids.trees.plans.logical.LogicalPlan;
import org.apache.doris.nereids.trees.plans.physical.PhysicalHiveTableSink;
import org.apache.doris.nereids.trees.plans.physical.PhysicalIcebergTableSink;
import org.apache.doris.nereids.trees.plans.physical.PhysicalTableSink;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.StmtExecutor;
import org.apache.doris.system.SystemInfoService;

import com.google.common.collect.ImmutableMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.Optional;

class LicenseOverwriteAdmissionTest {
    @AfterEach
    void clearContext() {
        ConnectContext.remove();
    }

    @Test
    void deniedHiveOrIcebergOverwriteCannotRegisterOrCreateTemporaryPartitions() throws Exception {
        checkDeniedOverwrite(Mockito.mock(HMSExternalTable.class), Mockito.mock(PhysicalHiveTableSink.class));
        checkDeniedOverwrite(Mockito.mock(IcebergExternalTable.class), Mockito.mock(PhysicalIcebergTableSink.class));
    }

    private static void checkDeniedOverwrite(TableIf table, PhysicalTableSink<?> sink) throws Exception {
        ConnectContext context = new ConnectContext();
        context.setStatementContext(new StatementContext(context, null));
        context.setThreadLocalInfo();
        LogicalPlan query = Mockito.mock(LogicalPlan.class);
        Env env = Mockito.mock(Env.class);
        InsertOverwriteManager manager = Mockito.mock(InsertOverwriteManager.class);
        Mockito.when(env.getInsertOverwriteManager()).thenReturn(manager);
        CascadesContext cascades = Mockito.mock(CascadesContext.class);
        Mockito.doReturn(table).when(sink).getTargetTable();
        Mockito.doReturn(Collections.singleton(sink)).when(sink).collect(Mockito.any());
        StmtExecutor executor = Mockito.mock(StmtExecutor.class);
        LicenseSqlException denied = new LicenseSqlException(6200,
                ImmutableMap.of("reason", "LICENSE_EXPIRED", "message", "LICENSE_EXPIRED"));
        Mockito.doThrow(denied).when(executor).checkLicenseExternalWrite(Mockito.any(NereidsPlanner.class));
        InsertOverwriteTableCommand command = new InsertOverwriteTableCommand(query, Optional.empty(),
                Optional.empty(), Optional.empty());
        try (MockedStatic<Env> environment = Mockito.mockStatic(Env.class);
                MockedStatic<InsertUtils> inserts = Mockito.mockStatic(InsertUtils.class);
                MockedStatic<InsertOverwriteUtil> partitions = Mockito.mockStatic(InsertOverwriteUtil.class);
                MockedStatic<CascadesContext> contexts = Mockito.mockStatic(CascadesContext.class);
                MockedConstruction<NereidsPlanner> planners = Mockito.mockConstruction(NereidsPlanner.class,
                        (planner, construction) -> Mockito.when(planner.getPhysicalPlan()).thenReturn(sink))) {
            environment.when(Env::getCurrentEnv).thenReturn(env);
            environment.when(Env::getCurrentSystemInfo)
                    .thenReturn(Mockito.mock(SystemInfoService.class));
            inserts.when(() -> InsertUtils.getTargetTable(query, context)).thenReturn(table);
            inserts.when(() -> InsertUtils.normalizePlan(query, table, Optional.of(cascades), Optional.empty()))
                    .thenReturn(query);
            contexts.when(() -> CascadesContext.initContext(context.getStatementContext(), query,
                    PhysicalProperties.ANY)).thenReturn(cascades);
            Assertions.assertSame(denied, Assertions.assertThrows(LicenseSqlException.class,
                    () -> command.run(context, executor)));
            Assertions.assertEquals(1, planners.constructed().size());
            Mockito.verify(executor).checkLicenseExternalWrite(planners.constructed().get(0));
            Mockito.verify(env, Mockito.never()).getInsertOverwriteManager();
            Mockito.verifyNoInteractions(manager);
            partitions.verifyNoInteractions();
        }
    }
}
