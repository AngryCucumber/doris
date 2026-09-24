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
import org.apache.doris.common.ErrorCode;
import org.apache.doris.nereids.NereidsPlanner;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.parser.NereidsParser;
import org.apache.doris.nereids.trees.plans.commands.ExecuteCommand;
import org.apache.doris.nereids.trees.plans.commands.PrepareCommand;
import org.apache.doris.qe.OriginStatement;
import org.apache.doris.qe.PointQueryExecutor;
import org.apache.doris.qe.PreparedStatementContext;
import org.apache.doris.qe.QueryState;
import org.apache.doris.qe.ShortCircuitQueryContext;
import org.apache.doris.qe.StmtExecutor;
import org.apache.doris.utframe.TestWithFeService;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/** Exercises ExecuteCommand's real fast-path choice and schema-change fallback without sending BE requests. */
class LicensePreparedAdmissionTest extends TestWithFeService {
    private static final String SQL = "select v from t where k=1";
    private static final String HANDLE = "license_point";

    @Override
    protected void runBeforeAll() throws Exception {
        createDatabaseAndUse("license_prepared");
        connectContext.getSessionVariable().setDisableNereidsRules("PRUNE_EMPTY_PARTITION");
        connectContext.getSessionVariable().setParallelResultSink(false);
        connectContext.getSessionVariable().enableGroupCommitFullPrepare = false;
        createTable("create table t(k int, v int) unique key(k) distributed by hash(k) buckets 1 "
                + "properties('replication_num'='1', 'enable_unique_key_merge_on_write'='true')");
    }

    @Override
    protected void runBeforeEach() {
        connectContext.getState().reset();
        connectContext.setThreadLocalInfo();
        connectContext.removePreparedQuery(HANDLE);
    }

    @Test
    void samePreparedHandleRechecksExpiryBeforeDirectExecution() throws Exception {
        AtomicReference<LicenseQueryStatus> status = new AtomicReference<>(LicenseQueryStatus.VALID);
        try (MockedStatic<Env> currentEnv = licenseEnvironment(status);
                MockedStatic<PointQueryExecutor> point = Mockito.mockStatic(PointQueryExecutor.class)) {
            StmtExecutor first = new StmtExecutor(connectContext, SQL);
            PreparedStatementContext prepared = registerPrepared(first);
            StatementContext firstStatement = connectContext.getStatementContext();
            ExecuteCommand command = new ExecuteCommand(HANDLE, prepared.command, firstStatement);
            point.when(() -> PointQueryExecutor.directExecuteShortCircuitQuery(first, prepared, firstStatement))
                    .thenAnswer(call -> {
                        first.markLicenseQueryStarted();
                        return null;
                    });
            command.run(connectContext, first);
            point.verify(() -> PointQueryExecutor.directExecuteShortCircuitQuery(first, prepared, firstStatement));

            status.set(LicenseQueryStatus.EXPIRED);
            StmtExecutor second = new StmtExecutor(connectContext, SQL);
            StatementContext secondStatement = connectContext.getStatementContext();
            secondStatement.setShortCircuitQuery(true);
            secondStatement.setShortCircuitQueryContext(prepared.shortCircuitQueryContext.get());
            LicenseSqlException denied = Assertions.assertThrows(LicenseSqlException.class,
                    () -> command.run(connectContext, second));
            Assertions.assertEquals(6200, denied.getMysqlErrorCode().getCode());
            Assertions.assertTrue(denied.getMessage().contains("LICENSE_EXPIRED"));
            Assertions.assertSame(prepared, connectContext.getPreparedStementContext(HANDLE));
            point.verifyNoMoreInteractions();
        }
    }

    @Test
    void changedSchemaReplansAndClearsEarlierStartedPermission() throws Exception {
        AtomicReference<LicenseQueryStatus> status = new AtomicReference<>(LicenseQueryStatus.VALID);
        try (MockedStatic<Env> currentEnv = licenseEnvironment(status);
                MockedStatic<PointQueryExecutor> point = Mockito.mockStatic(PointQueryExecutor.class)) {
            StmtExecutor executor = Mockito.spy(new StmtExecutor(connectContext, SQL));
            PreparedStatementContext prepared = registerPrepared(executor);
            StatementContext statement = connectContext.getStatementContext();
            ExecuteCommand command = new ExecuteCommand(HANDLE, prepared.command, statement);
            ShortCircuitQueryContext cached = prepared.shortCircuitQueryContext.get();
            MaterializedIndexMeta schema = cached.tbl.getIndexMetaByIndexId(cached.tbl.getBaseIndexId());
            int originalVersion = schema.getSchemaVersion();
            point.when(() -> PointQueryExecutor.directExecuteShortCircuitQuery(executor, prepared, statement))
                    .thenAnswer(call -> {
                        executor.markLicenseQueryStarted();
                        return null;
                    });
            try {
                command.run(connectContext, executor);
                point.verify(() -> PointQueryExecutor.directExecuteShortCircuitQuery(executor, prepared, statement));
                schema.setSchemaVersion(originalVersion + 1);
                status.set(LicenseQueryStatus.EXPIRED);

                command.run(connectContext, executor);

                Mockito.verify(executor).execute();
                Assertions.assertInstanceOf(NereidsPlanner.class, executor.planner());
                Assertions.assertEquals(QueryState.MysqlStateType.ERR, connectContext.getState().getStateType());
                Assertions.assertEquals(ErrorCode.ERR_LICENSE_QUERY_DENIED, connectContext.getState().getErrorCode());
                Assertions.assertTrue(connectContext.getState().getErrorMessage().contains("LICENSE_EXPIRED"));
                Assertions.assertFalse(prepared.shortCircuitQueryContext.filter(value -> value == cached).isPresent());
                point.verifyNoMoreInteractions();
            } finally {
                schema.setSchemaVersion(originalVersion);
            }
        }
    }

    private MockedStatic<Env> licenseEnvironment(AtomicReference<LicenseQueryStatus> status) {
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Mockito.when(manager.queryStatus()).thenAnswer(call -> status.get());
        Env controlled = Mockito.spy(Env.getCurrentEnv());
        Mockito.doReturn(manager).when(controlled).getLicenseManager();
        MockedStatic<Env> currentEnv = Mockito.mockStatic(Env.class, Mockito.CALLS_REAL_METHODS);
        currentEnv.when(Env::getCurrentEnv).thenReturn(controlled);
        return currentEnv;
    }

    private PreparedStatementContext registerPrepared(StmtExecutor executor) throws Exception {
        StatementContext statement = executor.getContext().getStatementContext();
        PrepareCommand prepare = new PrepareCommand(HANDLE, new NereidsParser().parseSingle(SQL),
                Collections.emptyList(), new OriginStatement(SQL, 0));
        PreparedStatementContext prepared = new PreparedStatementContext(prepare, connectContext, statement, SQL);
        OlapTable table = (OlapTable) Env.getCurrentInternalCatalog().getDbOrAnalysisException("license_prepared")
                .getTableOrAnalysisException("t");
        ShortCircuitQueryContext cached = Mockito.mock(ShortCircuitQueryContext.class);
        setField(cached, "tbl", table);
        setField(cached, "schemaVersion", table.getBaseSchemaVersion());
        prepared.shortCircuitQueryContext = Optional.of(cached);
        statement.setShortCircuitQuery(true);
        statement.setShortCircuitQueryContext(cached);
        connectContext.addPreparedStatementContext(HANDLE, prepared);
        return prepared;
    }

    private static void setField(ShortCircuitQueryContext target, String name, Object value) throws Exception {
        Field field = ShortCircuitQueryContext.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
