// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.common.ErrorCode;
import org.apache.doris.common.NereidsException;
import org.apache.doris.plsql.Conf;
import org.apache.doris.plsql.Exec;
import org.apache.doris.plsql.executor.PlSqlOperation;
import org.apache.doris.plsql.executor.PlsqlQueryExecutor;
import org.apache.doris.plsql.executor.PlsqlResult;
import org.apache.doris.plsql.executor.QueryExecutor;
import org.apache.doris.plsql.executor.QueryResult;
import org.apache.doris.qe.QueryState;
import org.apache.doris.utframe.TestWithFeService;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

/** Exercises the real procedure query bridge and top-level SQL error adapter with denied FE reads. */
class LicenseProcedureAdmissionTest extends TestWithFeService {
    @Override
    protected void runBeforeAll() throws Exception {
        createDatabaseAndUse("license_procedure");
        connectContext.getSessionVariable().setDisableNereidsRules("PRUNE_EMPTY_PARTITION");
        connectContext.getSessionVariable().setParallelResultSink(false);
        createTable("create table t(k int) duplicate key(k) distributed by hash(k) buckets 1 "
                + "properties('replication_num'='1')");
    }

    @Test
    void procedureQueryBridgeReturnsTypedFailureInsteadOfEmptyRows() {
        connectContext.getState().reset();
        connectContext.setThreadLocalInfo();
        connectContext.setProcedureExec(new PlSqlOperation().getExec());
        try {
            QueryResult result = new PlsqlQueryExecutor().executeQuery("select k from t", null);
            try {
                Assertions.assertTrue(result.error(), "Denied SELECT must not become an empty successful QueryResult");
                LicenseSqlException failure = LicenseSqlException.find(result.exception());
                Assertions.assertNotNull(failure, () -> "Unexpected query failure: " + result.exception());
                Assertions.assertEquals(6200, failure.getMysqlErrorCode().getCode());
                Assertions.assertEquals("45000", new String(failure.getMysqlErrorCode().getSqlState(),
                        StandardCharsets.UTF_8));
            } finally {
                result.close();
            }
        } finally {
            connectContext.setProcedureExec(null);
        }
    }

    @Test
    void topLevelProcedureKeeps6200AndDoesNotConvertDenialToEof() {
        assertProcedureDenial("BEGIN SELECT k FROM t; END;");
    }

    @Test
    void selectIntoKeepsOnlyTheStructuredLicenseFailure() {
        assertProcedureDenial("BEGIN DECLARE observed_count INT; SELECT COUNT(*) INTO observed_count FROM t; END;");
    }

    private void assertProcedureDenial(String statement) {
        connectContext.getState().reset();
        connectContext.setThreadLocalInfo();
        String expectedReason = LicenseQueryGuard.reason(connectContext.getEnv().getLicenseManager().queryStatus());
        PlSqlOperation operation = new PlSqlOperation();
        operation.execute(connectContext, statement);
        String message = connectContext.getState().getErrorMessage();
        Assertions.assertAll(
                () -> Assertions.assertEquals(QueryState.MysqlStateType.ERR,
                        connectContext.getState().getStateType()),
                () -> Assertions.assertEquals(ErrorCode.ERR_LICENSE_QUERY_DENIED,
                        connectContext.getState().getErrorCode()),
                () -> Assertions.assertEquals("45000", new String(
                        connectContext.getState().getErrorCode().getSqlState(), StandardCharsets.UTF_8)),
                () -> Assertions.assertFalse(message.contains("Unhandled exception"), message),
                () -> Assertions.assertFalse(message.contains("NullPointerException"), message),
                () -> Assertions.assertEquals(1L,
                        Arrays.stream(message.split("\\r?\\n")).filter(line -> line.matches("\\d+\\. .*")).count(),
                        message),
                () -> Assertions.assertEquals(expectedReason, JsonParser.parseString(
                        message.substring(message.indexOf('{'), message.lastIndexOf('}') + 1))
                        .getAsJsonObject().get("reason").getAsString()),
                () -> Assertions.assertFalse(connectContext.isRunProcedure()),
                () -> Assertions.assertNull(connectContext.getProcedureExec()));
    }

    @Test
    void wrappedLicenseFailureKeepsItsCodeThroughProcedureSignalFormatting() {
        PlsqlResult output = new PlsqlResult();
        Exec exec = new Exec(new Conf(), output, Mockito.mock(QueryExecutor.class), output);
        exec.init();
        LicenseSqlException license = new LicenseSqlException(6200,
                Collections.<String, Object>singletonMap("reason", "LICENSE_EXPIRED"));
        exec.signal(new NereidsException("wrapped", license));
        exec.printExceptions();
        Assertions.assertEquals(ErrorCode.ERR_LICENSE_QUERY_DENIED, output.getLastErrorCode());
        Assertions.assertTrue(output.getError().contains("LICENSE_EXPIRED"));
        Assertions.assertFalse(output.getError().contains("Unhandled exception"));
    }
}
