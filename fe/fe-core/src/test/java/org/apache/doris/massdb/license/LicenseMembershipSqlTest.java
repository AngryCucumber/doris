// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.DdlException;
import org.apache.doris.common.ErrorCode;
import org.apache.doris.common.NereidsException;
import org.apache.doris.common.jmockit.Deencapsulation;
import org.apache.doris.qe.QueryState;
import org.apache.doris.qe.StmtExecutor;
import org.apache.doris.utframe.TestWithFeService;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;

/** Exercise the complete ALTER command error path, including Nereids exception wrapping. */
class LicenseMembershipSqlTest extends TestWithFeService {
    @Test
    void rejectedAddKeepsLicenseCodeThroughActualSqlExecution() throws Exception {
        Env controlled = Mockito.spy(Env.getCurrentEnv());
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Deencapsulation.setField(controlled, "licenseManager", manager);
        Mockito.doReturn(manager).when(controlled).getLicenseManager();
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class, Mockito.CALLS_REAL_METHODS)) {
            current.when(Env::getCurrentEnv).thenReturn(controlled);
            for (String reason : new String[] {"LICENSE_BE_LIMIT_EXCEEDED", "LICENSE_FE_LIMIT_EXCEEDED",
                    "LICENSE_NOT_READY", "LICENSE_MEMBERSHIP_COMMIT_UNCERTAIN"}) {
                boolean conflict = reason.endsWith("LIMIT_EXCEEDED");
                ErrorCode code = conflict ? ErrorCode.ERR_LICENSE_CONFLICT : ErrorCode.ERR_LICENSE_NOT_READY;
                Mockito.doThrow(new DdlException(reason, code)).when(manager)
                        .runMembershipMutation(Mockito.anyInt(), Mockito.anyInt(), Mockito.any());
                connectContext.getState().reset();
                connectContext.setThreadLocalInfo();
                String sql = reason.startsWith("LICENSE_FE_")
                        ? "ALTER SYSTEM ADD OBSERVER '127.0.0.30:9010'"
                        : "ALTER SYSTEM ADD BACKEND '127.0.0.30:9050'";
                new StmtExecutor(connectContext, sql).execute();
                Assertions.assertEquals(QueryState.MysqlStateType.ERR, connectContext.getState().getStateType());
                Assertions.assertEquals(code, connectContext.getState().getErrorCode());
                Assertions.assertEquals(conflict ? "45000" : "HY000",
                        new String(connectContext.getState().getErrorCode().getSqlState(), StandardCharsets.US_ASCII));
                JsonObject body = JsonParser.parseString(connectContext.getState().getErrorMessage()).getAsJsonObject();
                Assertions.assertEquals(reason, body.get("reason").getAsString());
                Assertions.assertEquals("LICENSE_NOT_READY".equals(reason), body.get("retryable").getAsBoolean());
            }
            Mockito.verify(manager, Mockito.times(3))
                    .runMembershipMutation(Mockito.eq(0), Mockito.eq(1), Mockito.any());
            Mockito.verify(manager).runMembershipMutation(Mockito.eq(1), Mockito.eq(0), Mockito.any());
        }
    }

    @Test
    void ordinaryDdlErrorCannotBecomeLicenseDenialFromItsText() {
        Assertions.assertNull(LicenseSqlException.find(new NereidsException(
                new DdlException("LICENSE_BE_LIMIT_EXCEEDED"))));
    }
}
