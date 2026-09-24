// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.httpv2.rest;

import org.apache.doris.analysis.DescriptorTable;
import org.apache.doris.analysis.UserIdentity;
import org.apache.doris.catalog.Database;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.OlapTable;
import org.apache.doris.catalog.TableIf;
import org.apache.doris.datasource.InternalCatalog;
import org.apache.doris.httpv2.entity.ResponseBody;
import org.apache.doris.httpv2.exception.UnauthorizedException;
import org.apache.doris.httpv2.rest.manager.HttpUtils;
import org.apache.doris.massdb.license.LicenseQueryGuard;
import org.apache.doris.massdb.license.LicenseSqlException;
import org.apache.doris.mysql.privilege.PrivPredicate;
import org.apache.doris.nereids.NereidsPlanner;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.trees.plans.logical.LogicalPlan;
import org.apache.doris.planner.PlanFragment;
import org.apache.doris.plugin.PluginMgr;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.system.SystemInfoService;
import org.apache.doris.thrift.TDescriptorTable;
import org.apache.doris.thrift.TPlanFragment;

import com.google.common.collect.ImmutableMap;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.thrift.TSerializer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

class LicenseTableQueryPlanAdmissionTest {
    @AfterEach
    void clearContext() {
        ConnectContext.remove();
    }

    @Test
    void getAndPostReturnTransport403WithoutExecutablePlan() throws Exception {
        for (String method : new String[] {"GET", "POST"}) {
            assertDenied(method, false);
        }
    }

    @Test
    void expiryDuringSerializationStillDoesNotExposeAPlan() throws Exception {
        assertDenied("POST", true);
    }

    @Test
    void malformedBodyKeepsTheExistingResponseBeforeAdmission() throws Exception {
        Fixture fixture = new Fixture();
        try (MockedStatic<HttpUtils> body = Mockito.mockStatic(HttpUtils.class);
                MockedStatic<LicenseQueryGuard> guard = Mockito.mockStatic(LicenseQueryGuard.class)) {
            body.when(() -> HttpUtils.getBody(fixture.request)).thenReturn("{}");
            ResponseEntity<?> response = (ResponseEntity<?>) fixture.action.query_plan("db", "t",
                    fixture.request, fixture.response);
            Assertions.assertEquals(200, response.getStatusCode().value());
            Assertions.assertEquals(RestApiStatusCode.BAD_REQUEST.code,
                    ((ResponseBody<?>) response.getBody()).getCode());
            guard.verifyNoInteractions();
        }
    }

    @Test
    void permissionFailureKeepsTheExistingResponseBeforeAdmission() throws Exception {
        Fixture fixture = new Fixture();
        fixture.action.rejectPermission = true;
        try (MockedStatic<HttpUtils> body = Mockito.mockStatic(HttpUtils.class);
                MockedStatic<LicenseQueryGuard> guard = Mockito.mockStatic(LicenseQueryGuard.class)) {
            body.when(() -> HttpUtils.getBody(fixture.request)).thenReturn("{\"sql\":\"select k from internal.db.t\"}");
            ResponseEntity<?> response = (ResponseEntity<?>) fixture.action.query_plan("db", "t",
                    fixture.request, fixture.response);
            Assertions.assertEquals(200, response.getStatusCode().value());
            Map<?, ?> data = (Map<?, ?>) ((ResponseBody<?>) response.getBody()).getData();
            Assertions.assertEquals("original table permission denied", data.get("exception"));
            guard.verifyNoInteractions();
        }
    }

    private static void assertDenied(String method, boolean afterSerialization) throws Exception {
        Fixture fixture = new Fixture();
        Mockito.when(fixture.request.getMethod()).thenReturn(method);
        LogicalPlan rewritten = Mockito.mock(LogicalPlan.class);
        Mockito.when(rewritten.allMatch(Mockito.any())).thenReturn(true);
        DescriptorTable descriptors = Mockito.mock(DescriptorTable.class);
        Mockito.when(descriptors.toThrift()).thenReturn(new TDescriptorTable());
        PlanFragment fragment = Mockito.mock(PlanFragment.class);
        Mockito.when(fragment.toThrift()).thenReturn(new TPlanFragment());
        LicenseSqlException denied = new LicenseSqlException(6200,
                ImmutableMap.of("reason", "LICENSE_EXPIRED", "message", "LICENSE_EXPIRED"));
        AtomicInteger checks = new AtomicInteger();
        try (MockedStatic<Env> environment = Mockito.mockStatic(Env.class);
                MockedStatic<HttpUtils> body = Mockito.mockStatic(HttpUtils.class);
                MockedStatic<LicenseQueryGuard> guard = Mockito.mockStatic(LicenseQueryGuard.class);
                MockedConstruction<NereidsPlanner> planners = Mockito.mockConstruction(NereidsPlanner.class,
                        (planner, construction) -> {
                            Mockito.when(planner.planWithLock(Mockito.any(), Mockito.any(), Mockito.any()))
                                    .thenReturn(rewritten);
                            Mockito.when(planner.getScanNodes()).thenReturn(Collections.emptyList());
                            Mockito.when(planner.getFragments()).thenReturn(Collections.singletonList(fragment));
                            Mockito.when(planner.getDescTable()).thenReturn(descriptors);
                        });
                MockedConstruction<TSerializer> serializers = Mockito.mockConstruction(TSerializer.class,
                        (serializer, construction) -> Mockito.when(serializer.serialize(Mockito.any()))
                                .thenReturn(new byte[] {1}))) {
            environment.when(Env::getCurrentInternalCatalog).thenReturn(fixture.catalog);
            environment.when(Env::getCurrentEnv).thenReturn(fixture.env);
            environment.when(Env::getCurrentSystemInfo)
                    .thenReturn(Mockito.mock(SystemInfoService.class));
            body.when(() -> HttpUtils.getBody(fixture.request)).thenReturn("{\"sql\":\"select k from internal.db.t\"}");
            guard.when(() -> LicenseQueryGuard.check(Mockito.any(NereidsPlanner.class))).thenAnswer(call -> {
                if (!afterSerialization || checks.incrementAndGet() == 2) {
                    throw denied;
                }
                return null;
            });
            ResponseEntity<?> response = (ResponseEntity<?>) fixture.action.query_plan("db", "t",
                    fixture.request, fixture.response);
            Assertions.assertEquals(403, response.getStatusCode().value(), String.valueOf(response.getBody()));
            Map<?, ?> responseBody = (Map<?, ?>) response.getBody();
            Assertions.assertEquals("LICENSE_EXPIRED", responseBody.get("reason"));
            Assertions.assertFalse(responseBody.containsKey("opaqued_query_plan"));
            Assertions.assertFalse(responseBody.containsKey("partitions"));
            Assertions.assertEquals(2, planners.constructed().size());
            Assertions.assertEquals(afterSerialization ? 1 : 0, serializers.constructed().size());
            Mockito.verify(fixture.table).readUnlock();
        }
    }

    private static final class Fixture {
        private final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        private final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        private final InternalCatalog catalog = Mockito.mock(InternalCatalog.class);
        private final Env env = Mockito.mock(Env.class);
        private final OlapTable table = Mockito.mock(OlapTable.class);
        private final TestAction action = new TestAction();

        private Fixture() throws Exception {
            Mockito.when(env.getPluginMgr()).thenReturn(Mockito.mock(PluginMgr.class));
            ConnectContext context = new ConnectContext();
            context.setCurrentUserIdentity(UserIdentity.ROOT);
            context.setStatementContext(new StatementContext(context, null));
            context.setThreadLocalInfo();
            Database database = Mockito.mock(Database.class);
            Mockito.when(catalog.getDbOrMetaException("db")).thenReturn(database);
            Mockito.when(database.getTableOrMetaException("t", TableIf.TableType.OLAP)).thenReturn(table);
        }
    }

    private static final class TestAction extends TableQueryPlanAction {
        private boolean rejectPermission;

        @Override
        public boolean needRedirect(String scheme) {
            return false;
        }

        @Override
        public ActionAuthorizationInfo executeCheckPassword(HttpServletRequest request, HttpServletResponse response) {
            return null;
        }

        @Override
        protected void checkTblAuth(UserIdentity user, String db, String table, PrivPredicate predicate) {
            if (rejectPermission) {
                throw new UnauthorizedException("original table permission denied");
            }
        }
    }
}
