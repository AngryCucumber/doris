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

package org.apache.doris.httpv2.interceptor;

import org.apache.doris.catalog.Env;
import org.apache.doris.httpv2.meta.MetaService;
import org.apache.doris.httpv2.rest.BackendsAction;
import org.apache.doris.httpv2.rest.BootstrapFinishAction;
import org.apache.doris.httpv2.rest.GetSmallFileAction;
import org.apache.doris.httpv2.rest.HealthAction;
import org.apache.doris.httpv2.rest.LoadAction;
import org.apache.doris.httpv2.rest.MassDbLicenseFeRoleAction;
import org.apache.doris.httpv2.rest.StmtExecutionAction;
import org.apache.doris.httpv2.rest.UploadAction;
import org.apache.doris.massdblicense.MassDbLicenseLocalSnapshotStore;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

class MassDbLicenseHttpQueryInterceptorTest {
    @Test
    void exactIngressAndRecoveryHandlersStayAvailable() {
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "PUT", "/api/db/table/_stream_load", LoadAction.class));
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "GET", "/api/health", HealthAction.class));
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "POST", "/internal/massdb/license/roles/exchange",
                MassDbLicenseFeRoleAction.class));
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "POST", "/api/default/db/table/upload", UploadAction.class));
        Assertions.assertFalse(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "GET", "/api/default/db/table/upload", UploadAction.class));
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "POST", "/api/query/default/db", StmtExecutionAction.class));
        Assertions.assertFalse(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "POST", "/api/query_schema/default/db", StmtExecutionAction.class));
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "GET", "/api/bootstrap", BootstrapFinishAction.class));
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "GET", "/api/get_small_file", GetSmallFileAction.class));
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "GET", "/image", MetaService.class));
        Assertions.assertFalse(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "GET", "/dump", MetaService.class));
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "POST", "/rest/v2/manager/query/kill/query-id", BackendsAction.class));
    }

    @Test
    void metadataHandlerReturnsStableHttpErrorWithoutEnteringController() throws Exception {
        MassDbLicenseHttpQueryInterceptor interceptor =
                new MassDbLicenseHttpQueryInterceptor(() -> "MASSDB_LICENSE_EXPIRED");
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        Mockito.when(request.getMethod()).thenReturn("GET");
        Mockito.when(request.getRequestURI()).thenReturn("/api/backends");
        Mockito.when(response.getWriter()).thenReturn(new PrintWriter(body));
        org.springframework.web.method.HandlerMethod handler =
                Mockito.mock(org.springframework.web.method.HandlerMethod.class);
        Mockito.doReturn(BackendsAction.class).when(handler).getBeanType();

        boolean allowed = interceptor.preHandle(request, response, handler);

        Assertions.assertFalse(allowed);
        Mockito.verify(request).setAttribute(
                MassDbLicenseHttpQueryInterceptor.PROTECTED_READ_ATTRIBUTE, Boolean.TRUE);
        Mockito.verify(response).setStatus(403);
        Mockito.verify(response).setHeader(
                MassDbLicenseHttpQueryInterceptor.ERROR_HEADER, "MASSDB_LICENSE_EXPIRED");
        Assertions.assertTrue(body.toString().contains("MASSDB_LICENSE_EXPIRED"));
    }

    @Test
    void protectedFileStreamRechecksCurrentComponentDecision() {
        Env env = Mockito.mock(Env.class);
        Mockito.when(env.evaluateMassDbLicenseLocalQuery()).thenReturn(
                MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                        "MASSDB_LICENSE_EXPIRED"));
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getAttribute(
                MassDbLicenseHttpQueryInterceptor.PROTECTED_READ_ATTRIBUTE))
                .thenReturn(Boolean.TRUE);
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            IOException error = Assertions.assertThrows(IOException.class,
                    () -> MassDbLicenseHttpQueryInterceptor
                            .enforceProtectedResponseStream(request));
            Assertions.assertTrue(error.getMessage().contains(
                    "MASSDB_LICENSE_EXPIRED"));
        }
    }

    @Test
    void oldUnconfiguredClusterAndStaticUiRemainCompatible() throws Exception {
        MassDbLicenseHttpQueryInterceptor interceptor =
                new MassDbLicenseHttpQueryInterceptor(() -> null);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        Mockito.when(request.getMethod()).thenReturn("GET");
        Mockito.when(request.getRequestURI()).thenReturn("/api/backends");
        org.springframework.web.method.HandlerMethod handler =
                Mockito.mock(org.springframework.web.method.HandlerMethod.class);
        Mockito.doReturn(BackendsAction.class).when(handler).getBeanType();

        Assertions.assertTrue(interceptor.preHandle(request, response, handler));
        Assertions.assertTrue(MassDbLicenseHttpQueryInterceptor.isAlwaysAvailable(
                "GET", "/static/app.js", BackendsAction.class));
        Mockito.verify(response, Mockito.never()).setStatus(Mockito.anyInt());
    }
}
