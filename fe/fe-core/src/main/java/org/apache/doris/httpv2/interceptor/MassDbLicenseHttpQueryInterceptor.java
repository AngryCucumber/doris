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

import org.apache.doris.httpv2.meta.MetaService;
import org.apache.doris.httpv2.rest.BootstrapFinishAction;
import org.apache.doris.httpv2.rest.CancelLoadAction;
import org.apache.doris.httpv2.rest.CopyIntoAction;
import org.apache.doris.httpv2.rest.GetSmallFileAction;
import org.apache.doris.httpv2.rest.HealthAction;
import org.apache.doris.httpv2.rest.LoadAction;
import org.apache.doris.httpv2.rest.MassDbLicenseFeRoleAction;
import org.apache.doris.httpv2.rest.StmtExecutionAction;
import org.apache.doris.httpv2.rest.StreamingJobAction;
import org.apache.doris.httpv2.rest.UploadAction;
import org.apache.doris.massdblicense.MassDbLicenseQueryException;
import org.apache.doris.massdblicense.MassDbLicenseQueryGuard;
import org.apache.doris.massdblicense.MassDbLicenseQueryGuard.QueryOrigin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.Supplier;

/** Global HTTP read gate installed after handler dispatch and before controller execution. */
public final class MassDbLicenseHttpQueryInterceptor implements HandlerInterceptor {
    public static final String ERROR_HEADER = "X-MassDB-License-Error";
    public static final String PROTECTED_READ_ATTRIBUTE =
            MassDbLicenseHttpQueryInterceptor.class.getName() + ".protectedRead";

    private final Supplier<String> denialCodeSupplier;

    public MassDbLicenseHttpQueryInterceptor() {
        this(() -> MassDbLicenseQueryGuard.currentDenialCode(QueryOrigin.EXTERNAL_MYSQL));
    }

    MassDbLicenseHttpQueryInterceptor(Supplier<String> denialCodeSupplier) {
        this.denialCodeSupplier = Objects.requireNonNull(denialCodeSupplier, "denialCodeSupplier");
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())
                || isAlwaysAvailable(request, handler)) {
            return true;
        }
        request.setAttribute(PROTECTED_READ_ATTRIBUTE, Boolean.TRUE);
        String code = denialCodeSupplier.get();
        if (code == null) {
            return true;
        }
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        response.setHeader(ERROR_HEADER, code);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.getWriter().write("{\"code\":\"" + code + "\",\"message\":\""
                + MassDbLicenseQueryException.message(code) + "\"}");
        return false;
    }

    static boolean isAlwaysAvailable(HttpServletRequest request, Object handler) {
        String path = request.getRequestURI();
        if (!(handler instanceof HandlerMethod)) {
            return isStaticUiPath(path);
        }
        return isAlwaysAvailable(request.getMethod(), path,
                ((HandlerMethod) handler).getBeanType());
    }

    static boolean isAlwaysAvailable(String method, String path, Class<?> beanType) {
        if (MassDbLicenseFeRoleAction.class.isAssignableFrom(beanType)
                || beanType.getName().startsWith("org.apache.doris.httpv2.rest.MassDbLicense")
                || HealthAction.class.isAssignableFrom(beanType)
                || BootstrapFinishAction.class.isAssignableFrom(beanType)
                || GetSmallFileAction.class.isAssignableFrom(beanType)
                || LoadAction.class.isAssignableFrom(beanType)
                || CancelLoadAction.class.isAssignableFrom(beanType)
                || StreamingJobAction.class.isAssignableFrom(beanType)
                || CopyIntoAction.class.isAssignableFrom(beanType)) {
            return true;
        }
        if (UploadAction.class.isAssignableFrom(beanType)) {
            return "POST".equalsIgnoreCase(method)
                    || "PUT".equalsIgnoreCase(method)
                    || "DELETE".equalsIgnoreCase(method);
        }
        if (MetaService.class.isAssignableFrom(beanType)) {
            return "GET".equalsIgnoreCase(method) && isInternalMetaPath(path);
        }
        if (StmtExecutionAction.class.isAssignableFrom(beanType)) {
            return "POST".equalsIgnoreCase(method)
                    && path != null && path.startsWith("/api/query/");
        }
        if ("POST".equalsIgnoreCase(method) && path != null
                && path.startsWith("/rest/v2/manager/query/kill/")) {
            return true;
        }
        return isStaticUiPath(path);
    }

    /** Rechecks a protected file/result stream without affecting authenticated internal routes. */
    public static void enforceProtectedResponseStream(HttpServletRequest request) throws IOException {
        if (request != null
                && Boolean.TRUE.equals(request.getAttribute(PROTECTED_READ_ATTRIBUTE))) {
            try {
                MassDbLicenseQueryGuard.enforceMetadataRead(QueryOrigin.EXTERNAL_MYSQL);
            } catch (MassDbLicenseQueryException error) {
                throw new IOException(error.getMessage(), error);
            }
        }
    }

    private static boolean isInternalMetaPath(String path) {
        return "/image".equals(path)
                || "/info".equals(path)
                || "/version".equals(path)
                || "/put".equals(path)
                || "/journal_id".equals(path)
                || "/role".equals(path)
                || "/check".equals(path);
    }

    private static boolean isStaticUiPath(String path) {
        return path == null
                || "/".equals(path)
                || "/index.html".equals(path)
                || "/favicon.ico".equals(path)
                || "/notFound".equals(path)
                || "/error".equals(path)
                || "/rest/v1/login".equals(path)
                || "/rest/v1/logout".equals(path)
                || path.startsWith("/static/");
    }
}
