// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.httpv2.rest;

import org.apache.doris.analysis.UserIdentity;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.datasource.InternalCatalog;
import org.apache.doris.ha.FrontendNodeType;
import org.apache.doris.httpv2.controller.BaseController.ActionAuthorizationInfo;
import org.apache.doris.httpv2.exception.UnauthorizedException;
import org.apache.doris.massdb.license.LicenseManagementException;
import org.apache.doris.massdb.license.LicenseManagementResult;
import org.apache.doris.massdb.license.LicenseManager;
import org.apache.doris.massdb.license.LicenseManager.Action;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.system.Frontend;

import com.google.common.io.ByteStreams;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.LogFactory;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

class LicenseControllerTest {
    private final HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);

    @AfterEach
    void clearContext() {
        ConnectContext.remove();
    }

    @Test
    void strictBoundedRequestRejectsDuplicatesTypesTrailingJsonAndMalformedUtf8() throws Exception {
        Assertions.assertEquals("signed", payload("{\"certificate\":\"signed\"}"));
        for (String invalid : Arrays.asList("{}", "[]", "null", "{\"certificate\":1}",
                "{\"certificate\":\"a\",\"certificate\":\"b\"}",
                "{\"certificate\":\"a\",\"extra\":true}", "{\"certificate\":\"\"}",
                "{\"certificate\":\"a\"} {}")) {
            Assertions.assertThrows(LicenseController.BadLicenseRequest.class, () -> payload(invalid), invalid);
        }
        Assertions.assertThrows(LicenseController.BadLicenseRequest.class,
                () -> LicenseController.parsePayload(Action.IMPORT, new byte[] {(byte) 0xc0, (byte) 0xaf}));
        Assertions.assertNull(LicenseController.parsePayload(Action.CLOCK_CHALLENGE, new byte[0]));
        Assertions.assertNull(LicenseController.parsePayload(Action.CLOCK_CHALLENGE, bytes("{}")));
        Assertions.assertThrows(LicenseController.BadLicenseRequest.class,
                () -> LicenseController.parsePayload(Action.CLOCK_CHALLENGE, bytes("{\"x\":1}")));
        Assertions.assertEquals("ticket", LicenseController.parsePayload(Action.CLOCK_REPAIR,
                bytes("{\"repair_certificate\":\"ticket\"}")));
        Assertions.assertThrows(LicenseController.BadLicenseRequest.class,
                () -> LicenseController.parsePayload(Action.CLOCK_REPAIR, bytes("{\"certificate\":\"ticket\"}")));
    }

    @Test
    void bodyAndCertificateLimitsUseBytesAndIncludeChunkedRequests() throws Exception {
        byte[] exact = new byte[LicenseController.MAX_BODY_BYTES];
        Assertions.assertArrayEquals(exact,
                LicenseController.readBounded(new ByteArrayInputStream(exact), exact.length));
        Assertions.assertThrows(LicenseController.BadLicenseRequest.class, () -> LicenseController.readBounded(
                new ByteArrayInputStream(new byte[exact.length + 1]), exact.length));
        Assertions.assertEquals(65536, payload("{\"certificate\":\"" + repeat('a', 65536) + "\"}").length());
        Assertions.assertEquals("LICENSE_INPUT_TOO_LARGE", Assertions.assertThrows(
                LicenseController.BadLicenseRequest.class,
                () -> payload("{\"certificate\":\"" + repeat('a', 65537) + "\"}")).reason);
        Assertions.assertEquals("LICENSE_INPUT_TOO_LARGE", Assertions.assertThrows(
                LicenseController.BadLicenseRequest.class,
                () -> payload("{\"certificate\":\"" + repeat('中', 22000) + "\"}")).reason);
        Assertions.assertEquals(16384, LicenseController.parsePayload(Action.CLOCK_REPAIR,
                bytes("{\"repair_certificate\":\"" + repeat('a', 16384) + "\"}")).length());
        Assertions.assertEquals("LICENSE_INPUT_TOO_LARGE", Assertions.assertThrows(
                LicenseController.BadLicenseRequest.class, () -> LicenseController.parsePayload(Action.CLOCK_REPAIR,
                        bytes("{\"repair_certificate\":\"" + repeat('a', 16385) + "\"}"))).reason);

        StubController controller = new StubController();
        HttpServletRequest declared = request("POST", new byte[0]);
        Mockito.when(declared.getContentLengthLong()).thenReturn((long) exact.length + 1);
        Assertions.assertEquals(400, controller.importCertificate(declared, servletResponse).getStatusCode().value());
        Assertions.assertEquals(0, controller.authCalls);

        HttpServletRequest chunked = request("POST", new byte[exact.length + 1]);
        Mockito.when(chunked.getContentLengthLong()).thenReturn(-1L);
        Assertions.assertEquals(400, controller.importCertificate(chunked, servletResponse).getStatusCode().value());
        Assertions.assertEquals(0, controller.executions);
        ResponseEntity<?> fieldTooLarge = controller.importCertificate(request("POST",
                bytes("{\"certificate\":\"" + repeat('a', 65537) + "\"}")), servletResponse);
        Assertions.assertEquals(400, fieldTooLarge.getStatusCode().value());
        Assertions.assertEquals("LICENSE_INPUT_TOO_LARGE", body(fieldTooLarge).get("reason"));
        Assertions.assertEquals(0, controller.executions);
    }

    @Test
    void cookieWritesRequireBothSameOriginAndCsrfHeader() throws Exception {
        HttpServletRequest cookie = request("POST", bytes("{}"));
        Mockito.when(cookie.getHeader("Authorization")).thenReturn(null);
        Assertions.assertThrows(LicenseController.CsrfFailure.class, () -> LicenseController.checkWriteOrigin(cookie));
        Mockito.when(cookie.getHeader("Origin")).thenReturn("http://fe.example:8030");
        Assertions.assertThrows(LicenseController.CsrfFailure.class, () -> LicenseController.checkWriteOrigin(cookie));
        Mockito.when(cookie.getHeader(LicenseController.CSRF_HEADER)).thenReturn("1");
        LicenseController.checkWriteOrigin(cookie);
        for (String hostile : Arrays.asList("null", "https://fe.example:8030", "http://other.example:8030",
                "http://fe.example", "http://fe.example:8030/path", "http://x@fe.example:8030",
                "http://fe.example:8030#fragment")) {
            Mockito.when(cookie.getHeader("Origin")).thenReturn(hostile);
            Assertions.assertThrows(LicenseController.CsrfFailure.class,
                    () -> LicenseController.checkWriteOrigin(cookie), hostile);
        }
        HttpServletRequest basic = request("POST", bytes("{}"));
        LicenseController.checkWriteOrigin(basic);
        Mockito.when(basic.getHeader("Origin")).thenReturn("http://attacker.example");
        Assertions.assertThrows(LicenseController.CsrfFailure.class, () -> LicenseController.checkWriteOrigin(basic));
    }

    @Test
    void allPublicRoutesDispatchExactlyOneActionAndRestoreThreadContext() throws Exception {
        StubController controller = new StubController();
        ConnectContext original = new ConnectContext();
        original.setThreadLocalInfo();
        HttpServletRequest get = request("GET", new byte[0]);
        Assertions.assertEquals(200, controller.status(get, servletResponse).getStatusCode().value());
        Assertions.assertEquals(Action.STATUS, controller.action);
        controller.deployment(get, servletResponse);
        Assertions.assertEquals(Action.DEPLOYMENT, controller.action);
        controller.validate(request("POST", bytes("{\"certificate\":\"signed\"}")), servletResponse);
        Assertions.assertEquals(Action.VALIDATE, controller.action);
        Assertions.assertEquals("signed", controller.payload);
        controller.importCertificate(request("POST", bytes("{\"certificate\":\"signed\"}")), servletResponse);
        Assertions.assertEquals(Action.IMPORT, controller.action);
        controller.importReceipt(repeat('a', 64), get, servletResponse);
        Assertions.assertEquals(Action.IMPORT_RECEIPT, controller.action);
        Assertions.assertEquals(repeat('a', 64), controller.payload);
        controller.challenge(request("POST", bytes("{}")), servletResponse);
        Assertions.assertEquals(Action.CLOCK_CHALLENGE, controller.action);
        controller.repair(request("POST", bytes("{\"repair_certificate\":\"ticket\"}")), servletResponse);
        Assertions.assertEquals(Action.CLOCK_REPAIR, controller.action);
        controller.repairReceipt("ba22b82e-1cf6-4cff-bfab-911fedbabdea", get, servletResponse);
        Assertions.assertEquals(Action.CLOCK_REPAIR_RECEIPT, controller.action);
        Assertions.assertEquals(8, controller.executions);
        Assertions.assertEquals(original, ConnectContext.get());
        Assertions.assertFalse(LicenseController.validIdentifier(Action.IMPORT_RECEIPT, "../../deployment"));
        Assertions.assertFalse(LicenseController.validIdentifier(Action.CLOCK_REPAIR_RECEIPT, "id?x=true"));
    }

    @Test
    void ordinaryUserOnlyGetsStatusAndAuthenticationErrorsStayAuthenticationErrors() throws Exception {
        StubController controller = new StubController();
        controller.admin = false;
        ResponseEntity<?> status = controller.status(request("GET", new byte[0]), servletResponse);
        Assertions.assertEquals(200, status.getStatusCode().value());
        Assertions.assertFalse(controller.executedAsAdmin);
        Assertions.assertEquals("no-store", status.getHeaders().getCacheControl());
        Assertions.assertEquals(403,
                controller.deployment(request("GET", new byte[0]), servletResponse).getStatusCode().value());
        Assertions.assertEquals(403, controller.importCertificate(
                request("POST", bytes("{\"certificate\":\"secret\"}")), servletResponse).getStatusCode().value());
        Assertions.assertEquals(1, controller.executions);
        controller.authFailure = true;
        ResponseEntity<?> denied = controller.status(request("GET", new byte[0]), servletResponse);
        Assertions.assertEquals(401, denied.getStatusCode().value());
        Assertions.assertEquals("UNAUTHENTICATED", body(denied).get("reason"));
        Assertions.assertFalse(denied.getBody().toString().contains("secret"));
    }

    @Test
    void managerErrorsPreserveTransportReasonReceiptAndRetryAfter() throws Exception {
        StubController controller = new StubController();
        controller.failure = new LicenseManagementException("LICENSE_RATE_LIMITED", 429,
                "NOT_SUBMITTED", null, 0, 0);
        ResponseEntity<?> response = controller.validate(
                request("POST", bytes("{\"certificate\":\"secret\"}")), servletResponse);
        Assertions.assertEquals(429, response.getStatusCode().value());
        Assertions.assertEquals("6", response.getHeaders().getFirst("Retry-After"));
        Assertions.assertEquals("LICENSE_RATE_LIMITED", body(response).get("reason"));
        Assertions.assertFalse(response.getBody().toString().contains("secret"));
    }

    @Test
    void forwardingAuthenticatesPeerAndReauthenticatesOriginalIdentity() throws Exception {
        AuthenticationController controller = new AuthenticationController();
        HttpServletRequest request = request("POST", bytes("{}"));
        Mockito.when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(request.getHeader(LicenseController.FORWARDED_FOR)).thenReturn("192.0.2.5");
        Mockito.when(request.getHeader(LicenseController.FORWARDED_IDENTITY)).thenReturn(identity(UserIdentity.ROOT));
        Assertions.assertThrows(UnauthorizedException.class, () -> controller.authenticate(request, servletResponse));
        Mockito.when(request.getHeader(LicenseController.CLUSTER_TOKEN)).thenReturn("cluster-token");
        Mockito.when(controller.env.getFrontends(null)).thenReturn(Collections.singletonList(
                new Frontend(FrontendNodeType.FOLLOWER, "follower", "127.0.0.2", 9010)));
        Assertions.assertThrows(UnauthorizedException.class, () -> controller.authenticate(request, servletResponse));
        Mockito.when(controller.env.getFrontends(null)).thenReturn(Collections.singletonList(
                new Frontend(FrontendNodeType.FOLLOWER, "follower", "127.0.0.1", 9010)));
        ActionAuthorizationInfo authenticated = controller.authenticate(request, servletResponse);
        Assertions.assertEquals("192.0.2.5", authenticated.remoteIp);
        Assertions.assertEquals("192.0.2.5", controller.passwordCheckedIp);
        Mockito.when(request.getHeader(LicenseController.FORWARDED_IDENTITY)).thenReturn(identity(UserIdentity.ADMIN));
        Assertions.assertThrows(UnauthorizedException.class, () -> controller.authenticate(request, servletResponse));
    }

    @Test
    void malformedBasicCredentialsNeverLeakTheHeader() throws Exception {
        LicenseController controller = new LicenseController();
        HttpServletRequest request = request("GET", new byte[0]);
        Mockito.when(request.getHeader("Authorization")).thenReturn("Basic private-certificate-value!");
        UnauthorizedException failure = Assertions.assertThrows(UnauthorizedException.class,
                () -> controller.getAuthorizationInfo(request));
        Assertions.assertFalse(failure.getMessage().contains("private"));
        Mockito.when(request.getHeader("Authorization")).thenReturn("Bearer secret");
        Assertions.assertThrows(UnauthorizedException.class, () -> controller.getAuthorizationInfo(request));
    }

    @Test
    void actualHttpForwardingPreservesErrorStatusBodyAndCredentialsWithoutRedirects() throws Exception {
        Logger wire = (Logger) LogManager.getLogger("org.apache.http.wire");
        Logger headers = (Logger) LogManager.getLogger("org.apache.http.headers");
        Level oldWire = wire.getLevel();
        Level oldHeaders = headers.getLevel();
        CopyOnWriteArrayList<String> recorded = new CopyOnWriteArrayList<>();
        AbstractAppender appender = new AbstractAppender("license-http-secrets", null, null, false,
                Property.EMPTY_ARRAY) {
            @Override
            public void append(LogEvent event) {
                recorded.add(event.getMessage().getFormattedMessage());
            }
        };
        appender.start();
        wire.addAppender(appender);
        headers.addAppender(appender);
        wire.setLevel(Level.DEBUG);
        headers.setLevel(Level.DEBUG);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger status = new AtomicInteger(429);
        AtomicInteger requests = new AtomicInteger();
        AtomicReference<String> observedBody = new AtomicReference<>();
        AtomicReference<String> observedIp = new AtomicReference<>();
        AtomicReference<String> observedUser = new AtomicReference<>();
        server.createContext("/api/license/import", exchange -> {
            requests.incrementAndGet();
            observedBody.set(new String(ByteStreams.toByteArray(exchange.getRequestBody()), StandardCharsets.UTF_8));
            observedIp.set(exchange.getRequestHeaders().getFirst(LicenseController.FORWARDED_FOR));
            observedUser.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] result = bytes("{\"reason\":\"LICENSE_RATE_LIMITED\",\"submission_status\":\"NOT_SUBMITTED\"}");
            exchange.getResponseHeaders().add("Retry-After", "6");
            exchange.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"license-test\"");
            exchange.getResponseHeaders().add("Location", "http://127.0.0.1:" + server.getAddress().getPort()
                    + "/api/license/import");
            exchange.sendResponseHeaders(status.get(), result.length);
            exchange.getResponseBody().write(result);
            exchange.close();
        });
        server.start();
        try {
            Assertions.assertTrue(LogFactory.getLog("org.apache.http.wire").isDebugEnabled());
            Assertions.assertTrue(LogFactory.getLog("org.apache.http.headers").isDebugEnabled());
            StubController controller = new StubController();
            Mockito.when(controller.env.isMaster()).thenReturn(false);
            Mockito.when(controller.env.isReady()).thenReturn(true);
            Mockito.when(controller.env.getMasterHost()).thenReturn("127.0.0.1");
            Mockito.when(controller.env.getMasterHttpPort()).thenReturn(server.getAddress().getPort());
            Mockito.when(controller.env.getToken()).thenReturn("cluster-token");
            String document = "{\"certificate\":\"private-license-sentinel\"}";
            for (int expected : new int[] {400, 401, 403, 409, 429, 503}) {
                status.set(expected);
                ResponseEntity<?> forwarded = controller.importCertificate(
                        request("POST", bytes(document)), servletResponse);
                Assertions.assertEquals(expected, forwarded.getStatusCode().value());
                Assertions.assertEquals("LICENSE_RATE_LIMITED", body(forwarded).get("reason"));
                Assertions.assertEquals("6", forwarded.getHeaders().getFirst("Retry-After"));
            }
            Assertions.assertEquals(document, observedBody.get());
            Assertions.assertEquals("192.0.2.5", observedIp.get());
            Assertions.assertEquals(basic(), observedUser.get());
            status.set(307);
            ResponseEntity<?> redirect = controller.importCertificate(
                    request("POST", bytes(document)), servletResponse);
            Assertions.assertEquals(503, redirect.getStatusCode().value());
            Assertions.assertEquals("UNKNOWN", body(redirect).get("submission_status"));
            Assertions.assertEquals(7, requests.get());
            String logs = String.join("\n", recorded);
            Assertions.assertFalse(logs.contains("private-license-sentinel"));
            Assertions.assertFalse(logs.contains("cluster-token"));
            Assertions.assertFalse(logs.contains(basic()));
        } finally {
            server.stop(0);
            wire.removeAppender(appender);
            headers.removeAppender(appender);
            wire.setLevel(oldWire);
            headers.setLevel(oldHeaders);
            appender.stop();
        }
    }

    @Test
    void forwardingUsesPublishedHttpPortAndRegisteredIdentityForHttpsOverrides() throws Exception {
        boolean oldHttps = Config.enable_https;
        String[] oldPorts = Config.massdb_license_fe_management_ports;
        try {
            Env env = Mockito.mock(Env.class);
            Frontend first = Mockito.mock(Frontend.class);
            Frontend second = Mockito.mock(Frontend.class);
            Mockito.when(first.getHost()).thenReturn("127.0.0.1");
            Mockito.when(first.getEditLogPort()).thenReturn(9011);
            Mockito.when(first.getRpcPort()).thenReturn(9021);
            Mockito.when(second.getHost()).thenReturn("127.0.0.1");
            Mockito.when(second.getEditLogPort()).thenReturn(9012);
            Mockito.when(second.getRpcPort()).thenReturn(9022);
            Mockito.when(env.getFrontends(null)).thenReturn(Arrays.asList(first, second));
            Mockito.when(env.getMasterHost()).thenReturn("127.0.0.1");
            Mockito.when(env.getMasterRpcPort()).thenReturn(9022);
            Mockito.when(env.getMasterHttpPort()).thenReturn(18030);
            Config.massdb_license_fe_management_ports = new String[] {"127.0.0.1:9011=18431", "127.0.0.1:9012=18432"};
            Config.enable_https = false;
            Assertions.assertEquals(18030, LicenseController.masterManagementPort(env));
            Config.enable_https = true;
            Assertions.assertEquals(18432, LicenseController.masterManagementPort(env));
            Mockito.when(env.getMasterRpcPort()).thenReturn(0);
            Assertions.assertThrows(java.io.IOException.class, () -> LicenseController.masterManagementPort(env));
        } finally {
            Config.enable_https = oldHttps;
            Config.massdb_license_fe_management_ports = oldPorts;
        }
    }

    @Test
    void committedForwardResponseSurvivesInterruptedLocalApplyWait() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/license/import", exchange -> {
            byte[] result = bytes("{\"reason\":\"LICENSE_APPLIED\",\"submission_status\":\"APPLIED\","
                    + "\"committed_version\":7,\"applied_version\":7,\"fingerprint\":\"known\"}");
            exchange.sendResponseHeaders(200, result.length);
            exchange.getResponseBody().write(result);
            exchange.close();
        });
        server.start();
        try {
            StubController controller = new StubController();
            LicenseManager manager = Mockito.mock(LicenseManager.class);
            Mockito.when(controller.env.getLicenseManager()).thenReturn(manager);
            Mockito.when(controller.env.isMaster()).thenReturn(false);
            Mockito.when(controller.env.isReady()).thenReturn(true);
            Mockito.when(controller.env.getMasterHost()).thenReturn("127.0.0.1");
            Mockito.when(controller.env.getMasterHttpPort()).thenReturn(server.getAddress().getPort());
            Mockito.when(controller.env.getToken()).thenReturn("cluster-token");
            Mockito.when(manager.getAppliedVersion()).thenAnswer(call -> {
                Thread.currentThread().interrupt();
                return 6L;
            });
            ResponseEntity<?> pending = controller.importCertificate(
                    request("POST", bytes("{\"certificate\":\"signed\"}")), servletResponse);
            Assertions.assertEquals(202, pending.getStatusCode().value());
            Assertions.assertEquals("COMMITTED", body(pending).get("submission_status"));
            Assertions.assertEquals("known", body(pending).get("fingerprint"));
            Assertions.assertEquals(7, body(pending).get("committed_version"));
            Assertions.assertTrue(Thread.interrupted());

            Mockito.when(manager.getAppliedVersion()).thenReturn(7L);
            Thread.interrupted();
            ResponseEntity<?> applied = controller.importCertificate(
                    request("POST", bytes("{\"certificate\":\"signed\"}")), servletResponse);
            Assertions.assertEquals(200, applied.getStatusCode().value());
            Assertions.assertEquals("APPLIED", body(applied).get("submission_status"));
            Assertions.assertEquals(7L, body(applied).get("applied_version"));
        } finally {
            Thread.interrupted();
            server.stop(0);
        }
    }

    private static String payload(String text) throws Exception {
        return LicenseController.parsePayload(Action.IMPORT, bytes(text));
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String repeat(char character, int count) {
        char[] text = new char[count];
        Arrays.fill(text, character);
        return new String(text);
    }

    private static String identity(UserIdentity user) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(user.toString()));
    }

    private static String basic() {
        return "Basic " + Base64.getEncoder().encodeToString(bytes("root:password"));
    }

    private static Map<?, ?> body(ResponseEntity<?> response) {
        return (Map<?, ?>) response.getBody();
    }

    private static HttpServletRequest request(String method, byte[] body) throws Exception {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getMethod()).thenReturn(method);
        Mockito.when(request.getContentLengthLong()).thenReturn((long) body.length);
        Mockito.when(request.getHeader("Authorization")).thenReturn(basic());
        Mockito.when(request.getRemoteAddr()).thenReturn("192.0.2.5");
        Mockito.when(request.getScheme()).thenReturn("http");
        Mockito.when(request.getServerName()).thenReturn("fe.example");
        Mockito.when(request.getServerPort()).thenReturn(8030);
        ByteArrayInputStream input = new ByteArrayInputStream(body);
        Mockito.when(request.getInputStream()).thenReturn(new ServletInputStream() {
            @Override
            public int read() {
                return input.read();
            }

            @Override
            public boolean isFinished() {
                return input.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
                throw new UnsupportedOperationException();
            }
        });
        return request;
    }

    private static class StubController extends LicenseController {
        final Env env = Mockito.mock(Env.class);
        boolean admin = true;
        boolean authFailure;
        boolean executedAsAdmin;
        int authCalls;
        int executions;
        Action action;
        String payload;
        LicenseManagementException failure;

        StubController() {
            Mockito.when(env.isMaster()).thenReturn(true);
        }

        @Override
        protected Env environment() {
            return env;
        }

        @Override
        protected boolean isAdministrator() {
            return admin;
        }

        @Override
        protected ActionAuthorizationInfo authenticate(HttpServletRequest request, HttpServletResponse response) {
            authCalls++;
            if (authFailure) {
                throw new UnauthorizedException("secret");
            }
            ConnectContext context = new ConnectContext();
            context.setCurrentUserIdentity(UserIdentity.ROOT);
            context.setThreadLocalInfo();
            ActionAuthorizationInfo credentials = new ActionAuthorizationInfo();
            credentials.fullUserName = "root";
            credentials.password = "password";
            credentials.remoteIp = "192.0.2.5";
            return credentials;
        }

        @Override
        protected LicenseManagementResult execute(Action action, String payload,
                String principal, boolean administrator)
                throws LicenseManagementException {
            this.action = action;
            this.payload = payload;
            executedAsAdmin = administrator;
            executions++;
            if (failure != null) {
                throw failure;
            }
            Map<String, Object> body = new HashMap<>();
            body.put("reason", "LICENSE_OK");
            body.put("submission_status", "APPLIED");
            return new LicenseManagementResult(200, body);
        }
    }

    private static class AuthenticationController extends LicenseController {
        final Env env = Mockito.mock(Env.class);
        String passwordCheckedIp;

        AuthenticationController() {
            Mockito.when(env.getToken()).thenReturn("cluster-token");
            InternalCatalog catalog = Mockito.mock(InternalCatalog.class);
            Mockito.when(catalog.getName()).thenReturn(InternalCatalog.INTERNAL_CATALOG_NAME);
            Mockito.when(env.getInternalCatalog()).thenReturn(catalog);
        }

        @Override
        protected Env environment() {
            return env;
        }

        @Override
        protected UserIdentity checkPassword(ActionAuthorizationInfo auth) {
            passwordCheckedIp = auth.remoteIp;
            return UserIdentity.ROOT;
        }
    }
}
