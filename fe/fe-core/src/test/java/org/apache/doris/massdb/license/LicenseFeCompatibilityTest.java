// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.ha.FrontendNodeType;
import org.apache.doris.system.Backend;
import org.apache.doris.system.Frontend;
import org.apache.doris.system.SystemInfoService;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.base.Strings;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

class LicenseFeCompatibilityTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PACKAGE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String TRUST = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    @Test
    void allMembersMustProveIdenticalPackageTrustAndFormat() {
        Map<String, Object> local = capability(TRUST);
        Frontend member = member();
        ObjectNode remote = JSON.valueToTree(local);
        Assertions.assertTrue(LicenseFeCompatibility.matches(remote, member, local, true));
        for (String field : new String[] {"package_sha256", "trust_sha256", "module", "fe_node_name", "fe_host"}) {
            ObjectNode altered = remote.deepCopy();
            altered.put(field, "different");
            Assertions.assertFalse(LicenseFeCompatibility.matches(altered, member, local, true), field);
        }
        for (String field : new String[] {"schema_version", "format_version", "edit_log_port", "process_uuid"}) {
            ObjectNode altered = remote.deepCopy();
            altered.put(field, 0);
            Assertions.assertFalse(LicenseFeCompatibility.matches(altered, member, local, true), field);
        }
        ObjectNode altered = remote.deepCopy();
        altered.putArray("journal_opcodes").add(6200);
        Assertions.assertFalse(LicenseFeCompatibility.matches(altered, member, local, true));
    }

    @Test
    void missingOrCoercedIdentityIsNotProof() {
        Map<String, Object> local = capability(TRUST);
        ObjectNode remote = JSON.valueToTree(local);
        for (String field : new String[] {"schema_version", "format_version", "module", "journal_opcodes",
                "fe_node_name", "fe_host", "edit_log_port", "process_uuid", "package_sha256", "trust_sha256",
                "trust_ready"}) {
            ObjectNode altered = remote.deepCopy();
            altered.remove(field);
            Assertions.assertFalse(LicenseFeCompatibility.matches(altered, member(), local, true), field);
        }
        remote.put("format_version", "1");
        Assertions.assertFalse(LicenseFeCompatibility.matches(remote, member(), local, true));
    }

    @Test
    void unconfiguredTrustCanInitializeIdentityButCannotMatchInstalledTrust() {
        Map<String, Object> absent = capability(null);
        ObjectNode remote = JSON.valueToTree(absent);
        Assertions.assertTrue(LicenseFeCompatibility.matches(remote, member(), absent, true));
        Assertions.assertFalse(LicenseFeCompatibility.matches(remote, member(), capability(TRUST), true));
        remote.put("trust_ready", true);
        Assertions.assertFalse(LicenseFeCompatibility.matches(remote, member(), absent, true));
    }

    @Test
    void capabilityResponseBodyAndDeadlineAreBounded() throws Exception {
        long future = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        byte[] exact = new byte[64 * 1024];
        Assertions.assertArrayEquals(exact,
                LicenseFeCompatibility.readBounded(new ByteArrayInputStream(exact), future));
        Assertions.assertThrows(IOException.class, () -> LicenseFeCompatibility.readBounded(
                new ByteArrayInputStream(new byte[exact.length + 1]), future));
        Assertions.assertThrows(IOException.class, () -> LicenseFeCompatibility.readBounded(
                new ByteArrayInputStream(new byte[1]), System.nanoTime() - 1));
    }

    @Test
    void membershipVersionDistinguishesReplacementWithSameNodeCount() {
        long initial = LicenseFeCompatibility.membershipVersion(Arrays.asList("fe:a", "be:1"));
        Assertions.assertEquals(initial, LicenseFeCompatibility.membershipVersion(Arrays.asList("fe:a", "be:1")));
        Assertions.assertNotEquals(initial, LicenseFeCompatibility.membershipVersion(Arrays.asList("fe:a", "be:2")));
        Assertions.assertNotEquals(initial, LicenseFeCompatibility.membershipVersion(Arrays.asList("fe:b", "be:1")));
        Assertions.assertNotEquals(LicenseFeCompatibility.membershipVersion(Arrays.asList("ab", "c")),
                LicenseFeCompatibility.membershipVersion(Arrays.asList("a", "bc")));
        Assertions.assertTrue(initial >= 0);
    }

    @Test
    void frontendProofTracksRegisteredIdentityButNotOrderOrLiveness() {
        Env env = Mockito.mock(Env.class);
        Frontend first = new Frontend(FrontendNodeType.FOLLOWER, "first", "127.0.0.1", 9010);
        Frontend second = new Frontend(FrontendNodeType.OBSERVER, "second", "127.0.0.2", 9110);
        first.setIsAlive(true);
        second.setIsAlive(true);
        Mockito.when(env.getFrontends(null)).thenReturn(Arrays.asList(first, second));
        long accepted = LicenseFeCompatibility.frontendVersion(env);
        first.setIsAlive(false);
        second.setIsAlive(false);
        Mockito.when(env.getFrontends(null)).thenReturn(Arrays.asList(second, first));
        Assertions.assertEquals(accepted, LicenseFeCompatibility.frontendVersion(env));
        for (Frontend replacement : Arrays.asList(
                new Frontend(FrontendNodeType.FOLLOWER, "renamed", "127.0.0.1", 9010),
                new Frontend(FrontendNodeType.FOLLOWER, "first", "127.0.0.3", 9010),
                new Frontend(FrontendNodeType.FOLLOWER, "first", "127.0.0.1", 9210),
                new Frontend(FrontendNodeType.OBSERVER, "first", "127.0.0.1", 9010))) {
            Mockito.when(env.getFrontends(null)).thenReturn(Arrays.asList(replacement, second));
            Assertions.assertNotEquals(accepted, LicenseFeCompatibility.frontendVersion(env));
        }
        Mockito.when(env.getFrontends(null)).thenReturn(Collections.singletonList(first));
        Assertions.assertNotEquals(accepted, LicenseFeCompatibility.frontendVersion(env));
        Mockito.verify(env, Mockito.never()).getClusterInfo();
    }

    @Test
    void frontendProofSeparatesNodeNameAndIpv6HostBoundaries() {
        Env env = Mockito.mock(Env.class);
        Mockito.when(env.getFrontends(null)).thenReturn(Collections.singletonList(
                new Frontend(FrontendNodeType.FOLLOWER, "node:2001", "db8::1", 9010)));
        long proof = LicenseFeCompatibility.frontendVersion(env);
        Mockito.when(env.getFrontends(null)).thenReturn(Collections.singletonList(
                new Frontend(FrontendNodeType.FOLLOWER, "node", "2001:db8::1", 9010)));
        Assertions.assertNotEquals(proof, LicenseFeCompatibility.frontendVersion(env));
    }

    @Test
    void backendAddOrDropChangesCapacityMembershipWithoutInvalidatingFrontendProof() {
        Env env = Mockito.mock(Env.class);
        SystemInfoService backends = Mockito.mock(SystemInfoService.class);
        Mockito.when(env.getFrontends(null)).thenReturn(Collections.singletonList(member()));
        Mockito.when(env.getClusterInfo()).thenReturn(backends);
        Mockito.when(backends.getAllBackendIds(false)).thenReturn(Collections.singletonList(1L));
        Mockito.when(backends.getBackend(1L)).thenReturn(new Backend(1L, "127.0.0.3", 9050));
        Mockito.when(backends.getBackend(2L)).thenReturn(new Backend(2L, "127.0.0.4", 9050));
        long proof = LicenseFeCompatibility.frontendVersion(env);
        LicenseManager.Membership before = LicenseFeCompatibility.membership(env);
        Mockito.when(backends.getAllBackendIds(false)).thenReturn(Arrays.asList(1L, 2L));
        LicenseManager.Membership after = LicenseFeCompatibility.membership(env);
        Assertions.assertEquals(1, before.beNodes);
        Assertions.assertEquals(2, after.beNodes);
        Assertions.assertNotEquals(before.version, after.version);
        Assertions.assertEquals(proof, LicenseFeCompatibility.frontendVersion(env));
        Mockito.when(backends.getAllBackendIds(false)).thenReturn(Collections.emptyList());
        Assertions.assertEquals(0, LicenseFeCompatibility.membership(env).beNodes);
        Assertions.assertEquals(proof, LicenseFeCompatibility.frontendVersion(env));
    }

    @Test
    void registeredIdentitiesOnOneHostCanUseSeparateManagementPorts() throws Exception {
        Map<String, Integer> ports = LicenseFeCompatibility.managementPorts(new String[] {
                "127.0.0.2:9010=8030", "127.0.0.2:9110=8130", "future-fe:9210=8230"});
        Frontend first = new Frontend(FrontendNodeType.FOLLOWER, "first", "127.0.0.2", 9010);
        Frontend second = new Frontend(FrontendNodeType.OBSERVER, "second", "127.0.0.2", 9110);
        Frontend other = new Frontend(FrontendNodeType.FOLLOWER, "other", "127.0.0.3", 9010);
        Assertions.assertEquals(8030, LicenseFeCompatibility.managementPort(first, 8050, ports));
        Assertions.assertEquals(8130, LicenseFeCompatibility.managementPort(second, 8050, ports));
        Assertions.assertEquals(8050, LicenseFeCompatibility.managementPort(other, 8050, ports));
        Assertions.assertEquals(8050,
                LicenseFeCompatibility.managementPort(first, 8050,
                        LicenseFeCompatibility.managementPorts(new String[0])));
    }

    @Test
    void managementPortMappingSupportsBracketedIpv6() throws Exception {
        Map<String, Integer> ports = LicenseFeCompatibility.managementPorts(new String[] {"[::1]:9010=8130"});
        Frontend member = new Frontend(FrontendNodeType.FOLLOWER, "ipv6", "::1", 9010);
        Assertions.assertEquals(8130, LicenseFeCompatibility.managementPort(member, 8050, ports));
    }

    @Test
    void managementPortMappingCannotRewriteAHostUrlOrAmbiguousIdentity() {
        for (String invalid : new String[] {"", "127.0.0.2=8030", "127.0.0.2:9010=0",
                "127.0.0.2:9010=65536", "127.0.0.2:0=8030", "127.0.0.2:9010=-1",
                "127.0.0.2:9010=http://other-host:8030", "http://127.0.0.2:9010=8030",
                "user@127.0.0.2:9010=8030", "127.0.0.2:9010/path=8030", "127.0.0.2:9010=8030=8031",
                "::1:9010=8030"}) {
            Assertions.assertThrows(IOException.class,
                    () -> LicenseFeCompatibility.managementPorts(new String[] {invalid}), invalid);
        }
        Assertions.assertThrows(IOException.class, () -> LicenseFeCompatibility.managementPorts(new String[] {
                "127.0.0.2:9010=8030", "127.0.0.2:9010=8130"}));
        Assertions.assertThrows(IOException.class, () -> LicenseFeCompatibility.managementPorts(new String[1025]));
    }

    @Test
    void failedRemoteProofNamesMemberAndFieldWithoutLoggingRemoteValues() throws Exception {
        try (ProbeFixture probe = new ProbeFixture(); LogCapture logs = new LogCapture()) {
            Assertions.assertTrue(probe.check(new LicenseFeCompatibility.DiagnosticLimiter()));
            for (String field : new String[] {"package_sha256", "trust_sha256", "fe_node_name", "module"}) {
                ObjectNode altered = probe.capability.deepCopy();
                altered.put(field, "private.payload.signature");
                probe.respond(200, altered.toString());
                Assertions.assertFalse(probe.check(new LicenseFeCompatibility.DiagnosticLimiter()));
                String message = logs.nextMessage();
                Assertions.assertTrue(message.contains("node=remote-fe, host=127.0.0.1, editLogPort=9110"));
                Assertions.assertTrue(message.contains("reason=CAPABILITY_MISMATCH, field=" + field));
                Assertions.assertFalse(message.contains(PACKAGE));
                Assertions.assertFalse(message.contains(TRUST));
            }
        }
    }

    @Test
    void httpAndMalformedCapabilityFailuresHaveSafeReasons() throws Exception {
        try (ProbeFixture probe = new ProbeFixture(); LogCapture logs = new LogCapture()) {
            probe.respond(403, "private.payload.signature provider-secret-detail cluster-secret-material");
            Assertions.assertFalse(probe.check(new LicenseFeCompatibility.DiagnosticLimiter()));
            String forbidden = logs.nextMessage();
            Assertions.assertTrue(forbidden.contains("reason=HTTP_STATUS"));
            Assertions.assertTrue(forbidden.contains("httpStatus=403"));
            probe.respond(200, "{\"secret\":\"private.payload.signature\",provider-secret-detail}");
            Assertions.assertFalse(probe.check(new LicenseFeCompatibility.DiagnosticLimiter()));
            Assertions.assertTrue(logs.nextMessage().contains("reason=INVALID_CAPABILITY_JSON"));
            probe.respond(200, Strings.repeat("private.payload.signature", 3000));
            Assertions.assertFalse(probe.check(new LicenseFeCompatibility.DiagnosticLimiter()));
            Assertions.assertTrue(logs.nextMessage().contains("reason=CAPABILITY_TOO_LARGE"));
        }
    }

    @Test
    void unavailableRemoteProofIsDiagnosedWithoutProviderException() throws Exception {
        try (ProbeFixture probe = new ProbeFixture(); LogCapture logs = new LogCapture()) {
            probe.server.stop(0);
            Assertions.assertFalse(probe.check(new LicenseFeCompatibility.DiagnosticLimiter()));
            String message = logs.nextMessage();
            Assertions.assertTrue(message.contains("node=remote-fe"));
            Assertions.assertTrue(message.contains("reason=PROBE_UNAVAILABLE"));
            Assertions.assertFalse(message.contains("Connection refused"));
        }
    }

    @Test
    void repeatingFailedChecksShareOneBoundedWarningStream() throws Exception {
        try (ProbeFixture probe = new ProbeFixture(); LogCapture logs = new LogCapture()) {
            LicenseFeCompatibility.DiagnosticLimiter limiter = new LicenseFeCompatibility.DiagnosticLimiter();
            probe.respond(403, "private.payload.signature");
            for (int attempt = 0; attempt < 3; attempt++) {
                Assertions.assertFalse(probe.check(limiter));
            }
            Assertions.assertTrue(logs.nextMessage().contains("reason=HTTP_STATUS"));
            Assertions.assertEquals(1, logs.events.size());
        }
    }

    @Test
    void diagnosticLimitUsesElapsedTimeAcrossNanoTimeWrap() {
        LicenseFeCompatibility.DiagnosticLimiter limiter = new LicenseFeCompatibility.DiagnosticLimiter();
        long start = Long.MAX_VALUE - TimeUnit.SECONDS.toNanos(30);
        Assertions.assertTrue(limiter.acquire(start));
        Assertions.assertFalse(limiter.acquire(start + 1));
        Assertions.assertFalse(limiter.acquire(start + TimeUnit.SECONDS.toNanos(60) - 1));
        Assertions.assertTrue(limiter.acquire(start + TimeUnit.SECONDS.toNanos(60)));
    }

    @Test
    void localFailureIdentityCannotInjectMultilineLog() throws Exception {
        Env env = Mockito.mock(Env.class);
        Mockito.when(env.getNodeName()).thenReturn("local\r\n" + Strings.repeat("x", 200));
        Map<String, Object> local = capability(TRUST);
        local.put("package_sha256", null);
        try (LogCapture logs = new LogCapture()) {
            Assertions.assertFalse(LicenseFeCompatibility.checkAll(env, local,
                    new LicenseFeCompatibility.DiagnosticLimiter()));
            String message = logs.nextMessage();
            Assertions.assertTrue(message.contains("reason=LOCAL_PACKAGE_UNAVAILABLE"));
            Assertions.assertTrue(message.contains("node=local__"));
            Assertions.assertFalse(message.contains("\r"));
            Assertions.assertFalse(message.contains("\n"));
            Assertions.assertFalse(message.contains(Strings.repeat("x", 129)));
        }
    }

    private static final class ProbeFixture implements AutoCloseable {
        private final boolean originalHttps = Config.enable_https;
        private final String[] originalPorts = Config.massdb_license_fe_management_ports;
        private final HttpServer server;
        private final Env env = Mockito.mock(Env.class);
        private final Map<String, Object> local = capability(TRUST);
        private final ObjectNode capability = JSON.valueToTree(local);
        private volatile int status = 200;
        private volatile byte[] body;

        private ProbeFixture() throws IOException {
            capability.put("fe_node_name", "remote-fe");
            capability.put("fe_host", "127.0.0.1");
            capability.put("edit_log_port", 9110);
            respond(200, capability.toString());
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/api/license/capability", exchange -> {
                byte[] response = body;
                try {
                    exchange.sendResponseHeaders(status, response.length);
                    exchange.getResponseBody().write(response);
                } finally {
                    exchange.close();
                }
            });
            server.start();
            Config.enable_https = false;
            Config.massdb_license_fe_management_ports = new String[] {
                    "127.0.0.1:9110=" + server.getAddress().getPort()};
            Mockito.when(env.getNodeName()).thenReturn("fe-member");
            Mockito.when(env.getToken()).thenReturn("cluster-secret-material");
            Mockito.when(env.getFrontends(null)).thenReturn(Arrays.asList(member(),
                    new Frontend(FrontendNodeType.FOLLOWER, "remote-fe", "127.0.0.1", 9110)));
        }

        private void respond(int responseStatus, String responseBody) {
            status = responseStatus;
            body = responseBody.getBytes(StandardCharsets.UTF_8);
        }

        private boolean check(LicenseFeCompatibility.DiagnosticLimiter limiter) {
            return LicenseFeCompatibility.checkAll(env, local, limiter);
        }

        @Override
        public void close() {
            server.stop(0);
            Config.enable_https = originalHttps;
            Config.massdb_license_fe_management_ports = originalPorts;
        }
    }

    private static final class LogCapture implements AutoCloseable {
        private final List<LogEvent> events = new CopyOnWriteArrayList<>();
        private final Logger logger = (Logger) LogManager.getLogger(LicenseFeCompatibility.class);
        private final Level originalLevel = logger.getLevel();
        private final AbstractAppender appender = new AbstractAppender("license-fe-proof", null, null, false,
                Property.EMPTY_ARRAY) {
            @Override
            public void append(LogEvent event) {
                events.add(event.toImmutable());
            }
        };
        private int consumed;

        private LogCapture() {
            appender.start();
            logger.addAppender(appender);
            logger.setLevel(Level.WARN);
        }

        private String nextMessage() throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (events.size() <= consumed && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            Assertions.assertTrue(events.size() > consumed, "Expected a compatibility diagnostic");
            LogEvent event = events.get(consumed++);
            Assertions.assertNull(event.getThrown());
            String message = event.getMessage().getFormattedMessage();
            for (String secret : new String[] {"private.payload.signature", "provider-secret-detail",
                    "cluster-secret-material"}) {
                Assertions.assertFalse(message.contains(secret));
            }
            return message;
        }

        @Override
        public void close() {
            logger.removeAppender(appender);
            logger.setLevel(originalLevel);
            appender.stop();
        }
    }

    private static Frontend member() {
        return new Frontend(FrontendNodeType.FOLLOWER, "fe-member", "127.0.0.2", 9010);
    }

    private static Map<String, Object> capability(String trust) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schema_version", 1);
        result.put("format_version", 1);
        result.put("module", "massdbLicenseV1");
        result.put("journal_opcodes", Arrays.asList(6200, 6201, 6202, 6203, 6204, 6205));
        result.put("fe_node_name", "fe-member");
        result.put("fe_host", "127.0.0.2");
        result.put("edit_log_port", 9010);
        result.put("process_uuid", 123456789L);
        result.put("package_sha256", PACKAGE);
        result.put("trust_sha256", trust);
        result.put("trust_ready", trust != null);
        return result;
    }
}
