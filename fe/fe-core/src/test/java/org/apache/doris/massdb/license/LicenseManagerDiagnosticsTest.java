// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

class LicenseManagerDiagnosticsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PRIVATE_MARKER = "private.payload.signature";
    @TempDir
    Path directory;

    @Test
    void missingTrustWarnsOnceWithoutThePrivatePathOrProviderMessage() throws Exception {
        String path = directory.resolve("private-trust-path-does-not-exist.json").toString();
        assertTrustWarning(path, "reason=TRUST_STORE_LOAD_FAILED");
    }

    @Test
    void malformedTrustWarnsOnceWithoutEchoingTheFileContents() throws Exception {
        Path file = directory.resolve("private-trust-path-invalid.json");
        Files.write(file, ("{\"schema_version\":1,\"keys\":[" + PRIVATE_MARKER)
                .getBytes(StandardCharsets.UTF_8));
        assertTrustWarning(file.toString(), "License trust loading failed: reason=");
    }

    @Test
    void unconfiguredTrustWarnsOnceForEachManager() throws Exception {
        for (String path : new String[] {null, ""}) {
            assertTrustWarning(path, "License trust is not configured");
        }
    }

    @Test
    void checkpointEnvironmentDoesNotRepeatRuntimeTrustWarnings() throws Exception {
        LicenseManager.Host host = host(directory.resolve("private-trust-path-missing.json").toString());
        try (LogCapture logs = new LogCapture(); LicenseManager manager = new LicenseManager(host, true, new Time())) {
            manager.onReplayComplete();
            manager.capability();
            logs.flush();
            Assertions.assertTrue(logs.events.isEmpty());
        }
    }

    @Test
    void followerClockTransitionsLogOnMaintenanceWithoutQueryLoggingOrJournalWrites() throws Exception {
        LicenseManager.Host host = host(validTrust().toString());
        Time time = new Time();
        LicensePersistRecord initial = LicensePersistRecord.initial(UUID.randomUUID(), false, time.wall);
        try (LicenseManager manager = new LicenseManager(host, false, time); LogCapture logs = new LogCapture()) {
            manager.replay(initial);
            manager.onReplayComplete();
            manager.maintenance();
            Assertions.assertEquals(LicenseQueryStatus.MISSING, manager.queryStatus());
            logs.flush();
            Assertions.assertTrue(logs.events.isEmpty());

            time.wall += 300_001;
            for (int i = 0; i < 100; i++) {
                Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, manager.queryStatus());
            }
            logs.flush();
            Assertions.assertTrue(logs.events.isEmpty(), "Query consumers must not write diagnostic logs");
            for (int i = 0; i < 10; i++) {
                manager.maintenance();
            }
            logs.flush();
            Assertions.assertEquals(1, logs.events.size());
            Assertions.assertEquals(Level.WARN, logs.events.get(0).getLevel());
            Assertions.assertTrue(logs.message(0).contains("clock_epoch=0, applied_version=1, leader=false"));
            Assertions.assertTrue(logs.message(0).contains("CLOCK_SUSPECT"));

            // Exercise the same committed repair-epoch replay path used by a follower after a signed repair.
            LicenseClock.Facts repaired = new LicenseClock.Facts(1, 1, time.wall, 1);
            LicensePersistRecord repair = initial.withClock(LicensePersistRecord.REPAIR,
                    new LicenseClockRepair.State(initial.getDeploymentId(), repaired, Collections.emptyMap()));
            manager.replay(repair);
            Assertions.assertEquals(LicenseQueryStatus.MISSING, manager.queryStatus());
            logs.flush();
            Assertions.assertEquals(1, logs.events.size(), "Replay and query do not report the recovery transition");
            for (int i = 0; i < 10; i++) {
                manager.maintenance();
            }
            logs.flush();
            Assertions.assertEquals(2, logs.events.size());
            Assertions.assertEquals(Level.INFO, logs.events.get(1).getLevel());
            Assertions.assertTrue(logs.message(1).contains("no longer suspect: clock_epoch=1, applied_version=2"));
            Mockito.verify(host, Mockito.never()).commit(Mockito.anyShort(), Mockito.any());
        }
    }

    private void assertTrustWarning(String path, String expectedMessage) throws Exception {
        LicenseManager.Host host = host(path);
        try (LogCapture logs = new LogCapture(); LicenseManager manager = new LicenseManager(host, false, new Time())) {
            for (int i = 0; i < 10; i++) {
                manager.onReplayComplete();
                manager.capability();
                manager.maintenance();
                Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.queryStatus());
            }
            logs.flush();
            Assertions.assertEquals(1, logs.events.size());
            Assertions.assertEquals(Level.WARN, logs.events.get(0).getLevel());
            String message = logs.message(0);
            Assertions.assertTrue(message.contains(expectedMessage));
            Assertions.assertTrue(message.contains("massdb_license_trust_store_file"));
            Assertions.assertTrue(message.contains("restart this FE"));
            Assertions.assertFalse(message.contains(directory.toString()));
            Assertions.assertFalse(message.contains("private-trust-path"));
            Mockito.verify(host, Mockito.times(1)).trustStorePath();
        }
    }

    private Path validTrust() throws Exception {
        ObjectNode trust = JSON.createObjectNode().put("schema_version", 1);
        trust.putArray("keys").addObject().put("kid", "repair").put("purpose", "time_repair")
                .put("public_key_spki", Base64.getUrlEncoder().withoutPadding().encodeToString(
                        KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded()));
        Path file = directory.resolve("public-trust.json");
        Files.write(file, JSON.writeValueAsBytes(trust));
        return file;
    }

    private static LicenseManager.Host host(String path) {
        LicenseManager.Host host = Mockito.mock(LicenseManager.Host.class);
        Mockito.when(host.membership()).thenReturn(new LicenseManager.Membership(1, 0, 1));
        Mockito.when(host.trustStorePath()).thenReturn(path);
        Mockito.when(host.localCapability(Mockito.any())).thenReturn(Collections.emptyMap());
        return host;
    }

    private static final class Time implements LicenseClock.TimeSource {
        private long wall = 1_000_000;

        @Override
        public long wallTimeMillis() {
            return wall;
        }

        @Override
        public long monotonicNanos() {
            return 0;
        }
    }

    private static final class LogCapture implements AutoCloseable {
        private static final String BARRIER = "license-diagnostics-test-log-barrier";
        private final List<LogEvent> events = new CopyOnWriteArrayList<>();
        private final Logger logger = (Logger) LogManager.getLogger(LicenseManager.class);
        private final Level originalLevel = logger.getLevel();
        private volatile CountDownLatch barrier;
        private final AbstractAppender appender = new AbstractAppender("license-manager-diagnostics", null, null,
                false, Property.EMPTY_ARRAY) {
            @Override
            public void append(LogEvent event) {
                if (BARRIER.equals(event.getMessage().getFormattedMessage())) {
                    barrier.countDown();
                } else {
                    events.add(event.toImmutable());
                }
            }
        };

        private LogCapture() {
            appender.start();
            logger.addAppender(appender);
            logger.setLevel(Level.INFO);
        }

        private void flush() throws InterruptedException {
            barrier = new CountDownLatch(1);
            logger.info(BARRIER);
            Assertions.assertTrue(barrier.await(2, TimeUnit.SECONDS));
        }

        private String message(int index) {
            LogEvent event = events.get(index);
            Assertions.assertNull(event.getThrown());
            String message = event.getMessage().getFormattedMessage();
            Assertions.assertFalse(message.contains(PRIVATE_MARKER));
            return message;
        }

        @Override
        public void close() {
            logger.removeAppender(appender);
            logger.setLevel(originalLevel);
            appender.stop();
        }
    }
}
