// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.common.DdlException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

class LicenseManagerTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    @TempDir
    Path directory;
    private KeyPair issuer;
    private KeyPair repairKey;
    private FakeClock time;
    private Host host;
    private LicenseManager manager;
    private int principal;

    @BeforeEach
    void setUp() throws Exception {
        issuer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        repairKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        ObjectNode trust = JSON.createObjectNode().put("schema_version", 1);
        trust.putArray("keys").add(key("issuer", "license", issuer)).add(key("repair", "time_repair", repairKey));
        Path file = directory.resolve("trust.json");
        Files.write(file, JSON.writeValueAsBytes(trust));
        time = new FakeClock();
        host = new Host(file.toString());
        manager = new LicenseManager(host, false, time);
        manager.onReplayComplete();
    }

    @AfterEach
    void close() {
        manager.close();
    }

    @Test
    void idleReplayCompletionDoesNotRebuildMembershipButActualChangesStillPublish() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        LicenseSnapshot published = manager.getSnapshot();
        int reads = host.membershipReads.get();
        for (int i = 0; i < 10000; i++) {
            manager.onReplayComplete();
        }
        Assertions.assertSame(published, manager.getSnapshot());
        Assertions.assertEquals(reads, host.membershipReads.get());
        host.changeMembers(2, 3);
        manager.onMembershipChanged();
        Assertions.assertEquals(2, manager.getSnapshot().getRegisteredFe());
        Assertions.assertEquals(3, manager.getSnapshot().getRegisteredBe());
        Assertions.assertEquals(reads + 1, host.membershipReads.get());
        manager.replay(host.records.get(host.records.size() - 1).withClockSuspect());
        Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, manager.queryStatus());
        Assertions.assertEquals(reads + 2, host.membershipReads.get());
        manager.onReplayComplete();
        Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, manager.queryStatus());
        Assertions.assertEquals(reads + 2, host.membershipReads.get());
    }

    @Test
    void failedInitialPublicationCanRetryAndIncompleteMarkDoesNotNeedMembers() throws Exception {
        LicensePersistRecord initial = LicensePersistRecord.initial(UUID.randomUUID(), true, time.wall);
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.replay(initial);
            host.publicationFailure.set(true);
            Assertions.assertThrows(IllegalStateException.class, restored::onReplayComplete);
            Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, restored.queryStatus());
            restored.onReplayComplete();
            Assertions.assertNotEquals(LicenseQueryStatus.LICENSE_NOT_READY, restored.queryStatus());
            int reads = host.membershipReads.get();
            host.publicationFailure.set(true);
            restored.markRecoveryIncomplete();
            Assertions.assertEquals(reads, host.membershipReads.get());
            Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, restored.queryStatus());
            restored.onReplayComplete();
            Assertions.assertEquals(reads, host.membershipReads.get());
            Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, restored.queryStatus());
        } finally {
            host.publicationFailure.set(false);
        }
    }

    @Test
    void initializationProbeDoesNotHoldMemberQueueAndCannotCommitAcrossMemberChanges() throws Exception {
        host.probeEntered = new CountDownLatch(1);
        host.probeRelease = new CountDownLatch(1);
        ExecutorService callers = Executors.newSingleThreadExecutor();
        try {
            manager.onMasterStart(false);
            Assertions.assertTrue(host.probeEntered.await(5, TimeUnit.SECONDS));
            Future<?> removal = callers.submit(() -> {
                manager.runMembershipMutation(0, 0, () -> {
                    host.changeMembers(1, 0);
                    host.frontendVersion++;
                });
                return null;
            });
            removal.get(2, TimeUnit.SECONDS);
            Assertions.assertEquals(0, manager.getAppliedVersion());
            host.probeRelease.countDown();
            awaitBackgroundMaintenance();
            manager.runMembershipMutation(0, 0, () -> { });
            Assertions.assertEquals(0, manager.getAppliedVersion());
            host.probeEntered = null;
            manager.maintenance();
            Assertions.assertEquals(1, manager.getAppliedVersion());
        } finally {
            host.probeRelease.countDown();
            callers.shutdownNow();
        }
    }

    @Test
    void initializationProofCannotSurviveLeadershipChange() throws Exception {
        host.probeEntered = new CountDownLatch(1);
        host.probeRelease = new CountDownLatch(1);
        manager.onMasterStart(false);
        try {
            Assertions.assertTrue(host.probeEntered.await(5, TimeUnit.SECONDS));
            manager.onNonMaster();
            manager.onMasterStart(false);
            host.probeRelease.countDown();
            awaitBackgroundMaintenance();
            manager.runMembershipMutation(0, 0, () -> { });
            Assertions.assertEquals(0, manager.getAppliedVersion());
            host.probeEntered = null;
            manager.maintenance();
            Assertions.assertEquals(1, manager.getAppliedVersion());
        } finally {
            host.probeRelease.countDown();
        }
    }

    @Test
    void uncertainInitialCommitDoesNotRepeatTheCompatibilityProbe() throws Exception {
        host.throwAfterWrite = true;
        manager.onMasterStart(true);
        awaitBackgroundMaintenance();
        Assertions.assertEquals(0, manager.getAppliedVersion());
        Assertions.assertEquals(1, host.records.size());
        Assertions.assertEquals(1, host.activationProbes.get());

        host.throwAfterWrite = false;
        host.compatible = false;
        manager.onMasterStart(true);
        awaitBackgroundMaintenance();
        Assertions.assertEquals(1, host.activationProbes.get());
        Assertions.assertEquals(1, host.records.size());
        Assertions.assertEquals(0, manager.getAppliedVersion());
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.queryStatus());

        manager.replay(host.records.get(0));
        Assertions.assertEquals(1, manager.getAppliedVersion());
        Assertions.assertNotEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.queryStatus());
    }

    @Test
    void committedInitialRecordCanFinishApplyingWithoutAnotherCompatibilityProbe() throws Exception {
        host.failPublicationAfterCommit = true;
        manager.onMasterStart(true);
        awaitBackgroundMaintenance();
        Assertions.assertEquals(0, manager.getAppliedVersion());
        Assertions.assertEquals(1, host.records.size());
        Assertions.assertEquals(1, host.activationProbes.get());

        host.compatible = false;
        manager.onMasterStart(true);
        awaitBackgroundMaintenance();
        Assertions.assertEquals(1, host.activationProbes.get());
        Assertions.assertEquals(1, host.records.size());
        Assertions.assertEquals(1, manager.getAppliedVersion());
        Assertions.assertNotEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.queryStatus());
    }

    @Test
    void imageSnapshotSerializesMemberAndLicenseCommitsWithoutBlockingStatus() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        String renewal = certificate(2, 1000, 2300);
        int committed = host.records.size();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        List<String> events = Collections.synchronizedList(new ArrayList<>());
        ExecutorService clients = Executors.newFixedThreadPool(4);
        try {
            Future<String> image = clients.submit(() -> manager.runImageSnapshot(() -> {
                Assertions.assertFalse(Thread.holdsLock(manager));
                events.add("snapshot-enter");
                entered.countDown();
                Assertions.assertTrue(release.await(10, TimeUnit.SECONDS));
                Assertions.assertEquals(committed, host.records.size());
                Assertions.assertEquals(1, host.feNodes);
                events.add("snapshot-exit");
                return "image.ready";
            }));
            Assertions.assertTrue(entered.await(5, TimeUnit.SECONDS));
            Future<?> membership = clients.submit(() -> {
                manager.runMembershipMutation(1, 1, () -> {
                    host.changeMembers(2, 1);
                    events.add("member");
                });
                return null;
            });
            awaitMutationQueueSize(1);
            Future<LicenseManagementException> imported = clients.submit(() -> Assertions.assertThrows(
                    LicenseManagementException.class, () -> manager.execute(LicenseManager.Action.IMPORT,
                            renewal, "snapshot-renewal", true)));
            awaitMutationQueueSize(2);
            Assertions.assertFalse(membership.isDone());
            Assertions.assertFalse(imported.isDone());
            Future<Integer> status = clients.submit(() -> manager.execute(
                    LicenseManager.Action.STATUS, null, "snapshot-reader", false).getHttpStatus());
            Assertions.assertEquals(200, status.get(2, TimeUnit.SECONDS).intValue());
            Assertions.assertTrue(manager.queryStatus().permitsNewQuery());
            release.countDown();
            Assertions.assertEquals("image.ready", image.get(5, TimeUnit.SECONDS));
            membership.get(5, TimeUnit.SECONDS);
            // The preceding member commit invalidates the import prepared while the image held the queue.
            LicenseManagementException stale = imported.get(5, TimeUnit.SECONDS);
            Assertions.assertEquals(409, stale.getHttpStatus());
            Assertions.assertEquals("LICENSE_STALE_IMPORT_DECISION", stale.getReason());
            Assertions.assertEquals(Arrays.asList("snapshot-enter", "snapshot-exit", "member"), events);
            Assertions.assertEquals(committed, host.records.size());
            Assertions.assertEquals(200, run(LicenseManager.Action.IMPORT, renewal).getHttpStatus());
            Assertions.assertEquals(committed + 1, host.records.size());
        } finally {
            release.countDown();
            clients.shutdownNow();
            Assertions.assertTrue(clients.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void imageSnapshotRejectsUncertainAndUnappliedCommitsUntilColdReplayConfirmsThem() throws Exception {
        start();
        String first = certificate(1, 900, 2000);
        String second = certificate(2, 1000, 2300);
        AtomicBoolean wroteImage = new AtomicBoolean();
        host.throwAfterWrite = true;
        Assertions.assertThrows(LicenseManagementException.class, () -> run(LicenseManager.Action.IMPORT, first));
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.queryStatus());
        Assertions.assertThrows(IOException.class, () -> manager.runImageSnapshot(() -> {
            wroteImage.set(true);
            return "unsafe.image";
        }));
        Assertions.assertFalse(wroteImage.get());
        host.throwAfterWrite = false;
        LicensePersistRecord accepted = coldRecord(host.records.get(host.records.size() - 1));
        manager.replay(accepted);
        manager.replay(coldRecord(accepted));
        Assertions.assertTrue(manager.queryStatus().permitsNewQuery());
        Assertions.assertEquals("APPLIED", run(LicenseManager.Action.IMPORT_RECEIPT,
                LicenseVerifier.fingerprint(first)).getBody().get("submission_status"));
        Assertions.assertEquals("confirmed.image", manager.runImageSnapshot(() -> "confirmed.image"));

        host.failPublicationAfterCommit = true;
        Assertions.assertEquals(202, run(LicenseManager.Action.IMPORT, second).getHttpStatus());
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.queryStatus());
        Assertions.assertThrows(IOException.class, () -> manager.runImageSnapshot(() -> {
            wroteImage.set(true);
            return "unapplied.image";
        }));
        Assertions.assertFalse(wroteImage.get());
        LicensePersistRecord pending = coldRecord(host.records.get(host.records.size() - 1));
        manager.replay(pending);
        manager.replay(coldRecord(pending));
        Assertions.assertTrue(manager.queryStatus().permitsNewQuery());
        Assertions.assertEquals("APPLIED", run(LicenseManager.Action.IMPORT_RECEIPT,
                LicenseVerifier.fingerprint(second)).getBody().get("submission_status"));
        Assertions.assertEquals("applied.image", manager.runImageSnapshot(() -> "applied.image"));
    }

    @Test
    void closingCancelsQueuedImageAndMemberRequestsWithoutRunningTheirCallbacks() throws Exception {
        start();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean queuedImageRan = new AtomicBoolean();
        AtomicBoolean queuedMemberRan = new AtomicBoolean();
        ExecutorService clients = Executors.newFixedThreadPool(3);
        try {
            Future<IOException> running = clients.submit(() -> Assertions.assertThrows(IOException.class,
                    () -> manager.runImageSnapshot(() -> {
                        entered.countDown();
                        release.await(10, TimeUnit.SECONDS);
                        throw new IOException("sensitive image payload");
                    })));
            Assertions.assertTrue(entered.await(5, TimeUnit.SECONDS));
            Future<IOException> queued = clients.submit(() -> Assertions.assertThrows(IOException.class,
                    () -> manager.runImageSnapshot(() -> {
                        queuedImageRan.set(true);
                        return "must-not-exist.image";
                    })));
            awaitMutationQueueSize(1);
            Future<DdlException> member = clients.submit(() -> Assertions.assertThrows(DdlException.class,
                    () -> manager.runMembershipMutation(0, 0, () -> queuedMemberRan.set(true))));
            awaitMutationQueueSize(2);
            manager.close();
            Assertions.assertNotNull(queued.get(5, TimeUnit.SECONDS));
            Assertions.assertNotNull(member.get(5, TimeUnit.SECONDS));
            IOException failure = running.get(5, TimeUnit.SECONDS);
            Assertions.assertFalse(failure.toString().contains("sensitive image payload"));
            Assertions.assertNull(failure.getCause());
            Assertions.assertFalse(queuedImageRan.get());
            Assertions.assertFalse(queuedMemberRan.get());
            Assertions.assertThrows(IOException.class, () -> manager.runImageSnapshot(() -> "closed.image"));
        } finally {
            release.countDown();
            clients.shutdownNow();
            Assertions.assertTrue(clients.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void imageSnapshotFailuresAreSafeAndDoNotPoisonLaterSnapshots() throws Exception {
        // Read-only follower/uninitialized dumps need the barrier too, without acquiring master privileges.
        for (Exception cause : new Exception[] {new IOException("private certificate text"),
                new IllegalStateException("private certificate text")}) {
            IOException failure = Assertions.assertThrows(IOException.class,
                    () -> manager.runImageSnapshot(() -> {
                        throw cause;
                    }));
            Assertions.assertFalse(failure.toString().contains("private certificate text"));
            Assertions.assertNull(failure.getCause());
        }
        Assertions.assertEquals("follower.image", manager.runImageSnapshot(() -> "follower.image"));
        Assertions.assertEquals(0, manager.getAppliedVersion());
        try (LicenseManager checkpoint = new LicenseManager(host, true, time)) {
            Assertions.assertThrows(IOException.class, () -> checkpoint.runImageSnapshot(() -> "checkpoint.image"));
        }
    }

    @Test
    void coldReplayOfTheSameVersionWithDifferentFactsStillInvalidatesRecovery() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        long version = manager.getAppliedVersion();
        ObjectNode conflict = imageJson(image(manager));
        ObjectNode clock = (ObjectNode) conflict.get("clock");
        clock.put("high_water_millis", clock.get("high_water_millis").longValue() + 1);
        manager.replay(recordFromEnvelope(conflict));
        Assertions.assertEquals(version, manager.getAppliedVersion());
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.queryStatus());
        Assertions.assertTrue(image(manager)[0] != 0);
    }

    private void awaitMutationQueueSize(int expected) throws Exception {
        java.lang.reflect.Field field = LicenseManager.class.getDeclaredField("mutations");
        field.setAccessible(true);
        ThreadPoolExecutor worker = (ThreadPoolExecutor) field.get(manager);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (worker.getQueue().size() < expected && System.nanoTime() < deadline) {
            Thread.sleep(2);
        }
        Assertions.assertEquals(expected, worker.getQueue().size());
    }

    private static LicensePersistRecord coldRecord(LicensePersistRecord record) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        record.write(new DataOutputStream(bytes));
        return LicensePersistRecord.read(input(bytes.toByteArray()));
    }

    @Test
    void memberAdmissionRequiresCommittedCapacityAndOnlyProvenBootstrapHasOneFe() throws Exception {
        AtomicBoolean changed = new AtomicBoolean();
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.queryStatus());
        Assertions.assertThrows(DdlException.class,
                () -> manager.runMembershipMutation(0, 1, () -> changed.set(true)));
        start();
        Assertions.assertEquals("LICENSE_FE_LIMIT_EXCEEDED", Assertions.assertThrows(DdlException.class,
                () -> manager.runMembershipMutation(1, 0, () -> changed.set(true))).getDetailMessage());
        Assertions.assertEquals("LICENSE_BE_LIMIT_EXCEEDED", Assertions.assertThrows(DdlException.class,
                () -> manager.runMembershipMutation(0, 1, () -> changed.set(true))).getDetailMessage());
        Assertions.assertFalse(changed.get());
        manager.markRecoveryIncomplete();
        Assertions.assertEquals("LICENSE_NOT_READY", Assertions.assertThrows(DdlException.class,
                () -> manager.runMembershipMutation(1, 0, () -> changed.set(true))).getDetailMessage());
        // Recovery uncertainty must not prevent an operator from reducing existing membership safely.
        manager.runMembershipMutation(0, 0, () -> changed.set(true));
        Assertions.assertTrue(changed.get());
    }

    @Test
    void expiredCertificateKeepsCommittedCapacityAndUpdatesSnapshotsAtMembershipCommit() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 1100));
        time.advance(100_000);
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, manager.queryStatus());
        manager.runMembershipMutation(2, 5, () -> host.changeMembers(3, 5));
        Assertions.assertEquals(3, manager.getSnapshot().getRegisteredFe());
        Assertions.assertEquals(5, manager.getSnapshot().getRegisteredBe());
        AtomicBoolean changed = new AtomicBoolean();
        Assertions.assertEquals("LICENSE_FE_LIMIT_EXCEEDED", Assertions.assertThrows(DdlException.class,
                () -> manager.runMembershipMutation(1, 0, () -> changed.set(true))).getDetailMessage());
        Assertions.assertEquals("LICENSE_BE_LIMIT_EXCEEDED", Assertions.assertThrows(DdlException.class,
                () -> manager.runMembershipMutation(0, 1, () -> changed.set(true))).getDetailMessage());
        Assertions.assertFalse(changed.get());
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, manager.queryStatus());
        Assertions.assertEquals(3, manager.getSnapshot().getBaseMaxFeNodes());
    }

    @Test
    void expiredRenewalCanLowerBothLimitsOnlyAfterMembershipShrinksAndPersistsTheNewBase() throws Exception {
        start();
        String old = certificate(1, 900, 1100);
        run(LicenseManager.Action.IMPORT, old);
        manager.runMembershipMutation(2, 5, () -> host.changeMembers(3, 5));
        String lower = certificateWithLimits(2, 1000, 2000, 2, 3);
        manager.runMembershipMutation(0, 0, () -> host.changeMembers(2, 3));
        assertCapacityImportRejected(lower);
        manager.runMembershipMutation(1, 2, () -> host.changeMembers(3, 5));
        time.advance(100_000);
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, manager.queryStatus());
        assertCapacityImportRejected(lower);
        manager.runMembershipMutation(0, 0, () -> host.changeMembers(2, 5));
        assertCapacityImportRejected(lower);
        manager.runMembershipMutation(0, 0, () -> host.changeMembers(2, 3));
        Assertions.assertEquals("APPLIED", run(LicenseManager.Action.IMPORT, lower)
                .getBody().get("submission_status"));
        Assertions.assertTrue(manager.queryStatus().permitsNewQuery());
        Assertions.assertEquals(2, manager.getSnapshot().getBaseMaxFeNodes());
        Assertions.assertEquals(3, manager.getSnapshot().getBaseMaxBeNodes());
        assertAdditionalNodesRejected(manager);
        long version = manager.getAppliedVersion();
        run(LicenseManager.Action.IMPORT, old);
        Assertions.assertEquals(version, manager.getAppliedVersion());
        Assertions.assertEquals(3, manager.getSnapshot().getBaseMaxBeNodes());

        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(image(manager)));
            restored.onReplayComplete();
            restored.onMasterStart(false);
            awaitMaintenance();
            Assertions.assertTrue(restored.queryStatus().permitsNewQuery());
            Assertions.assertEquals(2, restored.getSnapshot().getBaseMaxFeNodes());
            Assertions.assertEquals(3, restored.getSnapshot().getBaseMaxBeNodes());
            assertAdditionalNodesRejected(restored);
        }
    }

    @Test
    void smallerPendingCapsAddsBeforeAndAfterRestartUntilLowerBaseCommitIsApplied() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 1100));
        manager.runMembershipMutation(1, 3, () -> host.changeMembers(2, 3));
        time.advance(100_000);
        run(LicenseManager.Action.IMPORT, certificateWithLimits(2, 1200, 2000, 2, 3));
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, manager.queryStatus());
        Assertions.assertEquals(5, manager.getSnapshot().getBaseMaxBeNodes());
        assertAdditionalNodesRejected(manager);
        byte[] pendingImage = image(manager);
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(pendingImage));
            restored.onReplayComplete();
            restored.onMasterStart(false);
            awaitMaintenance();
            Assertions.assertEquals(5, restored.getSnapshot().getBaseMaxBeNodes());
            assertAdditionalNodesRejected(restored);
        }
        time.advance(100_000);
        Assertions.assertTrue(manager.queryStatus().permitsNewQuery());
        assertAdditionalNodesRejected(manager);
        host.throwAfterWrite = true;
        manager.maintenance();
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.queryStatus());
        host.throwAfterWrite = false;
        LicensePersistRecord base = host.records.get(host.records.size() - 1);
        Assertions.assertEquals(LicensePersistRecord.BASE, base.getOperation());
        manager.replay(base);
        manager.replay(base);
        Assertions.assertEquals(2, manager.getSnapshot().getBaseMaxFeNodes());
        Assertions.assertEquals(3, manager.getSnapshot().getBaseMaxBeNodes());
        Assertions.assertNull(run(LicenseManager.Action.STATUS, null).getBody().get("pending"));
        assertAdditionalNodesRejected(manager);
    }

    @Test
    void memberGrowthBeforeLowerRenewalCommitRejectsTheStaleDecision() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 1100));
        manager.runMembershipMutation(1, 2, () -> host.changeMembers(2, 2));
        time.advance(100_000);
        String lower = certificateWithLimits(2, 1100, 2000, 2, 3);
        host.frontendVersion++;
        host.probeEntered = new CountDownLatch(1);
        host.probeRelease = new CountDownLatch(1);
        ExecutorService client = Executors.newSingleThreadExecutor();
        try {
            Future<Integer> imported = client.submit(() -> importStatus(lower, "lower-membership-race"));
            Assertions.assertTrue(host.probeEntered.await(5, TimeUnit.SECONDS));
            manager.runMembershipMutation(0, 2, () -> host.changeMembers(2, 4));
            host.probeRelease.countDown();
            Assertions.assertEquals(409, imported.get(5, TimeUnit.SECONDS));
            Assertions.assertEquals(5, manager.getSnapshot().getBaseMaxBeNodes());
            Assertions.assertEquals(1L, run(LicenseManager.Action.STATUS, null).getBody().get("highest_sequence"));
            assertCapacityImportRejected(lower);
        } finally {
            host.probeRelease.countDown();
            client.shutdownNow();
        }
    }

    private void assertCapacityImportRejected(String certificate) throws Exception {
        byte[] before = image(manager);
        int records = host.records.size();
        for (LicenseManager.Action action : new LicenseManager.Action[] {
                LicenseManager.Action.VALIDATE, LicenseManager.Action.IMPORT}) {
            LicenseManagementException failure = Assertions.assertThrows(LicenseManagementException.class,
                    () -> run(action, certificate));
            Assertions.assertEquals("LICENSE_NODE_LIMIT_TOO_SMALL", failure.getReason());
            Assertions.assertEquals(400, failure.getHttpStatus());
            Assertions.assertEquals(6201, failure.getSqlErrorCode());
            Assertions.assertEquals("45000", failure.getSqlState());
            Assertions.assertEquals("NOT_SUBMITTED", failure.getBody().get("submission_status"));
            Assertions.assertEquals(false, failure.getBody().get("retryable"));
            Assertions.assertArrayEquals(before, image(manager));
            Assertions.assertEquals(records, host.records.size());
        }
    }

    private static void assertAdditionalNodesRejected(LicenseManager target) {
        AtomicBoolean changed = new AtomicBoolean();
        Assertions.assertEquals("LICENSE_FE_LIMIT_EXCEEDED", Assertions.assertThrows(DdlException.class,
                () -> target.runMembershipMutation(1, 0, () -> changed.set(true))).getDetailMessage());
        Assertions.assertEquals("LICENSE_BE_LIMIT_EXCEEDED", Assertions.assertThrows(DdlException.class,
                () -> target.runMembershipMutation(0, 1, () -> changed.set(true))).getDetailMessage());
        Assertions.assertFalse(changed.get());
    }

    @Test
    void batchAdmissionRejectsBeforeAnyMemberSideEffectAndConcurrentAddsShareOneSlot() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        host.changeMembers(2, 4);
        AtomicInteger mutations = new AtomicInteger();
        Assertions.assertThrows(DdlException.class,
                () -> manager.runMembershipMutation(0, 2, mutations::incrementAndGet));
        Assertions.assertEquals(0, mutations.get());
        ExecutorService clients = Executors.newFixedThreadPool(2);
        CountDownLatch go = new CountDownLatch(1);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 2; i++) {
                results.add(clients.submit(() -> {
                    go.await();
                    try {
                        manager.runMembershipMutation(0, 1, () -> {
                            host.changeMembers(host.feNodes, host.beNodes + 1);
                            mutations.incrementAndGet();
                        });
                        return true;
                    } catch (DdlException e) {
                        Assertions.assertEquals("LICENSE_BE_LIMIT_EXCEEDED", e.getDetailMessage());
                        return false;
                    }
                }));
            }
            go.countDown();
            int successes = 0;
            for (Future<Boolean> result : results) {
                successes += result.get(5, TimeUnit.SECONDS) ? 1 : 0;
            }
            Assertions.assertEquals(1, successes);
            Assertions.assertEquals(1, mutations.get());
            Assertions.assertEquals(5, manager.getSnapshot().getRegisteredBe());
        } finally {
            go.countDown();
            clients.shutdownNow();
        }
    }

    @Test
    void failedMemberJournalKeepsActualRegisteredUsageAndFailedDropReleasesNothing() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        host.changeMembers(1, 3);
        Assertions.assertThrows(IllegalStateException.class,
                () -> manager.runMembershipMutation(0, 2, () -> {
                    host.changeMembers(1, 4);
                    throw new IllegalStateException("Existing journal failed after registering the first member");
                }));
        Assertions.assertEquals(4, manager.getSnapshot().getRegisteredBe());
        manager.runMembershipMutation(0, 1, () -> host.changeMembers(1, 5));
        Assertions.assertThrows(IllegalStateException.class,
                () -> manager.runMembershipMutation(0, 0, () -> {
                    throw new IllegalStateException("Drop not acknowledged; do not remove the member");
                }));
        Assertions.assertEquals(5, manager.getSnapshot().getRegisteredBe());
        Assertions.assertThrows(DdlException.class, () -> manager.runMembershipMutation(0, 1, () -> {
            throw new AssertionError("Admission must reject before running the callback");
        }));
        manager.runMembershipMutation(0, 0, () -> host.changeMembers(1, 4));
        Assertions.assertEquals(4, manager.getSnapshot().getRegisteredBe());
        manager.runMembershipMutation(0, 1, () -> host.changeMembers(1, 5));
        Assertions.assertEquals(5, manager.getSnapshot().getRegisteredBe());
    }

    @Test
    void futurePendingCapacityCannotAdmitMembersUntilBaseRecordIsApplied() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 1200));
        String deployment = run(LicenseManager.Action.DEPLOYMENT, null).getBody().get("deployment_id").toString();
        ObjectNode future = claims(deployment, 2, 1300, 2000);
        ((ObjectNode) future.get("limits")).put("max_fe_nodes", 6).put("max_be_nodes", 9);
        run(LicenseManager.Action.IMPORT, sign(future, "issuer", "massdb-license+jws", issuer));
        host.changeMembers(3, 5);
        time.advance(301_000);
        Assertions.assertEquals(LicenseQueryStatus.EXPIRING, manager.queryStatus());
        Assertions.assertThrows(DdlException.class, () -> manager.runMembershipMutation(1, 1, () -> {
            throw new AssertionError("A pending query entitlement cannot grant uncommitted capacity");
        }));
        host.throwAfterWrite = true;
        manager.maintenance();
        Assertions.assertThrows(DdlException.class, () -> manager.runMembershipMutation(1, 1, () -> {
            throw new AssertionError("An uncertain capacity commit cannot admit a member");
        }));
        host.throwAfterWrite = false;
        LicensePersistRecord base = host.records.get(host.records.size() - 1);
        Assertions.assertEquals(LicensePersistRecord.BASE, base.getOperation());
        manager.replay(base);
        manager.replay(base);
        manager.runMembershipMutation(3, 4, () -> host.changeMembers(6, 9));
        Assertions.assertEquals(6, manager.getSnapshot().getRegisteredFe());
        Assertions.assertEquals(9, manager.getSnapshot().getRegisteredBe());
    }

    @Test
    void acceptedMemberChangeInvalidatesAnImportPreparedBeforeItsCommit() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        String renewal = certificate(2, 900, 2500);
        host.frontendVersion++;
        host.probeEntered = new CountDownLatch(1);
        host.probeRelease = new CountDownLatch(1);
        ExecutorService client = Executors.newSingleThreadExecutor();
        try {
            Future<Integer> imported = client.submit(() -> importStatus(renewal, "membership-race"));
            Assertions.assertTrue(host.probeEntered.await(5, TimeUnit.SECONDS));
            manager.runMembershipMutation(0, 1, () -> host.changeMembers(1, 1));
            host.probeRelease.countDown();
            Assertions.assertEquals(409, imported.get(5, TimeUnit.SECONDS));
            Assertions.assertEquals(1L, run(LicenseManager.Action.STATUS, null).getBody().get("highest_sequence"));
            Assertions.assertEquals(1, manager.getSnapshot().getRegisteredBe());
        } finally {
            host.probeRelease.countDown();
            client.shutdownNow();
        }
    }

    @Test
    void identityIsCommittedOnlyByCompatibleMasterAndSurvivesRecovery() throws Exception {
        Assertions.assertThrows(LicenseManagementException.class,
                () -> manager.execute(LicenseManager.Action.DEPLOYMENT, null, "admin", true));
        Assertions.assertEquals(0, host.records.size());
        host.compatible = false;
        manager.onMasterStart(true);
        awaitMaintenance();
        Assertions.assertEquals(0, manager.getAppliedVersion());
        host.compatible = true;
        manager.maintenance();
        Map<String, Object> deployment = run(LicenseManager.Action.DEPLOYMENT, null).getBody();
        Assertions.assertEquals(5, deployment.size());
        Assertions.assertEquals(1, host.records.size());
        Assertions.assertTrue(host.records.get(0).isBootstrap());
        byte[] image = image(manager);
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(image));
            restored.onReplayComplete();
            restored.onMasterStart(false);
            Assertions.assertEquals(deployment, restored.execute(LicenseManager.Action.DEPLOYMENT,
                    null, "other", true).getBody());
        }
    }

    @Test
    void validateAndRejectedInputsNeverChangeCommittedFacts() throws Exception {
        start();
        String valid = certificate(1, 900, 2000);
        long version = manager.getAppliedVersion();
        Assertions.assertEquals("NOT_SUBMITTED", run(LicenseManager.Action.VALIDATE, valid)
                .getBody().get("submission_status"));
        Assertions.assertEquals(version, manager.getAppliedVersion());
        Assertions.assertFalse(manager.isActivated());
        run(LicenseManager.Action.IMPORT, valid);
        byte[] accepted = image(manager);
        LicenseManagementException bad = Assertions.assertThrows(LicenseManagementException.class,
                () -> run(LicenseManager.Action.IMPORT, valid + "x"));
        Assertions.assertEquals(400, bad.getHttpStatus());
        Assertions.assertFalse(bad.toString().contains(valid));
        Assertions.assertArrayEquals(accepted, image(manager));
        LicenseManagementException oversized = Assertions.assertThrows(LicenseManagementException.class,
                () -> run(LicenseManager.Action.IMPORT, new String(new char[65537])));
        Assertions.assertEquals("LICENSE_INPUT_TOO_LARGE", oversized.getReason());
        Assertions.assertArrayEquals(accepted, image(manager));
    }

    @Test
    void duplicateImportReturnsOriginalVersionEvenWhenCompatibilityProbeFails() throws Exception {
        start();
        String first = certificate(1, 900, 2000);
        Map<String, Object> original = run(LicenseManager.Action.IMPORT, first).getBody();
        String second = certificate(2, 900, 3000);
        run(LicenseManager.Action.IMPORT, second);
        long version = manager.getAppliedVersion();
        host.compatible = false;
        Map<String, Object> duplicate = run(LicenseManager.Action.IMPORT, first).getBody();
        Assertions.assertEquals(original.get("committed_version"), duplicate.get("committed_version"));
        Assertions.assertEquals(version, manager.getAppliedVersion());
        Assertions.assertEquals(2L, run(LicenseManager.Action.STATUS, null).getBody().get("highest_sequence"));
        // A temporarily offline, already verified FE does not prevent a normal renewal.
        run(LicenseManager.Action.IMPORT, certificate(3, 900, 4000));
        Assertions.assertEquals(3L, run(LicenseManager.Action.STATUS, null).getBody().get("highest_sequence"));
        host.frontendVersion = 2;
        Assertions.assertEquals("LICENSE_FE_UPGRADE_REQUIRED", Assertions.assertThrows(
                LicenseManagementException.class, () -> run(LicenseManager.Action.IMPORT,
                        certificate(4, 900, 5000))).getReason());
    }

    @Test
    void adminPolicyAndPublicStatusDoNotExposeCustomerOrRawCertificate() throws Exception {
        start();
        String certificate = certificate(1, 900, 2000);
        LicenseManagementException denied = Assertions.assertThrows(LicenseManagementException.class,
                () -> manager.execute(LicenseManager.Action.IMPORT, certificate, "reader", false));
        Assertions.assertEquals(403, denied.getHttpStatus());
        Assertions.assertEquals(1, manager.getAppliedVersion());
        run(LicenseManager.Action.IMPORT, certificate);
        Map<String, Object> publicStatus = manager.execute(LicenseManager.Action.STATUS, null,
                "reader", false).getBody();
        Assertions.assertEquals(3, publicStatus.size());
        Assertions.assertEquals(2000L, publicStatus.get("expires_at"));
        Assertions.assertFalse(JSON.writeValueAsString(run(LicenseManager.Action.STATUS, null).getBody())
                .contains(certificate));
    }

    @Test
    void pendingReadEntitlementAndCommittedBaseRemainSeparate() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 1200));
        run(LicenseManager.Action.IMPORT, certificate(2, 1300, 3000));
        time.advance(301_000);
        Assertions.assertEquals(LicenseQueryStatus.EXPIRING, manager.getSnapshot().queryStatus(1301));
        long before = manager.getAppliedVersion();
        manager.maintenance();
        Assertions.assertTrue(manager.getAppliedVersion() > before);
        Assertions.assertNull(run(LicenseManager.Action.STATUS, null).getBody().get("pending"));
        Assertions.assertEquals(LicensePersistRecord.BASE, host.records.get(3).getOperation());
    }

    @Test
    void uncertainCommitCanBeConfirmedByReplayWithoutApplyingItTwice() throws Exception {
        start();
        String certificate = certificate(1, 900, 2000);
        host.throwAfterWrite = true;
        LicenseManagementException uncertain = Assertions.assertThrows(LicenseManagementException.class,
                () -> run(LicenseManager.Action.IMPORT, certificate));
        Assertions.assertEquals("UNKNOWN", uncertain.getBody().get("submission_status"));
        Assertions.assertEquals(1, manager.getAppliedVersion());
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.getSnapshot().queryStatus(1000));
        LicensePersistRecord actuallyCommitted = host.records.get(host.records.size() - 1);
        host.throwAfterWrite = false;
        manager.replay(actuallyCommitted);
        manager.replay(actuallyCommitted);
        Assertions.assertEquals(2, manager.getAppliedVersion());
        Assertions.assertEquals("APPLIED", run(LicenseManager.Action.IMPORT_RECEIPT,
                LicenseVerifier.fingerprint(certificate)).getBody().get("submission_status"));
        Assertions.assertEquals(LicenseQueryStatus.EXPIRING, manager.getSnapshot().queryStatus(1000));
    }

    @Test
    void conflictingReplayCannotEraseActivationOrAcceptedIdentity() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        manager.replay(LicensePersistRecord.initial(UUID.randomUUID(), true, 1000000));
        Assertions.assertTrue(manager.isActivated());
        Assertions.assertEquals(2, manager.getAppliedVersion());
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.getSnapshot().queryStatus(1000));
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(image(manager)));
            restored.onReplayComplete();
            Assertions.assertTrue(restored.isActivated());
            Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, restored.getSnapshot().queryStatus(1000));
        }
    }

    @Test
    void corruptPendingIsIsolatedAndExpiredActiveRestoresWithoutFailure() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        run(LicenseManager.Action.IMPORT, certificate(2, 1800, 3000));
        byte[] image = image(manager);
        ObjectNode envelope = imageJson(image);
        ((ObjectNode) envelope.get("pending")).put("compact", "bad.slot.signature");
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(rewriteImage(envelope)));
            restored.onReplayComplete();
            Assertions.assertEquals(LicenseQueryStatus.EXPIRING, restored.getSnapshot().queryStatus(1000));
            Assertions.assertEquals(LicenseQueryStatus.EXPIRED, restored.getSnapshot().queryStatus(2100));
        }
        envelope = imageJson(image);
        ((ObjectNode) envelope.get("base")).put("compact", "bad.base.signature");
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(rewriteImage(envelope)));
            restored.onReplayComplete();
            Assertions.assertFalse(restored.getSnapshot().hasTrustedBaseCapacity());
            Assertions.assertEquals(LicenseQueryStatus.EXPIRING, restored.getSnapshot().queryStatus(1000));
        }
    }

    @Test
    void envelopeChecksumAndUnknownVersionFailBeforeBusinessRestore() throws Exception {
        start();
        byte[] corrupt = image(manager);
        corrupt[corrupt.length - 1] ^= 1;
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            Assertions.assertThrows(IOException.class, () -> restored.loadImage(input(corrupt)));
        }
        ObjectNode unknown = imageJson(image(manager));
        unknown.put("format_version", 2);
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            Assertions.assertThrows(IOException.class, () -> restored.loadImage(input(rewriteImage(unknown))));
        }
    }

    @Test
    void unchangedWatermarksReuseVerifiedSlotsWhileColdRecoveryAndOtherFactsRemainChecked() throws Exception {
        start();
        String active = certificate(1, 900, 2000);
        String pending = certificate(2, 1800, 3000);
        run(LicenseManager.Action.IMPORT, active);
        run(LicenseManager.Action.IMPORT, pending);
        byte[] saved = image(manager);
        LicensePersistRecord record = host.records.get(host.records.size() - 1);
        LicenseVerifier counted = Mockito.spy(new LicenseVerifier(
                Collections.singletonMap("issuer", issuer.getPublic())));
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.onReplayComplete();
            installVerifier(restored, counted);
            restored.loadImage(input(saved));
            // Active and base are identical; the first cold recovery verifies each distinct slot once.
            Mockito.verify(counted).verify(active);
            Mockito.verify(counted).verify(pending);
            Mockito.verifyNoMoreInteractions(counted);
            Mockito.clearInvocations(counted);
            for (int i = 0; i < 3; i++) {
                time.advance(60_000);
                record = watermark(record);
                restored.replay(record);
                Assertions.assertEquals(record.getVersion(), restored.getAppliedVersion());
            }
            Assertions.assertTrue(restored.queryStatus().permitsNewQuery());
            host.changeMembers(4, 6);
            time.advance(60_000);
            record = watermark(record);
            restored.replay(record);
            Assertions.assertEquals(4, restored.getSnapshot().getRegisteredFe());
            Assertions.assertEquals(6, restored.getSnapshot().getRegisteredBe());
            Assertions.assertEquals(LicenseQueryStatus.LIMIT_EXCEEDED, restored.queryStatus());
            restored.replay(record.withClockSuspect());
            Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, restored.queryStatus());
            Mockito.verifyNoInteractions(counted);
        }
        try (LicenseManager cold = new LicenseManager(host, false, time)) {
            cold.onReplayComplete();
            installVerifier(cold, counted);
            cold.loadImage(input(saved));
            // A verifier reused by another manager must not imply a shared, process-wide slot cache.
            Mockito.verify(counted).verify(active);
            Mockito.verify(counted).verify(pending);
            Mockito.verifyNoMoreInteractions(counted);
        }
    }

    @Test
    void verifiedSlotReuseRequiresExactBytesAndDoesNotRememberInvalidSlots() throws Exception {
        start();
        String original = certificate(1, 900, 2000);
        run(LicenseManager.Action.IMPORT, original);
        LicensePersistRecord record = host.records.get(host.records.size() - 1);
        LicenseVerifier counted = Mockito.spy(new LicenseVerifier(
                Collections.singletonMap("issuer", issuer.getPublic())));
        LicensePersistRecord.Restored previous = record.restore(counted);
        Mockito.verify(counted).verify(original);
        Mockito.clearInvocations(counted);
        String[] parts = original.split("\\.");
        ObjectNode claims = (ObjectNode) JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
        claims.put("expires_at", 2100);
        String tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(JSON.writeValueAsBytes(claims)) + "." + parts[2];
        ObjectNode envelope = imageJson(image(manager));
        ((ObjectNode) envelope.get("active")).put("compact", tampered);
        ((ObjectNode) envelope.get("base")).put("compact", tampered);
        LicensePersistRecord damaged = recordFromEnvelope(envelope);
        LicensePersistRecord.Restored invalid = damaged.restore(counted, previous);
        Assertions.assertTrue(invalid.invalidSlots);
        Assertions.assertNull(invalid.imports.getActive());
        Assertions.assertNull(invalid.imports.getEffectiveBase());
        Mockito.verify(counted, Mockito.times(2)).verify(tampered);
        Mockito.clearInvocations(counted);
        damaged.restore(counted, invalid);
        Mockito.verify(counted, Mockito.times(2)).verify(tampered);
        Mockito.clearInvocations(counted);
        record.restore(counted, invalid);
        Mockito.verify(counted).verify(original);
        // A different valid signature with the same identity must also be rechecked against receipts.
        String resigned = sign(claims, "issuer", "massdb-license+jws", issuer);
        ((ObjectNode) envelope.get("active")).put("compact", resigned);
        ((ObjectNode) envelope.get("base")).put("compact", resigned);
        Mockito.clearInvocations(counted);
        Assertions.assertThrows(IOException.class, () -> recordFromEnvelope(envelope).restore(counted, previous));
        Mockito.verify(counted).verify(resigned);
        Mockito.verifyNoMoreInteractions(counted);
    }

    @Test
    void verifiedSlotReuseRechecksChangedCommitVersionsAndVerifierTrust() throws Exception {
        start();
        String compact = certificate(1, 900, 2000);
        run(LicenseManager.Action.IMPORT, compact);
        LicensePersistRecord record = host.records.get(host.records.size() - 1);
        LicenseVerifier counted = Mockito.spy(new LicenseVerifier(
                Collections.singletonMap("issuer", issuer.getPublic())));
        LicensePersistRecord.Restored previous = record.restore(counted);
        Mockito.clearInvocations(counted);
        ObjectNode changedVersion = imageJson(image(manager));
        ((ObjectNode) changedVersion.get("active")).put("committed_version", 2);
        ((ObjectNode) changedVersion.get("base")).put("committed_version", 2);
        ((ObjectNode) changedVersion.get("receipts").get(0)).put("committed_version", 2);
        changedVersion.put("license_version", 2);
        LicensePersistRecord.Restored changed = recordFromEnvelope(changedVersion).restore(counted, previous);
        Assertions.assertEquals(2, changed.imports.getActive().getCommittedVersion());
        Assertions.assertEquals(2, changed.imports.getEffectiveBase().getCommittedVersion());
        Mockito.verify(counted).verify(compact);
        Mockito.verifyNoMoreInteractions(counted);
        LicenseVerifier sameKeysNewIdentity = Mockito.spy(new LicenseVerifier(
                Collections.singletonMap("issuer", issuer.getPublic())));
        Assertions.assertFalse(record.restore(sameKeysNewIdentity, previous).invalidSlots);
        Mockito.verify(sameKeysNewIdentity).verify(compact);
        for (LicenseVerifier changedTrust : new LicenseVerifier[] {
                new LicenseVerifier(Collections.emptyMap()),
                new LicenseVerifier(Collections.singletonMap("issuer", repairKey.getPublic()))}) {
            LicenseVerifier spy = Mockito.spy(changedTrust);
            LicensePersistRecord.Restored invalid = record.restore(spy, previous);
            Assertions.assertTrue(invalid.invalidSlots);
            Assertions.assertNull(invalid.imports.getActive());
            Assertions.assertNull(invalid.imports.getEffectiveBase());
            Mockito.verify(spy, Mockito.times(2)).verify(compact);
        }
    }

    @Test
    void verifiedSlotReuseNeverSkipsEnvelopeAndCrossSlotConsistencyChecks() throws Exception {
        start();
        String compact = certificate(1, 900, 2000);
        run(LicenseManager.Action.IMPORT, compact);
        LicensePersistRecord record = host.records.get(host.records.size() - 1);
        LicenseVerifier counted = Mockito.spy(new LicenseVerifier(
                Collections.singletonMap("issuer", issuer.getPublic())));
        LicensePersistRecord.Restored previous = record.restore(counted);
        Mockito.clearInvocations(counted);
        ObjectNode original = imageJson(image(manager));
        ObjectNode wrongReceipt = original.deepCopy();
        ((ObjectNode) wrongReceipt.get("receipts").get(0)).put("license_id", "conflicting-license");
        ObjectNode wrongSequence = original.deepCopy().put("highest_sequence", 0);
        ObjectNode wrongLicenseVersion = original.deepCopy().put("license_version", 0);
        ObjectNode wrongPendingOrder = original.deepCopy();
        wrongPendingOrder.set("pending", original.get("active").deepCopy());
        for (ObjectNode damaged : new ObjectNode[] {
                wrongReceipt, wrongSequence, wrongLicenseVersion, wrongPendingOrder}) {
            Assertions.assertThrows(IOException.class, () -> recordFromEnvelope(damaged).restore(counted, previous));
        }
        Assertions.assertThrows(IOException.class,
                () -> recordFromEnvelope(original.deepCopy().put("format_version", 2)).restore(counted, previous));
        Assertions.assertFalse(watermark(record).restore(counted, previous).invalidSlots);
        Mockito.verifyNoInteractions(counted);
    }

    @Test
    void failedPublicationDoesNotPublishItsNewlyVerifiedSlotsIntoTheReuseState() throws Exception {
        start();
        LicenseVerifier counted = Mockito.spy(new LicenseVerifier(
                Collections.singletonMap("issuer", issuer.getPublic())));
        installVerifier(manager, counted);
        String compact = certificate(1, 900, 2000);
        host.failPublicationAfterCommit = true;
        Assertions.assertEquals(202, run(LicenseManager.Action.IMPORT, compact).getHttpStatus());
        Assertions.assertEquals(1, manager.getAppliedVersion());
        Mockito.clearInvocations(counted);
        manager.maintenance();
        Assertions.assertEquals(2, manager.getAppliedVersion());
        Assertions.assertTrue(manager.queryStatus().permitsNewQuery());
        Mockito.verify(counted).verify(compact);
        Mockito.verifyNoMoreInteractions(counted);
        Mockito.clearInvocations(counted);
        time.advance(60_000);
        manager.maintenance();
        Assertions.assertEquals(3, manager.getAppliedVersion());
        Mockito.verifyNoInteractions(counted);
    }

    @Test
    void verificationQueueIsBoundedAndStatusRemainsAvailable() throws Exception {
        start();
        String candidate = certificate(1, 900, 2000);
        host.probeEntered = new CountDownLatch(2);
        host.probeRelease = new CountDownLatch(1);
        ExecutorService clients = Executors.newFixedThreadPool(35);
        List<Future<Integer>> requests = new ArrayList<>();
        try {
            for (int i = 0; i < 35; i++) {
                String user = "queue-user-" + i;
                requests.add(clients.submit(() -> {
                    try {
                        return manager.execute(LicenseManager.Action.IMPORT, candidate, user, true).getHttpStatus();
                    } catch (LicenseManagementException e) {
                        return e.getHttpStatus();
                    }
                }));
            }
            Assertions.assertTrue(host.probeEntered.await(5, TimeUnit.SECONDS));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            Future<Integer> rejected = null;
            while (rejected == null && System.nanoTime() < deadline) {
                for (Future<Integer> request : requests) {
                    if (request.isDone()) {
                        rejected = request;
                        break;
                    }
                }
                Thread.sleep(2);
            }
            Assertions.assertNotNull(rejected);
            Assertions.assertEquals(429, rejected.get().intValue());
            Assertions.assertEquals(200, manager.execute(LicenseManager.Action.STATUS, null, "reader", false)
                    .getHttpStatus());
            host.probeRelease.countDown();
            int successful = 0;
            for (Future<Integer> request : requests) {
                int status = request.get(5, TimeUnit.SECONDS);
                Assertions.assertTrue(status == 200 || status == 429);
                successful += status == 200 ? 1 : 0;
            }
            Assertions.assertEquals(34, successful);
            Assertions.assertEquals(2, manager.getAppliedVersion());
        } finally {
            host.probeRelease.countDown();
            clients.shutdownNow();
            Assertions.assertTrue(clients.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void rateLimitEnforcesBothBurstAndRollingMinuteWithoutBlockingStatus() throws Exception {
        start();
        String certificate = certificate(1, 900, 2000);
        for (int i = 0; i < 3; i++) {
            manager.execute(LicenseManager.Action.VALIDATE, certificate, "same-user", true);
        }
        Assertions.assertEquals(429, Assertions.assertThrows(LicenseManagementException.class,
                () -> manager.execute(LicenseManager.Action.VALIDATE, certificate, "same-user", true)).getHttpStatus());
        for (int i = 0; i < 7; i++) {
            time.advance(6000);
            manager.execute(LicenseManager.Action.VALIDATE, certificate, "same-user", true);
        }
        time.advance(6000);
        Assertions.assertEquals(429, Assertions.assertThrows(LicenseManagementException.class,
                () -> manager.execute(LicenseManager.Action.VALIDATE, certificate, "same-user", true)).getHttpStatus());
        Assertions.assertEquals(200, manager.execute(LicenseManager.Action.STATUS, null, "same-user", true)
                .getHttpStatus());
    }

    @Test
    void committedClockAnomalySurvivesRestartWithCorrectedWallTime() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        time.wall += 400_000;
        Assertions.assertEquals("CLOCK_SUSPECT", run(LicenseManager.Action.STATUS, null).getBody().get("status"));
        manager.maintenance();
        time.wall -= 400_000;
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(image(manager)));
            restored.onReplayComplete();
            Assertions.assertEquals("CLOCK_SUSPECT", restored.execute(LicenseManager.Action.STATUS,
                    null, "admin", true).getBody().get("status"));
        }
    }

    @Test
    void clockRepairCommitsNewEpochAndDuplicateDoesNotLowerItAgain() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        time.wall += 400_000;
        Assertions.assertEquals("CLOCK_SUSPECT", run(LicenseManager.Action.STATUS, null).getBody().get("status"));
        time.wall -= 400_000;
        ObjectNode challenge = JSON.valueToTree(run(LicenseManager.Action.CLOCK_CHALLENGE, null)
                .getBody().get("challenge"));
        String repairId = UUID.randomUUID().toString();
        ObjectNode claims = JSON.createObjectNode().put("schema_version", 1).put("product", "MassDB SQL")
                .put("deployment_id", challenge.get("deployment_id").textValue()).put("repair_id", repairId)
                .put("nonce", challenge.get("nonce").textValue())
                .put("clock_epoch", challenge.get("clock_epoch").longValue())
                .put("repair_authorization_version", challenge.get("repair_authorization_version").longValue())
                .put("leader_term", challenge.get("leader_term").textValue())
                .put("issued_at", 1000).put("not_before", 900).put("expires_at", 1500);
        String ticket = sign(claims, "repair", LicenseClockRepairVerifier.TYPE, repairKey);
        Map<String, Object> receipt = run(LicenseManager.Action.CLOCK_REPAIR, ticket).getBody();
        long applied = manager.getAppliedVersion();
        Assertions.assertEquals(repairId, receipt.get("repair_id"));
        Assertions.assertEquals(1L, receipt.get("clock_epoch"));
        Assertions.assertEquals("EXPIRING", run(LicenseManager.Action.STATUS, null).getBody().get("status"));
        Assertions.assertEquals(receipt, run(LicenseManager.Action.CLOCK_REPAIR, ticket).getBody());
        Assertions.assertEquals(applied, manager.getAppliedVersion());
    }

    @Test
    void followerResultUsesLocalAppliedVersionAndNeverChangesAnErrorIntoSuccess() {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("submission_status", "APPLIED");
        body.put("committed_version", 5L);
        body.put("reason", "LICENSE_APPLIED");
        body.put("message", "LICENSE_APPLIED");
        LicenseManagementResult result = new LicenseManagementResult(200, body);
        LicenseManagementResult waiting = result.withLocalAppliedVersion(4);
        Assertions.assertEquals(202, waiting.getHttpStatus());
        Assertions.assertEquals("COMMITTED", waiting.getBody().get("submission_status"));
        Assertions.assertEquals("LICENSE_COMMITTED_PENDING_APPLY", waiting.getBody().get("reason"));
        Assertions.assertEquals(waiting.getBody().get("reason"), waiting.getBody().get("message"));
        LicenseManagementResult applied = waiting.withLocalAppliedVersion(5);
        Assertions.assertEquals(200, applied.getHttpStatus());
        Assertions.assertEquals("APPLIED", applied.getBody().get("submission_status"));
        Assertions.assertEquals("LICENSE_APPLIED", applied.getBody().get("reason"));
        Assertions.assertEquals(applied.getBody().get("reason"), applied.getBody().get("message"));
        Assertions.assertEquals("LICENSE_APPLIED", result.getBody().get("message"));
        Assertions.assertEquals(403, new LicenseManagementResult(403, body).withLocalAppliedVersion(7).getHttpStatus());
    }

    @Test
    void moreThan1024RealImportsKeepBoundedReceiptsAndEvictedHistoryStaysUnknownAfterRestart() throws Exception {
        start();
        host.retainLatestOnly = true;
        String oldest = certificate(1, 900, 3000);
        run(LicenseManager.Action.IMPORT, oldest);
        String latest = null;
        for (int sequence = 2; sequence <= LicenseImportState.MAX_RECEIPTS + 2; sequence++) {
            latest = certificate(sequence, 900, 3000);
            Assertions.assertEquals(200, run(LicenseManager.Action.IMPORT, latest).getHttpStatus());
        }
        String discardedFingerprint = LicenseVerifier.fingerprint(oldest);
        String latestFingerprint = LicenseVerifier.fingerprint(latest);
        long applied = manager.getAppliedVersion();
        byte[] bytes = image(manager);
        ObjectNode envelope = imageJson(bytes);
        Assertions.assertEquals(LicenseImportState.MAX_RECEIPTS, envelope.get("receipts").size());
        Assertions.assertEquals(3, envelope.get("receipts").get(0).get("sequence").longValue());
        Assertions.assertTrue(envelope.get("submission_versions").size() <= LicenseImportState.MAX_RECEIPTS + 3);
        Assertions.assertTrue(bytes.length <= LicensePersistRecord.MAX_BYTES);
        LicenseManagementException evicted = Assertions.assertThrows(LicenseManagementException.class,
                () -> run(LicenseManager.Action.IMPORT_RECEIPT, discardedFingerprint));
        Assertions.assertEquals(6204, evicted.getSqlErrorCode());
        Assertions.assertEquals("UNKNOWN", evicted.getBody().get("submission_status"));
        Assertions.assertEquals("LICENSE_IMPORT_HISTORY_UNAVAILABLE", Assertions.assertThrows(
                LicenseManagementException.class, () -> run(LicenseManager.Action.IMPORT, oldest)).getReason());
        Assertions.assertEquals(applied, manager.getAppliedVersion());

        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(bytes));
            restored.onReplayComplete();
            restored.onMasterStart(false);
            Assertions.assertEquals(applied, restored.execute(LicenseManager.Action.IMPORT_RECEIPT,
                    latestFingerprint, "admin", true).getBody().get("committed_version"));
            Assertions.assertEquals("UNKNOWN", Assertions.assertThrows(LicenseManagementException.class,
                    () -> restored.execute(LicenseManager.Action.IMPORT_RECEIPT,
                            discardedFingerprint, "admin", true)).getBody().get("submission_status"));
            Assertions.assertEquals(applied, restored.getAppliedVersion());
        }
    }

    @Test
    void durableCommitFollowedByPublicationFailureReturns202AndReplayCompletesTheSameRecord() throws Exception {
        start();
        String candidate = certificate(1, 900, 2000);
        host.failPublicationAfterCommit = true;
        LicenseManagementResult submitted = run(LicenseManager.Action.IMPORT, candidate);
        Assertions.assertEquals(202, submitted.getHttpStatus());
        Assertions.assertEquals("LICENSE_COMMITTED_PENDING_APPLY", submitted.getBody().get("reason"));
        Assertions.assertEquals(submitted.getBody().get("reason"), submitted.getBody().get("message"));
        Assertions.assertEquals(true, submitted.getBody().get("retryable"));
        Assertions.assertEquals("COMMITTED", submitted.getBody().get("submission_status"));
        Assertions.assertEquals(LicenseVerifier.fingerprint(candidate), submitted.getBody().get("fingerprint"));
        Assertions.assertEquals(2L, submitted.getBody().get("committed_version"));
        Assertions.assertEquals(1L, submitted.getBody().get("applied_version"));
        Assertions.assertEquals(2, host.records.size());
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, manager.getSnapshot().queryStatus(1000));
        LicenseManagementResult waiting = run(LicenseManager.Action.IMPORT_RECEIPT,
                LicenseVerifier.fingerprint(candidate));
        Assertions.assertEquals(202, waiting.getHttpStatus());
        Assertions.assertEquals(true, waiting.getBody().get("retryable"));
        Assertions.assertEquals(submitted.getBody(), waiting.getBody());
        Assertions.assertEquals(202, run(LicenseManager.Action.IMPORT, candidate).getHttpStatus());
        Assertions.assertEquals(2, host.records.size());

        LicensePersistRecord durable = host.records.get(1);
        manager.replay(durable);
        manager.replay(durable);
        Assertions.assertEquals(2, manager.getAppliedVersion());
        Assertions.assertEquals("APPLIED", run(LicenseManager.Action.IMPORT_RECEIPT,
                LicenseVerifier.fingerprint(candidate)).getBody().get("submission_status"));
        Assertions.assertEquals(LicenseQueryStatus.EXPIRING, manager.getSnapshot().queryStatus(1000));
        Assertions.assertEquals(2, host.records.size());
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(image(manager)));
            restored.onReplayComplete();
            Assertions.assertEquals(2, restored.getAppliedVersion());
            Assertions.assertEquals(LicenseQueryStatus.EXPIRING, restored.getSnapshot().queryStatus(1000));
        }
    }

    @Test
    void durableRepairWithPublicationFailureKeepsPendingReceiptAndConflictUntilExactReplay() throws Exception {
        start();
        String certificate = certificate(1, 900, 2000);
        run(LicenseManager.Action.IMPORT, certificate);
        ObjectNode challenge = JSON.valueToTree(run(LicenseManager.Action.CLOCK_CHALLENGE, null)
                .getBody().get("challenge"));
        String ticket = repairTicket(challenge);
        ObjectNode claims = (ObjectNode) JSON.readTree(Base64.getUrlDecoder().decode(ticket.split("\\.")[1]));
        String repairId = claims.get("repair_id").textValue();
        String fingerprint = LicenseVerifier.fingerprint(ticket);
        String conflicting = sign(claims.deepCopy().put("expires_at", 1499),
                "repair", LicenseClockRepairVerifier.TYPE, repairKey);
        long appliedBefore = manager.getAppliedVersion();
        int recordsBefore = host.records.size();
        byte[] before = image(manager);
        host.failPublicationAfterCommit = true;
        for (int attempt = 0; attempt < 2; attempt++) {
            LicenseManagementResult submitted = run(LicenseManager.Action.CLOCK_REPAIR, ticket);
            Assertions.assertEquals(202, submitted.getHttpStatus());
            Assertions.assertEquals("COMMITTED", submitted.getBody().get("submission_status"));
            Assertions.assertEquals(repairId, submitted.getBody().get("repair_id"));
            Assertions.assertEquals(fingerprint, submitted.getBody().get("fingerprint"));
            Assertions.assertEquals(appliedBefore + 1, submitted.getBody().get("committed_version"));
            Assertions.assertEquals(appliedBefore, submitted.getBody().get("applied_version"));
            Assertions.assertEquals(recordsBefore + 1, host.records.size());
            Assertions.assertEquals(0L, run(LicenseManager.Action.STATUS, null).getBody().get("clock_epoch"));
            Assertions.assertArrayEquals(before, image(manager));
        }
        LicenseManagementResult waiting = run(LicenseManager.Action.CLOCK_REPAIR_RECEIPT, repairId);
        Assertions.assertEquals(202, waiting.getHttpStatus());
        Assertions.assertEquals(fingerprint, waiting.getBody().get("fingerprint"));
        LicenseManagementException conflict = Assertions.assertThrows(LicenseManagementException.class,
                () -> run(LicenseManager.Action.CLOCK_REPAIR, conflicting));
        Assertions.assertEquals(409, conflict.getHttpStatus());
        Assertions.assertEquals("LICENSE_REPAIR_CONFLICT", conflict.getReason());
        Assertions.assertArrayEquals(before, image(manager));
        Assertions.assertEquals(recordsBefore + 1, host.records.size());

        LicensePersistRecord durable = host.records.get(recordsBefore);
        manager.replay(durable);
        manager.replay(durable);
        LicenseManagementResult applied = run(LicenseManager.Action.CLOCK_REPAIR_RECEIPT, repairId);
        Assertions.assertEquals(200, applied.getHttpStatus());
        Assertions.assertEquals("APPLIED", applied.getBody().get("submission_status"));
        Assertions.assertEquals(1L, applied.getBody().get("clock_epoch"));
        Assertions.assertEquals(appliedBefore + 1, applied.getBody().get("committed_version"));
        Assertions.assertEquals(applied.getBody(), run(LicenseManager.Action.CLOCK_REPAIR, ticket).getBody());
        Assertions.assertEquals(appliedBefore + 1, manager.getAppliedVersion());
        Assertions.assertEquals(recordsBefore + 1, host.records.size());
        Assertions.assertEquals(3, manager.getSnapshot().getBaseMaxFeNodes());
        Assertions.assertEquals(5, manager.getSnapshot().getBaseMaxBeNodes());
        Assertions.assertEquals(LicenseVerifier.fingerprint(certificate),
                ((Map<?, ?>) run(LicenseManager.Action.STATUS, null).getBody().get("active")).get("fingerprint"));
    }

    @Test
    void absentInvalidAndOversizedTrustAllowDeploymentIdentityButNeverAcceptAnUntrustedCertificate() throws Exception {
        Path missing = directory.resolve("missing-trust.json");
        Path invalid = directory.resolve("invalid-trust.json");
        Path oversized = directory.resolve("oversized-trust.json");
        Files.write(invalid, "{\"schema_version\":1,\"keys\":[]}".getBytes(StandardCharsets.UTF_8));
        Files.write(oversized, new byte[65537]);
        for (Path path : new Path[] {missing, invalid, oversized}) {
            Host untrustedHost = new Host(path.toString());
            try (LicenseManager untrusted = new LicenseManager(untrustedHost, false, time)) {
                untrusted.onReplayComplete();
                untrusted.onMasterStart(true);
                awaitInitialized(untrusted);
                String deployment = untrusted.execute(LicenseManager.Action.DEPLOYMENT, null, "admin", true)
                        .getBody().get("deployment_id").toString();
                String candidate = sign(claims(deployment, 1, 900, 2000),
                        "issuer", "massdb-license+jws", issuer);
                byte[] before = image(untrusted);
                LicenseManagementException rejected = Assertions.assertThrows(LicenseManagementException.class,
                        () -> untrusted.execute(LicenseManager.Action.IMPORT, candidate, "admin", true));
                Assertions.assertEquals("LICENSE_UNTRUSTED_KEY", rejected.getReason());
                Assertions.assertArrayEquals(before, image(untrusted));
                Assertions.assertEquals(1, untrustedHost.records.size());
                Assertions.assertFalse(untrusted.isActivated());
                Assertions.assertNull(untrusted.capability().get("trust_sha256"));
                Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY,
                        untrusted.getSnapshot().queryStatus(1000));
            }
        }
    }

    @Test
    void differentConcurrentCandidatesRecheckTheCommittedVersionAndOnlyOneGetsAReceipt() throws Exception {
        start();
        String first = certificate(1, 900, 2000);
        String second = certificate(1, 900, 3000);
        host.probeEntered = new CountDownLatch(2);
        host.probeRelease = new CountDownLatch(1);
        ExecutorService clients = Executors.newFixedThreadPool(2);
        try {
            Future<Integer> firstResult = clients.submit(() -> importStatus(first, "concurrent-first"));
            Future<Integer> secondResult = clients.submit(() -> importStatus(second, "concurrent-second"));
            Assertions.assertTrue(host.probeEntered.await(5, TimeUnit.SECONDS));
            Assertions.assertEquals(1, manager.getAppliedVersion());
            host.probeRelease.countDown();
            int a = firstResult.get(5, TimeUnit.SECONDS);
            int b = secondResult.get(5, TimeUnit.SECONDS);
            Assertions.assertTrue(a == 200 && b == 409 || a == 409 && b == 200);
            String accepted = a == 200 ? first : second;
            String rejected = a == 409 ? first : second;
            Assertions.assertEquals("APPLIED", run(LicenseManager.Action.IMPORT_RECEIPT,
                    LicenseVerifier.fingerprint(accepted)).getBody().get("submission_status"));
            Assertions.assertEquals("UNKNOWN", Assertions.assertThrows(LicenseManagementException.class,
                    () -> run(LicenseManager.Action.IMPORT_RECEIPT,
                            LicenseVerifier.fingerprint(rejected))).getBody().get("submission_status"));
            Assertions.assertEquals(2, manager.getAppliedVersion());
            Assertions.assertEquals(2, host.records.size());
        } finally {
            host.probeRelease.countDown();
            clients.shutdownNow();
            Assertions.assertTrue(clients.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void concurrentIdenticalImportsConfirmOneDurableReceiptWhenPublicationFails() throws Exception {
        start();
        String candidate = certificate(1, 900, 2000);
        host.probeEntered = new CountDownLatch(2);
        host.probeRelease = new CountDownLatch(1);
        host.failPublicationAfterCommit = true;
        ExecutorService clients = Executors.newFixedThreadPool(2);
        try {
            Future<Integer> first = clients.submit(() -> importStatus(candidate, "concurrent-pending-first"));
            Future<Integer> second = clients.submit(() -> importStatus(candidate, "concurrent-pending-second"));
            Assertions.assertTrue(host.probeEntered.await(5, TimeUnit.SECONDS));
            Assertions.assertEquals(1, host.records.size());
            host.probeRelease.countDown();
            Assertions.assertEquals(202, first.get(5, TimeUnit.SECONDS).intValue());
            Assertions.assertEquals(202, second.get(5, TimeUnit.SECONDS).intValue());
            Assertions.assertEquals(2, host.records.size());
            Assertions.assertEquals(1, manager.getAppliedVersion());
            Assertions.assertEquals(202, run(LicenseManager.Action.IMPORT_RECEIPT,
                    LicenseVerifier.fingerprint(candidate)).getHttpStatus());
            manager.replay(host.records.get(1));
            Assertions.assertEquals(200, run(LicenseManager.Action.IMPORT, candidate).getHttpStatus());
            Assertions.assertEquals(2, manager.getAppliedVersion());
            Assertions.assertEquals(2, host.records.size());
        } finally {
            host.probeRelease.countDown();
            clients.shutdownNow();
            Assertions.assertTrue(clients.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void cancellingQueuedRequestReleasesItsSlotBeforeBusyWorkersAreUnblocked() throws Exception {
        start();
        String candidate = certificate(1, 900, 2000);
        host.probeEntered = new CountDownLatch(2);
        host.probeRelease = new CountDownLatch(1);
        List<AsyncImport> calls = new ArrayList<>();
        try {
            for (int i = 0; i < 2; i++) {
                calls.add(new AsyncImport(manager, candidate, "busy-" + i));
            }
            Assertions.assertTrue(host.probeEntered.await(5, TimeUnit.SECONDS));
            for (int i = 0; i < 32; i++) {
                calls.add(new AsyncImport(manager, candidate, "queued-" + i));
            }
            awaitWaiting(calls);
            Assertions.assertEquals(429, importStatus(candidate, "full-before-cancel"));
            AsyncImport cancelled = calls.get(2);
            cancelled.thread.interrupt();
            cancelled.thread.join(5000);
            Assertions.assertFalse(cancelled.thread.isAlive());
            Assertions.assertTrue(cancelled.result instanceof LicenseManagementException);
            Map<String, Object> cancellation = ((LicenseManagementException) cancelled.result).getBody();
            Assertions.assertEquals("UNKNOWN", cancellation.get("submission_status"));
            Assertions.assertEquals(LicenseVerifier.fingerprint(candidate), cancellation.get("fingerprint"));

            AsyncImport replacement = new AsyncImport(manager, candidate, "replacement");
            calls.add(replacement);
            awaitWaiting(Collections.singletonList(replacement));
            Assertions.assertEquals(429, importStatus(candidate, "full-after-replacement"));
            Assertions.assertEquals(1, host.records.size());
            host.probeRelease.countDown();
            for (AsyncImport call : calls) {
                call.thread.join(5000);
                Assertions.assertFalse(call.thread.isAlive());
                if (call != cancelled) {
                    Assertions.assertTrue(call.result instanceof LicenseManagementResult);
                    Assertions.assertEquals(200, ((LicenseManagementResult) call.result).getHttpStatus());
                }
            }
            Assertions.assertEquals(2, manager.getAppliedVersion());
            Assertions.assertEquals(2, host.records.size());
        } finally {
            host.probeRelease.countDown();
            for (AsyncImport call : calls) {
                call.thread.interrupt();
            }
            for (AsyncImport call : calls) {
                call.thread.join(5000);
                Assertions.assertFalse(call.thread.isAlive());
            }
        }
    }

    @Test
    void invalidCandidateMatrixUsesTheSamePolicyForValidateAndImportAndKeepsAllFacts() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(5, 900, 1700));
        run(LicenseManager.Action.IMPORT, certificate(6, 1800, 3000));
        String deployment = run(LicenseManager.Action.DEPLOYMENT, null).getBody().get("deployment_id").toString();
        ObjectNode valid = claims(deployment, 7, 900, 4000);
        Map<String, String> candidates = new LinkedHashMap<>();
        candidates.put(sign(valid, "unknown", "massdb-license+jws", issuer), "LICENSE_UNTRUSTED_KEY");
        candidates.put(sign(valid, "repair", "massdb-license+jws", repairKey), "LICENSE_UNTRUSTED_KEY");
        candidates.put(sign(valid, "issuer", LicenseClockRepairVerifier.TYPE, issuer), "LICENSE_INVALID_HEADER");
        candidates.put(sign(valid.deepCopy().put("deployment_id", UUID.randomUUID().toString()),
                "issuer", "massdb-license+jws", issuer), "LICENSE_DEPLOYMENT_MISMATCH");
        candidates.put(sign(claims(deployment, 4, 900, 4000), "issuer", "massdb-license+jws", issuer),
                "LICENSE_IMPORT_HISTORY_UNAVAILABLE");
        candidates.put(sign(claims(deployment, 5, 900, 4000), "issuer", "massdb-license+jws", issuer),
                "LICENSE_IMPORT_CONFLICT");
        candidates.put(sign(valid.deepCopy().put("expires_at", 1600), "issuer", "massdb-license+jws", issuer),
                "LICENSE_RENEWAL_REDUCTION");
        candidates.put(sign(valid.deepCopy().put("not_before", 1900), "issuer", "massdb-license+jws", issuer),
                "LICENSE_RENEWAL_REDUCTION");
        ObjectNode reduced = valid.deepCopy();
        ((ObjectNode) reduced.get("limits")).put("max_fe_nodes", 2);
        candidates.put(sign(reduced, "issuer", "massdb-license+jws", issuer), "LICENSE_NODE_LIMIT_TOO_SMALL");
        String[] tampered = sign(valid, "issuer", "massdb-license+jws", issuer).split("\\.");
        byte[] signature = Base64.getUrlDecoder().decode(tampered[2]);
        signature[0] ^= 1;
        candidates.put(tampered[0] + "." + tampered[1] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(signature), "LICENSE_INVALID_SIGNATURE");
        byte[] before = image(manager);
        for (Map.Entry<String, String> candidate : candidates.entrySet()) {
            for (LicenseManager.Action action : new LicenseManager.Action[] {
                    LicenseManager.Action.VALIDATE, LicenseManager.Action.IMPORT}) {
                LicenseManagementException failure = Assertions.assertThrows(LicenseManagementException.class,
                        () -> run(action, candidate.getKey()));
                Assertions.assertEquals(candidate.getValue(), failure.getReason());
                int expected = candidate.getValue().endsWith("HISTORY_UNAVAILABLE") ? 503
                        : candidate.getValue().endsWith("IMPORT_CONFLICT") ? 409 : 400;
                Assertions.assertEquals(expected, failure.getHttpStatus());
                Assertions.assertFalse(failure.toString().contains(candidate.getKey()));
                Assertions.assertArrayEquals(before, image(manager));
                Assertions.assertEquals(3, host.records.size());
            }
        }
    }

    @Test
    void pendingCapacityIsNotCommittedByTimeAndUncertainBaseActivationRecoversExactlyOnce() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 1200));
        String deployment = run(LicenseManager.Action.DEPLOYMENT, null).getBody().get("deployment_id").toString();
        ObjectNode future = claims(deployment, 2, 1300, 1500);
        ((ObjectNode) future.get("limits")).put("max_fe_nodes", 6).put("max_be_nodes", 9);
        run(LicenseManager.Action.IMPORT, sign(future, "issuer", "massdb-license+jws", issuer));
        time.advance(250_000);
        Assertions.assertEquals("EXPIRED", run(LicenseManager.Action.STATUS, null).getBody().get("status"));
        time.advance(51_000);
        Assertions.assertEquals("EXPIRING", run(LicenseManager.Action.STATUS, null).getBody().get("status"));
        Assertions.assertEquals(3, manager.getSnapshot().getBaseMaxFeNodes());
        Assertions.assertEquals(5, manager.getSnapshot().getBaseMaxBeNodes());
        Assertions.assertEquals(3, manager.getAppliedVersion());

        host.throwAfterWrite = true;
        manager.maintenance();
        Assertions.assertEquals(3, manager.getAppliedVersion());
        Assertions.assertEquals(3, manager.getSnapshot().getBaseMaxFeNodes());
        LicensePersistRecord durable = host.records.get(host.records.size() - 1);
        Assertions.assertEquals(LicensePersistRecord.BASE, durable.getOperation());
        host.throwAfterWrite = false;
        manager.replay(durable);
        manager.replay(durable);
        Assertions.assertEquals(4, manager.getAppliedVersion());
        Assertions.assertEquals(6, manager.getSnapshot().getBaseMaxFeNodes());
        Assertions.assertEquals(9, manager.getSnapshot().getBaseMaxBeNodes());
        Assertions.assertEquals("EXPIRING", run(LicenseManager.Action.STATUS, null).getBody().get("status"));
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(image(manager)));
            restored.onReplayComplete();
            time.advance(300_000);
            Assertions.assertEquals("EXPIRED", restored.execute(LicenseManager.Action.STATUS,
                    null, "admin", true).getBody().get("status"));
            Assertions.assertEquals(6, restored.getSnapshot().getBaseMaxFeNodes());
            Assertions.assertEquals(4, restored.getAppliedVersion());
        }
    }

    @Test
    void issuedClockChallengeCannotSurviveLeadershipChangeRestartOrIts24HourDeadline() throws Exception {
        start();
        run(LicenseManager.Action.IMPORT, certificate(1, 900, 2000));
        ObjectNode challenge = JSON.valueToTree(run(LicenseManager.Action.CLOCK_CHALLENGE, null)
                .getBody().get("challenge"));
        String beforeElection = repairTicket(challenge);
        manager.onNonMaster();
        manager.onMasterStart(false);
        byte[] afterElection = image(manager);
        Assertions.assertEquals("LICENSE_CHALLENGE_REQUIRED", Assertions.assertThrows(
                LicenseManagementException.class, () -> run(LicenseManager.Action.CLOCK_REPAIR,
                        beforeElection)).getReason());
        Assertions.assertArrayEquals(afterElection, image(manager));

        ObjectNode beforeRestart = JSON.valueToTree(run(LicenseManager.Action.CLOCK_CHALLENGE, null)
                .getBody().get("challenge"));
        String oldTicket = repairTicket(beforeRestart);
        byte[] image = image(manager);
        manager.onNonMaster();
        try (LicenseManager restored = new LicenseManager(host, false, time)) {
            restored.loadImage(input(image));
            restored.onReplayComplete();
            restored.onMasterStart(false);
            Assertions.assertEquals("LICENSE_CHALLENGE_REQUIRED", Assertions.assertThrows(
                    LicenseManagementException.class, () -> restored.execute(LicenseManager.Action.CLOCK_REPAIR,
                            oldTicket, "admin", true)).getReason());
            Assertions.assertArrayEquals(image, image(restored));
            ObjectNode fresh = JSON.valueToTree(restored.execute(LicenseManager.Action.CLOCK_CHALLENGE,
                    null, "admin-fresh", true).getBody().get("challenge"));
            String expires = repairTicket(fresh);
            time.advance(TimeUnit.HOURS.toMillis(24));
            byte[] beforeExpiredRequest = image(restored);
            Assertions.assertEquals("LICENSE_CHALLENGE_EXPIRED", Assertions.assertThrows(
                    LicenseManagementException.class, () -> restored.execute(LicenseManager.Action.CLOCK_REPAIR,
                            expires, "admin-expired", true)).getReason());
            Assertions.assertArrayEquals(beforeExpiredRequest, image(restored));
        }
    }

    private String repairTicket(ObjectNode challenge) throws Exception {
        ObjectNode claims = JSON.createObjectNode().put("schema_version", 1).put("product", "MassDB SQL")
                .put("deployment_id", challenge.get("deployment_id").textValue())
                .put("repair_id", UUID.randomUUID().toString()).put("nonce", challenge.get("nonce").textValue())
                .put("clock_epoch", challenge.get("clock_epoch").longValue())
                .put("repair_authorization_version", challenge.get("repair_authorization_version").longValue())
                .put("leader_term", challenge.get("leader_term").textValue())
                .put("issued_at", 1000).put("not_before", 900).put("expires_at", 1500);
        return sign(claims, "repair", LicenseClockRepairVerifier.TYPE, repairKey);
    }

    private int importStatus(String candidate, String user) {
        try {
            return manager.execute(LicenseManager.Action.IMPORT, candidate, user, true).getHttpStatus();
        } catch (LicenseManagementException failure) {
            return failure.getHttpStatus();
        }
    }

    private static final class AsyncImport {
        private final Thread thread;
        private volatile Object result;

        AsyncImport(LicenseManager target, String candidate, String principal) {
            thread = new Thread(() -> {
                try {
                    result = target.execute(LicenseManager.Action.IMPORT, candidate, principal, true);
                } catch (Exception failure) {
                    result = failure;
                }
            }, "license-manager-test-" + principal);
            thread.start();
        }
    }

    private static void awaitWaiting(List<AsyncImport> calls) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        for (AsyncImport call : calls) {
            while (call.thread.getState() != Thread.State.WAITING && call.result == null
                    && System.nanoTime() < deadline) {
                Thread.sleep(2);
            }
            Assertions.assertEquals(Thread.State.WAITING, call.thread.getState(),
                    "An accepted request must be waiting for a worker, not rejected or completed");
        }
    }

    private static void awaitInitialized(LicenseManager target) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (target.getAppliedVersion() == 0 && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        Assertions.assertEquals(1, target.getAppliedVersion());
    }

    private void start() throws Exception {
        manager.onMasterStart(true);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (manager.getAppliedVersion() == 0 && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        Assertions.assertEquals(1, manager.getAppliedVersion());
        awaitMaintenance();
    }

    private void awaitMaintenance() throws Exception {
        // Serialize behind startup initialization via a real management call once available.
        Thread.sleep(30);
    }

    private void awaitBackgroundMaintenance() throws Exception {
        java.lang.reflect.Field field = LicenseManager.class.getDeclaredField("maintenancePending");
        field.setAccessible(true);
        AtomicBoolean pending = (AtomicBoolean) field.get(manager);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (pending.get() && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        Assertions.assertFalse(pending.get(), "Background initialization did not finish");
    }

    private LicenseManagementResult run(LicenseManager.Action action, String payload) throws Exception {
        return manager.execute(action, payload, "admin-" + principal++, true);
    }

    private String certificate(long sequence, long notBefore, long expiresAt) throws Exception {
        String deployment = run(LicenseManager.Action.DEPLOYMENT, null).getBody().get("deployment_id").toString();
        return sign(claims(deployment, sequence, notBefore, expiresAt), "issuer", "massdb-license+jws", issuer);
    }

    private String certificateWithLimits(long sequence, long notBefore, long expiresAt, int maxFe, int maxBe)
            throws Exception {
        String deployment = run(LicenseManager.Action.DEPLOYMENT, null).getBody().get("deployment_id").toString();
        ObjectNode value = claims(deployment, sequence, notBefore, expiresAt);
        ((ObjectNode) value.get("limits")).put("max_fe_nodes", maxFe).put("max_be_nodes", maxBe);
        return sign(value, "issuer", "massdb-license+jws", issuer);
    }

    private static ObjectNode claims(String deployment, long sequence, long notBefore, long expiresAt) {
        ObjectNode claims = JSON.createObjectNode().put("schema_version", 1).put("policy_version", 1)
                .put("product", "MassDB SQL").put("deployment_id", deployment)
                .put("license_id", "license-" + sequence).put("issuer", "test issuer")
                .put("customer_id", "customer").put("edition", "enterprise").put("issued_at", 900)
                .put("not_before", notBefore).put("expires_at", expiresAt).put("sequence", sequence);
        claims.putArray("features").add("DATA_QUERY");
        claims.putObject("limits").put("max_fe_nodes", 3).put("max_be_nodes", 5);
        return claims;
    }

    private static String sign(ObjectNode claims, String kid, String type, KeyPair key) throws Exception {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        ObjectNode header = JSON.createObjectNode().put("alg", "Ed25519").put("typ", type).put("kid", kid);
        String input = encoder.encodeToString(JSON.writeValueAsBytes(header)) + "."
                + encoder.encodeToString(JSON.writeValueAsBytes(claims));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key.getPrivate());
        signer.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + encoder.encodeToString(signer.sign());
    }

    private static ObjectNode key(String kid, String purpose, KeyPair key) {
        return JSON.createObjectNode().put("kid", kid).put("purpose", purpose).put("public_key_spki",
                Base64.getUrlEncoder().withoutPadding().encodeToString(key.getPublic().getEncoded()));
    }

    private static byte[] image(LicenseManager manager) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        manager.saveImage(new DataOutputStream(bytes));
        return bytes.toByteArray();
    }

    private static DataInputStream input(byte[] bytes) {
        return new DataInputStream(new ByteArrayInputStream(bytes));
    }

    private static ObjectNode imageJson(byte[] bytes) throws Exception {
        DataInputStream input = input(bytes);
        input.readBoolean();
        input.readBoolean();
        byte[] json = new byte[input.readInt()];
        input.readFully(json);
        return (ObjectNode) JSON.readTree(json);
    }

    private static LicensePersistRecord recordFromEnvelope(ObjectNode envelope) throws Exception {
        try (DataInputStream bytes = input(rewriteImage(envelope))) {
            bytes.readBoolean();
            bytes.readBoolean();
            return LicensePersistRecord.read(bytes);
        }
    }

    private static LicensePersistRecord watermark(LicensePersistRecord record) throws Exception {
        LicenseClockRepair.State before = record.clockState();
        LicenseClock.Facts old = before.getFacts();
        LicenseClock.Facts next = new LicenseClock.Facts(old.getVersion() + 1, old.getClockEpoch(),
                old.getHighWaterMillis() + 60_000, old.getRepairAuthorizationVersion());
        return record.withClock(LicensePersistRecord.WATERMARK,
                new LicenseClockRepair.State(record.getDeploymentId(), next, before.getReceipts()));
    }

    private static void installVerifier(LicenseManager target, LicenseVerifier verifier) throws Exception {
        java.lang.reflect.Field field = LicenseManager.class.getDeclaredField("verifier");
        field.setAccessible(true);
        field.set(target, verifier);
    }

    private static byte[] rewriteImage(ObjectNode value) throws Exception {
        byte[] json = JSON.writeValueAsBytes(value);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeBoolean(false);
        output.writeBoolean(true);
        output.writeInt(json.length);
        output.write(json);
        output.write(MessageDigest.getInstance("SHA-256").digest(json));
        return bytes.toByteArray();
    }

    private static final class FakeClock implements LicenseClock.TimeSource {
        private long wall = 1_000_000;
        private long nanos;

        @Override
        public long wallTimeMillis() {
            return wall;
        }

        @Override
        public long monotonicNanos() {
            return nanos;
        }

        void advance(long millis) {
            wall += millis;
            nanos += TimeUnit.MILLISECONDS.toNanos(millis);
        }
    }

    private static final class Host implements LicenseManager.Host {
        private final String path;
        private final List<LicensePersistRecord> records = Collections.synchronizedList(new ArrayList<>());
        private volatile boolean compatible = true;
        private boolean throwAfterWrite;
        private boolean retainLatestOnly;
        private boolean failPublicationAfterCommit;
        private final AtomicBoolean publicationFailure = new AtomicBoolean();
        private long frontendVersion = 1;
        private volatile int feNodes = 1;
        private volatile int beNodes;
        private volatile long membershipVersion = 1;
        private volatile CountDownLatch probeEntered;
        private volatile CountDownLatch probeRelease;
        private final AtomicInteger membershipReads = new AtomicInteger();
        private final AtomicInteger activationProbes = new AtomicInteger();

        Host(String path) {
            this.path = path;
        }

        @Override
        public boolean isMaster() {
            return true;
        }

        @Override
        public LicenseManager.Membership membership() {
            membershipReads.incrementAndGet();
            if (publicationFailure.compareAndSet(true, false)) {
                throw new IllegalStateException("Injected snapshot publication failure after durable commit");
            }
            return new LicenseManager.Membership(feNodes, beNodes, membershipVersion);
        }

        void changeMembers(int frontends, int backends) {
            feNodes = frontends;
            beNodes = backends;
            membershipVersion++;
        }

        @Override
        public long frontendVersion() {
            return frontendVersion;
        }

        @Override
        public void commit(short operation, LicensePersistRecord record) throws IOException {
            if (retainLatestOnly) {
                records.clear();
            }
            records.add(record);
            if (failPublicationAfterCommit) {
                failPublicationAfterCommit = false;
                publicationFailure.set(true);
            }
            if (throwAfterWrite) {
                throw new IOException("Simulated acknowledgement loss");
            }
        }

        @Override
        public boolean activationReady() {
            activationProbes.incrementAndGet();
            if (probeEntered != null) {
                probeEntered.countDown();
                try {
                    if (!probeRelease.await(10, TimeUnit.SECONDS)) {
                        return false;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            return compatible;
        }

        @Override
        public String trustStorePath() {
            return path;
        }

        @Override
        public Map<String, Object> localCapability(String digest) {
            Map<String, Object> result = new java.util.LinkedHashMap<>();
            result.put("trust_sha256", digest);
            result.put("package_sha256", "0000000000000000000000000000000000000000000000000000000000000001");
            return result;
        }
    }
}
