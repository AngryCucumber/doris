// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

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
        LicenseManagementResult result = new LicenseManagementResult(200, body);
        Assertions.assertEquals(202, result.withLocalAppliedVersion(4).getHttpStatus());
        Assertions.assertEquals(200, result.withLocalAppliedVersion(5).getHttpStatus());
        Assertions.assertEquals(403, new LicenseManagementResult(403, body).withLocalAppliedVersion(7).getHttpStatus());
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

    private LicenseManagementResult run(LicenseManager.Action action, String payload) throws Exception {
        return manager.execute(action, payload, "admin-" + principal++, true);
    }

    private String certificate(long sequence, long notBefore, long expiresAt) throws Exception {
        ObjectNode claims = JSON.createObjectNode().put("schema_version", 1).put("policy_version", 1)
                .put("product", "MassDB SQL").put("deployment_id",
                        run(LicenseManager.Action.DEPLOYMENT, null).getBody().get("deployment_id").toString())
                .put("license_id", "license-" + sequence).put("issuer", "test issuer")
                .put("customer_id", "customer").put("edition", "enterprise").put("issued_at", 900)
                .put("not_before", notBefore).put("expires_at", expiresAt).put("sequence", sequence);
        claims.putArray("features").add("DATA_QUERY");
        claims.putObject("limits").put("max_fe_nodes", 3).put("max_be_nodes", 5);
        return sign(claims, "issuer", "massdb-license+jws", issuer);
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
        private long frontendVersion = 1;
        private volatile CountDownLatch probeEntered;
        private volatile CountDownLatch probeRelease;

        Host(String path) {
            this.path = path;
        }

        @Override
        public boolean isMaster() {
            return true;
        }

        @Override
        public LicenseManager.Membership membership() {
            return new LicenseManager.Membership(1, 0, 1);
        }

        @Override
        public long frontendVersion() {
            return frontendVersion;
        }

        @Override
        public void commit(short operation, LicensePersistRecord record) throws IOException {
            records.add(record);
            if (throwAfterWrite) {
                throw new IOException("Simulated acknowledgement loss");
            }
        }

        @Override
        public boolean activationReady() {
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
