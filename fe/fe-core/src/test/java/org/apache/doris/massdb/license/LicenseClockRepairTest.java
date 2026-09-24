// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

class LicenseClockRepairTest {
    private static final UUID DEPLOYMENT = UUID.fromString("003aaf16-b828-455a-8ce2-1bd393572102");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String HEADER = "{\"typ\":\"massdb-license-clock-repair+jws\","
            + "\"alg\":\"Ed25519\",\"kid\":\"repair-1\"}";
    private static final long NOW = 1_800_000_000_000L;
    private KeyPair keys;
    private LicenseClockRepairVerifier verifier;
    private LicenseClockTest.FakeTime time;
    private LicenseClock clock;
    private FakeStore store;
    private LicenseClockRepair manager;

    @BeforeEach
    void setUp() throws Exception {
        keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        verifier = new LicenseClockRepairVerifier(Collections.singletonMap("repair-1", keys.getPublic()));
        time = new LicenseClockTest.FakeTime(NOW);
        LicenseClock.Facts poisoned = new LicenseClock.Facts(0, 0, 4_070_908_800_000L, 0);
        clock = new LicenseClock(poisoned, time);
        store = new FakeStore(new LicenseClockRepair.State(DEPLOYMENT, poisoned, Collections.emptyMap()));
        manager = new LicenseClockRepair(DEPLOYMENT, clock, verifier, store);
        manager.beginLeadership();
    }

    @Test
    void repairIgnoresPoisonedWaterAndAtomicallyCommitsEpochReceiptOnly() throws Exception {
        LicenseClockRepair.Challenge challenge = manager.newChallenge();
        String ticket = sign(claims(challenge));
        LicenseClockRepair.PreparedRepair proposal = manager.prepareRepair(ticket);
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertEquals(0, store.state.getFacts().getClockEpoch());
        LicenseClockRepair.Receipt receipt = manager.commitRepair(proposal);
        Assertions.assertEquals(1, receipt.getClockEpoch());
        Assertions.assertEquals(NOW, receipt.getCorrectedMillis());
        Assertions.assertEquals("repair-1", receipt.getKeyId());
        byte[] fingerprint = MessageDigest.getInstance("SHA-256")
                .digest(ticket.getBytes(StandardCharsets.US_ASCII));
        StringBuilder expectedFingerprint = new StringBuilder(64);
        for (byte value : fingerprint) {
            expectedFingerprint.append(String.format("%02x", value & 255));
        }
        Assertions.assertEquals(expectedFingerprint.toString(), receipt.getFingerprint());
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertEquals(NOW / 1000, clock.trustedNowSeconds());
        Assertions.assertSame(receipt, manager.confirmRepair(receipt.getRepairId()));
        Assertions.assertEquals(17, store.unrelatedLicenseSequence);
        Assertions.assertEquals(NOW - 1, store.unrelatedLicenseExpiresAt);
        Assertions.assertEquals(9, store.unrelatedEffectiveCapacity);
        Assertions.assertEquals(2, store.state.getFacts().getRepairAuthorizationVersion());
    }

    @Test
    void repairDoesNotMakeAlreadyExpiredProductLicenseValid() throws Exception {
        LicenseClockRepair.Receipt receipt = manager.commitRepair(
                manager.prepareRepair(sign(claims(manager.newChallenge()))));
        Assertions.assertTrue(clock.trustedNowMillis() > store.unrelatedLicenseExpiresAt);
        Assertions.assertEquals(NOW, receipt.getCorrectedMillis());
    }

    @Test
    void challengeExportsExactPortableSchemaAndRandomNonce() throws Exception {
        LicenseClockRepair.Challenge first = manager.newChallenge();
        LicenseClockRepair.Challenge second = manager.newChallenge();
        Assertions.assertEquals(10, second.toClaims().size());
        Assertions.assertEquals(86400L, second.toClaims().get("valid_for_seconds"));
        Assertions.assertEquals(32, Base64.getUrlDecoder().decode(second.getNonce()).length);
        Assertions.assertNotEquals(first.getNonce(), second.getNonce());
        Assertions.assertEquals(first.getRepairAuthorizationVersion() + 1,
                second.getRepairAuthorizationVersion());
        Assertions.assertThrows(UnsupportedOperationException.class,
                () -> second.toClaims().put("valid_for_seconds", 0));
        Assertions.assertFalse(second.toClaims().containsKey("issued_monotonic_nanos"));
    }

    @Test
    void replacedAndRevokedChallengesCannotBeConsumed() throws Exception {
        String old = sign(claims(manager.newChallenge()));
        manager.newChallenge();
        reject(LicenseRepairException.Code.CHALLENGE_MISMATCH, () -> manager.prepareRepair(old));
        String current = sign(claims(manager.newChallenge()));
        manager.invalidateChallenge();
        reject(LicenseRepairException.Code.CHALLENGE_REQUIRED, () -> manager.prepareRepair(current));
    }

    @Test
    void monotonicChallengeExpiresAtExactlyTwentyFourHoursDespiteFrozenWall() throws Exception {
        String ticket = sign(claims(manager.newChallenge()));
        time.nano += 86400L * 1_000_000_000L - 1;
        Assertions.assertNotNull(manager.prepareRepair(ticket));
        time.nano++;
        reject(LicenseRepairException.Code.CHALLENGE_EXPIRED, () -> manager.prepareRepair(ticket));
    }

    @Test
    void commitRechecksChallengeTtlInsteadOfTrustingPreparation() throws Exception {
        LicenseClockRepair.PreparedRepair prepared = manager.prepareRepair(sign(claims(manager.newChallenge())));
        time.nano += 86400L * 1_000_000_000L;
        reject(LicenseRepairException.Code.CHALLENGE_EXPIRED, () -> manager.commitRepair(prepared));
        Assertions.assertEquals(0, store.state.getFacts().getClockEpoch());
    }

    @Test
    void restartAndLeadershipChangeInvalidateUnconsumedChallenge() throws Exception {
        String ticket = sign(claims(manager.newChallenge()));
        LicenseClock restored = new LicenseClock(store.state.getFacts(), time);
        LicenseClockRepair restarted = new LicenseClockRepair(DEPLOYMENT, restored, verifier, store);
        restarted.beginLeadership();
        reject(LicenseRepairException.Code.CHALLENGE_REQUIRED, () -> restarted.prepareRepair(ticket));
        restarted.newChallenge();
        reject(LicenseRepairException.Code.CHALLENGE_MISMATCH, () -> restarted.prepareRepair(ticket));
        manager.endLeadership();
        reject(LicenseRepairException.Code.NOT_LEADER, () -> manager.prepareRepair(ticket));
        manager.beginLeadership();
        reject(LicenseRepairException.Code.CHALLENGE_REQUIRED, () -> manager.prepareRepair(ticket));
    }

    @Test
    void challengeBindsDeploymentNonceEpochAuthorizationAndLeadership() throws Exception {
        ObjectNode valid = claims(manager.newChallenge());
        for (String field : new String[] {"deployment_id", "leader_term"}) {
            ObjectNode changed = valid.deepCopy();
            changed.put(field, UUID.randomUUID().toString());
            String ticket = sign(changed);
            reject(LicenseRepairException.Code.CHALLENGE_MISMATCH, () -> manager.prepareRepair(ticket));
        }
        for (String field : new String[] {"clock_epoch", "repair_authorization_version"}) {
            ObjectNode changed = valid.deepCopy();
            changed.put(field, valid.get(field).longValue() + 1);
            String ticket = sign(changed);
            reject(LicenseRepairException.Code.CHALLENGE_MISMATCH, () -> manager.prepareRepair(ticket));
        }
        ObjectNode changed = valid.deepCopy();
        changed.put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]));
        String ticket = sign(changed);
        reject(LicenseRepairException.Code.CHALLENGE_MISMATCH, () -> manager.prepareRepair(ticket));
    }

    @Test
    void correctedWallWindowIsInclusiveAtStartAndExclusiveAtEnd() throws Exception {
        ObjectNode claims = claims(manager.newChallenge());
        claims.put("not_before", NOW / 1000);
        claims.put("expires_at", NOW / 1000 + 10);
        String ticket = sign(claims);
        Assertions.assertNotNull(manager.prepareRepair(ticket));
        time.wall = NOW - 1;
        reject(LicenseRepairException.Code.LOCAL_TIME_OUTSIDE_REPAIR_WINDOW, () -> manager.prepareRepair(ticket));
        time.wall = NOW + 9_999;
        LicenseClockRepair.PreparedRepair prepared = manager.prepareRepair(ticket);
        time.wall++;
        reject(LicenseRepairException.Code.LOCAL_TIME_OUTSIDE_REPAIR_WINDOW, () -> manager.commitRepair(prepared));
    }

    @Test
    void failureBeforeJournalCommitLeavesClockAndConsumedSetUnchanged() throws Exception {
        LicenseClockRepair.PreparedRepair prepared = manager.prepareRepair(sign(claims(manager.newChallenge())));
        long version = store.state.getFacts().getVersion();
        store.failBefore = true;
        reject(LicenseRepairException.Code.COMMIT_UNCERTAIN, () -> manager.commitRepair(prepared));
        Assertions.assertEquals(version, clock.getCommittedFacts().getVersion());
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertNull(manager.confirmRepair(prepared.getRepairId()));
        Assertions.assertNotNull(manager.commitRepair(prepared));
    }

    @Test
    void responseLostAfterCommitIsConfirmedWithoutApplyingRepairTwice() throws Exception {
        LicenseClockRepair.PreparedRepair prepared = manager.prepareRepair(sign(claims(manager.newChallenge())));
        store.failAfter = true;
        reject(LicenseRepairException.Code.COMMIT_UNCERTAIN, () -> manager.commitRepair(prepared));
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertEquals(1, store.state.getFacts().getClockEpoch());
        LicenseClockRepair.Receipt confirmed = manager.confirmRepair(prepared.getRepairId());
        Assertions.assertNotNull(confirmed);
        Assertions.assertFalse(clock.isSuspect());
        reject(LicenseRepairException.Code.REPAIR_ALREADY_CONSUMED, () -> manager.commitRepair(prepared));
        Assertions.assertEquals(1, store.state.getFacts().getClockEpoch());
    }

    @Test
    void definiteCasConflictDoesNotPublishUncommittedEpoch() throws Exception {
        LicenseClockRepair.PreparedRepair prepared = manager.prepareRepair(sign(claims(manager.newChallenge())));
        store.conflict = true;
        reject(LicenseRepairException.Code.STALE_PREPARATION, () -> manager.commitRepair(prepared));
        Assertions.assertEquals(0, clock.getCommittedFacts().getClockEpoch());
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertTrue(store.state.getReceipts().isEmpty());
    }

    @Test
    void nonceConsumedAtomicallyAndReceiptSurvivesRestart() throws Exception {
        String ticket = sign(claims(manager.newChallenge()));
        LicenseClockRepair.Receipt receipt = manager.commitRepair(manager.prepareRepair(ticket));
        reject(LicenseRepairException.Code.REPAIR_ALREADY_CONSUMED, () -> manager.prepareRepair(ticket));
        LicenseClockRepair restarted = new LicenseClockRepair(DEPLOYMENT,
                new LicenseClock(store.state.getFacts(), time), verifier, store);
        Assertions.assertEquals(receipt.getCommittedVersion(),
                restarted.confirmRepair(receipt.getRepairId()).getCommittedVersion());
        restarted.beginLeadership();
        restarted.newChallenge();
        reject(LicenseRepairException.Code.REPAIR_ALREADY_CONSUMED, () -> restarted.prepareRepair(ticket));
    }

    @Test
    void periodicCheckpointDoesNotInvalidatePreparedOfflineChallenge() throws Exception {
        LicenseClock.Facts facts = new LicenseClock.Facts(0, 0, NOW, 0);
        clock = new LicenseClock(facts, time);
        store = new FakeStore(new LicenseClockRepair.State(DEPLOYMENT, facts, Collections.emptyMap()));
        manager = new LicenseClockRepair(DEPLOYMENT, clock, verifier, store);
        manager.beginLeadership();
        LicenseClockRepair.Challenge challenge = manager.newChallenge();
        LicenseClockRepair.PreparedRepair prepared = manager.prepareRepair(sign(claims(challenge)));
        time.advance(60_000);
        Assertions.assertTrue(manager.checkpoint(60_000));
        Assertions.assertEquals(challenge.getRepairAuthorizationVersion(),
                store.state.getFacts().getRepairAuthorizationVersion());
        Assertions.assertNotNull(manager.commitRepair(prepared));
    }

    @Test
    void preparationCannotBeMovedBetweenManagersOrReplacedChallenges() throws Exception {
        LicenseClockRepair.PreparedRepair prepared = manager.prepareRepair(sign(claims(manager.newChallenge())));
        LicenseClockRepair other = new LicenseClockRepair(DEPLOYMENT, clock, verifier, store);
        other.beginLeadership();
        reject(LicenseRepairException.Code.STALE_PREPARATION, () -> other.commitRepair(prepared));
        manager.newChallenge();
        reject(LicenseRepairException.Code.STALE_PREPARATION, () -> manager.commitRepair(prepared));
    }

    @Test
    void receiptRetentionIsBoundedAndOldEpochStillRejectsEvictedTicket() throws Exception {
        String oldest = null;
        UUID firstRepair = null;
        for (int i = 0; i <= LicenseClockRepair.MAX_RECEIPTS; i++) {
            String ticket = sign(claims(manager.newChallenge()));
            LicenseClockRepair.PreparedRepair prepared = manager.prepareRepair(ticket);
            manager.commitRepair(prepared);
            if (i == 0) {
                oldest = ticket;
                firstRepair = prepared.getRepairId();
            }
        }
        Assertions.assertEquals(LicenseClockRepair.MAX_RECEIPTS, store.state.getReceipts().size());
        Assertions.assertNull(manager.confirmRepair(firstRepair));
        manager.newChallenge();
        final String evicted = oldest;
        reject(LicenseRepairException.Code.CHALLENGE_MISMATCH, () -> manager.prepareRepair(evicted));
    }

    @Test
    void recoveredReceiptHistoryIsOrderedAndRejectsConflictingCommittedEpochs() {
        String fingerprint = String.format("%064x", 1);
        LicenseClockRepair.Receipt earlier = new LicenseClockRepair.Receipt(UUID.randomUUID(), 2, 1, NOW,
                "repair-1", fingerprint);
        LicenseClockRepair.Receipt later = new LicenseClockRepair.Receipt(UUID.randomUUID(), 4, 2, NOW,
                "repair-1", fingerprint);
        Map<UUID, LicenseClockRepair.Receipt> reverse = new LinkedHashMap<>();
        reverse.put(later.getRepairId(), later);
        reverse.put(earlier.getRepairId(), earlier);
        LicenseClock.Facts facts = new LicenseClock.Facts(4, 2, NOW, 4);
        LicenseClockRepair.State restored = new LicenseClockRepair.State(DEPLOYMENT, facts, reverse);
        Assertions.assertEquals(earlier.getRepairId(), restored.getReceipts().keySet().iterator().next());
        LicenseClockRepair.Receipt conflict = new LicenseClockRepair.Receipt(UUID.randomUUID(), 3, 1, NOW,
                "repair-1", fingerprint);
        reverse.put(conflict.getRepairId(), conflict);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new LicenseClockRepair.State(DEPLOYMENT, facts, reverse));
    }

    @Test
    void unknownKeysWrongPurposeAndWrongSignatureCannotRepairClock() throws Exception {
        String ticket = sign(claims(manager.newChallenge()));
        LicenseClockRepairVerifier noRepairTrust = new LicenseClockRepairVerifier(Collections.emptyMap());
        reject(LicenseRepairException.Code.UNTRUSTED_REPAIR_KEY, () -> noRepairTrust.verify(ticket));
        String wrongType = sign(HEADER.replace("massdb-license-clock-repair+jws", "massdb-license+jws"),
                claims(manager.newChallenge()).toString().getBytes(StandardCharsets.UTF_8));
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(wrongType));
        KeyPair original = keys;
        keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String wrongSignature = sign(claims(manager.newChallenge()));
        keys = original;
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(wrongSignature));
    }

    @Test
    void rejectsWrongSchemaUnknownFieldsMissingFieldsAndNumericCoercion() throws Exception {
        ObjectNode valid = claims(manager.newChallenge());
        for (String field : new String[] {"schema_version", "clock_epoch", "repair_authorization_version",
                "issued_at", "not_before", "expires_at"}) {
            ObjectNode changed = valid.deepCopy();
            changed.put(field, 1.0);
            invalidClaims(changed);
        }
        ObjectNode changed = valid.deepCopy();
        changed.put("schema_version", 2);
        invalidClaims(changed);
        changed = valid.deepCopy();
        changed.put("unexpected", true);
        invalidClaims(changed);
        changed = valid.deepCopy();
        changed.remove("product");
        invalidClaims(changed);
        changed = valid.deepCopy();
        changed.put("clock_epoch", Long.MAX_VALUE);
        invalidClaims(changed);
        changed = valid.deepCopy();
        changed.put("repair_authorization_version", 0);
        invalidClaims(changed);
    }

    @Test
    void rejectsAmbiguousUuidNonceAndExcessiveRepairWindow() throws Exception {
        ObjectNode valid = claims(manager.newChallenge());
        ObjectNode changed = valid.deepCopy();
        changed.put("deployment_id", DEPLOYMENT.toString().toUpperCase());
        invalidClaims(changed);
        changed = valid.deepCopy();
        changed.put("nonce", valid.get("nonce").textValue() + "=");
        invalidClaims(changed);
        changed = valid.deepCopy();
        changed.put("nonce", "AA");
        invalidClaims(changed);
        changed = valid.deepCopy();
        changed.put("expires_at", changed.get("not_before").longValue() + 86401);
        invalidClaims(changed);
        changed = valid.deepCopy();
        changed.put("expires_at", changed.get("not_before").longValue());
        invalidClaims(changed);
    }

    @Test
    void rejectsDuplicateKeysMalformedUtf8TrailingJsonAndNonCanonicalBase64() throws Exception {
        String payload = claims(manager.newChallenge()).toString();
        String duplicate = sign(HEADER, payload.replaceFirst("\\{", "{\"schema_version\":1,")
                .getBytes(StandardCharsets.UTF_8));
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(duplicate));
        String malformed = sign(HEADER, new byte[] {'{', (byte) 0xc3, (byte) 0x28, '}'});
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(malformed));
        String trailing = sign(HEADER, (payload + " {}").getBytes(StandardCharsets.UTF_8));
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(trailing));
        String valid = sign(HEADER, payload.getBytes(StandardCharsets.UTF_8));
        String padded = valid + "=";
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(padded));
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify("a.b.c.d"));
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(null));
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify("."));
    }

    @Test
    void rejectsUnknownHeadersUnsupportedAlgorithmAndOversizedEnvelope() throws Exception {
        byte[] payload = claims(manager.newChallenge()).toString().getBytes(StandardCharsets.UTF_8);
        for (String header : new String[] {HEADER.replace("Ed25519", "none"),
                HEADER.replace("{", "{\"jku\":\"https://example.test/key\","),
                HEADER.replace("{", "{\"kid\":\"repair-1\",")}) {
            String ticket = sign(header, payload);
            reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(ticket));
        }
        String large = new String(new char[LicenseClockRepairVerifier.MAX_COMPACT_LENGTH + 1]).replace('\0', 'a');
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(large));
    }

    @Test
    void storeLoadFailuresAndExhaustedAuthorizationDoNotIssueChallenges() throws Exception {
        store.failLoad = true;
        reject(LicenseRepairException.Code.STORE_UNAVAILABLE, manager::newChallenge);
        store.failLoad = false;
        LicenseClock.Facts exhausted = new LicenseClock.Facts(1, 0,
                clock.getCommittedFacts().getHighWaterMillis(), Long.MAX_VALUE);
        store.state = new LicenseClockRepair.State(DEPLOYMENT, exhausted, Collections.emptyMap());
        reject(LicenseRepairException.Code.VERSION_EXHAUSTED, manager::newChallenge);
    }

    private void invalidClaims(ObjectNode claims) throws Exception {
        String compact = sign(claims);
        reject(LicenseRepairException.Code.INVALID_TICKET, () -> verifier.verify(compact));
    }

    private ObjectNode claims(LicenseClockRepair.Challenge challenge) {
        ObjectNode node = JSON.createObjectNode();
        node.put("schema_version", 1);
        node.put("product", "MassDB SQL");
        node.put("deployment_id", challenge.getDeploymentId().toString());
        node.put("repair_id", UUID.randomUUID().toString());
        node.put("nonce", challenge.getNonce());
        node.put("clock_epoch", challenge.getClockEpoch());
        node.put("repair_authorization_version", challenge.getRepairAuthorizationVersion());
        node.put("leader_term", challenge.getLeaderTerm().toString());
        node.put("issued_at", time.wall / 1000);
        node.put("not_before", time.wall / 1000 - 60);
        node.put("expires_at", time.wall / 1000 + 3600);
        return node;
    }

    private String sign(ObjectNode claims) throws Exception {
        return sign(HEADER, claims.toString().getBytes(StandardCharsets.UTF_8));
    }

    private String sign(String header, byte[] claims) throws Exception {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String input = encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(claims);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keys.getPrivate());
        signer.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + encoder.encodeToString(signer.sign());
    }

    private void reject(LicenseRepairException.Code code, org.junit.jupiter.api.function.Executable action) {
        LicenseRepairException error = Assertions.assertThrows(LicenseRepairException.class, action);
        Assertions.assertEquals(code, error.getCode());
        Assertions.assertEquals(code.name(), error.getMessage());
    }

    private static final class FakeStore implements LicenseClockRepair.Store {
        private LicenseClockRepair.State state;
        private boolean failBefore;
        private boolean failAfter;
        private boolean failLoad;
        private boolean conflict;
        private final long unrelatedLicenseSequence = 17;
        private final long unrelatedLicenseExpiresAt = NOW - 1;
        private final int unrelatedEffectiveCapacity = 9;

        private FakeStore(LicenseClockRepair.State state) {
            this.state = state;
        }

        @Override
        public LicenseClockRepair.State load() throws LicenseClockRepair.StoreException {
            if (failLoad) {
                throw new LicenseClockRepair.StoreException();
            }
            return state;
        }

        @Override
        public boolean compareAndSet(long expectedVersion, LicenseClockRepair.State replacement)
                throws LicenseClockRepair.StoreException {
            if (conflict) {
                conflict = false;
                return false;
            }
            if (failBefore) {
                failBefore = false;
                throw new LicenseClockRepair.StoreException();
            }
            if (state.getFacts().getVersion() != expectedVersion) {
                return false;
            }
            state = replacement;
            if (failAfter) {
                failAfter = false;
                throw new LicenseClockRepair.StoreException();
            }
            return true;
        }
    }
}
