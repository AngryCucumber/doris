// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.UUID;

class LicenseSnapshotTest {
    private static final UUID DEPLOYMENT = UUID.fromString("9e40496a-d09d-42df-b77b-6b036efb4f8e");
    private static final long NOW = 1_800_000_000L;
    private static KeyPair key;
    private static LicenseVerifier verifier;

    @BeforeAll
    static void initialize() throws Exception {
        key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        verifier = new LicenseVerifier(Collections.singletonMap("test-key", key.getPublic()));
    }

    @Test
    void checksTimeAtEveryAdmissionIncludingExactExpiry() throws Exception {
        LicenseDocument active = certificate(1, NOW, NOW + 3_000_000L, 3, 10, true, DEPLOYMENT);
        LicenseSnapshot snapshot = snapshot(active, null, active, 3, 10);
        Assertions.assertEquals(LicenseQueryStatus.NOT_YET_VALID, snapshot.queryStatus(NOW - 1));
        Assertions.assertEquals(LicenseQueryStatus.VALID, snapshot.queryStatus(NOW));
        Assertions.assertEquals(LicenseQueryStatus.EXPIRING, snapshot.queryStatus(NOW + 3_000_000L - 1));
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, snapshot.queryStatus(NOW + 3_000_000L));
        Assertions.assertEquals(10, snapshot.getBaseMaxBeNodes(),
                "Query expiry must not erase committed base capacity");
    }

    @Test
    void pendingQueryActivationDoesNotActivateUncommittedQuota() throws Exception {
        LicenseDocument active = certificate(1, NOW - 100, NOW + 100, 1, 2, true, DEPLOYMENT);
        LicenseDocument pending = certificate(2, NOW + 100, NOW + 1000, 3, 6, true, DEPLOYMENT);
        LicenseSnapshot beforeMarker = snapshot(active, pending, active, 1, 3);
        Assertions.assertEquals(active, beforeMarker.currentCertificate(NOW + 99));
        Assertions.assertEquals(pending, beforeMarker.currentCertificate(NOW + 100));
        Assertions.assertEquals(2, beforeMarker.getBaseMaxBeNodes());
        Assertions.assertEquals(LicenseQueryStatus.LIMIT_EXCEEDED, beforeMarker.queryStatus(NOW + 99));
        Assertions.assertTrue(beforeMarker.queryStatus(NOW + 100).permitsNewQuery());
        LicenseSnapshot afterMarker = snapshot(active, pending, pending, 1, 3);
        Assertions.assertTrue(afterMarker.queryStatus(NOW + 100).permitsNewQuery());
        Assertions.assertEquals(6, afterMarker.getBaseMaxBeNodes());
        Assertions.assertEquals(2, beforeMarker.getBaseMaxBeNodes(),
                "Publishing a successor must not mutate old snapshots");
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, afterMarker.queryStatus(NOW + 1000));
        Assertions.assertEquals(6, afterMarker.getBaseMaxBeNodes());
    }

    @Test
    void futureOnlyCertificateCannotSupplyCommittedCapacity() throws Exception {
        LicenseDocument future = certificate(1, NOW + 100, NOW + 1000, 3, 6, true, DEPLOYMENT);
        LicenseSnapshot snapshot = snapshot(null, future, null, 1, 0);
        Assertions.assertEquals(LicenseQueryStatus.NOT_YET_VALID, snapshot.queryStatus(NOW));
        Assertions.assertFalse(snapshot.hasTrustedBaseCapacity());
        Assertions.assertThrows(IllegalStateException.class, snapshot::getBaseMaxFeNodes);
        Assertions.assertThrows(IllegalStateException.class, snapshot::getBaseMaxBeNodes);
        Assertions.assertTrue(snapshot.queryStatus(NOW + 100).permitsNewQuery());
        Assertions.assertFalse(snapshot.hasTrustedBaseCapacity());
    }

    @Test
    void isolatedBaseDamageDoesNotBlockValidQueryOrCreateNodeCapacity() throws Exception {
        LicenseDocument active = certificate(1, NOW, NOW + 1000, 3, 10, true, DEPLOYMENT);
        LicenseSnapshot missingBase = new LicenseSnapshot(DEPLOYMENT, active, null, null,
                3, 10, true, false, true, 5, 7);
        Assertions.assertTrue(missingBase.queryStatus(NOW).permitsNewQuery());
        Assertions.assertFalse(missingBase.hasTrustedBaseCapacity());
        Assertions.assertThrows(IllegalStateException.class, missingBase::getBaseMaxBeNodes);
        Assertions.assertEquals(LicenseQueryStatus.LIMIT_EXCEEDED,
                snapshot(active, null, null, 3, 11).queryStatus(NOW));
        LicenseDocument foreignBase = certificate(1, NOW, NOW + 1000, 30, 100, true, UUID.randomUUID());
        LicenseSnapshot wrongBase = snapshot(active, null, foreignBase, 3, 10);
        Assertions.assertTrue(wrongBase.queryStatus(NOW).permitsNewQuery());
        Assertions.assertFalse(wrongBase.hasTrustedBaseCapacity());
        Assertions.assertThrows(IllegalStateException.class, wrongBase::getBaseMaxFeNodes);
    }

    @Test
    void quotaCountsRegisteredMembersAtLimitAndAfterDrop() throws Exception {
        LicenseDocument active = certificate(1, NOW, NOW + 1000, 3, 10, true, DEPLOYMENT);
        Assertions.assertTrue(snapshot(active, null, active, 3, 10).queryStatus(NOW).permitsNewQuery());
        Assertions.assertEquals(LicenseQueryStatus.LIMIT_EXCEEDED,
                snapshot(active, null, active, 4, 10).queryStatus(NOW));
        Assertions.assertEquals(LicenseQueryStatus.LIMIT_EXCEEDED,
                snapshot(active, null, active, 3, 11).queryStatus(NOW));
        Assertions.assertTrue(snapshot(active, null, active, 3, 10).queryStatus(NOW).permitsNewQuery());
        Assertions.assertEquals(11, snapshot(active, null, active, 3, 11).getRegisteredBe());
    }

    @Test
    void recoveryAndClockFlagsCannotBeBypassedByValidSignature() throws Exception {
        LicenseDocument active = certificate(1, NOW, NOW + 1000, 3, 10, true, DEPLOYMENT);
        LicenseSnapshot notReady = new LicenseSnapshot(DEPLOYMENT, active, null, active,
                1, 1, false, false, false, 5, 7);
        LicenseSnapshot clockSuspect = new LicenseSnapshot(DEPLOYMENT, active, null, active,
                1, 1, true, true, false, 5, 7);
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, notReady.queryStatus(NOW));
        Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, clockSuspect.queryStatus(NOW));
        Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, snapshot(active, null, active, 1, 1).queryStatus(-1));
        Assertions.assertEquals(5, notReady.getLicenseVersion());
        Assertions.assertEquals(7, notReady.getMembershipVersion());
    }

    @Test
    void missingAndIsolatedInvalidSlotsHaveDistinctStates() throws Exception {
        Assertions.assertEquals(LicenseQueryStatus.MISSING, snapshot(null, null, null, 1, 0).queryStatus(NOW));
        LicenseSnapshot invalid = new LicenseSnapshot(DEPLOYMENT, null, null, null,
                1, 0, true, false, true, 5, 7);
        Assertions.assertEquals(LicenseQueryStatus.INVALID, invalid.queryStatus(NOW));
        LicenseDocument active = certificate(1, NOW, NOW + 1000, 3, 10, true, DEPLOYMENT);
        LicenseSnapshot isolatedBadPending = new LicenseSnapshot(DEPLOYMENT, active, null, active,
                1, 1, true, false, true, 5, 7);
        Assertions.assertTrue(isolatedBadPending.queryStatus(NOW).permitsNewQuery());
    }

    @Test
    void featureAndDeploymentAreNotImpliedBySignature() throws Exception {
        LicenseDocument noQuery = certificate(1, NOW, NOW + 1000, 3, 10, false, DEPLOYMENT);
        Assertions.assertEquals(LicenseQueryStatus.FEATURE_NOT_LICENSED,
                snapshot(noQuery, null, noQuery, 1, 1).queryStatus(NOW));
        LicenseDocument anotherCluster = certificate(1, NOW, NOW + 1000, 3, 10, true, UUID.randomUUID());
        Assertions.assertEquals(LicenseQueryStatus.INVALID,
                snapshot(anotherCluster, null, anotherCluster, 1, 1).queryStatus(NOW));
        for (LicenseQueryStatus status : LicenseQueryStatus.values()) {
            if (status != LicenseQueryStatus.VALID && status != LicenseQueryStatus.EXPIRING) {
                Assertions.assertFalse(status.permitsNewQuery());
            }
        }
    }

    @Test
    void rejectsInvalidPublicationMetadata() throws Exception {
        Assertions.assertThrows(IllegalArgumentException.class, () -> snapshot(null, null, null, -1, 0));
        LicenseDocument same = certificate(1, NOW, NOW + 1000, 3, 10, true, DEPLOYMENT);
        Assertions.assertThrows(IllegalArgumentException.class, () -> snapshot(same, same, same, 1, 1));
    }

    @Test
    void managementReportsExpiryFeatureAndBothNodeLimitsIndependently() throws Exception {
        LicenseDocument expired = certificate(1, NOW - 100, NOW, 3, 10, false, DEPLOYMENT);
        LicenseSnapshot snapshot = snapshot(expired, null, expired, 4, 11);
        LicenseSnapshot.Evaluation details = snapshot.evaluate(NOW);
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, details.getPrimaryStatus());
        Assertions.assertTrue(details.isFeLimitExceeded());
        Assertions.assertTrue(details.isBeLimitExceeded());
        Assertions.assertEquals(EnumSet.of(LicenseSnapshot.Reason.EXPIRED,
                LicenseSnapshot.Reason.FEATURE_NOT_LICENSED, LicenseSnapshot.Reason.FE_LIMIT_EXCEEDED,
                LicenseSnapshot.Reason.BE_LIMIT_EXCEEDED), details.getReasons());
        Assertions.assertThrows(UnsupportedOperationException.class, () -> details.getReasons().clear());
        Assertions.assertThrows(UnsupportedOperationException.class, () -> details.getWarnings().clear());
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, snapshot.queryStatus(NOW));
    }

    @Test
    void managementWarningsForIsolatedSlotsAndMissingBaseDoNotDenyValidQueries() throws Exception {
        LicenseDocument active = certificate(1, NOW, NOW + 3_000_000L, 3, 10, true, DEPLOYMENT);
        LicenseSnapshot snapshot = new LicenseSnapshot(DEPLOYMENT, active, null, null,
                3, 10, true, false, true, 5, 7);
        LicenseSnapshot.Evaluation details = snapshot.evaluate(NOW);
        Assertions.assertEquals(LicenseQueryStatus.VALID, details.getPrimaryStatus());
        Assertions.assertTrue(details.getReasons().isEmpty());
        Assertions.assertFalse(details.isFeLimitExceeded());
        Assertions.assertFalse(details.isBeLimitExceeded());
        Assertions.assertEquals(EnumSet.of(LicenseSnapshot.Warning.INVALID_SLOTS_ISOLATED,
                LicenseSnapshot.Warning.BASE_CAPACITY_UNAVAILABLE), details.getWarnings());
        Assertions.assertTrue(snapshot.queryStatus(NOW).permitsNewQuery());
    }

    @Test
    void managementNeverTreatsForeignOrAbsentCertificateLimitsAsCurrentEntitlement() throws Exception {
        LicenseDocument foreign = certificate(1, NOW, NOW + 1000, 1, 1, false, UUID.randomUUID());
        LicenseSnapshot.Evaluation wrong = snapshot(foreign, null, foreign, 100, 100).evaluate(NOW);
        Assertions.assertEquals(EnumSet.of(LicenseSnapshot.Reason.INVALID), wrong.getReasons());
        Assertions.assertFalse(wrong.isFeLimitExceeded());
        Assertions.assertFalse(wrong.isBeLimitExceeded());
        LicenseDocument pending = certificate(1, NOW + 100, NOW + 1000, 1, 1, true, DEPLOYMENT);
        LicenseSnapshot.Evaluation future = snapshot(null, pending, null, 3, 10).evaluate(NOW);
        Assertions.assertEquals(EnumSet.of(LicenseSnapshot.Reason.NOT_YET_VALID), future.getReasons());
        Assertions.assertFalse(future.isFeLimitExceeded());
        LicenseSnapshot allFaults = new LicenseSnapshot(DEPLOYMENT, null, null, null,
                1, 1, false, true, true, 5, 7);
        Assertions.assertEquals(EnumSet.of(LicenseSnapshot.Reason.LICENSE_NOT_READY,
                LicenseSnapshot.Reason.CLOCK_SUSPECT, LicenseSnapshot.Reason.INVALID),
                allFaults.evaluate(NOW).getReasons());
    }

    @Test
    void liveClockOwnsDynamicSuspectWhileLicenseReadinessRemainsASnapshotGate() throws Exception {
        LicenseDocument active = certificate(1, NOW, NOW + 1000, 3, 10, true, DEPLOYMENT);
        ChangingTime time = new ChangingTime(NOW * 1000);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(0, 0, time.wall, 1), time);
        time.clock = clock;
        LicenseSnapshot previouslySuspect = new LicenseSnapshot(DEPLOYMENT, active, null, active,
                1, 1, true, true, false, 5, 7);
        Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, previouslySuspect.queryStatus(NOW));
        Assertions.assertTrue(previouslySuspect.queryStatus(clock).permitsNewQuery());
        Assertions.assertFalse(previouslySuspect.evaluate(clock).getReasons()
                .contains(LicenseSnapshot.Reason.CLOCK_SUSPECT));
        LicenseSnapshot previouslyHealthy = snapshot(active, null, active, 1, 1);
        time.wall += LicenseClock.DEFAULT_FORWARD_TOLERANCE_MILLIS + 1;
        Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, previouslyHealthy.queryStatus(clock));
        Assertions.assertTrue(previouslyHealthy.evaluate(clock).getReasons()
                .contains(LicenseSnapshot.Reason.CLOCK_SUSPECT));
        time.wall = NOW * 1000;
        clock.applyCommitted(new LicenseClock.Facts(1, 1, time.wall, 2));
        Assertions.assertTrue(previouslySuspect.queryStatus(clock).permitsNewQuery());
        time.wall = (NOW + 1001) * 1000;
        clock.applyCommitted(new LicenseClock.Facts(2, 2, time.wall, 3));
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, previouslySuspect.queryStatus(clock),
                "Repair changes the clock epoch, never the signed license expiry");
        LicenseSnapshot notReady = new LicenseSnapshot(DEPLOYMENT, active, null, active,
                1, 1, false, false, false, 5, 7);
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY, notReady.queryStatus(clock));
    }

    @Test
    void liveClockRetriesARepairEpochAndRejectsTwoConsecutiveEpochChanges() throws Exception {
        LicenseDocument active = certificate(1, NOW, NOW + 1000, 3, 10, true, DEPLOYMENT);
        LicenseSnapshot snapshot = snapshot(active, null, active, 1, 1);
        ChangingTime time = new ChangingTime((NOW + 2000) * 1000);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(0, 0, time.wall, 1), time);
        time.clock = clock;
        time.repairs = 1;
        Assertions.assertTrue(snapshot.queryStatus(clock).permitsNewQuery(),
                "Do not combine old-epoch expired time with a repaired-epoch healthy flag");
        Assertions.assertEquals(1, clock.getClockEpoch());
        Assertions.assertEquals(0, time.repairs);
        time.repairs = 2;
        Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, snapshot.queryStatus(clock));
        Assertions.assertEquals(0, time.repairs, "Hot admission must make at most two attempts");
        Assertions.assertFalse(clock.isSuspect(), "Denial was caused by unstable epochs, not the new clock");
        Assertions.assertTrue(snapshot.queryStatus(clock).permitsNewQuery());
        time.repairs = 2;
        Assertions.assertEquals(LicenseQueryStatus.CLOCK_SUSPECT, snapshot.evaluate(clock).getPrimaryStatus());
    }

    private static final class ChangingTime implements LicenseClock.TimeSource {
        private long wall;
        private LicenseClock clock;
        private int repairs;
        private boolean applyingRepair;

        private ChangingTime(long wall) {
            this.wall = wall;
        }

        @Override
        public long wallTimeMillis() {
            long before = wall;
            if (clock != null && repairs > 0 && !applyingRepair) {
                repairs--;
                applyingRepair = true;
                try {
                    LicenseClock.Facts previous = clock.getCommittedFacts();
                    wall = NOW * 1000;
                    clock.applyCommitted(new LicenseClock.Facts(previous.getVersion() + 1,
                            previous.getClockEpoch() + 1, wall, previous.getRepairAuthorizationVersion() + 1));
                } finally {
                    applyingRepair = false;
                }
            }
            return before;
        }

        @Override
        public long monotonicNanos() {
            return 0;
        }
    }

    private static LicenseSnapshot snapshot(LicenseDocument active, LicenseDocument pending,
            LicenseDocument base, int fe, int be) {
        return new LicenseSnapshot(DEPLOYMENT, active, pending, base, fe, be,
                true, false, false, 5, 7);
    }

    private static LicenseDocument certificate(long sequence, long notBefore, long expiresAt,
            int fe, int be, boolean query, UUID deployment) throws Exception {
        String header = "{\"alg\":\"Ed25519\",\"typ\":\"massdb-license+jws\",\"kid\":\"test-key\"}";
        String payload = "{\"schema_version\":1,\"policy_version\":1,\"license_id\":\"test-" + sequence
                + "\",\"issuer\":\"test\",\"customer_id\":\"test\",\"edition\":\"test\","
                + "\"product\":\"MassDB SQL\",\"deployment_id\":\"" + deployment + "\","
                + "\"issued_at\":1,\"not_before\":" + notBefore + ",\"expires_at\":" + expiresAt
                + ",\"sequence\":" + sequence + ",\"features\":[" + (query ? "\"DATA_QUERY\"" : "")
                + "],\"limits\":{\"max_fe_nodes\":" + fe + ",\"max_be_nodes\":" + be + "}}";
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String input = encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(key.getPrivate());
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return verifier.verify(input + "." + encoder.encodeToString(signature.sign()));
    }
}
