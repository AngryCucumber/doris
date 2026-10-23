// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

class LicenseClockTest {
    /** Tight tolerances and no settling period: the clock denies as soon as it is suspect. */
    static final LicenseClock.Settings STRICT = new LicenseClock.Settings(5_000, 5_000, 0);
    /** A one-minute rollback tolerance, so forward corrections of a few seconds count as small. */
    private static final LicenseClock.Settings LENIENT = new LicenseClock.Settings(60_000, 5_000, 0);
    private static final long HOUR = TimeUnit.HOURS.toMillis(1);

    @Test
    void monotonicProgressAndSmallRollbackCannotExtendExpiryAndSuspicionClearsItself() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = clock(time, 100_000L);
        time.advance(10_000);
        Assertions.assertEquals(110, clock.trustedNowSeconds());
        time.wall -= 5_000;
        Assertions.assertEquals(110, clock.trustedNowSeconds());
        Assertions.assertFalse(clock.isSuspect());
        time.advance(1_000);
        Assertions.assertEquals(111, clock.trustedNowSeconds());
        time.wall--;
        clock.trustedNowSeconds();
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertTrue(clock.diagnostics().isRollbackSuspect());
        // The trusted time never moved; once the wall clock is back within tolerance the state clears.
        time.wall += 1;
        Assertions.assertEquals(111, clock.trustedNowSeconds());
        Assertions.assertFalse(clock.isSuspect());
    }

    @Test
    void defaultsMatchTheReviewDesign() {
        Assertions.assertEquals(12 * HOUR, LicenseClock.DEFAULT_ROLLBACK_TOLERANCE_MILLIS);
        Assertions.assertEquals(5 * 60_000, LicenseClock.DEFAULT_STARTUP_TOLERANCE_MILLIS);
        Assertions.assertEquals(10 * 60_000, LicenseClock.DEFAULT_SETTLING_MILLIS);
        Assertions.assertEquals(5 * 60_000, LicenseClock.CONFIRM_SMALL_FORWARD_MILLIS);
        Assertions.assertEquals(HOUR, LicenseClock.ACCEPT_FORWARD_MILLIS);
        // The startup tolerance and the settling period are bounded whatever the configuration says.
        LicenseClock.Settings loose = new LicenseClock.Settings(48 * HOUR, 48 * HOUR, 48 * HOUR);
        Assertions.assertEquals(48 * HOUR, loose.getRollbackToleranceMillis());
        Assertions.assertEquals(LicenseClock.MAX_STARTUP_TOLERANCE_MILLIS, loose.getStartupToleranceMillis());
        Assertions.assertEquals(LicenseClock.MAX_SETTLING_MILLIS, loose.getSettlingMillis());
        Assertions.assertThrows(IllegalArgumentException.class, () -> new LicenseClock.Settings(-1, 0, 0));
    }

    @Test
    void inProcessRollbackWithinTwelveHoursOnlyWarnsAndBeyondItClearsWhenTheWallReturns() {
        FakeTime time = new FakeTime(10 * 24 * HOUR);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(0, 0, time.wall, 0), time,
                new LicenseClock.Settings(LicenseClock.DEFAULT_ROLLBACK_TOLERANCE_MILLIS,
                        LicenseClock.DEFAULT_STARTUP_TOLERANCE_MILLIS, 0));
        long before = clock.trustedNowMillis();
        time.wall -= HOUR;
        Assertions.assertEquals(before, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
        time.wall -= 12 * HOUR;
        Assertions.assertEquals(before, clock.trustedNowMillis());
        Assertions.assertTrue(clock.isSuspect());
        // Watermarks keep flowing with the confirmed time while suspect.
        time.advance(60_000);
        LicenseClock.Facts checkpoint = clock.prepareCheckpoint(60_000);
        Assertions.assertNotNull(checkpoint);
        Assertions.assertEquals(before + 60_000, checkpoint.getHighWaterMillis());
        time.wall += 13 * HOUR;
        clock.trustedNowMillis();
        Assertions.assertFalse(clock.isSuspect());
    }

    @Test
    void forwardCorrectionIsPendingUntilItHasHeldAndIsDiscardedWhenTakenBack() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(0, 0, 100_000L, 0), time, LENIENT);
        time.wall += 10_000;
        Assertions.assertEquals(100_000, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertEquals(LicenseClock.Event.FORWARD_PENDING, clock.observe());
        Assertions.assertEquals(10_000, clock.diagnostics().getPendingForwardMillis());
        time.advance(LicenseClock.CONFIRM_SMALL_FORWARD_MILLIS - 1);
        Assertions.assertEquals(LicenseClock.Event.NONE, clock.observe());
        Assertions.assertEquals(100_000 + LicenseClock.CONFIRM_SMALL_FORWARD_MILLIS - 1, clock.trustedNowMillis());
        time.advance(1);
        Assertions.assertEquals(LicenseClock.Event.FORWARD_CONFIRMED, clock.observe());
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
        Assertions.assertEquals(0, clock.diagnostics().getPendingForwardMillis());

        // Corrected back before confirmation: nothing happened.
        time.wall += 20_000;
        Assertions.assertEquals(LicenseClock.Event.FORWARD_PENDING, clock.observe());
        time.advance(60_000);
        time.wall -= 20_000;
        Assertions.assertEquals(LicenseClock.Event.FORWARD_DISCARDED, clock.observe());
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
    }

    @Test
    void pendingCandidateIsWhatHeldThroughoutNotThePeak() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(0, 0, 100_000L, 0), time, LENIENT);
        time.wall += 30_000;
        clock.observe();
        time.advance(1_000);
        time.wall -= 20_000;
        Assertions.assertEquals(LicenseClock.Event.NONE, clock.observe());
        Assertions.assertEquals(10_000, clock.diagnostics().getPendingForwardMillis());
        time.advance(LicenseClock.CONFIRM_SMALL_FORWARD_MILLIS);
        Assertions.assertEquals(LicenseClock.Event.FORWARD_CONFIRMED, clock.observe());
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
    }

    @Test
    void largeForwardJumpWaitsForTheAcceptanceBoundOrAnAdministrator() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = clock(time, 100_000L);
        time.wall += 3 * 24 * HOUR;
        clock.observe();
        time.advance(LicenseClock.CONFIRM_SMALL_FORWARD_MILLIS);
        Assertions.assertEquals(LicenseClock.Event.NONE, clock.observe());
        Assertions.assertEquals(100_000 + LicenseClock.CONFIRM_SMALL_FORWARD_MILLIS, clock.trustedNowMillis());
        time.advance(LicenseClock.ACCEPT_FORWARD_MILLIS - LicenseClock.CONFIRM_SMALL_FORWARD_MILLIS);
        Assertions.assertEquals(LicenseClock.Event.FORWARD_CONFIRMED, clock.observe());
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());

        FakeTime adminTime = new FakeTime(100_000L);
        LicenseClock admin = clock(adminTime, 100_000L);
        Assertions.assertEquals(0, admin.confirmPending());
        adminTime.wall += 3 * 24 * HOUR;
        admin.observe();
        Assertions.assertEquals(3 * 24 * HOUR, admin.confirmPending());
        Assertions.assertEquals(adminTime.wall, admin.trustedNowMillis());
        Assertions.assertEquals(0, admin.confirmPending());
    }

    @Test
    void peerAgreementConfirmsAtOnceAndAnOutlierNeverConfirmsAutomatically() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = clock(time, 100_000L);
        time.wall += 10_000;
        clock.observe();
        clock.setPeerVerdict(LicenseClock.PeerVerdict.AGREE);
        Assertions.assertEquals(LicenseClock.Event.FORWARD_CONFIRMED, clock.observe());
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());

        FakeTime outlierTime = new FakeTime(100_000L);
        LicenseClock outlier = clock(outlierTime, 100_000L);
        outlierTime.wall += 10_000;
        outlier.observe();
        outlier.setPeerVerdict(LicenseClock.PeerVerdict.OUTLIER);
        outlierTime.advance(2 * LicenseClock.ACCEPT_FORWARD_MILLIS);
        Assertions.assertEquals(LicenseClock.Event.NONE, outlier.observe());
        Assertions.assertEquals(100_000 + 2 * LicenseClock.ACCEPT_FORWARD_MILLIS, outlier.trustedNowMillis());
        Assertions.assertEquals(10_000, outlier.confirmPending());
        Assertions.assertEquals(outlierTime.wall, outlier.trustedNowMillis());
    }

    @Test
    void startupWallAheadOfWatermarkCountsForAdmissionButEntersWatermarksOnlyAfterSettling() {
        FakeTime time = new FakeTime(2 * 24 * HOUR);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(0, 0, 100_000, 0), time,
                new LicenseClock.Settings(5_000, 5_000, 10 * 60_000));
        // Admission uses the wall clock at once: restarting never buys time.
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
        Assertions.assertEquals(100_000, clock.confirmedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertTrue(clock.diagnostics().isPendingStartup());
        time.advance(60_000);
        LicenseClock.Facts checkpoint = clock.prepareCheckpoint(60_000);
        Assertions.assertEquals(160_000, checkpoint.getHighWaterMillis());
        Assertions.assertEquals(LicenseClock.Event.NONE, clock.observe());
        time.advance(9 * 60_000);
        Assertions.assertEquals(LicenseClock.Event.FORWARD_CONFIRMED, clock.observe());
        Assertions.assertEquals(time.wall, clock.confirmedNowMillis());
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
    }

    @Test
    void fastBootClockCorrectedByNtpWithinTheSettlingPeriodLeavesNoTrace() {
        FakeTime time = new FakeTime(100_000 + 2 * HOUR);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(0, 0, 100_000, 0), time,
                new LicenseClock.Settings(60_000, 5_000, 10 * 60_000));
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
        time.advance(8 * 60_000);
        clock.observe();
        // NTP steps the clock back to the truth: eight minutes after a watermark of 100_000.
        time.wall = 100_000 + 8 * 60_000;
        Assertions.assertEquals(LicenseClock.Event.FORWARD_DISCARDED, clock.observe());
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
        Assertions.assertEquals(time.wall, clock.confirmedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
        LicenseClock.Facts checkpoint = clock.prepareCheckpoint(1);
        Assertions.assertEquals(time.wall, checkpoint.getHighWaterMillis());
        // A later partial correction still ahead of the watermark is confirmed at its held value.
        time.wall += 30_000;
        clock.observe();
        time.advance(10 * 60_000);
        Assertions.assertEquals(LicenseClock.Event.FORWARD_CONFIRMED, clock.observe());
        Assertions.assertEquals(time.wall, clock.confirmedNowMillis());
    }

    @Test
    void slowBootClockIsSuspectOnlyAfterSettlingAndClearsWhenNtpCatchesUp() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(0, 0, 100_000 + 2 * 24 * HOUR, 0), time,
                new LicenseClock.Settings(12 * HOUR, 5 * 60_000, 10 * 60_000));
        Assertions.assertEquals(100_000 + 2 * 24 * HOUR, clock.trustedNowMillis());
        Assertions.assertTrue(clock.isLocalSuspect());
        Assertions.assertTrue(clock.diagnostics().isStartupSuspect());
        Assertions.assertFalse(clock.isSuspect(), "A settling clock only warns");
        Assertions.assertFalse(clock.settled());
        time.advance(10 * 60_000);
        Assertions.assertTrue(clock.settled());
        Assertions.assertTrue(clock.isSuspect());
        // Watermarks still flow with the confirmed lower bound.
        Assertions.assertEquals(100_000 + 2 * 24 * HOUR + 10 * 60_000,
                clock.prepareCheckpoint(60_000).getHighWaterMillis());
        time.wall = 100_000 + 2 * 24 * HOUR + 10 * 60_000;
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertFalse(clock.isLocalSuspect());
    }

    @Test
    void replicatedWatermarkAheadOfTheWallUsesTheStartupToleranceAndClearsItself() {
        FakeTime time = new FakeTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        Assertions.assertTrue(clock.applyCommitted(new LicenseClock.Facts(1, 0, 105_000, 0)));
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertEquals(105_000, clock.trustedNowMillis());
        Assertions.assertTrue(clock.applyCommitted(new LicenseClock.Facts(2, 0, 105_001, 0)));
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertEquals(105_001, clock.trustedNowMillis());
        time.wall = 105_001;
        clock.trustedNowMillis();
        Assertions.assertFalse(clock.isSuspect());
    }

    @Test
    void followersOnlyReportSuspicionAndAReplicatedMasterSuspicionDeniesEverywhere() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = clock(time, 100_000L);
        clock.setEnforced(false);
        time.wall -= 60_000;
        clock.trustedNowMillis();
        Assertions.assertTrue(clock.isLocalSuspect());
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertFalse(clock.read().isSuspect());
        clock.setCommittedSuspect(true);
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertTrue(clock.read().isSuspect());
        clock.setCommittedSuspect(false);
        clock.setEnforced(true);
        Assertions.assertTrue(clock.isSuspect());
    }

    @Test
    void restartUsesHighWaterEvenInsideStartupTolerance() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock within = clock(time, 105_000L);
        Assertions.assertEquals(105_000, within.trustedNowMillis());
        Assertions.assertFalse(within.isSuspect());
        LicenseClock outside = clock(time, 105_001L);
        Assertions.assertEquals(105_001, outside.trustedNowMillis());
        Assertions.assertTrue(outside.isSuspect());
    }

    @Test
    void checkpointIsPreparedWithoutMutationThenAppliedIdempotently() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = clock(time, 100_000L);
        Assertions.assertNull(clock.prepareCheckpoint(60_000));
        time.advance(60_000);
        LicenseClock.Facts candidate = clock.prepareCheckpoint(60_000);
        Assertions.assertEquals(0, clock.getCommittedFacts().getVersion());
        Assertions.assertEquals(1, candidate.getVersion());
        Assertions.assertEquals(160_000, candidate.getHighWaterMillis());
        Assertions.assertTrue(clock.applyCommitted(candidate));
        Assertions.assertFalse(clock.applyCommitted(candidate));
        Assertions.assertEquals(160_000, clock.trustedNowMillis());
        Assertions.assertNull(clock.prepareCheckpoint(60_000));
    }

    @Test
    void sameEpochKeepsTheLocalMaximumAndIgnoresRegressedFactsWithoutThrowing() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(4, 2, 100_000, 7), time, STRICT);
        Assertions.assertFalse(clock.applyCommitted(new LicenseClock.Facts(3, 1, 1, 0)));
        // A same-version conflict is ignored; replay never throws.
        Assertions.assertFalse(clock.applyCommitted(new LicenseClock.Facts(4, 2, 100_001, 7)));
        Assertions.assertEquals(100_000, clock.getCommittedFacts().getHighWaterMillis());
        // A lower watermark from a degraded master aligns the version but never lowers local progress.
        Assertions.assertTrue(clock.applyCommitted(new LicenseClock.Facts(5, 2, 99_999, 7)));
        Assertions.assertEquals(5, clock.getCommittedFacts().getVersion());
        Assertions.assertEquals(100_000, clock.getCommittedFacts().getHighWaterMillis());
        Assertions.assertEquals(100_000, clock.trustedNowMillis());
        // Older epoch or authorization is a master that skipped a repair: ignored entirely.
        Assertions.assertFalse(clock.applyCommitted(new LicenseClock.Facts(6, 2, 100_001, 6)));
        Assertions.assertFalse(clock.applyCommitted(new LicenseClock.Facts(6, 1, 100_001, 7)));
        Assertions.assertEquals(5, clock.getCommittedFacts().getVersion());
        Assertions.assertFalse(clock.accepts(new LicenseClock.Facts(5, 2, 100_001, 7)));
        Assertions.assertTrue(clock.accepts(new LicenseClock.Facts(6, 2, 100_001, 7)));
    }

    @Test
    void repairedEpochResetsLocalBaselineAndDoesNotReplicateMonotonicAbsoluteTime() {
        FakeTime firstTime = new FakeTime(100_000);
        FakeTime secondTime = new FakeTime(100_000);
        secondTime.nano = 500_000_000_000L;
        LicenseClock first = clock(firstTime, 4_000_000_000_000L);
        LicenseClock second = clock(secondTime, 4_000_000_000_000L);
        Assertions.assertTrue(first.isSuspect());
        LicenseClock.Facts repaired = new LicenseClock.Facts(1, 1, 100_000, 1);
        first.applyCommitted(repaired);
        second.applyCommitted(repaired);
        Assertions.assertFalse(first.isSuspect());
        Assertions.assertFalse(second.isSuspect());
        firstTime.advance(2_000);
        secondTime.advance(2_000);
        Assertions.assertEquals(102_000, first.trustedNowMillis());
        Assertions.assertEquals(first.trustedNowMillis(), second.trustedNowMillis());
    }

    @Test
    void repairDropsAPendingForwardCorrection() {
        FakeTime time = new FakeTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        time.wall += 50_000;
        clock.observe();
        Assertions.assertEquals(50_000, clock.diagnostics().getPendingForwardMillis());
        clock.applyCommitted(new LicenseClock.Facts(1, 1, 120_000, 1));
        Assertions.assertEquals(0, clock.diagnostics().getPendingForwardMillis());
        Assertions.assertEquals(150_000, clock.trustedNowMillis(), "A repair anchors on the larger of wall and water");
    }

    @Test
    void epochCheckRejectsMixedSamplesAndTuplePreservesItsOriginalEpoch() {
        FakeTime time = new FakeTime(100_000);
        LicenseClock clock = clock(time, 4_000_000_000_000L);
        long epoch = clock.getClockEpoch();
        LicenseClock.Reading before = clock.read();
        clock.applyCommitted(new LicenseClock.Facts(1, 1, 100_000, 1));
        Assertions.assertFalse(clock.isCurrentEpoch(epoch));
        Assertions.assertTrue(before.isSuspect());
        Assertions.assertEquals(0, before.getClockEpoch());
        Assertions.assertEquals(4_000_000_000_000L, before.getTrustedMillis());
        LicenseClock.Reading after = clock.read();
        Assertions.assertFalse(after.isSuspect());
        Assertions.assertEquals(1, after.getClockEpoch());
        Assertions.assertEquals(100_000, after.getTrustedMillis());
    }

    @Test
    void repairWithLocalClockStillBehindRemainsSuspect() {
        FakeTime time = new FakeTime(100_000);
        LicenseClock clock = clock(time, 4_000_000_000_000L);
        clock.applyCommitted(new LicenseClock.Facts(1, 1, 110_000, 1));
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertEquals(110_000, clock.trustedNowMillis());
    }

    @Test
    void monotonicWrapIsValidButNegativeElapsedAndInvalidWallFailClosed() {
        FakeTime time = new FakeTime(100_000);
        time.nano = Long.MAX_VALUE - 500_000_000L;
        LicenseClock clock = clock(time, 100_000);
        time.advance(1_000);
        Assertions.assertEquals(101_000, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
        FakeTime reversed = new FakeTime(100_000);
        LicenseClock bad = clock(reversed, 100_000);
        reversed.nano--;
        bad.trustedNowMillis();
        Assertions.assertTrue(bad.isSuspect());
        FakeTime invalid = new FakeTime(-1);
        Assertions.assertTrue(clock(invalid, 0).isSuspect());
    }

    @Test
    void concurrentCheckpointsAndReadersNeverObserveRegressingTime() throws Exception {
        FakeTime time = new FakeTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        ExecutorService pool = Executors.newFixedThreadPool(6);
        try {
            List<Callable<Void>> tasks = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                tasks.add(() -> {
                    long last = 0;
                    for (int n = 0; n < 10_000; n++) {
                        long now = clock.trustedNowMillis();
                        Assertions.assertTrue(now >= last && now >= 100_000);
                        last = now;
                    }
                    return null;
                });
            }
            tasks.add(() -> {
                for (int n = 1; n <= 1_000; n++) {
                    clock.applyCommitted(new LicenseClock.Facts(n, 0, 100_000 + n, 0));
                }
                return null;
            });
            for (Future<Void> result : pool.invokeAll(tasks)) {
                result.get();
            }
            time.advance(1_000);
            Assertions.assertEquals(102_000, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void pausesAroundTheWallSampleNeitherMoveTheClockNorRaiseSuspicionWithinTolerance() {
        for (long pause : new long[] {6_001, 300_001}) {
            SamplingTime time = new SamplingTime(100_000);
            LicenseClock clock = new LicenseClock(new LicenseClock.Facts(0, 0, 100_000, 0), time,
                    new LicenseClock.Settings(LicenseClock.DEFAULT_ROLLBACK_TOLERANCE_MILLIS, 5_000, 0));
            time.pauseBeforeWall = pause;
            // The wall sample lands after the pause, but only the monotonic elapsed time counts.
            Assertions.assertEquals(100_000, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
            time.pauseAfterWall = pause;
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
            // A pause inside observe() inflates one sample; the candidate is what holds across samples.
            time.pauseBeforeWall = pause;
            clock.observe();
            Assertions.assertTrue(clock.diagnostics().getPendingForwardMillis() <= pause);
            time.advance(1_000);
            Assertions.assertEquals(LicenseClock.Event.FORWARD_DISCARDED, clock.observe());
        }
    }

    @Test
    void startupAndRepairAnchorsRetryPausedSamplesAndForwardJumpsStayPending() {
        for (boolean beforeWall : new boolean[] {true, false}) {
            SamplingTime time = new SamplingTime(100_000);
            time.pauseBeforeWall = beforeWall ? 600_001 : 0;
            time.pauseAfterWall = beforeWall ? 0 : 600_001;
            LicenseClock clock = clock(time, 100_000);
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
            Assertions.assertEquals(3, time.wallReads);
            time.advance(10_000);
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
            LicenseClock.Facts checkpoint = clock.prepareCheckpoint(1);
            Assertions.assertNotNull(checkpoint);
            clock.applyCommitted(checkpoint);
            // The paused sample left the wall clock ahead of the watermark: a startup candidate that admission
            // already uses, while another forward jump only widens what waits for confirmation.
            Assertions.assertTrue(clock.diagnostics().isPendingStartup());
            time.wall += 300_001;
            Assertions.assertEquals(time.wall - 300_001, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
            // Without a settling period the startup candidate confirms at once; the new jump then waits.
            Assertions.assertEquals(LicenseClock.Event.FORWARD_CONFIRMED, clock.observe());
            Assertions.assertEquals(time.wall - 300_001, clock.confirmedNowMillis());
            Assertions.assertEquals(LicenseClock.Event.FORWARD_PENDING, clock.observe());
            Assertions.assertEquals(300_001, clock.diagnostics().getPendingForwardMillis());

            time.pauseBeforeWall = beforeWall ? 600_001 : 0;
            time.pauseAfterWall = beforeWall ? 0 : 600_001;
            clock.applyCommitted(new LicenseClock.Facts(2, 1, time.wall, 1));
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
            Assertions.assertEquals(0, clock.diagnostics().getPendingForwardMillis());
        }
    }

    @Test
    void persistentlyUnreliableAnchorSamplesFailClosedWithinABoundedAttemptCount() {
        SamplingTime time = new SamplingTime(100_000);
        time.pauseEveryWall = 2;
        LicenseClock clock = clock(time, 100_000);
        Assertions.assertEquals(32, time.wallReads);
        // 32 paired attempts plus the creation instant of the settling period.
        Assertions.assertEquals(65, time.monotonicReads);
        Assertions.assertTrue(clock.isSuspect());
        time.pauseEveryWall = 0;
        time.advance(1);
        // The confirmed time is still a sound lower bound: watermarks are written regardless.
        Assertions.assertNotNull(clock.prepareCheckpoint(1));
        clock.applyCommitted(new LicenseClock.Facts(1, 1, time.wall, 1));
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
    }

    @Test
    void checkpointSamplingPauseCannotInflateTheWatermarkOffset() {
        SamplingTime time = new SamplingTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        time.pauseBeforeWall = 6_001;
        clock.applyCommitted(new LicenseClock.Facts(1, 0, 106_001, 0));
        Assertions.assertEquals(106_001, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
        time.advance(1_000);
        Assertions.assertEquals(107_001, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
    }

    @Test
    void concurrentCorrectionCannotMakeAnOlderWallSampleLookLikeRollback() {
        SamplingTime time = new SamplingTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        time.afterWall = () -> {
            time.wall += 10_000;
            Assertions.assertEquals(100_000, clock.trustedNowMillis());
        };
        clock.trustedNowMillis();
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertEquals(100_000, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
    }

    @Test
    void repeatedSmallRollbacksCannotResetTheTolerance() {
        FakeTime rollbackTime = new FakeTime(100_000);
        LicenseClock rollback = clock(rollbackTime, 100_000);
        for (int i = 1; i <= 5; i++) {
            rollbackTime.wall -= 1_000;
            Assertions.assertEquals(100_000, rollback.trustedNowMillis());
            Assertions.assertFalse(rollback.isSuspect());
        }
        rollbackTime.wall--;
        rollback.trustedNowMillis();
        Assertions.assertTrue(rollback.isSuspect());
    }

    @Test
    void steadyReadsKeepOneReadOfEachTimeSourceAndNoWriteOnTheSharedFlag() {
        SamplingTime time = new SamplingTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        time.monotonicReads = 0;
        time.wallReads = 0;
        for (int i = 0; i < 1_000; i++) {
            time.advance(1);
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
        }
        Assertions.assertEquals(1_000, time.monotonicReads);
        Assertions.assertEquals(1_000, time.wallReads);
        time.wall++;
        Assertions.assertEquals(time.wall - 1, clock.trustedNowMillis());
        Assertions.assertEquals(1_001, time.monotonicReads);
        Assertions.assertEquals(1_001, time.wallReads);
    }

    @Test
    void exhaustedVersionIsReportedOnlyWhenACheckpointIsPrepared() {
        FakeTime normal = new FakeTime(100_000);
        LicenseClock exhausted = new LicenseClock(new LicenseClock.Facts(Long.MAX_VALUE, 0, 0, 0), normal, STRICT);
        normal.advance(1);
        Assertions.assertThrows(IllegalStateException.class, () -> exhausted.prepareCheckpoint(1));
        Assertions.assertThrows(IllegalArgumentException.class, () -> exhausted.prepareCheckpoint(0));
    }

    private static LicenseClock clock(FakeTime time, long highWater) {
        return new LicenseClock(new LicenseClock.Facts(0, 0, highWater, 0), time, STRICT);
    }

    static class FakeTime implements LicenseClock.TimeSource {
        volatile long wall;
        volatile long nano;

        FakeTime(long wall) {
            this.wall = wall;
        }

        void advance(long millis) {
            wall += millis;
            nano += millis * 1_000_000L;
        }

        @Override
        public long wallTimeMillis() {
            return wall;
        }

        @Override
        public long monotonicNanos() {
            return nano;
        }
    }

    private static final class SamplingTime extends FakeTime {
        private long pauseBeforeWall;
        private long pauseAfterWall;
        private long pauseEveryWall;
        private int wallReads;
        private int monotonicReads;
        private Runnable afterWall;

        private SamplingTime(long wall) {
            super(wall);
        }

        @Override
        public long wallTimeMillis() {
            wallReads++;
            advance(pauseBeforeWall + pauseEveryWall);
            pauseBeforeWall = 0;
            long result = wall;
            advance(pauseAfterWall);
            pauseAfterWall = 0;
            Runnable action = afterWall;
            afterWall = null;
            if (action != null) {
                action.run();
            }
            return result;
        }

        @Override
        public long monotonicNanos() {
            monotonicReads++;
            return nano;
        }
    }
}
