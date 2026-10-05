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

class LicenseClockTest {
    @Test
    void monotonicProgressAndSmallRollbackCannotExtendExpiry() {
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
    }

    @Test
    void smallForwardMovementCrossesExpiryImmediatelyAndCannotBeUndone() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = clock(time, 100_000L);
        time.wall += 10_000;
        Assertions.assertEquals(110, clock.trustedNowSeconds());
        Assertions.assertFalse(clock.isSuspect());
        time.wall -= 4_000;
        time.advance(1_000);
        Assertions.assertEquals(111, clock.trustedNowSeconds());
        Assertions.assertFalse(clock.isSuspect());
    }

    @Test
    void rollbackIsMeasuredAgainstObservedForwardProgressNotOnlyOriginalBaseline() {
        FakeTime time = new FakeTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        time.wall += 20_000;
        Assertions.assertEquals(120_000, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
        time.wall -= 6_000;
        Assertions.assertEquals(120_000, clock.trustedNowMillis());
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertNull(clock.prepareCheckpoint(1));
    }

    @Test
    void replicatedSameEpochWaterUsesTheSameRollbackToleranceAsRestart() {
        FakeTime time = new FakeTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        clock.applyCommitted(new LicenseClock.Facts(1, 0, 105_000, 0));
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertEquals(105_000, clock.trustedNowMillis());
        clock.applyCommitted(new LicenseClock.Facts(2, 0, 105_001, 0));
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertEquals(105_001, clock.trustedNowMillis());
        time.wall = 105_001;
        Assertions.assertTrue(clock.isSuspect());
    }

    @Test
    void largeForwardJumpIsStickyAndCannotCheckpointPollutedTime() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = clock(time, 100_000L);
        time.wall += 300_001;
        Assertions.assertEquals(400_001, clock.trustedNowMillis());
        Assertions.assertTrue(clock.isSuspect());
        time.wall = 100_000;
        Assertions.assertEquals(400_001, clock.trustedNowMillis());
        Assertions.assertTrue(clock.isSuspect());
        Assertions.assertNull(clock.prepareCheckpoint(1));
    }

    @Test
    void forwardThresholdIsInclusiveAndFutureProgressKeepsItsUpperBound() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = clock(time, 100_000L);
        time.wall += 300_000;
        Assertions.assertEquals(400_000, clock.trustedNowMillis());
        Assertions.assertFalse(clock.isSuspect());
        time.wall = 100_000;
        time.advance(10_000);
        Assertions.assertEquals(410_000, clock.trustedNowMillis());
    }

    @Test
    void restartUsesHighWaterEvenInsideRollbackTolerance() {
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
        Assertions.assertEquals(160_000, candidate.getHighWaterMillis());
        Assertions.assertTrue(clock.applyCommitted(candidate));
        Assertions.assertFalse(clock.applyCommitted(candidate));
        Assertions.assertEquals(160_000, clock.trustedNowMillis());
        Assertions.assertNull(clock.prepareCheckpoint(60_000));
    }

    @Test
    void sameEpochCannotLowerWaterOrAuthorizationAndConflictsAreRejected() {
        FakeTime time = new FakeTime(100_000L);
        LicenseClock clock = new LicenseClock(new LicenseClock.Facts(4, 2, 100_000, 7), time);
        Assertions.assertFalse(clock.applyCommitted(new LicenseClock.Facts(3, 1, 1, 0)));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> clock.applyCommitted(new LicenseClock.Facts(4, 2, 100_001, 7)));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> clock.applyCommitted(new LicenseClock.Facts(5, 2, 99_999, 7)));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> clock.applyCommitted(new LicenseClock.Facts(5, 2, 100_001, 6)));
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
    void concurrentCheckpointCannotLoseObservedForwardProgress() throws Exception {
        FakeTime time = new FakeTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        ExecutorService pool = Executors.newFixedThreadPool(6);
        try {
            List<Callable<Void>> tasks = new ArrayList<>();
            time.wall = 110_000;
            for (int i = 0; i < 5; i++) {
                tasks.add(() -> {
                    for (int n = 0; n < 10_000; n++) {
                        Assertions.assertTrue(clock.trustedNowMillis() >= 110_000);
                    }
                    return null;
                });
            }
            tasks.add(() -> {
                for (int n = 1; n <= 1_000; n++) {
                    clock.applyCommitted(new LicenseClock.Facts(n, 0, 100_000, 0));
                }
                return null;
            });
            for (Future<Void> result : pool.invokeAll(tasks)) {
                result.get();
            }
            time.wall = 100_000;
            time.advance(1_000);
            Assertions.assertEquals(111_000, clock.trustedNowMillis());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void pausesAroundTheWallSampleDoNotBecomeClockCorrections() {
        for (long pause : new long[] {6_001, 300_001}) {
            SamplingTime time = new SamplingTime(100_000);
            LicenseClock clock = clock(time, 100_000);
            time.pauseBeforeWall = pause;
            Assertions.assertEquals(time.wall + pause, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());

            // A genuine small forward movement combined with a post-wall pause must not
            // be converted into an even larger correction by the next normal sample.
            time.wall += 1_000;
            time.pauseAfterWall = pause;
            clock.trustedNowMillis();
            Assertions.assertFalse(clock.isSuspect());
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
        }
    }

    @Test
    void genuineForwardJumpDuringAPostWallPauseIsDetectedByTheNextStableSample() {
        SamplingTime time = new SamplingTime(100_000);
        LicenseClock clock = clock(time, 100_000);
        time.wall += 300_001;
        time.pauseAfterWall = 600_001;
        clock.trustedNowMillis();
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
        Assertions.assertTrue(clock.isSuspect());
    }

    @Test
    void startupAndRepairAnchorsRetryPausedSamplesWithoutExpandingTheForwardTolerance() {
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
            Assertions.assertFalse(clock.isSuspect());
            LicenseClock.Facts checkpoint = clock.prepareCheckpoint(1);
            Assertions.assertNotNull(checkpoint);
            clock.applyCommitted(checkpoint);
            time.wall += 300_001;
            clock.trustedNowMillis();
            Assertions.assertTrue(clock.isSuspect());

            clock.restoreSuspect();
            time.pauseBeforeWall = beforeWall ? 600_001 : 0;
            time.pauseAfterWall = beforeWall ? 0 : 600_001;
            clock.applyCommitted(new LicenseClock.Facts(2, 1, time.wall, 1));
            Assertions.assertEquals(time.wall, clock.trustedNowMillis());
            Assertions.assertFalse(clock.isSuspect());
            checkpoint = clock.prepareCheckpoint(1);
            Assertions.assertNotNull(checkpoint);
            clock.applyCommitted(checkpoint);
            time.wall += 300_001;
            clock.trustedNowMillis();
            Assertions.assertTrue(clock.isSuspect());
        }
    }

    @Test
    void persistentlyUnreliableAnchorSamplesFailClosedWithinABoundedAttemptCount() {
        SamplingTime time = new SamplingTime(100_000);
        time.pauseEveryWall = 2;
        LicenseClock clock = clock(time, 100_000);
        Assertions.assertEquals(32, time.wallReads);
        Assertions.assertEquals(64, time.monotonicReads);
        Assertions.assertTrue(clock.isSuspect());
        time.pauseEveryWall = 0;
        Assertions.assertNull(clock.prepareCheckpoint(1));
        Assertions.assertTrue(clock.isSuspect());
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
            Assertions.assertEquals(110_000, clock.trustedNowMillis());
        };
        clock.trustedNowMillis();
        Assertions.assertFalse(clock.isSuspect());
        Assertions.assertEquals(110_000, clock.trustedNowMillis());
    }

    @Test
    void repeatedSmallCorrectionsCannotResetTheExistingTolerances() {
        FakeTime forwardTime = new FakeTime(100_000);
        LicenseClock forward = clock(forwardTime, 100_000);
        for (int i = 1; i <= 10; i++) {
            forwardTime.wall += 30_000;
            Assertions.assertEquals(forwardTime.wall, forward.trustedNowMillis());
            Assertions.assertFalse(forward.isSuspect());
            LicenseClock.Facts checkpoint = forward.prepareCheckpoint(1);
            Assertions.assertNotNull(checkpoint);
            forward.applyCommitted(checkpoint);
        }
        forwardTime.wall++;
        forward.trustedNowMillis();
        Assertions.assertTrue(forward.isSuspect());

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
    void steadyReadsKeepOneReadOfEachTimeSourceAndOnlyCorrectionsConfirmMonotonicTime() {
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
        Assertions.assertEquals(time.wall, clock.trustedNowMillis());
        Assertions.assertEquals(1_002, time.monotonicReads);
        Assertions.assertEquals(1_001, time.wallReads);
    }

    @Test
    void saturatedTimeAndCounterExhaustionFailClosed() {
        FakeTime time = new FakeTime(LicenseClock.MAX_MILLIS);
        LicenseClock clock = clock(time, LicenseClock.MAX_MILLIS);
        clock.trustedNowMillis();
        Assertions.assertTrue(clock.isSuspect());
        FakeTime normal = new FakeTime(100_000);
        LicenseClock exhausted = new LicenseClock(new LicenseClock.Facts(Long.MAX_VALUE, 0, 0, 0), normal);
        Assertions.assertThrows(IllegalStateException.class, () -> exhausted.prepareCheckpoint(1));
    }

    private static LicenseClock clock(FakeTime time, long highWater) {
        return new LicenseClock(new LicenseClock.Facts(0, 0, highWater, 0), time);
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
