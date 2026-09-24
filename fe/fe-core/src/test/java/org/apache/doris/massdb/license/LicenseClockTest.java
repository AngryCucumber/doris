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

    static final class FakeTime implements LicenseClock.TimeSource {
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
}
