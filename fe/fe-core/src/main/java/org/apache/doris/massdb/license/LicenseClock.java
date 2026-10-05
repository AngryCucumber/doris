// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Local, injectable monotonic license clock. No query performs I/O, locking or parsing.
 * The normal monotonic path is bounded;
 * positive wall-clock corrections update a lock-free atomic maximum.
 * The management owner periodically prepares/commits watermarks; it must never publish uncommitted
 * facts. Monotonic values are process-local and deliberately absent from {@link Facts}.
 */
public final class LicenseClock {
    public static final long MAX_MILLIS = 253402300799999L;
    public static final long DEFAULT_ROLLBACK_TOLERANCE_MILLIS = 5_000L;
    public static final long DEFAULT_FORWARD_TOLERANCE_MILLIS = 300_000L;
    private static final long NANOS_PER_MILLI = 1_000_000L;
    private static final int MAX_ANCHOR_SAMPLE_ATTEMPTS = 32;
    private static final long MAX_ANCHOR_SAMPLE_NANOS = NANOS_PER_MILLI;

    public interface TimeSource {
        long wallTimeMillis();

        long monotonicNanos();
    }

    public static final TimeSource SYSTEM = new TimeSource() {
        @Override
        public long wallTimeMillis() {
            return System.currentTimeMillis();
        }

        @Override
        public long monotonicNanos() {
            return System.nanoTime();
        }
    };

    /** Only committed metadata may cross the P2 journal/image boundary. */
    public static final class Facts {
        private final long version;
        private final long clockEpoch;
        private final long highWaterMillis;
        private final long repairAuthorizationVersion;

        public Facts(long version, long clockEpoch, long highWaterMillis, long repairAuthorizationVersion) {
            if (version < 0 || clockEpoch < 0 || repairAuthorizationVersion < 0
                    || highWaterMillis < 0 || highWaterMillis > MAX_MILLIS) {
                throw new IllegalArgumentException("Invalid committed clock facts");
            }
            this.version = version;
            this.clockEpoch = clockEpoch;
            this.highWaterMillis = highWaterMillis;
            this.repairAuthorizationVersion = repairAuthorizationVersion;
        }

        public long getVersion() {
            return version;
        }

        public long getClockEpoch() {
            return clockEpoch;
        }

        public long getHighWaterMillis() {
            return highWaterMillis;
        }

        public long getRepairAuthorizationVersion() {
            return repairAuthorizationVersion;
        }

        public boolean sameAs(Facts other) {
            return other != null && version == other.version && clockEpoch == other.clockEpoch
                    && highWaterMillis == other.highWaterMillis
                    && repairAuthorizationVersion == other.repairAuthorizationVersion;
        }
    }

    /** Consistent epoch-scoped value for administrative consumers that permit an allocation. */
    public static final class Reading {
        private final long trustedMillis;
        private final long clockEpoch;
        private final boolean suspect;

        private Reading(long trustedMillis, long clockEpoch, boolean suspect) {
            this.trustedMillis = trustedMillis;
            this.clockEpoch = clockEpoch;
            this.suspect = suspect;
        }

        public long getTrustedMillis() {
            return trustedMillis;
        }

        public long getClockEpoch() {
            return clockEpoch;
        }

        public boolean isSuspect() {
            return suspect;
        }
    }

    private static final class Anchor {
        private final Facts facts;
        private final AtomicLong trustedOffsetMillis;
        private final long wallMillis;
        private final long monotonicNanos;
        private final long wallSampleStartNanos;
        private final AtomicBoolean suspect;

        private Anchor(Facts facts, long trustedMillis, long wallMillis, long monotonicNanos,
                long wallSampleStartNanos, boolean suspect) {
            this.facts = facts;
            this.trustedOffsetMillis = new AtomicLong(trustedMillis);
            this.wallMillis = wallMillis;
            this.monotonicNanos = monotonicNanos;
            this.wallSampleStartNanos = wallSampleStartNanos;
            this.suspect = new AtomicBoolean(suspect);
        }

        private Anchor(Facts facts, Anchor prior) {
            this.facts = facts;
            this.trustedOffsetMillis = prior.trustedOffsetMillis;
            this.wallMillis = prior.wallMillis;
            this.monotonicNanos = prior.monotonicNanos;
            this.wallSampleStartNanos = prior.wallSampleStartNanos;
            this.suspect = prior.suspect;
        }
    }

    private final TimeSource source;
    private final long rollbackToleranceMillis;
    private final long forwardToleranceMillis;
    private volatile Anchor anchor;

    public LicenseClock(Facts restored, TimeSource source) {
        this(restored, source, DEFAULT_ROLLBACK_TOLERANCE_MILLIS, DEFAULT_FORWARD_TOLERANCE_MILLIS);
    }

    public LicenseClock(Facts restored, TimeSource source, long rollbackToleranceMillis,
            long forwardToleranceMillis) {
        this.source = Objects.requireNonNull(source, "source");
        if (rollbackToleranceMillis < 0 || forwardToleranceMillis < 0
                || rollbackToleranceMillis > MAX_MILLIS || forwardToleranceMillis > MAX_MILLIS) {
            throw new IllegalArgumentException("Invalid clock tolerances");
        }
        this.rollbackToleranceMillis = rollbackToleranceMillis;
        this.forwardToleranceMillis = forwardToleranceMillis;
        this.anchor = freshAnchor(Objects.requireNonNull(restored, "restored"));
    }

    /** Allocation-free hot path; small wall-clock corrections never move this clock backwards. */
    public long trustedNowMillis() {
        Anchor current = anchor;
        return read(current);
    }

    public long trustedNowSeconds() {
        return trustedNowMillis() / 1000;
    }

    /**
     * Allocation-free callers capture getClockEpoch(), read time, then this flag and finally
     * validate isCurrentEpoch(epoch). On an epoch change they must retry or deny conservatively.
     */
    public boolean isSuspect() {
        return anchor.suspect.get();
    }

    /** Restores an already committed anomaly fact; only a later repair epoch can clear it. */
    void restoreSuspect() {
        anchor.suspect.set(true);
    }

    public Facts getCommittedFacts() {
        return anchor.facts;
    }

    public long getClockEpoch() {
        return anchor.facts.clockEpoch;
    }

    public boolean isCurrentEpoch(long epoch) {
        return anchor.facts.clockEpoch == epoch;
    }

    public Reading read() {
        Anchor current = anchor;
        long trusted = read(current);
        return new Reading(trusted, current.facts.clockEpoch, current.suspect.get());
    }

    /**
     * Management-only preparation. The returned candidate is not applied or persisted here.
     * A minimum advance limits journal volume; suspect clocks cannot poison a new checkpoint.
     */
    public synchronized Facts prepareCheckpoint(long minimumAdvanceMillis) {
        if (minimumAdvanceMillis <= 0) {
            throw new IllegalArgumentException("Checkpoint interval must be positive");
        }
        Anchor current = anchor;
        long now = read(current);
        if (current.suspect.get() || now - current.facts.highWaterMillis < minimumAdvanceMillis) {
            return null;
        }
        if (current.facts.version == Long.MAX_VALUE) {
            throw new IllegalStateException("Clock version exhausted");
        }
        return new Facts(current.facts.version + 1, current.facts.clockEpoch, now,
                current.facts.repairAuthorizationVersion);
    }

    /**
     * Applies verified committed facts, including replicated repair epochs. A lower watermark is
     * legal only in a later epoch; no local monotonic timestamp is replicated. Stale replay is a
     * no-op, conflicting replay is rejected. The P2 adapter remains responsible for authenticity.
     */
    public synchronized boolean applyCommitted(Facts committed) {
        Objects.requireNonNull(committed, "committed");
        Anchor old = anchor;
        if (committed.version < old.facts.version) {
            return false;
        }
        if (committed.version == old.facts.version) {
            if (!old.facts.sameAs(committed)) {
                throw new IllegalArgumentException("Conflicting clock metadata version");
            }
            return false;
        }
        if (committed.clockEpoch < old.facts.clockEpoch
                || committed.repairAuthorizationVersion < old.facts.repairAuthorizationVersion
                || (committed.clockEpoch > old.facts.clockEpoch
                    && committed.repairAuthorizationVersion == old.facts.repairAuthorizationVersion)
                || (committed.clockEpoch == old.facts.clockEpoch
                    && committed.highWaterMillis < old.facts.highWaterMillis)) {
            throw new IllegalArgumentException("Clock metadata regressed without repair");
        }
        if (committed.clockEpoch > old.facts.clockEpoch) {
            anchor = freshAnchor(committed);
        } else {
            read(old);
            long wall = source.wallTimeMillis();
            if (wall < 0 || wall > MAX_MILLIS || committed.highWaterMillis - wall > rollbackToleranceMillis) {
                old.suspect.set(true);
            }
            // The wall read (or the read above) may have been descheduled. Pair the fixed
            // watermark with the latest monotonic sample, never the stale pre-wall sample.
            long elapsed = elapsedMillis(old, source.monotonicNanos());
            increaseOffset(old, committed.highWaterMillis - elapsed);
            // Preserve the atomic progress object: readers of the preceding metadata view must
            // not lose an observed forward movement when a checkpoint is applied concurrently.
            anchor = new Anchor(committed, old);
        }
        return true;
    }

    long wallTimeMillis() {
        return source.wallTimeMillis();
    }

    long monotonicNanos() {
        return source.monotonicNanos();
    }

    private Anchor freshAnchor(Facts facts) {
        long before = 0;
        long wall = 0;
        long after = 0;
        boolean invalid = false;
        for (int attempt = 0; attempt < MAX_ANCHOR_SAMPLE_ATTEMPTS; attempt++) {
            before = source.monotonicNanos();
            wall = source.wallTimeMillis();
            after = source.monotonicNanos();
            invalid = wall < 0 || wall > MAX_MILLIS || after - before < 0;
            if (invalid || after - before <= MAX_ANCHOR_SAMPLE_NANOS) {
                break;
            }
        }
        boolean paired = !invalid && after - before <= MAX_ANCHOR_SAMPLE_NANOS;
        long bounded = Math.max(0, Math.min(MAX_MILLIS, wall));
        // Retry a descheduled management sample instead of retaining its entire pause as
        // permanent forward-jump tolerance. Only a tightly paired interval may be retained.
        // If every bounded attempt is unreliable, fail closed without throwing into replay.
        return new Anchor(facts, Math.max(bounded, facts.highWaterMillis), bounded, after,
                paired ? before : after,
                !paired || facts.highWaterMillis - bounded > rollbackToleranceMillis);
    }

    private long read(Anchor current) {
        // Capture progress first: a concurrent correction after our wall sample must not
        // make that older sample look like a rollback.
        long offset = current.trustedOffsetMillis.get();
        long monotonic = source.monotonicNanos();
        long wall = source.wallTimeMillis();
        long elapsed = elapsedMillis(current, monotonic);
        long expectedTrusted = addBounded(offset, elapsed);
        if (wall < 0 || wall > MAX_MILLIS || expectedTrusted - wall > rollbackToleranceMillis) {
            current.suspect.set(true);
        }
        if (wall >= 0 && wall <= MAX_MILLIS && wall - elapsed > offset) {
            // Only a candidate forward correction needs a second monotonic read. A pause
            // between the first read and the wall read is elapsed time, not a correction.
            // A pause after the wall read likewise must not advance the trusted offset.
            long after = source.monotonicNanos();
            if (after - monotonic < 0) {
                current.suspect.set(true);
            }
            elapsed = elapsedMillis(current, after);
            long wallElapsed = (after - current.wallSampleStartNanos) / NANOS_PER_MILLI;
            long expectedWall = addBounded(current.wallMillis, wallElapsed);
            if (wall - expectedWall > forwardToleranceMillis) {
                current.suspect.set(true);
            }
            offset = increaseOffset(current, wall - elapsed);
        }
        long trusted = addBounded(offset, elapsed);
        if (trusted == MAX_MILLIS) {
            current.suspect.set(true);
        }
        return trusted;
    }

    private static long increaseOffset(Anchor current, long candidate) {
        long existing = current.trustedOffsetMillis.get();
        while (candidate > existing) {
            if (current.trustedOffsetMillis.compareAndSet(existing, candidate)) {
                return candidate;
            }
            existing = current.trustedOffsetMillis.get();
        }
        return existing;
    }

    private static long elapsedMillis(Anchor current, long monotonic) {
        // Signed subtraction also handles System.nanoTime() wrapping across Long.MAX_VALUE.
        long elapsed = monotonic - current.monotonicNanos;
        if (elapsed < 0) {
            current.suspect.set(true);
            return 0;
        }
        return elapsed / NANOS_PER_MILLI;
    }

    private static long addBounded(long millis, long delta) {
        return delta > MAX_MILLIS - millis ? MAX_MILLIS : millis + delta;
    }
}
