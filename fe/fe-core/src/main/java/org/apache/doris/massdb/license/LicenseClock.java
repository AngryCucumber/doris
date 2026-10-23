// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Local, injectable monotonic license clock. No query performs I/O, locking or parsing.
 *
 * <p>The confirmed trusted time is the committed watermark plus the monotonic time elapsed in this
 * process, plus wall-clock forward progress that has been confirmed. A forward wall-clock correction is
 * first a pending candidate: it is confirmed by the management thread after it has held for a while, by
 * agreement of the other FEs, or by an administrator, and it is discarded if the wall clock is corrected
 * back first. Queries, imports and watermarks use the confirmed time. Only the startup candidate (a wall
 * clock ahead of the restored watermark) also counts for admission before it is confirmed, so restarting
 * never buys time; it is still kept out of watermarks until the settling period has passed, so a wrong
 * boot clock that NTP corrects in time leaves no trace.
 *
 * <p>A wall clock behind the confirmed time is a suspicion, never a change of the trusted time. It is
 * re-evaluated on every read and clears by itself when the wall clock returns within tolerance. The
 * startup and replayed-watermark check uses the small startup tolerance; the in-process check uses the
 * large rollback tolerance. A suspicion denies queries only when this process is the serving master and
 * has left its settling period; a replicated master suspicion denies everywhere.
 */
public final class LicenseClock {
    public static final long MAX_MILLIS = 253402300799999L;
    public static final long DEFAULT_ROLLBACK_TOLERANCE_MILLIS = TimeUnit.HOURS.toMillis(12);
    public static final long DEFAULT_STARTUP_TOLERANCE_MILLIS = TimeUnit.MINUTES.toMillis(5);
    public static final long DEFAULT_SETTLING_MILLIS = TimeUnit.MINUTES.toMillis(10);
    public static final long MAX_STARTUP_TOLERANCE_MILLIS = TimeUnit.HOURS.toMillis(1);
    public static final long MAX_SETTLING_MILLIS = TimeUnit.HOURS.toMillis(1);
    /** A forward jump within the rollback tolerance is confirmed once it has held this long. */
    public static final long CONFIRM_SMALL_FORWARD_MILLIS = TimeUnit.MINUTES.toMillis(5);
    /** Any pending forward jump is accepted once it has held this long without correction or confirmation. */
    public static final long ACCEPT_FORWARD_MILLIS = TimeUnit.HOURS.toMillis(1);
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

    /** What the other FEs' wall clocks say about this one; UNKNOWN when there is no majority to compare with. */
    public enum PeerVerdict {
        UNKNOWN, AGREE, OUTLIER
    }

    /** Tolerances and the settling period; values are validated and bounded here, not by the caller. */
    public static final class Settings {
        public static final Settings DEFAULT = new Settings(DEFAULT_ROLLBACK_TOLERANCE_MILLIS,
                DEFAULT_STARTUP_TOLERANCE_MILLIS, DEFAULT_SETTLING_MILLIS);

        final long rollbackToleranceMillis;
        final long startupToleranceMillis;
        final long settlingMillis;

        public Settings(long rollbackToleranceMillis, long startupToleranceMillis, long settlingMillis) {
            if (rollbackToleranceMillis < 0 || rollbackToleranceMillis > MAX_MILLIS
                    || startupToleranceMillis < 0 || settlingMillis < 0) {
                throw new IllegalArgumentException("Invalid clock tolerances");
            }
            this.rollbackToleranceMillis = rollbackToleranceMillis;
            // The startup tolerance bounds how much downtime a wall clock reset to the pre-shutdown value can
            // skip; it never grows with the in-process tolerance.
            this.startupToleranceMillis = Math.min(startupToleranceMillis, MAX_STARTUP_TOLERANCE_MILLIS);
            this.settlingMillis = Math.min(settlingMillis, MAX_SETTLING_MILLIS);
        }

        public long getRollbackToleranceMillis() {
            return rollbackToleranceMillis;
        }

        public long getStartupToleranceMillis() {
            return startupToleranceMillis;
        }

        public long getSettlingMillis() {
            return settlingMillis;
        }
    }

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

    /** Management-side view of the pending forward correction, for status pages and logs. */
    public static final class Diagnostics {
        private final boolean localSuspect;
        private final boolean rollbackSuspect;
        private final boolean startupSuspect;
        private final boolean settled;
        private final long pendingForwardMillis;
        private final long pendingAgeMillis;
        private final boolean pendingStartup;
        private final PeerVerdict peerVerdict;

        private Diagnostics(boolean localSuspect, boolean rollbackSuspect, boolean startupSuspect, boolean settled,
                long pendingForwardMillis, long pendingAgeMillis, boolean pendingStartup, PeerVerdict peerVerdict) {
            this.localSuspect = localSuspect;
            this.rollbackSuspect = rollbackSuspect;
            this.startupSuspect = startupSuspect;
            this.settled = settled;
            this.pendingForwardMillis = pendingForwardMillis;
            this.pendingAgeMillis = pendingAgeMillis;
            this.pendingStartup = pendingStartup;
            this.peerVerdict = peerVerdict;
        }

        public boolean isLocalSuspect() {
            return localSuspect;
        }

        public boolean isRollbackSuspect() {
            return rollbackSuspect;
        }

        public boolean isStartupSuspect() {
            return startupSuspect;
        }

        public boolean isSettled() {
            return settled;
        }

        public long getPendingForwardMillis() {
            return pendingForwardMillis;
        }

        public long getPendingAgeMillis() {
            return pendingAgeMillis;
        }

        public boolean isPendingStartup() {
            return pendingStartup;
        }

        public PeerVerdict getPeerVerdict() {
            return peerVerdict;
        }
    }

    /** Outcome of one management observation, for rate-limited logging by the owner. */
    public enum Event {
        NONE, FORWARD_PENDING, FORWARD_CONFIRMED, FORWARD_DISCARDED
    }

    private static final class Anchor {
        private final Facts facts;
        /** Confirmed progress: committed watermark and confirmed forward corrections, as an offset. */
        private final AtomicLong confirmedOffsetMillis;
        /** Confirmed progress or the unconfirmed startup candidate, whichever is larger; admission only. */
        private final AtomicLong admissionOffsetMillis;
        private final long wallMillis;
        private final long monotonicNanos;
        private final long wallSampleStartNanos;
        private final AtomicBoolean rollbackSuspect;
        private final AtomicBoolean startupSuspect;

        private Anchor(Facts facts, long confirmedMillis, long admissionMillis, long wallMillis, long monotonicNanos,
                long wallSampleStartNanos, boolean startupSuspect) {
            this.facts = facts;
            this.confirmedOffsetMillis = new AtomicLong(confirmedMillis);
            this.admissionOffsetMillis = new AtomicLong(Math.max(confirmedMillis, admissionMillis));
            this.wallMillis = wallMillis;
            this.monotonicNanos = monotonicNanos;
            this.wallSampleStartNanos = wallSampleStartNanos;
            this.rollbackSuspect = new AtomicBoolean(false);
            this.startupSuspect = new AtomicBoolean(startupSuspect);
        }

        private Anchor(Facts facts, Anchor prior) {
            this.facts = facts;
            this.confirmedOffsetMillis = prior.confirmedOffsetMillis;
            this.admissionOffsetMillis = prior.admissionOffsetMillis;
            this.wallMillis = prior.wallMillis;
            this.monotonicNanos = prior.monotonicNanos;
            this.wallSampleStartNanos = prior.wallSampleStartNanos;
            this.rollbackSuspect = prior.rollbackSuspect;
            this.startupSuspect = prior.startupSuspect;
        }
    }

    /** The forward correction waiting for confirmation; management thread only. */
    private static final class Pending {
        /** The smallest offset the wall clock implied since the candidate appeared: what has held throughout. */
        private long candidateOffsetMillis;
        private final long sinceNanos;
        private final boolean startup;

        private Pending(long candidateOffsetMillis, long sinceNanos, boolean startup) {
            this.candidateOffsetMillis = candidateOffsetMillis;
            this.sinceNanos = sinceNanos;
            this.startup = startup;
        }
    }

    private final TimeSource source;
    private final Settings settings;
    private final long createdNanos;
    private volatile Anchor anchor;
    private volatile boolean enforced = true;
    private volatile boolean committedSuspect;
    private volatile PeerVerdict peerVerdict = PeerVerdict.UNKNOWN;
    private Pending pending;

    public LicenseClock(Facts restored, TimeSource source) {
        this(restored, source, Settings.DEFAULT);
    }

    public LicenseClock(Facts restored, TimeSource source, Settings settings) {
        this.source = Objects.requireNonNull(source, "source");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.createdNanos = source.monotonicNanos();
        this.anchor = freshAnchor(Objects.requireNonNull(restored, "restored"), true);
    }

    /** Allocation-free hot path; the admission time never moves backwards within an epoch. */
    public long trustedNowMillis() {
        Anchor current = anchor;
        return read(current, true);
    }

    public long trustedNowSeconds() {
        return trustedNowMillis() / 1000;
    }

    /** The confirmed time only: watermarks, imports and status pages; never ahead of what is persisted safe. */
    public long confirmedNowMillis() {
        Anchor current = anchor;
        return read(current, false);
    }

    /**
     * Whether queries must be denied for this clock. A replicated master suspicion always denies. A local
     * suspicion denies only while this process is the serving master and has left its settling period: a
     * follower's wall clock never enters its trusted time, and a wrong boot clock usually gets corrected
     * within the settling period. Allocation-free callers capture getClockEpoch(), read time, then this
     * flag and finally validate isCurrentEpoch(epoch). On an epoch change they must retry or deny.
     */
    public boolean isSuspect() {
        if (committedSuspect) {
            return true;
        }
        Anchor current = anchor;
        return enforced && (current.rollbackSuspect.get() || current.startupSuspect.get()) && settled();
    }

    /** The local suspicion as observed, regardless of role or settling; diagnostics and master persistence. */
    public boolean isLocalSuspect() {
        Anchor current = anchor;
        return current.rollbackSuspect.get() || current.startupSuspect.get();
    }

    public boolean settled() {
        long age = source.monotonicNanos() - createdNanos;
        // A monotonic clock that went backwards is itself an anomaly: fail closed rather than stay unsettled.
        return age < 0 || age >= TimeUnit.MILLISECONDS.toNanos(settings.settlingMillis);
    }

    /** The serving master enforces its own suspicion; followers and observers only report it. */
    public void setEnforced(boolean enforced) {
        this.enforced = enforced;
    }

    public boolean isEnforced() {
        return enforced;
    }

    /** The master's persisted suspicion, replicated through the record; cleared by a later record. */
    public void setCommittedSuspect(boolean committedSuspect) {
        this.committedSuspect = committedSuspect;
    }

    public boolean isCommittedSuspect() {
        return committedSuspect;
    }

    public void setPeerVerdict(PeerVerdict verdict) {
        this.peerVerdict = Objects.requireNonNull(verdict, "verdict");
    }

    public PeerVerdict getPeerVerdict() {
        return peerVerdict;
    }

    public Settings getSettings() {
        return settings;
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
        long trusted = read(current, true);
        return new Reading(trusted, current.facts.clockEpoch, isSuspect());
    }

    /**
     * Management-only preparation. The returned candidate is not applied or persisted here. Only
     * confirmed time is written, so a suspect clock cannot poison a checkpoint and a watermark is
     * written in every state; a minimum advance limits journal volume.
     */
    public synchronized Facts prepareCheckpoint(long minimumAdvanceMillis) {
        if (minimumAdvanceMillis <= 0) {
            throw new IllegalArgumentException("Checkpoint interval must be positive");
        }
        Anchor current = anchor;
        long now = read(current, false);
        if (now - current.facts.highWaterMillis < minimumAdvanceMillis) {
            return null;
        }
        if (current.facts.version == Long.MAX_VALUE) {
            throw new IllegalStateException("Clock version exhausted");
        }
        return new Facts(current.facts.version + 1, current.facts.clockEpoch, now,
                current.facts.repairAuthorizationVersion);
    }

    /**
     * Applies replicated committed facts leniently. Every record carries the whole clock state, so a
     * record that skipped predecessors is still complete; stale facts, a same-version conflict or facts
     * from an older epoch or authorization (a master that itself skipped a repair) are ignored and the
     * local clock keeps its maximum. Nothing is thrown into replay. A lower watermark is adopted only
     * in a later epoch; no local monotonic timestamp is replicated. The P2 adapter remains responsible
     * for authenticity. Returns whether the facts were adopted.
     */
    public synchronized boolean applyCommitted(Facts committed) {
        Objects.requireNonNull(committed, "committed");
        Anchor old = anchor;
        if (committed.version <= old.facts.version
                || committed.clockEpoch < old.facts.clockEpoch
                || committed.repairAuthorizationVersion < old.facts.repairAuthorizationVersion) {
            return false;
        }
        if (committed.clockEpoch > old.facts.clockEpoch) {
            // A repair resets the baseline; its corrected time is confirmed by construction.
            pending = null;
            anchor = freshAnchor(committed, false);
            return true;
        }
        // Same epoch: the watermark only ever rises. A lower replicated value aligns the version and
        // authorization but never lowers the local progress.
        Facts adopted = committed.highWaterMillis >= old.facts.highWaterMillis ? committed
                : new Facts(committed.version, committed.clockEpoch, old.facts.highWaterMillis,
                        committed.repairAuthorizationVersion);
        read(old, false);
        long wall = source.wallTimeMillis();
        if (wall < 0 || wall > MAX_MILLIS || adopted.highWaterMillis - wall > settings.startupToleranceMillis) {
            old.startupSuspect.set(true);
        }
        // The wall read (or the read above) may have been descheduled. Pair the fixed
        // watermark with the latest monotonic sample, never the stale pre-wall sample.
        long elapsed = elapsedMillis(old, source.monotonicNanos());
        confirm(old, adopted.highWaterMillis - elapsed);
        // Preserve the atomic progress object: readers of the preceding metadata view must
        // not lose an observed forward movement when a checkpoint is applied concurrently.
        anchor = new Anchor(adopted, old);
        return true;
    }

    /** Whether replicated facts would be adopted; management-side diagnostics only. */
    public boolean accepts(Facts committed) {
        Facts current = anchor.facts;
        return committed.version > current.version && committed.clockEpoch >= current.clockEpoch
                && committed.repairAuthorizationVersion >= current.repairAuthorizationVersion;
    }

    /**
     * Management cadence (about once a second). Tracks the forward correction the wall clock implies,
     * confirms it when it has held long enough, when the other FEs agree or after the acceptance bound,
     * and discards it when the wall clock is corrected back. The startup candidate waits for the settling
     * period instead. An outlier verdict suspends automatic confirmation until the peers agree or an
     * administrator confirms.
     */
    public synchronized Event observe() {
        Anchor current = anchor;
        long monotonic = source.monotonicNanos();
        long wall = source.wallTimeMillis();
        long elapsed = elapsedMillis(current, monotonic);
        long confirmed = current.confirmedOffsetMillis.get();
        if (wall < 0 || wall > MAX_MILLIS) {
            return Event.NONE;
        }
        long wallOffset = wall - elapsed;
        if (wallOffset <= confirmed) {
            boolean discarded = pending != null;
            pending = null;
            current.admissionOffsetMillis.set(confirmed);
            return discarded ? Event.FORWARD_DISCARDED : Event.NONE;
        }
        if (pending == null) {
            pending = new Pending(wallOffset, monotonic, false);
            return Event.FORWARD_PENDING;
        }
        pending.candidateOffsetMillis = Math.min(pending.candidateOffsetMillis, wallOffset);
        if (pending.candidateOffsetMillis <= confirmed) {
            // What held throughout is nothing: the correction was taken back.
            pending = null;
            current.admissionOffsetMillis.set(confirmed);
            return Event.FORWARD_DISCARDED;
        }
        long ageNanos = monotonic - pending.sinceNanos;
        boolean due;
        if (pending.startup) {
            due = ageNanos >= TimeUnit.MILLISECONDS.toNanos(settings.settlingMillis);
        } else {
            boolean small = pending.candidateOffsetMillis - confirmed <= settings.rollbackToleranceMillis;
            long waitMillis = small ? CONFIRM_SMALL_FORWARD_MILLIS : ACCEPT_FORWARD_MILLIS;
            due = ageNanos >= TimeUnit.MILLISECONDS.toNanos(waitMillis);
        }
        PeerVerdict verdict = peerVerdict;
        if (verdict == PeerVerdict.AGREE || (due && verdict != PeerVerdict.OUTLIER)) {
            confirm(current, pending.candidateOffsetMillis);
            pending = null;
            return Event.FORWARD_CONFIRMED;
        }
        return Event.NONE;
    }

    /** Administrator confirmation of the pending forward correction; returns the confirmed advance in millis. */
    public synchronized long confirmPending() {
        Anchor current = anchor;
        if (pending == null) {
            return 0;
        }
        long before = current.confirmedOffsetMillis.get();
        long after = confirm(current, pending.candidateOffsetMillis);
        pending = null;
        return Math.max(0, after - before);
    }

    public synchronized Diagnostics diagnostics() {
        Anchor current = anchor;
        long confirmed = current.confirmedOffsetMillis.get();
        long forward = pending == null ? 0 : Math.max(0, pending.candidateOffsetMillis - confirmed);
        long age = pending == null ? 0 : Math.max(0, (source.monotonicNanos() - pending.sinceNanos) / NANOS_PER_MILLI);
        return new Diagnostics(current.rollbackSuspect.get() || current.startupSuspect.get(),
                current.rollbackSuspect.get(), current.startupSuspect.get(), settled(), forward, age,
                pending != null && pending.startup, peerVerdict);
    }

    long wallTimeMillis() {
        return source.wallTimeMillis();
    }

    long monotonicNanos() {
        return source.monotonicNanos();
    }

    private Anchor freshAnchor(Facts facts, boolean startup) {
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
        boolean suspect = !paired || facts.highWaterMillis - bounded > settings.startupToleranceMillis;
        if (startup && paired && bounded > facts.highWaterMillis) {
            // A wall clock ahead of the watermark counts for admission at once (restarting buys nothing) but
            // is confirmed into watermarks only after the settling period.
            pending = new Pending(bounded, after, true);
            return new Anchor(facts, facts.highWaterMillis, bounded, bounded, after, before, suspect);
        }
        pending = null;
        // A repair's corrected time is the new confirmed baseline; the wall clock is not consulted for it.
        long confirmed = startup ? facts.highWaterMillis : Math.max(bounded, facts.highWaterMillis);
        return new Anchor(facts, confirmed, confirmed, bounded, after, paired ? before : after, suspect);
    }

    private long read(Anchor current, boolean admission) {
        // Capture progress first: a concurrent correction after our wall sample must not
        // make that older sample look like a rollback.
        long confirmed = current.confirmedOffsetMillis.get();
        long offset = admission ? Math.max(confirmed, current.admissionOffsetMillis.get()) : confirmed;
        long monotonic = source.monotonicNanos();
        long wall = source.wallTimeMillis();
        // Signed subtraction also handles System.nanoTime() wrapping across Long.MAX_VALUE.
        long elapsedNanos = monotonic - current.monotonicNanos;
        long elapsed = elapsedNanos < 0 ? 0 : elapsedNanos / NANOS_PER_MILLI;
        long expectedTrusted = addBounded(confirmed, elapsed);
        boolean validWall = wall >= 0 && wall <= MAX_MILLIS;
        // Re-evaluated on every read: a wall clock back within tolerance clears the suspicion by itself.
        // Write the shared flag only on a change so the hot path does not contend on it.
        boolean rollback = elapsedNanos < 0 || !validWall
                || expectedTrusted - wall > settings.rollbackToleranceMillis;
        if (current.rollbackSuspect.get() != rollback) {
            current.rollbackSuspect.set(rollback);
        }
        if (current.startupSuspect.get() && validWall && expectedTrusted - wall <= settings.startupToleranceMillis) {
            current.startupSuspect.set(false);
        }
        long trusted = addBounded(offset, elapsed);
        if (trusted == MAX_MILLIS) {
            current.rollbackSuspect.set(true);
        }
        return trusted;
    }

    /** Raises the confirmed offset to the candidate; the admission offset follows. Returns the new value. */
    private static long confirm(Anchor current, long candidate) {
        long confirmed = increase(current.confirmedOffsetMillis, candidate);
        increase(current.admissionOffsetMillis, confirmed);
        return confirmed;
    }

    private static long increase(AtomicLong value, long candidate) {
        long existing = value.get();
        while (candidate > existing) {
            if (value.compareAndSet(existing, candidate)) {
                return candidate;
            }
            existing = value.get();
        }
        return existing;
    }

    private static long elapsedMillis(Anchor current, long monotonic) {
        // Signed subtraction also handles System.nanoTime() wrapping across Long.MAX_VALUE.
        long elapsed = monotonic - current.monotonicNanos;
        if (elapsed < 0) {
            current.rollbackSuspect.set(true);
            return 0;
        }
        return elapsed / NANOS_PER_MILLI;
    }

    private static long addBounded(long millis, long delta) {
        return delta > MAX_MILLIS - millis ? MAX_MILLIS : millis + delta;
    }
}
