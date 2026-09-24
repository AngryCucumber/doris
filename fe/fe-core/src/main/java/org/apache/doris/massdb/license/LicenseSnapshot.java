// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Immutable evaluation of already verified license and membership facts.
 *
 * <p>The future manager must isolate invalid recovery slots before publishing this object, and
 * supply the committed base-capacity certificate separately from active/pending query entitlement.
 * It must atomically publish snapshots after metadata application. A pending certificate cannot
 * increase the base capacity just because the wall clock advances.
 *
 * <p>This class does not implement persistence, import admission or query interception. The caller
 * supplies trusted UTC seconds or a LicenseClock, never a session/browser clock. Primary query
 * status performs bounded comparisons without allocation, I/O, locks or certificate parsing.
 * Administrative evaluations allocate immutable reason sets and never change license facts.
 */
public final class LicenseSnapshot {
    /** Independent management reasons; constructing this set is never part of queryStatus. */
    public enum Reason {
        LICENSE_NOT_READY,
        CLOCK_SUSPECT,
        MISSING,
        INVALID,
        NOT_YET_VALID,
        EXPIRED,
        FEATURE_NOT_LICENSED,
        FE_LIMIT_EXCEEDED,
        BE_LIMIT_EXCEEDED
    }

    /** Diagnostic warnings do not independently deny an otherwise valid query entitlement. */
    public enum Warning {
        INVALID_SLOTS_ISOLATED,
        BASE_CAPACITY_UNAVAILABLE
    }

    /** Allocated only for management/status consumers, not for each SQL or protocol request. */
    public static final class Evaluation {
        private final LicenseQueryStatus primaryStatus;
        private final Set<Reason> reasons;
        private final Set<Warning> warnings;

        private Evaluation(LicenseQueryStatus primaryStatus, EnumSet<Reason> reasons, EnumSet<Warning> warnings) {
            this.primaryStatus = primaryStatus;
            this.reasons = Collections.unmodifiableSet(EnumSet.copyOf(reasons));
            this.warnings = Collections.unmodifiableSet(EnumSet.copyOf(warnings));
        }

        public LicenseQueryStatus getPrimaryStatus() {
            return primaryStatus;
        }

        public Set<Reason> getReasons() {
            return reasons;
        }

        public Set<Warning> getWarnings() {
            return warnings;
        }

        public boolean isFeLimitExceeded() {
            return reasons.contains(Reason.FE_LIMIT_EXCEEDED);
        }

        public boolean isBeLimitExceeded() {
            return reasons.contains(Reason.BE_LIMIT_EXCEEDED);
        }
    }

    private static final long MAX_EPOCH_SECONDS = 253402300799L;
    private static final long EXPIRING_SECONDS = 30L * 24 * 60 * 60;

    private final UUID deploymentId;
    private final LicenseDocument active;
    private final LicenseDocument pending;
    private final LicenseDocument effectiveBaseCertificate;
    private final int registeredFe;
    private final int registeredBe;
    private final boolean licenseReady;
    private final boolean clockSuspect;
    private final boolean invalidSlotsPresent;
    private final long licenseVersion;
    private final long membershipVersion;

    public LicenseSnapshot(UUID deploymentId, LicenseDocument active, LicenseDocument pending,
            LicenseDocument effectiveBaseCertificate, int registeredFe, int registeredBe,
            boolean licenseReady, boolean clockSuspect, boolean invalidSlotsPresent,
            long licenseVersion, long membershipVersion) {
        this.deploymentId = Objects.requireNonNull(deploymentId, "deploymentId");
        if (registeredFe < 0 || registeredBe < 0 || licenseVersion < 0 || membershipVersion < 0) {
            throw new IllegalArgumentException("Negative license or membership metadata");
        }
        if (active != null && pending != null && pending.getSequence() <= active.getSequence()) {
            throw new IllegalArgumentException("Pending sequence must follow active sequence");
        }
        this.active = active;
        this.pending = pending;
        this.effectiveBaseCertificate = effectiveBaseCertificate;
        this.registeredFe = registeredFe;
        this.registeredBe = registeredBe;
        this.licenseReady = licenseReady;
        this.clockSuspect = clockSuspect;
        this.invalidSlotsPresent = invalidSlotsPresent;
        this.licenseVersion = licenseVersion;
        this.membershipVersion = membershipVersion;
    }

    /** The selected certificate is not itself an admission decision. */
    public LicenseDocument currentCertificate(long trustedNowSeconds) {
        if (pending != null && trustedNowSeconds >= pending.getNotBefore()) {
            return pending;
        }
        return active;
    }

    public LicenseQueryStatus queryStatus(long trustedNowSeconds) {
        return queryStatus(trustedNowSeconds, clockSuspect);
    }

    /**
     * Allocation-free live-clock admission. The supplied clock's current committed epoch owns
     * the time-suspect decision; the snapshot's older sampled clockSuspect flag is not reused.
     * License recovery readiness remains a snapshot prerequisite. A repair during evaluation
     * retries at most once, then denies conservatively until a stable reading is available.
     */
    public LicenseQueryStatus queryStatus(LicenseClock clock) {
        Objects.requireNonNull(clock, "clock");
        if (!licenseReady) {
            return LicenseQueryStatus.LICENSE_NOT_READY;
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            long epoch = clock.getClockEpoch();
            long now = clock.trustedNowSeconds();
            boolean suspect = clock.isSuspect();
            LicenseQueryStatus result = queryStatus(now, suspect);
            if (clock.isCurrentEpoch(epoch)) {
                return result;
            }
        }
        return LicenseQueryStatus.CLOCK_SUSPECT;
    }

    private LicenseQueryStatus queryStatus(long trustedNowSeconds, boolean currentClockSuspect) {
        if (!licenseReady) {
            return LicenseQueryStatus.LICENSE_NOT_READY;
        }
        if (currentClockSuspect || trustedNowSeconds < 0 || trustedNowSeconds > MAX_EPOCH_SECONDS) {
            return LicenseQueryStatus.CLOCK_SUSPECT;
        }
        LicenseDocument current = currentCertificate(trustedNowSeconds);
        if (current == null) {
            if (pending != null) {
                return LicenseQueryStatus.NOT_YET_VALID;
            }
            return invalidSlotsPresent ? LicenseQueryStatus.INVALID : LicenseQueryStatus.MISSING;
        }
        if (!deploymentId.equals(current.getDeploymentId())) {
            return LicenseQueryStatus.INVALID;
        }
        if (trustedNowSeconds < current.getNotBefore()) {
            return LicenseQueryStatus.NOT_YET_VALID;
        }
        if (trustedNowSeconds >= current.getExpiresAt()) {
            return LicenseQueryStatus.EXPIRED;
        }
        if (!current.hasFeature("DATA_QUERY")) {
            return LicenseQueryStatus.FEATURE_NOT_LICENSED;
        }
        // A damaged base-capacity slot must not invalidate a trustworthy query entitlement.
        // The committed base marker gates future member admission, not existing query use.
        if (registeredFe > current.getMaxFeNodes() || registeredBe > current.getMaxBeNodes()) {
            return LicenseQueryStatus.LIMIT_EXCEEDED;
        }
        return current.getExpiresAt() - trustedNowSeconds <= EXPIRING_SECONDS
                ? LicenseQueryStatus.EXPIRING : LicenseQueryStatus.VALID;
    }

    /** Uses the snapshot's sampled suspect flag; status pages with a live clock use the overload. */
    public Evaluation evaluate(long trustedNowSeconds) {
        return evaluate(trustedNowSeconds, clockSuspect);
    }

    /** Management-only, epoch-consistent diagnostics; a continuously changing epoch is suspect. */
    public Evaluation evaluate(LicenseClock clock) {
        Objects.requireNonNull(clock, "clock");
        LicenseClock.Reading reading = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            reading = clock.read();
            if (clock.isCurrentEpoch(reading.getClockEpoch())) {
                return evaluate(reading.getTrustedMillis() / 1000, reading.isSuspect());
            }
        }
        return evaluate(reading.getTrustedMillis() / 1000, true);
    }

    private Evaluation evaluate(long trustedNowSeconds, boolean currentClockSuspect) {
        EnumSet<Reason> reasons = EnumSet.noneOf(Reason.class);
        EnumSet<Warning> warnings = EnumSet.noneOf(Warning.class);
        if (!licenseReady) {
            reasons.add(Reason.LICENSE_NOT_READY);
        }
        boolean timeInRange = trustedNowSeconds >= 0 && trustedNowSeconds <= MAX_EPOCH_SECONDS;
        if (currentClockSuspect || !timeInRange) {
            reasons.add(Reason.CLOCK_SUSPECT);
        }
        if (invalidSlotsPresent) {
            warnings.add(Warning.INVALID_SLOTS_ISOLATED);
        }
        if (!hasTrustedBaseCapacity()) {
            warnings.add(Warning.BASE_CAPACITY_UNAVAILABLE);
        }
        LicenseDocument current = currentCertificate(trustedNowSeconds);
        if (current == null) {
            Reason unavailable = pending != null ? Reason.NOT_YET_VALID
                    : invalidSlotsPresent ? Reason.INVALID : Reason.MISSING;
            reasons.add(unavailable);
        } else if (!deploymentId.equals(current.getDeploymentId())) {
            reasons.add(Reason.INVALID);
        } else {
            if (timeInRange && trustedNowSeconds < current.getNotBefore()) {
                reasons.add(Reason.NOT_YET_VALID);
            }
            if (timeInRange && trustedNowSeconds >= current.getExpiresAt()) {
                reasons.add(Reason.EXPIRED);
            }
            if (!current.hasFeature("DATA_QUERY")) {
                reasons.add(Reason.FEATURE_NOT_LICENSED);
            }
            if (registeredFe > current.getMaxFeNodes()) {
                reasons.add(Reason.FE_LIMIT_EXCEEDED);
            }
            if (registeredBe > current.getMaxBeNodes()) {
                reasons.add(Reason.BE_LIMIT_EXCEEDED);
            }
        }
        return new Evaluation(queryStatus(trustedNowSeconds, currentClockSuspect), reasons, warnings);
    }

    public boolean hasTrustedBaseCapacity() {
        return effectiveBaseCertificate != null
                && deploymentId.equals(effectiveBaseCertificate.getDeploymentId());
    }

    /**
     * Committed capacity, not permission to ADD a member. The manager must still check readiness,
     * serialize membership changes and commit admission. Missing recovery data cannot imply a
     * fresh cluster: the separately proven initial bootstrap allowance is outside this class.
     */
    public int getBaseMaxFeNodes() {
        requireTrustedBaseCapacity();
        return effectiveBaseCertificate.getMaxFeNodes();
    }

    public int getBaseMaxBeNodes() {
        requireTrustedBaseCapacity();
        return effectiveBaseCertificate.getMaxBeNodes();
    }

    private void requireTrustedBaseCapacity() {
        if (!hasTrustedBaseCapacity()) {
            throw new IllegalStateException("No trusted committed base capacity");
        }
    }

    public int getRegisteredFe() {
        return registeredFe;
    }

    public int getRegisteredBe() {
        return registeredBe;
    }

    public long getLicenseVersion() {
        return licenseVersion;
    }

    public long getMembershipVersion() {
        return membershipVersion;
    }
}
