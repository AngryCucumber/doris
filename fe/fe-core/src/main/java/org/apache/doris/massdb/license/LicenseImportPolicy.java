// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.massdb.license.LicenseImportState.Receipt;
import org.apache.doris.massdb.license.LicenseImportState.Slot;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Pure import and pending-capacity admission. No journal, HTTP/SQL entry point or publication hook.
 * A caller must serialize the final recheck with license, membership and trust changes; persist
 * the returned facts; then publish exactly those committed facts without a second admission check.
 */
public final class LicenseImportPolicy {
    private static final long ISSUED_AT_TOLERANCE_SECONDS = 300;

    /** State sampled in the caller's import/membership serialization domain. */
    public static final class Context {
        private final long trustedNowSeconds;
        private final boolean clockSuspect;
        private final boolean recoveryReady;
        private final int registeredFe;
        private final int registeredBe;
        private final int reservedFe;
        private final int reservedBe;
        private final long membershipVersion;

        public Context(long trustedNowSeconds, boolean clockSuspect, boolean recoveryReady,
                int registeredFe, int registeredBe, int reservedFe, int reservedBe, long membershipVersion) {
            if (registeredFe < 0 || registeredBe < 0 || reservedFe < 0 || reservedBe < 0
                    || membershipVersion < 0) {
                throw new IllegalArgumentException("Negative membership facts");
            }
            this.trustedNowSeconds = trustedNowSeconds;
            this.clockSuspect = clockSuspect;
            this.recoveryReady = recoveryReady;
            this.registeredFe = registeredFe;
            this.registeredBe = registeredBe;
            this.reservedFe = reservedFe;
            this.reservedBe = reservedBe;
            this.membershipVersion = membershipVersion;
        }
    }

    /** A proposal only. Its toPersist value must never be published before durable success. */
    public static final class Prepared {
        private final long expectedLicenseVersion;
        private final long expectedMembershipVersion;
        private final LicenseImportState toPersist;
        private final Receipt receipt;
        private final boolean idempotent;
        private final String compact;
        private final long coverageGapSeconds;

        private Prepared(LicenseImportState original, Context context, LicenseImportState toPersist,
                Receipt receipt, boolean idempotent, String compact, long coverageGapSeconds) {
            this.expectedLicenseVersion = original.getLicenseVersion();
            this.expectedMembershipVersion = context.membershipVersion;
            this.toPersist = toPersist;
            this.receipt = receipt;
            this.idempotent = idempotent;
            this.compact = compact;
            this.coverageGapSeconds = coverageGapSeconds;
        }

        public long getExpectedLicenseVersion() {
            return expectedLicenseVersion;
        }

        public long getExpectedMembershipVersion() {
            return expectedMembershipVersion;
        }

        public LicenseImportState getToPersist() {
            return toPersist;
        }

        /** Null for base activation, which is not a second import of the same certificate. */
        public Receipt getReceipt() {
            return receipt;
        }

        public boolean isIdempotent() {
            return idempotent;
        }

        public boolean requiresPersistence() {
            return !idempotent;
        }

        public long getCoverageGapSeconds() {
            return coverageGapSeconds;
        }
    }

    public Prepared prepare(String compact, LicenseImportState state, Context context, LicenseVerifier verifier)
            throws LicenseException {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(verifier, "verifier");
        String fingerprint = LicenseVerifier.fingerprint(compact);
        Receipt previous = state.findReceipt(fingerprint);
        if (previous != null) {
            return new Prepared(state, context, state, previous, true, compact, 0);
        }
        LicenseDocument candidate = verifier.verify(compact);
        if (!state.getDeploymentId().equals(candidate.getDeploymentId())) {
            reject(LicenseErrorCode.DEPLOYMENT_MISMATCH);
        }
        if (state.hasIdentityConflict(candidate)) {
            reject(LicenseErrorCode.IMPORT_CONFLICT);
        }
        if (candidate.getSequence() <= state.getHighestSequence()) {
            reject(LicenseErrorCode.IMPORT_HISTORY_UNAVAILABLE);
        }
        requireReady(context);
        long now = context.trustedNowSeconds;
        if (candidate.getIssuedAt() > Math.min(LicenseVerifier.MAX_EPOCH_SECOND,
                now + ISSUED_AT_TOLERANCE_SECONDS)) {
            reject(LicenseErrorCode.ISSUED_IN_FUTURE);
        }
        if (candidate.getExpiresAt() <= now) {
            reject(LicenseErrorCode.CERTIFICATE_EXPIRED);
        }
        if (!candidate.hasFeature("DATA_QUERY")) {
            reject(LicenseErrorCode.FEATURE_NOT_LICENSED);
        }
        requireCapacity(candidate, state, context);
        long version = nextVersion(state);
        Slot normalizedActive = state.getActive();
        Slot normalizedPending = state.getPending();
        Slot base = state.getEffectiveBase();
        if (normalizedPending != null && now >= normalizedPending.getDocument().getNotBefore()) {
            normalizedActive = normalizedPending;
            base = promotedBase(base, normalizedPending, now);
        }
        Slot accepted = new Slot(candidate, compact, version);
        Slot active;
        Slot pending;
        if (candidate.getNotBefore() <= now) {
            active = accepted;
            pending = null;
            base = promotedBase(base, accepted, now);
        } else {
            active = normalizedActive;
            pending = accepted;
        }
        // Compare with the original accepted promises, not a mutation made during normalization.
        preserveCoverage(state.getActive(), active, pending, now);
        preserveCoverage(state.getPending(), active, pending, now);
        List<Receipt> receipts = new ArrayList<>(state.getReceipts());
        Receipt receipt = accepted.receipt();
        receipts.add(receipt);
        if (receipts.size() > LicenseImportState.MAX_RECEIPTS) {
            receipts.remove(0);
        }
        LicenseImportState proposed = LicenseImportState.restore(state.getDeploymentId(), active, pending, base,
                candidate.getSequence(), version, receipts);
        long gap = pending != null && active != null
                ? Math.max(0, pending.getDocument().getNotBefore() - active.getDocument().getExpiresAt()) : 0;
        return new Prepared(state, context, proposed, receipt, false, compact, gap);
    }

    /**
     * Re-evaluate immediately before persistence under the caller's short serialization boundary.
     * Membership/version changes require a fresh user decision; time, readiness and current trust
     * are always checked again. This method still does not durably commit anything.
     */
    public Prepared recheckForCommit(Prepared prepared, LicenseImportState current, Context context,
            LicenseVerifier currentVerifier) throws LicenseException {
        Objects.requireNonNull(prepared, "prepared");
        if (prepared.expectedLicenseVersion != current.getLicenseVersion()
                || prepared.expectedMembershipVersion != context.membershipVersion
                || !prepared.toPersist.getDeploymentId().equals(current.getDeploymentId())) {
            reject(LicenseErrorCode.STALE_IMPORT_DECISION);
        }
        return prepared.compact == null ? prepareBaseActivation(current, context)
                : prepare(prepared.compact, current, context, currentVerifier);
    }

    /**
     * Explicit durable base-capacity promotion. It remains necessary if a stopped FE missed the
     * pending certificate's entire query-validity interval. Reading a snapshot never promotes it.
     * A no-op proposal is safe to acknowledge without writing another journal record.
     */
    public Prepared prepareBaseActivation(LicenseImportState state, Context context) throws LicenseException {
        requireReady(context);
        Slot pending = state.getPending();
        if (pending == null || context.trustedNowSeconds < pending.getDocument().getNotBefore()) {
            return new Prepared(state, context, state, null, true, null, 0);
        }
        requireCapacity(pending.getDocument(), state, context);
        Slot base = promotedBase(state.getEffectiveBase(), pending, context.trustedNowSeconds);
        LicenseImportState proposed = LicenseImportState.restore(state.getDeploymentId(), pending, null, base,
                state.getHighestSequence(), nextVersion(state), state.getReceipts());
        return new Prepared(state, context, proposed, null, false, null, 0);
    }

    private static Slot promotedBase(Slot base, Slot candidate, long now) throws LicenseException {
        if (base == null) {
            return candidate;
        }
        LicenseDocument previous = base.getDocument();
        LicenseDocument next = candidate.getDocument();
        if (previous.getExpiresAt() > now && (next.getMaxFeNodes() < previous.getMaxFeNodes()
                || next.getMaxBeNodes() < previous.getMaxBeNodes())) {
            reject(LicenseErrorCode.NODE_LIMIT_TOO_SMALL);
        }
        return next.getSequence() > previous.getSequence() ? candidate : base;
    }

    private static long nextVersion(LicenseImportState state) throws LicenseException {
        if (state.getLicenseVersion() == Long.MAX_VALUE) {
            reject(LicenseErrorCode.IMPORT_CONFLICT);
        }
        return state.getLicenseVersion() + 1;
    }

    private static void requireReady(Context context) throws LicenseException {
        if (!context.recoveryReady) {
            reject(LicenseErrorCode.IMPORT_NOT_READY);
        }
        if (context.clockSuspect || context.trustedNowSeconds < 0
                || context.trustedNowSeconds > LicenseVerifier.MAX_EPOCH_SECOND) {
            reject(LicenseErrorCode.CLOCK_SUSPECT);
        }
    }

    private static void requireCapacity(LicenseDocument candidate, LicenseImportState state, Context context)
            throws LicenseException {
        long requiredFe = (long) context.registeredFe + context.reservedFe;
        long requiredBe = (long) context.registeredBe + context.reservedBe;
        for (Slot old : new Slot[] {state.getActive(), state.getPending(), state.getEffectiveBase()}) {
            // An expired promise must not prevent renewal after the registered membership has shrunk.
            // Unexpired active and future promises still protect their full accepted capacity.
            if (old != null && old.getDocument().getExpiresAt() > context.trustedNowSeconds) {
                requiredFe = Math.max(requiredFe, old.getDocument().getMaxFeNodes());
                requiredBe = Math.max(requiredBe, old.getDocument().getMaxBeNodes());
            }
        }
        if (candidate.getMaxFeNodes() < requiredFe || candidate.getMaxBeNodes() < requiredBe) {
            reject(LicenseErrorCode.NODE_LIMIT_TOO_SMALL);
        }
    }

    private static void preserveCoverage(Slot old, Slot active, Slot pending, long now) throws LicenseException {
        if (old == null) {
            return;
        }
        LicenseDocument promised = old.getDocument();
        long start = Math.max(now, promised.getNotBefore());
        long end = promised.getExpiresAt();
        if (start >= end) {
            return;
        }
        long split = pending == null ? end : pending.getDocument().getNotBefore();
        if (start < split) {
            requireCoverage(active, promised, start, Math.min(end, split));
        }
        if (end > split) {
            requireCoverage(pending, promised, Math.max(start, split), end);
        }
    }

    private static void requireCoverage(Slot slot, LicenseDocument promised, long start, long end)
            throws LicenseException {
        if (slot == null) {
            reject(LicenseErrorCode.RENEWAL_REDUCTION);
        }
        LicenseDocument actual = slot.getDocument();
        if (actual.getNotBefore() > start || actual.getExpiresAt() < end
                || !actual.getFeatures().containsAll(promised.getFeatures())
                || actual.getMaxFeNodes() < promised.getMaxFeNodes()
                || actual.getMaxBeNodes() < promised.getMaxBeNodes()) {
            reject(LicenseErrorCode.RENEWAL_REDUCTION);
        }
    }

    private static void reject(LicenseErrorCode reason) throws LicenseException {
        throw new LicenseException(reason);
    }
}
