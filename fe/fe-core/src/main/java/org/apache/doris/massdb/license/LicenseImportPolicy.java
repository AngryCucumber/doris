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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Pure import and pending-capacity admission. No journal, HTTP/SQL entry point or publication hook.
 * A caller must serialize the final recheck with license, membership and trust changes; persist
 * the returned facts; then publish exactly those committed facts without a second admission check.
 *
 * <p>A valid certificate with a higher sequence replaces every accepted active and pending promise.
 * Expiry, start time, quota and features are not compared with the replaced certificates; only the
 * registered plus reserved membership limits admission. Reductions are reported as changes. The one
 * exception keeps metadata readable by every earlier licensed FE: a future certificate may not lower quota.
 */
public final class LicenseImportPolicy {
    private static final long ISSUED_AT_TOLERANCE_SECONDS = 300;

    /** Fixed operator-facing change codes; they never reject or alter an import. */
    public enum ChangeCode {
        EXPIRY_SHORTENED, COVERAGE_GAP, FE_LIMIT_REDUCED, BE_LIMIT_REDUCED, PENDING_DISCARDED, FEATURES_REMOVED
    }

    /** A factual difference between the current committed promises and the accepted candidate. */
    public static final class Change {
        private final ChangeCode code;
        private final Map<String, Object> value;

        private Change(ChangeCode code, Object... fields) {
            this.code = code;
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("code", code.name());
            for (int i = 0; i < fields.length; i += 2) {
                result.put((String) fields[i], fields[i + 1]);
            }
            this.value = Collections.unmodifiableMap(result);
        }

        public ChangeCode getCode() {
            return code;
        }

        /** Response form: {@code code} followed by the code-specific numeric or identity fields. */
        public Map<String, Object> toMap() {
            return value;
        }
    }

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
        private final List<Change> changes;

        private Prepared(LicenseImportState original, Context context, LicenseImportState toPersist,
                Receipt receipt, boolean idempotent, String compact, long coverageGapSeconds) {
            this(original, context, toPersist, receipt, idempotent, compact, coverageGapSeconds,
                    Collections.emptyList());
        }

        private Prepared(LicenseImportState original, Context context, LicenseImportState toPersist,
                Receipt receipt, boolean idempotent, String compact, long coverageGapSeconds, List<Change> changes) {
            this.expectedLicenseVersion = original.getLicenseVersion();
            this.expectedMembershipVersion = context.membershipVersion;
            this.toPersist = toPersist;
            this.receipt = receipt;
            this.idempotent = idempotent;
            this.compact = compact;
            this.coverageGapSeconds = coverageGapSeconds;
            this.changes = Collections.unmodifiableList(new ArrayList<>(changes));
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

        /** Empty for idempotent receipts and base activation; never a second admission rule. */
        public List<Change> getChanges() {
            return changes;
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
        requireCapacity(candidate, context);
        long version = nextVersion(state);
        Slot normalizedActive = state.getActive();
        Slot normalizedPending = state.getPending();
        Slot base = state.getEffectiveBase();
        if (normalizedPending != null && now >= normalizedPending.getDocument().getNotBefore()) {
            normalizedActive = normalizedPending;
            base = promotedBase(base, normalizedPending);
        }
        Slot currentBase = base;
        if (candidate.getNotBefore() > now) {
            requireDowngradeReadablePending(candidate, normalizedActive, currentBase);
        }
        Slot accepted = new Slot(candidate, compact, version);
        Slot active;
        Slot pending;
        // The candidate replaces both promises. The committed pending survives only as the new active.
        if (candidate.getNotBefore() <= now) {
            active = accepted;
            pending = null;
            base = promotedBase(base, accepted);
        } else {
            active = normalizedActive;
            pending = accepted;
        }
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
        Slot discarded = state.getPending() != null && active != state.getPending() ? state.getPending() : null;
        return new Prepared(state, context, proposed, receipt, false, compact, gap,
                changes(candidate, normalizedActive, currentBase, discarded, gap));
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
        requireCapacity(pending.getDocument(), context);
        Slot base = promotedBase(state.getEffectiveBase(), pending);
        LicenseImportState proposed = LicenseImportState.restore(state.getDeploymentId(), pending, null, base,
                state.getHighestSequence(), nextVersion(state), state.getReceipts());
        return new Prepared(state, context, proposed, null, false, null, 0);
    }

    /** Capacity is not compared: the newer accepted certificate replaces the base by sequence alone. */
    private static Slot promotedBase(Slot base, Slot candidate) {
        if (base == null) {
            return candidate;
        }
        return candidate.getDocument().getSequence() > base.getDocument().getSequence() ? candidate : base;
    }

    private static List<Change> changes(LicenseDocument candidate, Slot current, Slot base, Slot discarded,
            long gap) {
        List<Change> result = new ArrayList<>();
        LicenseDocument active = current == null ? null : current.getDocument();
        if (active != null && candidate.getExpiresAt() < active.getExpiresAt()) {
            result.add(new Change(ChangeCode.EXPIRY_SHORTENED, "previous_expires_at", active.getExpiresAt(),
                    "expires_at", candidate.getExpiresAt()));
        }
        if (gap > 0) {
            result.add(new Change(ChangeCode.COVERAGE_GAP, "gap_seconds", gap));
        }
        LicenseDocument committedBase = base == null ? null : base.getDocument();
        int previousFe = -1;
        int previousBe = -1;
        for (LicenseDocument document : new LicenseDocument[] {active, committedBase}) {
            if (document != null) {
                previousFe = Math.max(previousFe, document.getMaxFeNodes());
                previousBe = Math.max(previousBe, document.getMaxBeNodes());
            }
        }
        if (candidate.getMaxFeNodes() < previousFe) {
            result.add(new Change(ChangeCode.FE_LIMIT_REDUCED, "previous_limit", previousFe,
                    "limit", candidate.getMaxFeNodes()));
        }
        if (candidate.getMaxBeNodes() < previousBe) {
            result.add(new Change(ChangeCode.BE_LIMIT_REDUCED, "previous_limit", previousBe,
                    "limit", candidate.getMaxBeNodes()));
        }
        if (discarded != null) {
            LicenseDocument pending = discarded.getDocument();
            result.add(new Change(ChangeCode.PENDING_DISCARDED, "license_id", pending.getLicenseId(),
                    "sequence", pending.getSequence()));
        }
        if (active != null) {
            List<String> removed = new ArrayList<>();
            for (String feature : active.getFeatures()) {
                if (!candidate.hasFeature(feature)) {
                    removed.add(feature);
                }
            }
            if (!removed.isEmpty()) {
                result.add(new Change(ChangeCode.FEATURES_REMOVED, "features", removed));
            }
        }
        return result;
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

    /**
     * Every licensed FE before 2026-10-15 rejects, while recovering, a pending certificate whose quota is lower
     * than the retained active or base certificate; versions before 2026-09-30 do so even after that certificate
     * expired, and the failed replay stops the FE. Never write that state, so a whole-cluster downgrade or an older
     * FE replaying newer journals is not blocked by license metadata. Lower quota must start immediately.
     */
    private static void requireDowngradeReadablePending(LicenseDocument candidate, Slot active, Slot base)
            throws LicenseException {
        for (Slot retained : new Slot[] {active, base}) {
            if (retained != null && (candidate.getMaxFeNodes() < retained.getDocument().getMaxFeNodes()
                    || candidate.getMaxBeNodes() < retained.getDocument().getMaxBeNodes())) {
                reject(LicenseErrorCode.RENEWAL_REDUCTION);
            }
        }
    }

    /** Only actual registered members plus in-flight ADD reservations; stopped or offline nodes still count. */
    private static void requireCapacity(LicenseDocument candidate, Context context) throws LicenseException {
        long requiredFe = (long) context.registeredFe + context.reservedFe;
        long requiredBe = (long) context.registeredBe + context.reservedBe;
        if (candidate.getMaxFeNodes() < requiredFe || candidate.getMaxBeNodes() < requiredBe) {
            reject(LicenseErrorCode.NODE_LIMIT_TOO_SMALL);
        }
    }

    private static void reject(LicenseErrorCode reason) throws LicenseException {
        throw new LicenseException(reason);
    }
}
