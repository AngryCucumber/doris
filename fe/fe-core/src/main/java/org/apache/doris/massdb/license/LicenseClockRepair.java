// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Management-only prepare/commit/confirm core. Store is a contract for the future P2 journal
 * adapter, not a journal implementation. Clock facts and consumed receipts commit atomically;
 * license certificates, highest accepted sequence and committed node capacities are not replaced.
 * ADMIN checks, throttling and audit belong to the future API/manager boundary.
 */
public final class LicenseClockRepair {
    public static final long CHALLENGE_VALID_SECONDS = 86400L;
    public static final int MAX_RECEIPTS = 1024;
    private static final long CHALLENGE_VALID_NANOS = CHALLENGE_VALID_SECONDS * 1_000_000_000L;

    public interface Store {
        /** Returns committed state only, never an uncommitted local proposal. */
        State load() throws StoreException;

        /**
         * Atomically compare clock version and commit facts plus receipts, preserving every
         * non-clock metadata field. The P2 adapter must also fence this write using the existing
         * FE Master/journal leadership authority; a former Master must never commit here even if
         * its local endLeadership notification is delayed. False means a definite CAS conflict.
         * An exception means
         * unknown outcome; callers must load/confirm before assuming success or retrying.
         */
        boolean compareAndSet(long expectedVersion, State replacement) throws StoreException;
    }

    public static final class StoreException extends Exception {
        public StoreException() {
            super("Clock metadata store unavailable or commit outcome unknown");
        }
    }

    public static final class Receipt {
        private final UUID repairId;
        private final long committedVersion;
        private final long clockEpoch;
        private final long correctedMillis;
        private final String keyId;
        private final String fingerprint;

        public Receipt(UUID repairId, long committedVersion, long clockEpoch, long correctedMillis,
                String keyId, String fingerprint) {
            this.repairId = Objects.requireNonNull(repairId, "repairId");
            if (committedVersion < 1 || clockEpoch < 1 || correctedMillis < 0
                    || correctedMillis > LicenseClock.MAX_MILLIS || !LicenseText.matches(keyId, 128, true)
                    || fingerprint == null || !fingerprint.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Invalid clock repair receipt");
            }
            this.committedVersion = committedVersion;
            this.clockEpoch = clockEpoch;
            this.correctedMillis = correctedMillis;
            this.keyId = keyId;
            this.fingerprint = fingerprint;
        }

        public UUID getRepairId() {
            return repairId;
        }

        public long getCommittedVersion() {
            return committedVersion;
        }

        public long getClockEpoch() {
            return clockEpoch;
        }

        public long getCorrectedMillis() {
            return correctedMillis;
        }

        public String getKeyId() {
            return keyId;
        }

        public String getFingerprint() {
            return fingerprint;
        }
    }

    /** Immutable bounded clock-only journal/image payload. */
    public static final class State {
        private final UUID deploymentId;
        private final LicenseClock.Facts facts;
        private final Map<UUID, Receipt> receipts;

        public State(UUID deploymentId, LicenseClock.Facts facts, Map<UUID, Receipt> receipts) {
            this.deploymentId = Objects.requireNonNull(deploymentId, "deploymentId");
            this.facts = Objects.requireNonNull(facts, "facts");
            if (receipts == null || receipts.size() > MAX_RECEIPTS) {
                throw new IllegalArgumentException("Invalid clock repair receipt set");
            }
            for (Map.Entry<UUID, Receipt> entry : receipts.entrySet()) {
                Receipt receipt = entry.getValue();
                if (receipt == null || !receipt.repairId.equals(entry.getKey())
                        || receipt.committedVersion > facts.getVersion()
                        || receipt.clockEpoch > facts.getClockEpoch()) {
                    throw new IllegalArgumentException("Invalid clock repair receipt");
                }
            }
            List<Receipt> ordered = new ArrayList<>(receipts.values());
            ordered.sort(Comparator.comparingLong(Receipt::getCommittedVersion));
            Map<UUID, Receipt> copy = new LinkedHashMap<>();
            long previousVersion = 0;
            long previousEpoch = 0;
            for (Receipt receipt : ordered) {
                if (receipt.committedVersion <= previousVersion || receipt.clockEpoch <= previousEpoch) {
                    throw new IllegalArgumentException("Conflicting clock repair receipt history");
                }
                previousVersion = receipt.committedVersion;
                previousEpoch = receipt.clockEpoch;
                copy.put(receipt.repairId, receipt);
            }
            this.receipts = Collections.unmodifiableMap(copy);
        }

        public UUID getDeploymentId() {
            return deploymentId;
        }

        public LicenseClock.Facts getFacts() {
            return facts;
        }

        public Map<UUID, Receipt> getReceipts() {
            return receipts;
        }
    }

    /** The nonce exists only in the issuing process/leadership term, never in replicated state. */
    public static final class Challenge {
        private final UUID deploymentId;
        private final UUID leaderTerm;
        private final String nonce;
        private final long clockEpoch;
        private final long repairAuthorizationVersion;
        private final long observedWallAt;
        private final long observedHighWaterAt;
        private final long issuedMonotonicNanos;

        private Challenge(UUID deploymentId, UUID leaderTerm, String nonce, long clockEpoch,
                long repairAuthorizationVersion, long observedWallAt, long observedHighWaterAt,
                long issuedMonotonicNanos) {
            this.deploymentId = deploymentId;
            this.leaderTerm = leaderTerm;
            this.nonce = nonce;
            this.clockEpoch = clockEpoch;
            this.repairAuthorizationVersion = repairAuthorizationVersion;
            this.observedWallAt = observedWallAt;
            this.observedHighWaterAt = observedHighWaterAt;
            this.issuedMonotonicNanos = issuedMonotonicNanos;
        }

        /** Exact challenge schema consumed by the offline issuer. No monotonic absolute value leaks. */
        public Map<String, Object> toClaims() {
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("schema_version", 1);
            fields.put("product", "MassDB SQL");
            fields.put("deployment_id", deploymentId.toString());
            fields.put("nonce", nonce);
            fields.put("clock_epoch", clockEpoch);
            fields.put("repair_authorization_version", repairAuthorizationVersion);
            fields.put("leader_term", leaderTerm.toString());
            fields.put("observed_wall_at", observedWallAt);
            fields.put("observed_high_water_at", observedHighWaterAt);
            fields.put("valid_for_seconds", CHALLENGE_VALID_SECONDS);
            return Collections.unmodifiableMap(fields);
        }

        public UUID getDeploymentId() {
            return deploymentId;
        }

        public UUID getLeaderTerm() {
            return leaderTerm;
        }

        public String getNonce() {
            return nonce;
        }

        public long getClockEpoch() {
            return clockEpoch;
        }

        public long getRepairAuthorizationVersion() {
            return repairAuthorizationVersion;
        }
    }

    /** Immutable verified proposal; cannot be constructed by clients or used in another manager. */
    public static final class PreparedRepair {
        private final LicenseClockRepair owner;
        private final Challenge challenge;
        private final LicenseClockRepairVerifier.Ticket ticket;

        private PreparedRepair(LicenseClockRepair owner, Challenge challenge,
                LicenseClockRepairVerifier.Ticket ticket) {
            this.owner = owner;
            this.challenge = challenge;
            this.ticket = ticket;
        }

        public UUID getRepairId() {
            return ticket.getRepairId();
        }

        public long getExpectedClockEpoch() {
            return ticket.getClockEpoch();
        }
    }

    private final UUID deploymentId;
    private final LicenseClock clock;
    private final LicenseClockRepairVerifier verifier;
    private final Store store;
    private final SecureRandom random;
    private UUID leaderTerm;
    private Challenge challenge;

    public LicenseClockRepair(UUID deploymentId, LicenseClock clock, LicenseClockRepairVerifier verifier, Store store) {
        this(deploymentId, clock, verifier, store, new SecureRandom());
    }

    LicenseClockRepair(UUID deploymentId, LicenseClock clock, LicenseClockRepairVerifier verifier,
            Store store, SecureRandom random) {
        this.deploymentId = Objects.requireNonNull(deploymentId, "deploymentId");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.store = Objects.requireNonNull(store, "store");
        this.random = Objects.requireNonNull(random, "random");
    }

    /** Call only after the existing FE leadership mechanism grants the local Master role. */
    public synchronized void beginLeadership() {
        leaderTerm = UUID.randomUUID();
        challenge = null;
    }

    public synchronized void endLeadership() {
        leaderTerm = null;
        challenge = null;
    }

    public synchronized Challenge newChallenge() throws LicenseRepairException {
        requireLeader();
        State before = refresh();
        long wall = clock.wallTimeMillis();
        requireValidWall(wall);
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        LicenseClock.Facts old = before.facts;
        if (old.getClockEpoch() == Long.MAX_VALUE
                || old.getRepairAuthorizationVersion() >= Long.MAX_VALUE - 1
                || old.getVersion() >= Long.MAX_VALUE - 1) {
            throw failure(LicenseRepairException.Code.VERSION_EXHAUSTED);
        }
        LicenseClock.Facts replacement = new LicenseClock.Facts(next(old.getVersion()), old.getClockEpoch(),
                old.getHighWaterMillis(), next(old.getRepairAuthorizationVersion()));
        // An uncertain replacement must never leave the previous challenge locally consumable.
        challenge = null;
        commit(before, new State(deploymentId, replacement, before.receipts));
        challenge = new Challenge(deploymentId, leaderTerm,
                Base64.getUrlEncoder().withoutPadding().encodeToString(nonce), replacement.getClockEpoch(),
                replacement.getRepairAuthorizationVersion(), wall / 1000, old.getHighWaterMillis() / 1000,
                clock.monotonicNanos());
        return challenge;
    }

    /** Called for explicit revocation or changes to repair permissions/policy, not normal renewal. */
    public synchronized void invalidateChallenge() throws LicenseRepairException {
        requireLeader();
        challenge = null;
        State before = refresh();
        LicenseClock.Facts old = before.facts;
        LicenseClock.Facts replacement = new LicenseClock.Facts(next(old.getVersion()), old.getClockEpoch(),
                old.getHighWaterMillis(), next(old.getRepairAuthorizationVersion()));
        commit(before, new State(deploymentId, replacement, before.receipts));
    }

    public synchronized PreparedRepair prepareRepair(String compact) throws LicenseRepairException {
        requireLeader();
        State current = refresh();
        LicenseClockRepairVerifier.Ticket ticket = verifier.verify(compact);
        validate(ticket, challenge, current);
        return new PreparedRepair(this, challenge, ticket);
    }

    /** Rechecks leadership, nonce, epochs, monotonic TTL and corrected wall time at actual commit. */
    public synchronized Receipt commitRepair(PreparedRepair prepared) throws LicenseRepairException {
        requireLeader();
        if (prepared == null || prepared.owner != this || prepared.challenge != challenge) {
            throw failure(LicenseRepairException.Code.STALE_PREPARATION);
        }
        State before = refresh();
        validate(prepared.ticket, prepared.challenge, before);
        long corrected = clock.wallTimeMillis();
        requireWindow(prepared.ticket, corrected);
        LicenseClock.Facts old = before.facts;
        LicenseClock.Facts replacement = new LicenseClock.Facts(next(old.getVersion()), next(old.getClockEpoch()),
                corrected, next(old.getRepairAuthorizationVersion()));
        Receipt receipt = new Receipt(prepared.ticket.getRepairId(), replacement.getVersion(),
                replacement.getClockEpoch(), corrected, prepared.ticket.getKeyId(), prepared.ticket.getFingerprint());
        Map<UUID, Receipt> receipts = new LinkedHashMap<>(before.receipts);
        receipts.put(receipt.repairId, receipt);
        while (receipts.size() > MAX_RECEIPTS) {
            receipts.remove(receipts.keySet().iterator().next());
        }
        commit(before, new State(deploymentId, replacement, receipts));
        challenge = null;
        return receipt;
    }

    /** Confirmation is read-only and works after expiry, restart or lost commit responses. */
    public synchronized Receipt confirmRepair(UUID repairId) throws LicenseRepairException {
        Objects.requireNonNull(repairId, "repairId");
        return refresh().receipts.get(repairId);
    }

    /** Periodic management checkpoint, independent of challenge authorization version. */
    public synchronized boolean checkpoint(long minimumAdvanceMillis) throws LicenseRepairException {
        requireLeader();
        State before = refresh();
        LicenseClock.Facts candidate = clock.prepareCheckpoint(minimumAdvanceMillis);
        if (candidate == null) {
            return false;
        }
        commit(before, new State(deploymentId, candidate, before.receipts));
        return true;
    }

    private State refresh() throws LicenseRepairException {
        State state;
        try {
            state = store.load();
        } catch (StoreException e) {
            throw failure(LicenseRepairException.Code.STORE_UNAVAILABLE);
        }
        if (state == null || !deploymentId.equals(state.deploymentId)
                || state.facts.getVersion() < clock.getCommittedFacts().getVersion()) {
            throw failure(LicenseRepairException.Code.STALE_PREPARATION);
        }
        clock.applyCommitted(state.facts);
        return state;
    }

    private void commit(State before, State replacement) throws LicenseRepairException {
        try {
            if (!store.compareAndSet(before.facts.getVersion(), replacement)) {
                throw failure(LicenseRepairException.Code.STALE_PREPARATION);
            }
        } catch (StoreException e) {
            throw failure(LicenseRepairException.Code.COMMIT_UNCERTAIN);
        }
        clock.applyCommitted(replacement.facts);
    }

    private void validate(LicenseClockRepairVerifier.Ticket ticket, Challenge expected, State state)
            throws LicenseRepairException {
        if (state.receipts.containsKey(ticket.getRepairId())) {
            throw failure(LicenseRepairException.Code.REPAIR_ALREADY_CONSUMED);
        }
        if (expected == null) {
            throw failure(LicenseRepairException.Code.CHALLENGE_REQUIRED);
        }
        long elapsed = clock.monotonicNanos() - expected.issuedMonotonicNanos;
        if (elapsed < 0 || elapsed >= CHALLENGE_VALID_NANOS) {
            throw failure(LicenseRepairException.Code.CHALLENGE_EXPIRED);
        }
        if (!deploymentId.equals(ticket.getDeploymentId()) || !leaderTerm.equals(ticket.getLeaderTerm())
                || !expected.leaderTerm.equals(leaderTerm) || !expected.nonce.equals(ticket.getNonce())
                || expected.clockEpoch != ticket.getClockEpoch()
                || expected.repairAuthorizationVersion != ticket.getRepairAuthorizationVersion()
                || state.facts.getClockEpoch() != expected.clockEpoch
                || state.facts.getRepairAuthorizationVersion() != expected.repairAuthorizationVersion) {
            throw failure(LicenseRepairException.Code.CHALLENGE_MISMATCH);
        }
        requireWindow(ticket, clock.wallTimeMillis());
    }

    private void requireLeader() throws LicenseRepairException {
        if (leaderTerm == null) {
            throw failure(LicenseRepairException.Code.NOT_LEADER);
        }
    }

    private static void requireWindow(LicenseClockRepairVerifier.Ticket ticket, long millis)
            throws LicenseRepairException {
        requireValidWall(millis);
        if (millis / 1000 < ticket.getNotBefore() || millis / 1000 >= ticket.getExpiresAt()) {
            throw failure(LicenseRepairException.Code.LOCAL_TIME_OUTSIDE_REPAIR_WINDOW);
        }
    }

    private static void requireValidWall(long millis) throws LicenseRepairException {
        if (millis < 0 || millis > LicenseClock.MAX_MILLIS) {
            throw failure(LicenseRepairException.Code.LOCAL_TIME_OUTSIDE_REPAIR_WINDOW);
        }
    }

    private static long next(long value) throws LicenseRepairException {
        if (value == Long.MAX_VALUE) {
            throw failure(LicenseRepairException.Code.VERSION_EXHAUSTED);
        }
        return value + 1;
    }

    private static LicenseRepairException failure(LicenseRepairException.Code code) {
        return new LicenseRepairException(code);
    }
}
