// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.common.DdlException;
import org.apache.doris.common.ErrorCode;

import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** FE-owned management service. Query consumers only read published snapshots and the trusted clock. */
public final class LicenseManager implements AutoCloseable {
    public enum Action {
        STATUS, DEPLOYMENT, VALIDATE, IMPORT, IMPORT_RECEIPT,
        CLOCK_CHALLENGE, CLOCK_REPAIR, CLOCK_REPAIR_RECEIPT
    }

    /** The existing FE journal and leadership remain the authority for durable writes. */
    public interface Host {
        boolean isMaster();

        Membership membership();

        default long frontendVersion() {
            return membership().version;
        }

        void commit(short operation, LicensePersistRecord record) throws IOException;

        boolean activationReady();

        String trustStorePath();

        Map<String, Object> localCapability(String trustDigest);
    }

    public static final class Membership {
        public final int feNodes;
        public final int beNodes;
        public final long version;

        public Membership(int feNodes, int beNodes, long version) {
            if (feNodes < 0 || beNodes < 0 || version < 0) {
                throw new IllegalArgumentException("Invalid license membership snapshot");
            }
            this.feNodes = feNodes;
            this.beNodes = beNodes;
            this.version = version;
        }
    }

    @FunctionalInterface
    public interface MembershipMutation {
        void run() throws DdlException;
    }

    private static final UUID UNINITIALIZED = new UUID(0, 0);
    private static final int MAX_RATE_IDENTITIES = 4096;
    private final Host host;
    private final boolean checkpoint;
    private final LicenseClock.TimeSource time;
    private final LicenseImportPolicy policy = new LicenseImportPolicy();
    private final ThreadPoolExecutor verification;
    private final ThreadPoolExecutor mutations;
    private final Map<String, Bucket> rates = new LinkedHashMap<>();
    private final AtomicBoolean maintenancePending = new AtomicBoolean();
    private volatile LicensePersistRecord committed;
    private volatile long appliedVersion;
    private volatile LicenseImportState imports;
    private volatile LicenseClock clock;
    private volatile LicenseClockRepair repair;
    private volatile LicenseSnapshot snapshot;
    private volatile LicenseVerifier verifier = new LicenseVerifier(Collections.emptyMap());
    private volatile LicenseClockRepairVerifier repairVerifier = new LicenseClockRepairVerifier(Collections.emptyMap());
    private volatile String trustDigest;
    private volatile boolean trustLoaded;
    private volatile boolean recoveryComplete;
    private volatile boolean recoveryIncomplete;
    private volatile boolean invalidSlots;
    private volatile boolean leader;
    private volatile boolean bootstrapEligible;
    private volatile boolean closed;
    private volatile LicensePersistRecord uncertainCommit;
    private volatile LicensePersistRecord committedPendingApply;
    private ScheduledExecutorService scheduler;

    public LicenseManager(Host host, boolean checkpoint) {
        this(host, checkpoint, LicenseClock.SYSTEM);
    }

    LicenseManager(Host host, boolean checkpoint, LicenseClock.TimeSource time) {
        this.host = host;
        this.checkpoint = checkpoint;
        this.time = time;
        verification = checkpoint ? null : executor(2, "license-verification");
        mutations = checkpoint ? null : executor(1, "license-commit");
        snapshot = new LicenseSnapshot(UNINITIALIZED, null, null, null, 0, 0,
                false, false, false, 0, 0);
    }

    private static ThreadPoolExecutor executor(int workers, String name) {
        return new ThreadPoolExecutor(workers, workers, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(32), threads(name), new ThreadPoolExecutor.AbortPolicy());
    }

    private static ThreadFactory threads(String name) {
        AtomicInteger next = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, name + "-" + next.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    public LicenseManagementResult execute(Action action, String payload, String principal, boolean administrator)
            throws LicenseManagementException {
        if (closed || checkpoint) {
            throw failure("LICENSE_NOT_READY", 503, "NOT_SUBMITTED", null);
        }
        if (action == Action.STATUS) {
            return status(administrator);
        }
        if (!administrator) {
            throw failure("LICENSE_ADMIN_REQUIRED", 403, "NOT_SUBMITTED", null);
        }
        if (!host.isMaster() || !leader) {
            throw failure("LICENSE_NOT_LEADER", 503, "NOT_SUBMITTED", null);
        }
        requireInitialized();
        if (action == Action.DEPLOYMENT) {
            Membership membership = host.membership();
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("schema_version", 1);
            body.put("product", "MassDB SQL");
            body.put("deployment_id", committed.getDeploymentId().toString());
            body.put("registered_fe_nodes", membership.feNodes);
            body.put("registered_be_nodes", membership.beNodes);
            return new LicenseManagementResult(200, body);
        }
        if (action == Action.IMPORT_RECEIPT) {
            return importReceipt(payload);
        }
        if (action == Action.CLOCK_REPAIR_RECEIPT) {
            return repairReceipt(payload);
        }
        // Size rejection precedes rate accounting, queue allocation and cryptographic verification.
        if (action != Action.CLOCK_CHALLENGE) {
            int maximum = action == Action.CLOCK_REPAIR ? LicenseClockRepairVerifier.MAX_COMPACT_LENGTH
                    : LicenseVerifier.MAX_COMPACT_LENGTH;
            if (payload == null || payload.length() > maximum) {
                throw failure("LICENSE_INPUT_TOO_LARGE", 400, "NOT_SUBMITTED", null);
            }
        }
        rate(principal);
        String fingerprint = null;
        if (action == Action.IMPORT || action == Action.VALIDATE || action == Action.CLOCK_REPAIR) {
            try {
                fingerprint = LicenseVerifier.fingerprint(payload);
            } catch (LicenseException e) {
                throw importFailure(e, null);
            }
        }
        try {
            return await(submit(verification, () -> manage(action, payload)), fingerprint);
        } catch (LicenseManagementException failure) {
            if (action == Action.CLOCK_REPAIR && "UNKNOWN".equals(failure.getBody().get("submission_status"))) {
                throw new LicenseManagementException(failure.getReason(), failure.getHttpStatus(), "UNKNOWN",
                        fingerprint, LicenseConfirmationIds.repairIdHint(payload), 0, getAppliedVersion());
            }
            throw failure;
        }
    }

    private LicenseManagementResult manage(Action action, String payload) throws LicenseManagementException {
        requireInitialized();
        if (action == Action.CLOCK_CHALLENGE) {
            return mutate(() -> {
                requireWritable();
                try {
                    Map<String, Object> body = response("LICENSE_APPLIED", "APPLIED", null, getAppliedVersion());
                    body.put("challenge", repair.newChallenge().toClaims());
                    body.put("committed_version", getAppliedVersion());
                    body.put("applied_version", getAppliedVersion());
                    return new LicenseManagementResult(200, body);
                } catch (LicenseRepairException e) {
                    if (committedPendingApply != null) {
                        return knownCommit(null, null);
                    }
                    throw repairFailure(e);
                }
            }, null);
        }
        if (action == Action.CLOCK_REPAIR) {
            return repair(payload);
        }
        final String fingerprint;
        final LicenseImportPolicy.Prepared prepared;
        try {
            fingerprint = LicenseVerifier.fingerprint(payload);
            LicensePersistRecord pending = committedPendingApply;
            if (action == Action.IMPORT && pending != null
                    && pending.submissionVersion(fingerprint) > getAppliedVersion()) {
                return importReceipt(fingerprint);
            }
            prepared = policy.prepare(payload, imports, context(), verifier);
        } catch (LicenseException e) {
            throw importFailure(e, null);
        }
        if (action == Action.VALIDATE) {
            Map<String, Object> body = response("LICENSE_VALIDATED", "NOT_SUBMITTED", fingerprint, 0);
            body.put("idempotent", prepared.isIdempotent());
            body.put("coverage_gap_seconds", prepared.getCoverageGapSeconds());
            body.put("expected_license_version", prepared.getExpectedLicenseVersion());
            body.put("expected_membership_version", prepared.getExpectedMembershipVersion());
            return new LicenseManagementResult(200, body);
        }
        if (prepared.isIdempotent()) {
            return importReceipt(fingerprint);
        }
        final long frontendVersion = host.frontendVersion();
        final String packageDigest = (String) capability().get("package_sha256");
        if (!committed.matchesRollout(packageDigest, trustDigest, frontendVersion) && !host.activationReady()) {
            throw failure("LICENSE_FE_UPGRADE_REQUIRED", 503, "NOT_SUBMITTED", fingerprint);
        }
        return mutate(() -> {
            try {
                LicensePersistRecord pending = committedPendingApply;
                if (pending != null && pending.submissionVersion(fingerprint) > getAppliedVersion()) {
                    return importReceipt(fingerprint);
                }
                LicenseImportState.Receipt previous = imports.findReceipt(fingerprint);
                if (previous != null) {
                    return importReceipt(fingerprint);
                }
                requireWritable();
                LicenseImportPolicy.Prepared checked = policy.recheckForCommit(prepared, imports, context(), verifier);
                if (frontendVersion != host.frontendVersion()) {
                    throw failure("LICENSE_STALE_IMPORT_DECISION", 409, "NOT_SUBMITTED", fingerprint);
                }
                LicensePersistRecord next = committed.withImports(LicensePersistRecord.ACCEPT,
                        checked.getToPersist(), true).withRollout(packageDigest, trustDigest, frontendVersion);
                persist(next, fingerprint);
                return importReceipt(fingerprint);
            } catch (LicenseException e) {
                throw importFailure(e, fingerprint);
            } catch (IOException e) {
                throw failure("LICENSE_METADATA_UNAVAILABLE", 503, "NOT_SUBMITTED", fingerprint);
            }
        }, fingerprint);
    }

    private LicenseManagementResult repair(String payload) throws LicenseManagementException {
        final LicenseClockRepairVerifier.Ticket ticket;
        try {
            ticket = repairVerifier.verify(payload);
        } catch (LicenseRepairException e) {
            throw repairFailure(e);
        }
        return mutate(() -> {
            try {
                LicensePersistRecord pending = committedPendingApply;
                if (pending != null) {
                    LicenseClockRepair.Receipt waiting = pending.clockState().getReceipts().get(ticket.getRepairId());
                    if (waiting != null && pending.submissionVersion(waiting.getFingerprint()) > getAppliedVersion()) {
                        if (!waiting.getFingerprint().equals(ticket.getFingerprint())) {
                            throw failure("LICENSE_REPAIR_CONFLICT", 409, "NOT_SUBMITTED", ticket.getFingerprint());
                        }
                        return knownCommit(pending, ticket.getFingerprint(), ticket.getRepairId().toString());
                    }
                }
                LicenseClockRepair.Receipt previous = committed.clockState().getReceipts().get(ticket.getRepairId());
                if (previous != null) {
                    if (!previous.getFingerprint().equals(ticket.getFingerprint())) {
                        throw failure("LICENSE_REPAIR_CONFLICT", 409, "NOT_SUBMITTED", ticket.getFingerprint());
                    }
                    return repairReceipt(ticket.getRepairId().toString());
                }
                requireWritable();
                repair.commitRepair(repair.prepareRepair(payload));
                return repairReceipt(ticket.getRepairId().toString());
            } catch (LicenseRepairException e) {
                if (committedPendingApply != null) {
                    return knownCommit(ticket.getFingerprint(), ticket.getRepairId().toString());
                }
                LicenseManagementException failure = repairFailure(e);
                throw new LicenseManagementException(failure.getReason(), failure.getHttpStatus(),
                        (String) failure.getBody().get("submission_status"), ticket.getFingerprint(),
                        ticket.getRepairId().toString(), 0, getAppliedVersion());
            } catch (IOException e) {
                throw failure("LICENSE_NOT_READY", 503, "UNKNOWN", ticket.getFingerprint());
            }
        }, ticket.getFingerprint());
    }

    private synchronized LicenseManagementResult importReceipt(String fingerprint) throws LicenseManagementException {
        if (fingerprint == null || !fingerprint.matches("[0-9a-f]{64}")) {
            throw failure("LICENSE_INVALID_FINGERPRINT", 400, "NOT_SUBMITTED", null);
        }
        LicensePersistRecord pending = committedPendingApply;
        if (pending != null && pending.submissionVersion(fingerprint) > getAppliedVersion()) {
            return knownCommit(pending, fingerprint, null);
        }
        LicenseImportState.Receipt receipt = imports.findReceipt(fingerprint);
        if (receipt == null) {
            throw failure("LICENSE_IMPORT_HISTORY_UNAVAILABLE", 503, "UNKNOWN", fingerprint);
        }
        long version = committed.submissionVersion(fingerprint);
        if (version == 0) {
            throw failure("LICENSE_IMPORT_HISTORY_UNAVAILABLE", 503, "UNKNOWN", fingerprint);
        }
        Map<String, Object> body = response("LICENSE_APPLIED", "APPLIED", fingerprint, version);
        body.put("license_id", receipt.getLicenseId());
        body.put("sequence", receipt.getSequence());
        body.put("license_version", receipt.getCommittedVersion());
        return new LicenseManagementResult(200, body);
    }

    private synchronized LicenseManagementResult repairReceipt(String id) throws LicenseManagementException {
        try {
            UUID parsed = UUID.fromString(id);
            if (!parsed.toString().equals(id)) {
                throw new IllegalArgumentException();
            }
            LicensePersistRecord pending = committedPendingApply;
            if (pending != null) {
                LicenseClockRepair.Receipt waiting = pending.clockState().getReceipts().get(parsed);
                if (waiting != null && pending.submissionVersion(waiting.getFingerprint()) > getAppliedVersion()) {
                    return knownCommit(pending, waiting.getFingerprint(), id);
                }
            }
            LicenseClockRepair.Receipt receipt = committed.clockState().getReceipts().get(parsed);
            if (receipt == null) {
                throw failure("LICENSE_REPAIR_HISTORY_UNAVAILABLE", 503, "UNKNOWN", null);
            }
            long version = committed.submissionVersion(receipt.getFingerprint());
            Map<String, Object> body = response("LICENSE_APPLIED", "APPLIED", receipt.getFingerprint(), version);
            body.put("repair_id", id);
            body.put("clock_epoch", receipt.getClockEpoch());
            return new LicenseManagementResult(200, body);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw failure("LICENSE_INVALID_REPAIR_ID", 400, "NOT_SUBMITTED", null);
        } catch (IOException e) {
            throw failure("LICENSE_NOT_READY", 503, "UNKNOWN", null);
        }
    }

    private synchronized LicenseManagementResult status(boolean administrator) {
        LicenseClock currentClock = clock;
        LicenseSnapshot current = snapshot;
        LicenseClock.Reading reading = currentClock == null ? null : currentClock.read();
        long seconds = reading == null ? 0 : reading.getTrustedMillis() / 1000;
        LicenseSnapshot.Evaluation evaluation = reading == null ? current.evaluate(seconds) : current.evaluate(reading);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", evaluation.getPrimaryStatus().name());
        LicenseImportState state = imports;
        LicenseDocument effective = state == null ? null : currentCertificate(state, seconds);
        body.put("expires_at", effective == null ? null : effective.getExpiresAt());
        body.put("administrator", administrator);
        if (administrator) {
            LicensePersistRecord record = committed;
            body.put("deployment_id", record == null ? null : record.getDeploymentId().toString());
            body.put("activated", record != null && record.isActivated());
            body.put("recovery_ready", ready());
            body.put("reasons", evaluation.getReasons());
            body.put("warnings", evaluation.getWarnings());
            body.put("trusted_utc", seconds);
            body.put("clock_epoch", reading == null ? null : reading.getClockEpoch());
            body.put("registered_fe_nodes", current.getRegisteredFe());
            body.put("registered_be_nodes", current.getRegisteredBe());
            body.put("max_fe_nodes", effective == null ? null : effective.getMaxFeNodes());
            body.put("max_be_nodes", effective == null ? null : effective.getMaxBeNodes());
            body.put("base_max_fe_nodes", current.hasTrustedBaseCapacity() ? current.getBaseMaxFeNodes() : null);
            body.put("base_max_be_nodes", current.hasTrustedBaseCapacity() ? current.getBaseMaxBeNodes() : null);
            body.put("active", state == null ? null : details(state.getActive()));
            body.put("pending", state == null ? null : details(state.getPending()));
            body.put("highest_sequence", state == null ? 0 : state.getHighestSequence());
            body.put("applied_version", getAppliedVersion());
        }
        return new LicenseManagementResult(200, body);
    }

    private static LicenseDocument currentCertificate(LicenseImportState state, long seconds) {
        if (state.getPending() != null && seconds >= state.getPending().getDocument().getNotBefore()) {
            return state.getPending().getDocument();
        }
        return state.getActive() == null ? null : state.getActive().getDocument();
    }

    private static Map<String, Object> details(LicenseImportState.Slot slot) {
        if (slot == null) {
            return null;
        }
        LicenseDocument document = slot.getDocument();
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("license_id", document.getLicenseId());
        value.put("fingerprint", document.getFingerprint());
        value.put("customer_id", document.getCustomerId());
        value.put("issuer", document.getIssuer());
        value.put("edition", document.getEdition());
        value.put("sequence", document.getSequence());
        value.put("not_before", document.getNotBefore());
        value.put("expires_at", document.getExpiresAt());
        value.put("max_fe_nodes", document.getMaxFeNodes());
        value.put("max_be_nodes", document.getMaxBeNodes());
        value.put("features", document.getFeatures());
        return value;
    }

    private LicenseImportPolicy.Context context() {
        Membership members = host.membership();
        LicenseClock.Reading reading = clock.read();
        return new LicenseImportPolicy.Context(reading.getTrustedMillis() / 1000, reading.isSuspect(), ready(),
                members.feNodes, members.beNodes, 0, 0, members.version);
    }

    private boolean ready() {
        return recoveryComplete && !recoveryIncomplete && uncertainCommit == null && committedPendingApply == null
                && committed != null && trustDigest != null;
    }

    private void requireInitialized() throws LicenseManagementException {
        if (!recoveryComplete || recoveryIncomplete || committed == null || imports == null || repair == null) {
            throw failure("LICENSE_NOT_READY", 503, "NOT_SUBMITTED", null);
        }
    }

    private void requireWritable() throws LicenseManagementException {
        requireInitialized();
        if (!leader || !host.isMaster()) {
            throw failure("LICENSE_NOT_LEADER", 503, "NOT_SUBMITTED", null);
        }
        if (uncertainCommit != null) {
            throw failure("LICENSE_COMMIT_UNCERTAIN", 503, "UNKNOWN", null);
        }
        if (committedPendingApply != null) {
            throw failure("LICENSE_NOT_READY", 503, "NOT_SUBMITTED", null);
        }
    }

    private Map<String, Object> response(String reason, String submission, String fingerprint, long version) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", reason);
        body.put("message", reason);
        body.put("retryable", false);
        body.put("submission_status", submission);
        body.put("fingerprint", fingerprint);
        body.put("committed_version", version);
        body.put("applied_version", getAppliedVersion());
        return body;
    }

    private LicenseManagementException failure(String reason, int status, String submission, String fingerprint) {
        return new LicenseManagementException(reason, status, submission, fingerprint, 0, getAppliedVersion());
    }

    private LicenseManagementException importFailure(LicenseException exception, String fingerprint) {
        LicenseErrorCode code = exception.getErrorCode();
        int status;
        switch (code) {
            case IMPORT_CONFLICT:
            case STALE_IMPORT_DECISION:
                status = 409;
                break;
            case IMPORT_NOT_READY:
            case VERIFICATION_UNAVAILABLE:
            case IMPORT_HISTORY_UNAVAILABLE:
                status = 503;
                break;
            default:
                status = 400;
        }
        return failure("LICENSE_" + code.name(), status,
                code == LicenseErrorCode.IMPORT_HISTORY_UNAVAILABLE ? "UNKNOWN" : "NOT_SUBMITTED", fingerprint);
    }

    private LicenseManagementException repairFailure(LicenseRepairException exception) {
        LicenseRepairException.Code code = exception.getCode();
        int status = code == LicenseRepairException.Code.COMMIT_UNCERTAIN
                || code == LicenseRepairException.Code.STORE_UNAVAILABLE
                || code == LicenseRepairException.Code.NOT_LEADER ? 503
                : code == LicenseRepairException.Code.STALE_PREPARATION ? 409 : 400;
        return failure("LICENSE_" + code.name(), status,
                code == LicenseRepairException.Code.COMMIT_UNCERTAIN ? "UNKNOWN" : "NOT_SUBMITTED", null);
    }

    private static final class Bucket {
        double tokens = 3;
        long at;
        final ArrayDeque<Long> recent = new ArrayDeque<>();

        Bucket(long at) {
            this.at = at;
        }
    }

    private void rate(String principal) throws LicenseManagementException {
        if (principal == null || principal.length() > 1024) {
            throw failure("LICENSE_ADMIN_REQUIRED", 403, "NOT_SUBMITTED", null);
        }
        long now = time.monotonicNanos();
        synchronized (rates) {
            Bucket bucket = rates.get(principal);
            if (bucket == null) {
                Iterator<Bucket> existing = rates.values().iterator();
                while (existing.hasNext()) {
                    if (now - existing.next().at >= TimeUnit.MINUTES.toNanos(1)) {
                        existing.remove();
                    }
                }
                if (rates.size() >= MAX_RATE_IDENTITIES) {
                    throw failure("LICENSE_RATE_LIMITED", 429, "NOT_SUBMITTED", null);
                }
                bucket = new Bucket(now);
                rates.put(principal, bucket);
            }
            long elapsed = Math.max(0, now - bucket.at);
            bucket.tokens = Math.min(3, bucket.tokens + elapsed / 6_000_000_000.0);
            bucket.at = now;
            while (!bucket.recent.isEmpty() && now - bucket.recent.peekFirst() >= TimeUnit.MINUTES.toNanos(1)) {
                bucket.recent.removeFirst();
            }
            if (bucket.tokens < 1 || bucket.recent.size() >= 10) {
                throw failure("LICENSE_RATE_LIMITED", 429, "NOT_SUBMITTED", null);
            }
            bucket.tokens--;
            bucket.recent.addLast(now);
        }
    }

    private Future<LicenseManagementResult> submit(ThreadPoolExecutor executor,
            Callable<LicenseManagementResult> work) throws LicenseManagementException {
        try {
            return executor.submit(work);
        } catch (RejectedExecutionException e) {
            throw failure("LICENSE_MANAGEMENT_BUSY", 429, "NOT_SUBMITTED", null);
        }
    }

    private LicenseManagementResult mutate(Callable<LicenseManagementResult> work, String fingerprint)
            throws LicenseManagementException {
        return await(submit(mutations, work), fingerprint);
    }

    /**
     * Serialize member admission, its existing journal acknowledgement and publication with imports/base activation.
     * The caller must enter before acquiring Env/member locks; journal callbacks never acquire this queue.
     * Removal is permitted even when license recovery or time is unavailable, retaining existing safety checks.
     */
    public void runMembershipMutation(int additionalFe, int additionalBe, MembershipMutation work)
            throws DdlException {
        if (additionalFe < 0 || additionalBe < 0) {
            throw new IllegalArgumentException("Negative license member admission");
        }
        if (closed || checkpoint) {
            throw new DdlException("LICENSE_NOT_READY", ErrorCode.ERR_LICENSE_NOT_READY);
        }
        final Future<?> future;
        try {
            future = mutations.submit(() -> {
                if (!leader || !host.isMaster()) {
                    throw new DdlException("LICENSE_NOT_LEADER", ErrorCode.ERR_LICENSE_NOT_READY);
                }
                if (additionalFe != 0 || additionalBe != 0) {
                    requireCapacity(additionalFe, additionalBe);
                }
                try {
                    work.run();
                } finally {
                    // Existing ADD may have registered an earlier batch member before a later journal failure.
                    // Count that authoritative state even on failure; never invent a rollback/free reservation.
                    publish();
                }
                return null;
            });
        } catch (RejectedExecutionException e) {
            throw new DdlException("LICENSE_MANAGEMENT_BUSY", ErrorCode.ERR_LICENSE_NOT_READY);
        }
        try {
            future.get();
        } catch (InterruptedException e) {
            future.cancel(false);
            if (future instanceof Runnable) {
                mutations.remove((Runnable) future);
            }
            Thread.currentThread().interrupt();
            throw new DdlException("LICENSE_MEMBERSHIP_COMMIT_UNCERTAIN", ErrorCode.ERR_LICENSE_NOT_READY);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof DdlException) {
                throw (DdlException) e.getCause();
            }
            if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            }
            if (e.getCause() instanceof Error) {
                throw (Error) e.getCause();
            }
            throw new DdlException("LICENSE_MEMBERSHIP_COMMIT_UNCERTAIN", ErrorCode.ERR_LICENSE_NOT_READY);
        }
    }

    private void requireCapacity(int additionalFe, int additionalBe) throws DdlException {
        if (!ready()) {
            throw new DdlException("LICENSE_NOT_READY", ErrorCode.ERR_LICENSE_NOT_READY);
        }
        Membership members = host.membership();
        LicenseImportState currentImports = imports;
        LicenseSnapshot current = snapshot(currentImports, members, true, invalidSlots);
        int maxFe;
        int maxBe;
        if (current.hasTrustedBaseCapacity()) {
            maxFe = current.getBaseMaxFeNodes();
            maxBe = current.getBaseMaxBeNodes();
        } else if (committed.isBootstrap() && !committed.isActivated() && imports.getHighestSequence() == 0) {
            // The real initial FE is installed by Env bootstrap, never inferred from missing/corrupt slots.
            maxFe = 1;
            maxBe = 0;
        } else {
            throw new DdlException("LICENSE_BASE_CAPACITY_UNAVAILABLE", ErrorCode.ERR_LICENSE_NOT_READY);
        }
        // An accepted smaller renewal reserves its ceiling until activation commits the new base.
        // Larger pending limits never grant capacity early. This is only on the member ADD path.
        if (currentImports.getPending() != null) {
            LicenseDocument pending = currentImports.getPending().getDocument();
            maxFe = Math.min(maxFe, pending.getMaxFeNodes());
            maxBe = Math.min(maxBe, pending.getMaxBeNodes());
        }
        if ((long) members.feNodes + additionalFe > maxFe) {
            throw new DdlException("LICENSE_FE_LIMIT_EXCEEDED", ErrorCode.ERR_LICENSE_CONFLICT);
        }
        if ((long) members.beNodes + additionalBe > maxBe) {
            throw new DdlException("LICENSE_BE_LIMIT_EXCEEDED", ErrorCode.ERR_LICENSE_CONFLICT);
        }
    }

    /** Replay and image load only refresh the immutable view; they do not perform new member admission. */
    public void onMembershipChanged() {
        publish();
    }

    private LicenseManagementResult await(Future<LicenseManagementResult> future, String fingerprint)
            throws LicenseManagementException {
        try {
            return future.get();
        } catch (InterruptedException e) {
            // Interrupting the requester cannot prove that the journal did not commit.
            future.cancel(false);
            if (future instanceof Runnable) {
                verification.remove((Runnable) future);
                mutations.remove((Runnable) future);
            }
            Thread.currentThread().interrupt();
            throw failure("LICENSE_COMMIT_UNCERTAIN", 503, "UNKNOWN", fingerprint);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof LicenseManagementException) {
                LicenseManagementException failure = (LicenseManagementException) e.getCause();
                if (failure.getHttpStatus() == 202) {
                    return new LicenseManagementResult(202, failure.getBody());
                }
                throw failure;
            }
            throw failure("LICENSE_MANAGEMENT_UNAVAILABLE", 503, "UNKNOWN", fingerprint);
        }
    }

    /** No state monitor is held across the existing journal's durable acknowledgement. */
    private void persist(LicensePersistRecord next, String fingerprint) throws LicenseManagementException {
        if (!leader || !host.isMaster() || recoveryIncomplete) {
            throw failure("LICENSE_NOT_LEADER", 503, "NOT_SUBMITTED", fingerprint);
        }
        try {
            host.commit(next.getOperation(), next);
        } catch (IOException | RuntimeException e) {
            uncertainCommit = next;
            publishUnavailable();
            throw failure("LICENSE_COMMIT_UNCERTAIN", 503, "UNKNOWN", fingerprint);
        }
        try {
            committedPendingApply = next;
            replay(next);
            if (getAppliedVersion() != next.getVersion()) {
                throw new IOException("License record was not applied");
            }
            committedPendingApply = null;
        } catch (IOException | RuntimeException e) {
            // A local application failure cannot undo the acknowledged journal commit.
            // Keep its receipt confirmable and retry this exact record before any later mutation.
            publishUnavailable();
            throw new LicenseManagementException("LICENSE_COMMITTED_PENDING_APPLY", 202, "COMMITTED",
                    fingerprint, next.getVersion(), getAppliedVersion());
        }
    }

    private LicenseManagementResult knownCommit(String fingerprint, String repairId) {
        return knownCommit(committedPendingApply, fingerprint, repairId);
    }

    private LicenseManagementResult knownCommit(LicensePersistRecord record, String fingerprint, String repairId) {
        Map<String, Object> body = response("LICENSE_COMMITTED_PENDING_APPLY", "COMMITTED", fingerprint,
                record.getVersion());
        body.put("retryable", true);
        if (repairId != null) {
            body.put("repair_id", repairId);
        }
        return new LicenseManagementResult(202, body);
    }

    public synchronized void replay(LicensePersistRecord record) throws IOException {
        loadTrust();
        if (committed != null && record.getVersion() == appliedVersion && record.sameAs(committed)) {
            return;
        }
        if (committed == null ? record.getVersion() != 1
                : record.getVersion() != committed.getVersion() + 1
                    || !record.getDeploymentId().equals(committed.getDeploymentId())
                    || committed.isActivated() && !record.isActivated()
                    || record.isBootstrap() != committed.isBootstrap()) {
            markRecoveryIncomplete();
            return;
        }
        apply(record);
    }

    private void apply(LicensePersistRecord record) throws IOException {
        LicensePersistRecord.Restored restored = record.restore(verifier);
        LicenseClockRepair.State clockState = record.clockState();
        // Prepare all fallible metadata/snapshot work before replacing any published facts.
        Membership members = host.membership();
        boolean complete = recoveryComplete && !recoveryIncomplete && record.isComplete() && trustDigest != null
                && (uncertainCommit == null || record.sameAs(uncertainCommit))
                && (committedPendingApply == null || record.sameAs(committedPendingApply));
        LicenseSnapshot replacement = snapshot(restored.imports, members, complete, restored.invalidSlots);
        LicenseClock nextClock = clock == null ? new LicenseClock(clockState.getFacts(), time) : clock;
        LicenseClockRepair nextRepair = repair;
        if (!checkpoint && nextRepair == null) {
            nextRepair = new LicenseClockRepair(record.getDeploymentId(), nextClock, repairVerifier, new ClockStore());
            if (leader && host.isMaster()) {
                nextRepair.beginLeadership();
            }
        }
        if (clock != null) {
            try {
                nextClock.applyCommitted(clockState.getFacts());
            } catch (IllegalArgumentException e) {
                throw new IOException("Inconsistent committed license clock");
            }
        }
        if (record.isClockSuspect()) {
            nextClock.restoreSuspect();
        }
        clock = nextClock;
        repair = nextRepair;
        imports = restored.imports;
        invalidSlots = restored.invalidSlots;
        committed = record;
        if (!record.isComplete()) {
            recoveryIncomplete = true;
        }
        if (record.sameAs(uncertainCommit)) {
            uncertainCommit = null;
        }
        if (record.sameAs(committedPendingApply)) {
            committedPendingApply = null;
        }
        snapshot = replacement;
        appliedVersion = record.getVersion();
    }

    private final class ClockStore implements LicenseClockRepair.Store {
        @Override
        public LicenseClockRepair.State load() throws LicenseClockRepair.StoreException {
            try {
                return committed.clockState();
            } catch (IOException | RuntimeException e) {
                throw new LicenseClockRepair.StoreException();
            }
        }

        @Override
        public boolean compareAndSet(long expectedVersion, LicenseClockRepair.State replacement)
                throws LicenseClockRepair.StoreException {
            try {
                requireWritable();
                if (committed.clockState().getFacts().getVersion() != expectedVersion) {
                    return false;
                }
                short operation = replacement.getFacts().getClockEpoch() > clock.getClockEpoch()
                        || replacement.getFacts().getRepairAuthorizationVersion()
                            != clock.getCommittedFacts().getRepairAuthorizationVersion()
                        ? LicensePersistRecord.REPAIR : LicensePersistRecord.WATERMARK;
                persist(committed.withClock(operation, replacement), null);
                return true;
            } catch (LicenseManagementException | IOException e) {
                throw new LicenseClockRepair.StoreException();
            }
        }
    }

    private synchronized void loadTrust() {
        if (trustLoaded) {
            return;
        }
        trustLoaded = true;
        String path = host.trustStorePath();
        if (path == null || path.isEmpty()) {
            return;
        }
        try (InputStream input = Files.newInputStream(Paths.get(path))) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int count;
            while (buffer.size() <= 65536
                    && (count = input.read(chunk, 0, Math.min(chunk.length, 65537 - buffer.size()))) != -1) {
                buffer.write(chunk, 0, count);
            }
            byte[] bytes = buffer.toByteArray();
            LicenseTrustStore trust = LicenseTrustStore.parse(bytes);
            verifier = trust.newLicenseVerifier();
            repairVerifier = new LicenseClockRepairVerifier(trust.getKeys(LicenseTrustStore.Purpose.TIME_REPAIR));
            trustDigest = digest(bytes);
        } catch (IOException | LicenseException | RuntimeException e) {
            // Management remains available for diagnostics; no fallback key or implicit entitlement.
            trustDigest = null;
        }
    }

    private static String digest(byte[] bytes) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder result = new StringBuilder(64);
            for (byte value : hash) {
                result.append(String.format("%02x", value & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable");
        }
    }

    private synchronized void publish() {
        snapshot = snapshot(imports, host.membership(), ready(), invalidSlots);
    }

    private synchronized void publishUnavailable() {
        LicenseSnapshot previous = snapshot;
        snapshot = snapshot(imports, new Membership(previous.getRegisteredFe(), previous.getRegisteredBe(),
                previous.getMembershipVersion()), false, invalidSlots);
    }

    private static LicenseSnapshot snapshot(LicenseImportState state, Membership members,
            boolean ready, boolean invalidSlots) {
        return new LicenseSnapshot(state == null ? UNINITIALIZED : state.getDeploymentId(),
                state == null || state.getActive() == null ? null : state.getActive().getDocument(),
                state == null || state.getPending() == null ? null : state.getPending().getDocument(),
                state == null || state.getEffectiveBase() == null ? null : state.getEffectiveBase().getDocument(),
                members.feNodes, members.beNodes, ready, false, invalidSlots,
                state == null ? 0 : state.getLicenseVersion(), members.version);
    }

    public synchronized void loadImage(DataInput input) throws IOException {
        loadTrust();
        recoveryIncomplete |= input.readBoolean();
        if (input.readBoolean()) {
            apply(LicensePersistRecord.read(input));
        }
    }

    public synchronized void saveImage(DataOutput output) throws IOException {
        output.writeBoolean(recoveryIncomplete);
        output.writeBoolean(committed != null);
        if (committed != null) {
            committed.write(output);
        }
    }

    public void markRecoveryIncomplete() {
        recoveryIncomplete = true;
        publish();
    }

    public void onReplayComplete() {
        loadTrust();
        recoveryComplete = true;
        publish();
    }

    public void onMasterStart(boolean pristineBootstrap) {
        if (checkpoint) {
            return;
        }
        loadTrust();
        leader = true;
        bootstrapEligible = pristineBootstrap;
        recoveryComplete = true;
        if (repair != null) {
            repair.beginLeadership();
        }
        queueMaintenance();
    }

    public void onNonMaster() {
        leader = false;
        if (repair != null) {
            repair.endLeadership();
        }
    }

    public synchronized void start() {
        if (!checkpoint && scheduler == null && !closed) {
            scheduler = Executors.newSingleThreadScheduledExecutor(threads("license-maintenance"));
            scheduler.scheduleWithFixedDelay(this::queueMaintenance, 1, 1, TimeUnit.SECONDS);
        }
    }

    private void queueMaintenance() {
        if (checkpoint || closed || !maintenancePending.compareAndSet(false, true)) {
            return;
        }
        try {
            mutations.execute(() -> {
                try {
                    maintenance();
                } finally {
                    maintenancePending.set(false);
                }
            });
        } catch (RejectedExecutionException e) {
            maintenancePending.set(false);
        }
    }

    void maintenance() {
        try {
            publish();
            if (!leader || !host.isMaster() || recoveryIncomplete || uncertainCommit != null) {
                return;
            }
            if (committedPendingApply != null) {
                replay(committedPendingApply);
                if (committedPendingApply != null) {
                    return;
                }
            }
            if (committed == null) {
                if (!host.activationReady()) {
                    return;
                }
                long wall = time.wallTimeMillis();
                if (wall < 0 || wall > LicenseClock.MAX_MILLIS) {
                    return;
                }
                persist(LicensePersistRecord.initial(UUID.randomUUID(), bootstrapEligible, wall), null);
            }
            if (clock.isSuspect() && !committed.isClockSuspect()) {
                persist(committed.withClockSuspect(), null);
            }
            if (ready() && !clock.isSuspect()) {
                LicenseImportPolicy.Prepared prepared = policy.prepareBaseActivation(imports, context());
                if (prepared.requiresPersistence()) {
                    persist(committed.withImports(LicensePersistRecord.BASE, prepared.getToPersist(), false), null);
                }
                repair.checkpoint(60_000);
            }
        } catch (LicenseManagementException | LicenseException | LicenseRepairException | IOException e) {
            // Retry only from current committed facts. Error details are exposed through safe status.
        }
    }

    public long getAppliedVersion() {
        return appliedVersion;
    }

    public boolean isActivated() {
        LicensePersistRecord record = committed;
        return record != null && record.isActivated();
    }

    public LicenseSnapshot getSnapshot() {
        return snapshot;
    }

    /** The query hot path reads only the published view and allocation-free trusted clock. */
    public LicenseQueryStatus queryStatus() {
        LicenseClock currentClock = clock;
        return currentClock == null ? LicenseQueryStatus.LICENSE_NOT_READY : snapshot.queryStatus(currentClock);
    }

    public Map<String, Object> capability() {
        loadTrust();
        return host.localCapability(trustDigest);
    }

    @Override
    public void close() {
        closed = true;
        onNonMaster();
        synchronized (this) {
            if (scheduler != null) {
                scheduler.shutdownNow();
            }
        }
        if (verification != null) {
            verification.shutdownNow();
            mutations.shutdownNow();
        }
    }
}
