// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Immutable, already committed facts. Construction does not commit or publish them. */
public final class LicenseImportState {
    public static final int MAX_RECEIPTS = 1024;

    /** A verified certificate and the version at which it was originally accepted. */
    public static final class Slot {
        private final LicenseDocument document;
        private final String compact;
        private final long committedVersion;

        // Only the import policy may reuse a document it just verified. External recovery callers
        // must go through verify(), never turn deserialized claim fields into a verified document.
        Slot(LicenseDocument document, String compact, long committedVersion) {
            this.document = Objects.requireNonNull(document, "document");
            this.compact = Objects.requireNonNull(compact, "compact");
            if (committedVersion < 1) {
                throw new IllegalArgumentException("Invalid committed license version");
            }
            try {
                if (!document.getFingerprint().equals(LicenseVerifier.fingerprint(compact))) {
                    throw new IllegalArgumentException("Certificate identity mismatch");
                }
            } catch (LicenseException e) {
                throw new IllegalArgumentException("Invalid stored certificate");
            }
            this.committedVersion = committedVersion;
        }

        /** Independently reverify a raw stored slot; validity time is an admission concern. */
        public static Slot verify(String compact, long committedVersion, LicenseVerifier verifier)
                throws LicenseException {
            return new Slot(Objects.requireNonNull(verifier, "verifier").verify(compact), compact,
                    committedVersion);
        }

        public LicenseDocument getDocument() {
            return document;
        }

        /** Sensitive payload: for controlled persistence, never logs or public status responses. */
        public String getCompact() {
            return compact;
        }

        public long getCommittedVersion() {
            return committedVersion;
        }

        Receipt receipt() {
            return new Receipt(document.getFingerprint(), document.getLicenseId(), document.getSequence(),
                    committedVersion);
        }
    }

    /** A durable historical acknowledgement, not a currently effective entitlement. */
    public static final class Receipt {
        private final String fingerprint;
        private final String licenseId;
        private final long sequence;
        private final long committedVersion;

        public Receipt(String fingerprint, String licenseId, long sequence, long committedVersion) {
            if (fingerprint == null || !fingerprint.matches("[0-9a-f]{64}")
                    || !LicenseText.matches(licenseId, 256, true) || sequence < 1 || committedVersion < 1) {
                throw new IllegalArgumentException("Invalid license receipt");
            }
            this.fingerprint = fingerprint;
            this.licenseId = licenseId;
            this.sequence = sequence;
            this.committedVersion = committedVersion;
        }

        public String getFingerprint() {
            return fingerprint;
        }

        public String getLicenseId() {
            return licenseId;
        }

        public long getSequence() {
            return sequence;
        }

        public long getCommittedVersion() {
            return committedVersion;
        }
    }

    private final UUID deploymentId;
    private final Slot active;
    private final Slot pending;
    private final Slot effectiveBase;
    private final long highestSequence;
    private final long licenseVersion;
    private final List<Receipt> receipts;

    private LicenseImportState(UUID deploymentId, Slot active, Slot pending, Slot effectiveBase,
            long highestSequence, long licenseVersion, List<Receipt> receipts) {
        this.deploymentId = Objects.requireNonNull(deploymentId, "deploymentId");
        if (highestSequence < 0 || licenseVersion < 0 || receipts == null || receipts.size() > MAX_RECEIPTS) {
            throw new IllegalArgumentException("Invalid license state metadata");
        }
        Slot[] slots = {active, pending, effectiveBase};
        for (Slot slot : slots) {
            if (slot != null && (!deploymentId.equals(slot.document.getDeploymentId())
                    || slot.document.getSequence() > highestSequence || slot.committedVersion > licenseVersion)) {
                throw new IllegalArgumentException("License slot does not match state metadata");
            }
        }
        if (active != null && pending != null
                && pending.document.getSequence() <= active.document.getSequence()) {
            throw new IllegalArgumentException("Pending sequence must follow active sequence");
        }
        if (effectiveBase != null
                && ((active != null && effectiveBase.document.getSequence() > active.document.getSequence())
                || (pending != null && effectiveBase.document.getSequence() >= pending.document.getSequence()))) {
            throw new IllegalArgumentException("Base marker does not match active and pending order");
        }
        requireNondecreasingCapacity(effectiveBase, active);
        requireNondecreasingCapacity(active, pending);
        requireNondecreasingCapacity(effectiveBase, pending);
        for (int first = 0; first < slots.length; first++) {
            for (int second = first + 1; second < slots.length; second++) {
                if (slots[first] != null && slots[second] != null) {
                    requireCompatibleIdentity(slots[first].receipt(), slots[second].receipt());
                }
            }
        }
        long previousVersion = 0;
        long previousSequence = 0;
        Set<String> ids = new HashSet<>();
        Set<String> fingerprints = new HashSet<>();
        List<Receipt> copy = new ArrayList<>(receipts.size());
        for (Receipt receipt : receipts) {
            if (receipt == null || receipt.committedVersion <= previousVersion
                    || receipt.sequence <= previousSequence || receipt.committedVersion > licenseVersion
                    || receipt.sequence > highestSequence || !ids.add(receipt.licenseId)
                    || !fingerprints.add(receipt.fingerprint)) {
                throw new IllegalArgumentException("Invalid ordered license receipt history");
            }
            previousVersion = receipt.committedVersion;
            previousSequence = receipt.sequence;
            for (Slot slot : slots) {
                if (slot != null) {
                    requireCompatibleIdentity(slot.receipt(), receipt);
                }
            }
            copy.add(receipt);
        }
        this.active = active;
        this.pending = pending;
        this.effectiveBase = effectiveBase;
        this.highestSequence = highestSequence;
        this.licenseVersion = licenseVersion;
        this.receipts = Collections.unmodifiableList(copy);
    }

    private static void requireNondecreasingCapacity(Slot older, Slot newer) {
        if (older != null && newer != null && (older.document.getMaxFeNodes() > newer.document.getMaxFeNodes()
                || older.document.getMaxBeNodes() > newer.document.getMaxBeNodes())) {
            throw new IllegalArgumentException("Restored license capacity decreases across accepted slots");
        }
    }

    private static void requireCompatibleIdentity(Receipt first, Receipt second) {
        boolean sameFingerprint = first.fingerprint.equals(second.fingerprint);
        boolean sameId = first.licenseId.equals(second.licenseId);
        boolean sameSequence = first.sequence == second.sequence;
        boolean sameVersion = first.committedVersion == second.committedVersion;
        if ((sameFingerprint || sameId || sameSequence || sameVersion)
                && !(sameFingerprint && sameId && sameSequence && sameVersion)) {
            throw new IllegalArgumentException("Conflicting restored license identity or original commit version");
        }
        if (Long.compare(first.sequence, second.sequence)
                != Long.compare(first.committedVersion, second.committedVersion)) {
            throw new IllegalArgumentException("Restored license sequence and commit order disagree");
        }
    }

    public static LicenseImportState empty(UUID deploymentId) {
        return restore(deploymentId, null, null, null, 0, 0, Collections.emptyList());
    }

    /**
     * The persistence layer must first call Slot.verify for each raw slot and isolate invalid slots.
     * Global counters/receipts must come from the same committed metadata cut; conflicting facts
     * reject reconstruction rather than inventing a historical acknowledgement. Missing base data
     * is retained as missing; no bootstrap or base capacity is inferred here.
     */
    public static LicenseImportState restore(UUID deploymentId, Slot active, Slot pending, Slot effectiveBase,
            long highestSequence, long licenseVersion, List<Receipt> receipts) {
        return new LicenseImportState(deploymentId, active, pending, effectiveBase,
                highestSequence, licenseVersion, receipts);
    }

    Receipt findReceipt(String fingerprint) {
        for (Slot slot : new Slot[] {active, pending, effectiveBase}) {
            if (slot != null && slot.document.getFingerprint().equals(fingerprint)) {
                return slot.receipt();
            }
        }
        for (Receipt receipt : receipts) {
            if (receipt.fingerprint.equals(fingerprint)) {
                return receipt;
            }
        }
        return null;
    }

    boolean hasIdentityConflict(LicenseDocument candidate) {
        for (Slot slot : new Slot[] {active, pending, effectiveBase}) {
            if (slot != null && (slot.document.getSequence() == candidate.getSequence()
                    || slot.document.getLicenseId().equals(candidate.getLicenseId()))) {
                return true;
            }
        }
        for (Receipt receipt : receipts) {
            if (receipt.sequence == candidate.getSequence() || receipt.licenseId.equals(candidate.getLicenseId())) {
                return true;
            }
        }
        return false;
    }

    public UUID getDeploymentId() {
        return deploymentId;
    }

    public Slot getActive() {
        return active;
    }

    public Slot getPending() {
        return pending;
    }

    public Slot getEffectiveBase() {
        return effectiveBase;
    }

    public long getHighestSequence() {
        return highestSequence;
    }

    public long getLicenseVersion() {
        return licenseVersion;
    }

    public List<Receipt> getReceipts() {
        return receipts;
    }

    public long getEarliestRetainedVersion() {
        return receipts.isEmpty() ? 0 : receipts.get(0).committedVersion;
    }
}
