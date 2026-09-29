// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.massdb.license.LicenseImportPolicy.Context;
import org.apache.doris.massdb.license.LicenseImportPolicy.Prepared;
import org.apache.doris.massdb.license.LicenseImportState.Receipt;
import org.apache.doris.massdb.license.LicenseImportState.Slot;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

class LicenseImportPolicyTest {
    private static final UUID DEPLOYMENT = UUID.fromString("dc3e8fbe-9a3a-4e46-81f9-e909b67811ab");
    private static final ObjectMapper JSON = new ObjectMapper();
    private final LicenseImportPolicy policy = new LicenseImportPolicy();
    private KeyPair key;
    private LicenseVerifier verifier;
    private LicenseImportState empty;

    @BeforeEach
    void setUp() throws Exception {
        key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        verifier = new LicenseVerifier(Collections.singletonMap("issuer", key.getPublic()));
        empty = LicenseImportState.empty(DEPLOYMENT);
    }

    @Test
    void initialActiveAndFutureImportsProduceImmutableUnpublishedFacts() throws Exception {
        String compact = sign(claims(1, 900, 2000));
        Prepared first = policy.prepare(compact, empty, now(1000), verifier);
        Assertions.assertTrue(first.requiresPersistence());
        Assertions.assertFalse(first.isIdempotent());
        Assertions.assertNull(empty.getActive());
        Assertions.assertEquals(0, empty.getLicenseVersion());
        LicenseImportState state = first.getToPersist();
        Assertions.assertEquals(1, state.getLicenseVersion());
        Assertions.assertSame(state.getActive(), state.getEffectiveBase());
        Assertions.assertNull(state.getPending());
        Assertions.assertEquals(1, first.getReceipt().getCommittedVersion());
        Assertions.assertEquals(1, state.getEarliestRetainedVersion());
        Assertions.assertEquals(compact, state.getActive().getCompact());
        Assertions.assertFalse(state.toString().contains(compact));
        Assertions.assertFalse(first.toString().contains(compact));
        Assertions.assertThrows(UnsupportedOperationException.class, () -> state.getReceipts().clear());
        Prepared future = policy.prepare(sign(claims(2, 1800, 3000)), state, now(1000), verifier);
        Assertions.assertSame(state.getActive(), future.getToPersist().getActive());
        Assertions.assertSame(state.getEffectiveBase(), future.getToPersist().getEffectiveBase());
        Assertions.assertEquals(2, future.getToPersist().getPending().getDocument().getSequence());
        Assertions.assertEquals(2, future.getToPersist().getPending().getCommittedVersion());
        Assertions.assertEquals(0, future.getCoverageGapSeconds());
    }

    @Test
    void gapIsExplicitAndDoesNotExtendOldCertificate() throws Exception {
        LicenseImportState state = accept(empty, claims(1, 900, 1200), 1000);
        Prepared future = policy.prepare(sign(claims(2, 1300, 3000)), state, now(1000), verifier);
        Assertions.assertEquals(100, future.getCoverageGapSeconds());
        LicenseSnapshot snapshot = snapshot(future.getToPersist());
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, snapshot.queryStatus(1250));
        Assertions.assertEquals(LicenseQueryStatus.EXPIRING, snapshot.queryStatus(1300));
        Assertions.assertEquals(1200, state.getActive().getDocument().getExpiresAt());
    }

    @Test
    void currentImportMustPreserveActiveAndFuturePendingCoverageAndFeatures() throws Exception {
        LicenseImportState active = accept(empty, claims(1, 900, 2000), 1000);
        ObjectNode pendingClaims = claims(2, 1800, 4000);
        pendingClaims.withArray("features").add("FUTURE_FEATURE");
        LicenseImportState state = accept(active, pendingClaims, 1000);
        reject(LicenseErrorCode.RENEWAL_REDUCTION, state, claims(3, 900, 3999), now(1000));
        reject(LicenseErrorCode.RENEWAL_REDUCTION, state, claims(3, 900, 5000), now(1000));
        ObjectNode full = claims(3, 900, 5000);
        full.withArray("features").add("FUTURE_FEATURE");
        LicenseImportState replaced = accept(state, full, 1000);
        Assertions.assertNull(replaced.getPending());
        Assertions.assertEquals(3, replaced.getActive().getDocument().getSequence());
        Assertions.assertEquals(3, replaced.getEffectiveBase().getDocument().getSequence());
        Assertions.assertSame(active.getActive(), state.getActive());
        Assertions.assertEquals(2, state.getPending().getDocument().getSequence());
    }

    @Test
    void futureReplacementCannotLosePendingStartButEquivalentActiveCanBridge() throws Exception {
        LicenseImportState active = accept(empty, claims(1, 900, 1200), 1000);
        LicenseImportState pending = accept(active, claims(2, 1100, 4000), 1000);
        reject(LicenseErrorCode.RENEWAL_REDUCTION, pending, claims(3, 1201, 5000), now(1000));
        LicenseImportState bridged = accept(pending, claims(3, 1150, 5000), 1000);
        Assertions.assertEquals(1150, bridged.getPending().getDocument().getNotBefore());
        ObjectNode expanded = claims(2, 1100, 4000);
        expanded.withArray("features").add("EXTRA");
        LicenseImportState withFeature = accept(active, expanded, 1000);
        ObjectNode later = claims(3, 1150, 5000);
        later.withArray("features").add("EXTRA");
        reject(LicenseErrorCode.RENEWAL_REDUCTION, withFeature, later, now(1000));
        later.put("not_before", 1100);
        Assertions.assertNotNull(accept(withFeature, later, 1000).getPending());
    }

    @Test
    void pendingHigherCapacityCannotBeBridgedBySmallerActive() throws Exception {
        LicenseImportState active = accept(empty, claims(1, 900, 3000), 1000);
        ObjectNode larger = claims(2, 1100, 4000);
        larger.with("limits").put("max_be_nodes", 9);
        LicenseImportState state = accept(active, larger, 1000);
        ObjectNode later = claims(3, 1150, 5000);
        later.with("limits").put("max_be_nodes", 9);
        reject(LicenseErrorCode.RENEWAL_REDUCTION, state, later, now(1000));
        later.put("not_before", 1100);
        Assertions.assertNotNull(accept(state, later, 1000).getPending());
    }

    @Test
    void unexpiredFutureCapsAndReservationsCountWithoutOverflow() throws Exception {
        LicenseImportState state = accept(empty, claims(1, 900, 1100), 1000);
        ObjectNode larger = claims(2, 1050, 3000);
        larger.with("limits").put("max_fe_nodes", 4);
        LicenseImportState withPending = accept(state, larger, 1000);
        reject(LicenseErrorCode.NODE_LIMIT_TOO_SMALL, withPending, claims(3, 1050, 4000), now(1000));
        reject(LicenseErrorCode.NODE_LIMIT_TOO_SMALL, empty, claims(1, 900, 2000),
                new Context(1000, false, true, 3, 8, 1, 0, 1));
        ObjectNode maximum = claims(1, 900, 2000);
        maximum.with("limits").put("max_fe_nodes", Integer.MAX_VALUE).put("max_be_nodes", Integer.MAX_VALUE);
        reject(LicenseErrorCode.NODE_LIMIT_TOO_SMALL, empty, maximum,
                new Context(1000, false, true, Integer.MAX_VALUE, 0, 1, 0, 1));
    }

    @Test
    void reducedFeAndBeRenewalsBecomeAdmissibleExactlyAtExpiry() throws Exception {
        LicenseImportState state = accept(empty, claims(1, 900, 1100), 1000);
        for (int[] limits : new int[][] {{2, 8}, {3, 5}, {2, 5}}) {
            ObjectNode reduced = claims(2, 900, 3000);
            reduced.with("limits").put("max_fe_nodes", limits[0]).put("max_be_nodes", limits[1]);
            // A backdated new not_before does not restore the old certificate's expired promise.
            reject(LicenseErrorCode.NODE_LIMIT_TOO_SMALL, state, reduced,
                    new Context(1099, false, true, limits[0], 5, 0, 0, 1));
            Prepared accepted = policy.prepare(sign(reduced), state,
                    new Context(1100, false, true, limits[0], 5, 0, 0, 1), verifier);
            LicenseImportState renewed = accepted.getToPersist();
            Assertions.assertSame(renewed.getActive(), renewed.getEffectiveBase());
            Assertions.assertNull(renewed.getPending());
            Assertions.assertEquals(limits[0], renewed.getEffectiveBase().getDocument().getMaxFeNodes());
            Assertions.assertEquals(limits[1], renewed.getEffectiveBase().getDocument().getMaxBeNodes());
            Assertions.assertEquals(2, renewed.getHighestSequence());
            Assertions.assertEquals(2, renewed.getLicenseVersion());
            Assertions.assertEquals(2, renewed.getReceipts().size());
        }
        Assertions.assertEquals(3, state.getEffectiveBase().getDocument().getMaxFeNodes());
        Assertions.assertEquals(8, state.getEffectiveBase().getDocument().getMaxBeNodes());
    }

    @Test
    void expiredRenewalStillCountsRegisteredMembersAndReservations() throws Exception {
        LicenseImportState state = accept(empty, claims(1, 900, 1100), 1000);
        ObjectNode reduced = claims(2, 1100, 3000);
        reduced.with("limits").put("max_fe_nodes", 2).put("max_be_nodes", 5);
        for (Context overLimit : new Context[] {
                new Context(1100, false, true, 3, 5, 0, 0, 1),
                new Context(1100, false, true, 2, 6, 0, 0, 1),
                new Context(1100, false, true, 2, 5, 1, 0, 1),
                new Context(1100, false, true, 2, 5, 0, 1, 1)}) {
            reject(LicenseErrorCode.NODE_LIMIT_TOO_SMALL, state, reduced, overLimit);
        }
        Prepared admitted = policy.prepare(sign(reduced), state,
                new Context(1100, false, true, 2, 5, 0, 0, 1), verifier);
        Assertions.assertEquals(2, admitted.getToPersist().getActive().getDocument().getMaxFeNodes());
        Assertions.assertEquals(5, admitted.getToPersist().getActive().getDocument().getMaxBeNodes());
        assertCommitFailure(LicenseErrorCode.STALE_IMPORT_DECISION, admitted, state,
                new Context(1100, false, true, 3, 5, 0, 0, 2), verifier);
        assertCommitFailure(LicenseErrorCode.NODE_LIMIT_TOO_SMALL, admitted, state,
                new Context(1100, false, true, 3, 5, 0, 0, 1), verifier);
        assertCommitFailure(LicenseErrorCode.NODE_LIMIT_TOO_SMALL, admitted, state,
                new Context(1099, false, true, 2, 5, 0, 0, 1), verifier);
        Assertions.assertEquals(1, state.getHighestSequence());
    }

    @Test
    void unexpiredPendingPromiseSurvivesActiveExpiryUntilItsOwnExpiry() throws Exception {
        LicenseImportState active = accept(empty, claims(1, 900, 1100), 1000);
        ObjectNode expanded = claims(2, 1500, 2500);
        expanded.with("limits").put("max_fe_nodes", 4).put("max_be_nodes", 10);
        LicenseImportState state = accept(active, expanded, 1000);
        ObjectNode reduced = claims(3, 1100, 3000);
        reduced.with("limits").put("max_fe_nodes", 2).put("max_be_nodes", 5);
        for (long at : new long[] {1100, 1499, 1500, 2499}) {
            reject(LicenseErrorCode.NODE_LIMIT_TOO_SMALL, state, reduced,
                    new Context(at, false, true, 2, 5, 0, 0, 1));
        }
        LicenseImportState renewed = policy.prepare(sign(reduced), state,
                new Context(2500, false, true, 2, 5, 0, 0, 1), verifier).getToPersist();
        Assertions.assertNull(renewed.getPending());
        Assertions.assertEquals(3, renewed.getEffectiveBase().getDocument().getSequence());
        Assertions.assertEquals(2, renewed.getEffectiveBase().getDocument().getMaxFeNodes());
        Assertions.assertEquals(5, renewed.getEffectiveBase().getDocument().getMaxBeNodes());
    }

    @Test
    void reducedFutureRenewalSurvivesRecoveryAndRequiresExplicitBaseActivation() throws Exception {
        LicenseImportState old = accept(empty, claims(1, 900, 1100), 1000);
        ObjectNode reduced = claims(2, 1200, 1400);
        reduced.with("limits").put("max_be_nodes", 5);
        Prepared accepted = policy.prepare(sign(reduced), old, now(1100), verifier);
        LicenseImportState pending = accepted.getToPersist();
        Assertions.assertEquals(100, accepted.getCoverageGapSeconds());
        Assertions.assertSame(old.getEffectiveBase(), pending.getEffectiveBase());
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, snapshot(pending).queryStatus(1199));
        Assertions.assertEquals(LicenseQueryStatus.EXPIRING, snapshot(pending).queryStatus(1200));
        LicenseImportState restored = LicenseImportState.restore(DEPLOYMENT,
                Slot.verify(pending.getActive().getCompact(), 1, verifier),
                Slot.verify(pending.getPending().getCompact(), 2, verifier),
                Slot.verify(pending.getEffectiveBase().getCompact(), 1, verifier),
                2, 2, pending.getReceipts());
        Assertions.assertEquals(8, restored.getEffectiveBase().getDocument().getMaxBeNodes());
        Assertions.assertEquals(5, restored.getPending().getDocument().getMaxBeNodes());
        Assertions.assertFalse(policy.prepareBaseActivation(restored, now(1199)).requiresPersistence());
        for (long at : new long[] {1200, 1500}) {
            Assertions.assertEquals(LicenseErrorCode.NODE_LIMIT_TOO_SMALL,
                    Assertions.assertThrows(LicenseException.class,
                            () -> policy.prepareBaseActivation(restored,
                                    new Context(at, false, true, 3, 6, 0, 0, 1))).getErrorCode());
        }
        Prepared activation = policy.prepareBaseActivation(restored, now(1200));
        Assertions.assertFalse(policy.recheckForCommit(activation, restored, now(1199), verifier)
                .requiresPersistence());
        LicenseImportState activated = policy.recheckForCommit(activation, restored, now(1200), verifier)
                .getToPersist();
        Assertions.assertNull(activated.getPending());
        Assertions.assertSame(activated.getActive(), activated.getEffectiveBase());
        Assertions.assertEquals(5, activated.getEffectiveBase().getDocument().getMaxBeNodes());
        Assertions.assertEquals(3, activated.getLicenseVersion());
        Assertions.assertEquals(2, activated.getActive().getCommittedVersion());
        Assertions.assertEquals(2, activated.getReceipts().size());
        LicenseImportState missedInterval = policy.prepareBaseActivation(restored, now(1500)).getToPersist();
        Assertions.assertEquals(5, missedInterval.getEffectiveBase().getDocument().getMaxBeNodes());
        Assertions.assertEquals(LicenseQueryStatus.EXPIRED, snapshot(missedInterval).queryStatus(1500));
        LicenseImportState dueAtImportCommit = policy.recheckForCommit(accepted, old, now(1200), verifier)
                .getToPersist();
        Assertions.assertNull(dueAtImportCommit.getPending());
        Assertions.assertEquals(5, dueAtImportCommit.getEffectiveBase().getDocument().getMaxBeNodes());
        ObjectNode next = claims(3, 1500, 2000);
        next.with("limits").put("max_be_nodes", 5);
        LicenseImportState normalized = accept(restored, next, 1450);
        Assertions.assertEquals(2, normalized.getActive().getDocument().getSequence());
        Assertions.assertEquals(2, normalized.getEffectiveBase().getDocument().getSequence());
        Assertions.assertEquals(5, normalized.getEffectiveBase().getDocument().getMaxBeNodes());
        Assertions.assertEquals(3, normalized.getPending().getDocument().getSequence());
    }

    @Test
    void reducedRenewalKeepsOldReceiptsWithoutRestoringOldCapacity() throws Exception {
        LicenseImportState old = accept(empty, claims(1, 900, 1100), 1000);
        ObjectNode reduced = claims(2, 1100, 3000);
        reduced.with("limits").put("max_be_nodes", 5);
        LicenseImportState renewed = accept(old, reduced, 1100);
        for (String compact : new String[] {old.getActive().getCompact(), renewed.getActive().getCompact()}) {
            Prepared retry = policy.prepare(compact, renewed, now(4000),
                    new LicenseVerifier(Collections.emptyMap()));
            Assertions.assertTrue(retry.isIdempotent());
            Assertions.assertSame(renewed, retry.getToPersist());
            Assertions.assertEquals(5, retry.getToPersist().getEffectiveBase().getDocument().getMaxBeNodes());
        }
        ObjectNode rollback = claims(1, 1100, 4000).put("license_id", "rollback");
        reject(LicenseErrorCode.IMPORT_CONFLICT, renewed, rollback, now(1100));
        Assertions.assertEquals(2, renewed.getHighestSequence());
        Assertions.assertEquals(1, renewed.getReceipts().get(0).getCommittedVersion());
        Assertions.assertEquals(2, renewed.getReceipts().get(1).getCommittedVersion());
    }

    @Test
    void fingerprintReceiptsConfirmCoveredExpiredAndRetiredKeyImportsWithoutReapplying() throws Exception {
        String old = sign(claims(1, 900, 2000));
        LicenseImportState first = policy.prepare(old, empty, now(1000), verifier).getToPersist();
        LicenseImportState newer = accept(first, claims(2, 900, 3000), 1000);
        LicenseVerifier retired = new LicenseVerifier(Collections.emptyMap());
        Context unavailable = new Context(4000, true, false, 100, 100, 0, 0, 2);
        Prepared receipt = policy.prepare(old, newer, unavailable, retired);
        Assertions.assertTrue(receipt.isIdempotent());
        Assertions.assertFalse(receipt.requiresPersistence());
        Assertions.assertSame(newer, receipt.getToPersist());
        Assertions.assertEquals(1, receipt.getReceipt().getCommittedVersion());
        Assertions.assertEquals(2, newer.getActive().getDocument().getSequence());
    }

    @Test
    void knownIdOrSequenceWithDifferentBytesConflictsAndUnretainedHistoryIsUnknown() throws Exception {
        LicenseImportState state = accept(empty, claims(1, 900, 2000), 1000);
        ObjectNode idConflict = claims(2, 900, 3000);
        idConflict.put("license_id", "license-1");
        reject(LicenseErrorCode.IMPORT_CONFLICT, state, idConflict, now(1000));
        ObjectNode sequenceConflict = claims(1, 900, 3000);
        sequenceConflict.put("license_id", "other-license");
        reject(LicenseErrorCode.IMPORT_CONFLICT, state, sequenceConflict, now(1000));
        LicenseImportState historyMissing = LicenseImportState.restore(DEPLOYMENT, state.getActive(), null,
                state.getEffectiveBase(), 9, 9, Collections.emptyList());
        reject(LicenseErrorCode.IMPORT_HISTORY_UNAVAILABLE, historyMissing, claims(2, 900, 3000), now(1000));
        String original = state.getActive().getCompact();
        Assertions.assertTrue(policy.prepare(original, historyMissing, now(5000),
                new LicenseVerifier(Collections.emptyMap())).isIdempotent());
    }

    @Test
    void receiptHistoryIsBoundedOrderedAndEvictionDoesNotInventSuccess() throws Exception {
        List<Receipt> receipts = new ArrayList<>();
        String discarded = sign(claims(1, 900, 1100));
        receipts.add(new Receipt(LicenseVerifier.fingerprint(discarded), "license-1", 1, 1));
        for (int sequence = 2; sequence <= 1024; sequence++) {
            receipts.add(new Receipt(String.format("%064x", sequence), "license-" + sequence, sequence, sequence));
        }
        LicenseImportState history = LicenseImportState.restore(DEPLOYMENT, null, null, null,
                1024, 1024, receipts);
        receipts.clear();
        Assertions.assertEquals(1024, history.getReceipts().size());
        LicenseImportState next = accept(history, claims(1025, 900, 2000), 1000);
        Assertions.assertEquals(1024, next.getReceipts().size());
        Assertions.assertEquals(2, next.getEarliestRetainedVersion());
        Assertions.assertEquals(1025, next.getReceipts().get(1023).getCommittedVersion());
        Assertions.assertEquals(LicenseErrorCode.IMPORT_HISTORY_UNAVAILABLE,
                Assertions.assertThrows(LicenseException.class,
                        () -> policy.prepare(discarded, next, now(1000), verifier)).getErrorCode());
    }

    @Test
    void futureBaseRequiresExplicitCommitEvenAfterWholeValidityIntervalWasMissed() throws Exception {
        ObjectNode future = claims(1, 1100, 1200);
        future.with("limits").put("max_be_nodes", 20);
        LicenseImportState pending = accept(empty, future, 1000);
        Assertions.assertNull(pending.getEffectiveBase());
        LicenseSnapshot snapshot = snapshot(pending);
        Assertions.assertEquals(1, snapshot.currentCertificate(1150).getSequence());
        Assertions.assertFalse(snapshot.hasTrustedBaseCapacity());
        Assertions.assertNull(pending.getEffectiveBase());
        Prepared early = policy.prepareBaseActivation(pending, now(1099));
        Assertions.assertFalse(early.requiresPersistence());
        Prepared matured = policy.prepareBaseActivation(pending, now(1300));
        Assertions.assertTrue(matured.requiresPersistence());
        Assertions.assertNull(pending.getEffectiveBase());
        Assertions.assertEquals(2, matured.getToPersist().getLicenseVersion());
        Assertions.assertEquals(1, matured.getToPersist().getActive().getCommittedVersion());
        Assertions.assertEquals(1, matured.getToPersist().getEffectiveBase().getCommittedVersion());
        Assertions.assertEquals(20, matured.getToPersist().getEffectiveBase().getDocument().getMaxBeNodes());
        Assertions.assertEquals(1, matured.getToPersist().getReceipts().size());
        Assertions.assertFalse(policy.prepareBaseActivation(matured.getToPersist(), now(1400)).requiresPersistence());
        Assertions.assertEquals(LicenseErrorCode.CLOCK_SUSPECT, Assertions.assertThrows(LicenseException.class,
                () -> policy.prepareBaseActivation(pending,
                        new Context(1300, true, true, 3, 5, 0, 0, 1))).getErrorCode());
    }

    @Test
    void importNormalizesMaturePendingAndRetainsItsBaseAfterExpiry() throws Exception {
        LicenseImportState active = accept(empty, claims(1, 900, 1200), 1000);
        ObjectNode pending = claims(2, 1100, 1300);
        pending.with("limits").put("max_be_nodes", 20);
        LicenseImportState state = accept(active, pending, 1000);
        ObjectNode next = claims(3, 1600, 2000);
        next.with("limits").put("max_be_nodes", 20);
        LicenseImportState future = accept(state, next, 1500);
        Assertions.assertEquals(2, future.getActive().getDocument().getSequence());
        Assertions.assertEquals(2, future.getEffectiveBase().getDocument().getSequence());
        Assertions.assertEquals(3, future.getPending().getDocument().getSequence());
        Assertions.assertEquals(1, state.getEffectiveBase().getDocument().getSequence());
    }

    @Test
    void damagedBaseSlotIsNotInferredByGettersOrNoOpActivation() throws Exception {
        LicenseImportState good = accept(empty, claims(1, 900, 2000), 1000);
        LicenseImportState damaged = LicenseImportState.restore(DEPLOYMENT, good.getActive(), null, null,
                1, 1, good.getReceipts());
        Assertions.assertEquals(LicenseQueryStatus.EXPIRING, snapshot(damaged).queryStatus(1000));
        Assertions.assertFalse(snapshot(damaged).hasTrustedBaseCapacity());
        Assertions.assertSame(damaged, policy.prepareBaseActivation(damaged, now(1000)).getToPersist());
        Assertions.assertNull(damaged.getEffectiveBase());
    }

    @Test
    void recheckRejectsVersionMembershipClockExpiryQuotaAndTrustChangesBeforeCommit() throws Exception {
        String compact = sign(claims(1, 900, 2000));
        Prepared prepared = policy.prepare(compact, empty, now(1000), verifier);
        Assertions.assertEquals(1, policy.recheckForCommit(prepared, empty, now(1001), verifier)
                .getToPersist().getLicenseVersion());
        assertCommitFailure(LicenseErrorCode.STALE_IMPORT_DECISION, prepared, prepared.getToPersist(), now(1000),
                verifier);
        assertCommitFailure(LicenseErrorCode.STALE_IMPORT_DECISION, prepared, empty,
                new Context(1000, false, true, 3, 5, 0, 0, 2), verifier);
        assertCommitFailure(LicenseErrorCode.CLOCK_SUSPECT, prepared, empty,
                new Context(1000, true, true, 3, 5, 0, 0, 1), verifier);
        assertCommitFailure(LicenseErrorCode.CERTIFICATE_EXPIRED, prepared, empty, now(2000), verifier);
        assertCommitFailure(LicenseErrorCode.NODE_LIMIT_TOO_SMALL, prepared, empty,
                new Context(1000, false, true, 4, 5, 0, 0, 1), verifier);
        assertCommitFailure(LicenseErrorCode.UNTRUSTED_KEY, prepared, empty, now(1000),
                new LicenseVerifier(Collections.emptyMap()));
        Assertions.assertNull(empty.getActive());
    }

    @Test
    void recheckOfFutureImportCanBecomeActiveWithoutExtendingOrReapplyingHistory() throws Exception {
        Prepared prepared = policy.prepare(sign(claims(1, 1100, 2000)), empty, now(1000), verifier);
        Assertions.assertNull(prepared.getToPersist().getActive());
        Prepared atCommit = policy.recheckForCommit(prepared, empty, now(1100), verifier);
        Assertions.assertNull(atCommit.getToPersist().getPending());
        Assertions.assertNotNull(atCommit.getToPersist().getEffectiveBase());
        Assertions.assertEquals(2000, atCommit.getToPersist().getActive().getDocument().getExpiresAt());
        Assertions.assertEquals(1, atCommit.getReceipt().getCommittedVersion());
    }

    @Test
    void rejectsWrongDeploymentTimeCapabilityAndReadinessWithoutStateMutation() throws Exception {
        ObjectNode wrong = claims(1, 900, 2000);
        wrong.put("deployment_id", "00000000-0000-0000-0000-000000000000");
        reject(LicenseErrorCode.DEPLOYMENT_MISMATCH, empty, wrong, now(1000));
        ObjectNode futureIssued = claims(1, 900, 2000);
        futureIssued.put("issued_at", 1301);
        reject(LicenseErrorCode.ISSUED_IN_FUTURE, empty, futureIssued, now(1000));
        futureIssued.put("issued_at", 1300);
        Assertions.assertNotNull(accept(empty, futureIssued, 1000).getActive());
        reject(LicenseErrorCode.CERTIFICATE_EXPIRED, empty, claims(1, 900, 1000), now(1000));
        ObjectNode noFeature = claims(1, 900, 2000);
        noFeature.putArray("features");
        reject(LicenseErrorCode.FEATURE_NOT_LICENSED, empty, noFeature, now(1000));
        reject(LicenseErrorCode.IMPORT_NOT_READY, empty, claims(1, 900, 2000),
                new Context(1000, false, false, 3, 5, 0, 0, 1));
        reject(LicenseErrorCode.CLOCK_SUSPECT, empty, claims(1, 900, 2000), now(-1));
        reject(LicenseErrorCode.CLOCK_SUSPECT, empty, claims(1, 900, 2000), now(Long.MAX_VALUE));
        Assertions.assertEquals(0, empty.getHighestSequence());
        Assertions.assertTrue(empty.getReceipts().isEmpty());
    }

    @Test
    void maxSequenceAndVersionAreCheckedWithoutOverflow() throws Exception {
        ObjectNode maximum = claims(Long.MAX_VALUE, 900, 2000);
        LicenseImportState state = accept(empty, maximum, 1000);
        Assertions.assertEquals(Long.MAX_VALUE, state.getHighestSequence());
        Assertions.assertTrue(policy.prepare(state.getActive().getCompact(), state, now(1000), verifier)
                .isIdempotent());
        reject(LicenseErrorCode.IMPORT_HISTORY_UNAVAILABLE, state, claims(2, 900, 3000), now(1000));
        LicenseImportState exhausted = LicenseImportState.restore(DEPLOYMENT, null, null, null,
                0, Long.MAX_VALUE, Collections.emptyList());
        reject(LicenseErrorCode.IMPORT_CONFLICT, exhausted, claims(1, 900, 2000), now(1000));
        ObjectNode farFuture = claims(1, LicenseVerifier.MAX_EPOCH_SECOND - 1, LicenseVerifier.MAX_EPOCH_SECOND);
        farFuture.put("issued_at", LicenseVerifier.MAX_EPOCH_SECOND);
        Assertions.assertNotNull(accept(empty, farFuture, LicenseVerifier.MAX_EPOCH_SECOND - 1).getActive());
    }

    @Test
    void restoredStateAndSlotsRejectInconsistentMetadataAndPreserveOriginalVersions() throws Exception {
        LicenseImportState state = accept(empty, claims(1, 900, 2000), 1000);
        Slot slot = state.getActive();
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new Slot(slot.getDocument(), slot.getCompact() + "x", 1));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> LicenseImportState.restore(DEPLOYMENT, slot, null, slot, 0, 1, Collections.emptyList()));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> LicenseImportState.restore(DEPLOYMENT, slot, null, slot, 1, 0, Collections.emptyList()));
        List<Receipt> repeated = new ArrayList<>(state.getReceipts());
        repeated.add(state.getReceipts().get(0));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> LicenseImportState.restore(DEPLOYMENT, slot, null, slot, 1, 1, repeated));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new Context(1000, false, true, -1, 0, 0, 0, 1));
    }

    @Test
    void publicRecoveryFactoryReverifiesRawBytesAndKeepsExpiredSignedSlots() throws Exception {
        String compact = sign(claims(1, 1, 2).put("issued_at", 1));
        Slot recovered = Slot.verify(compact, 7, verifier);
        Assertions.assertEquals(2, recovered.getDocument().getExpiresAt());
        Assertions.assertEquals(7, recovered.getCommittedVersion());
        String[] segments = compact.split("\\.");
        ObjectNode forged = claims(1, 1, 2).put("issued_at", 1);
        forged.with("limits").put("max_be_nodes", 100000);
        String tampered = segments[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(forged.toString().getBytes(StandardCharsets.UTF_8)) + "." + segments[2];
        Assertions.assertEquals(LicenseErrorCode.INVALID_SIGNATURE, Assertions.assertThrows(LicenseException.class,
                () -> Slot.verify(tampered, 7, verifier)).getErrorCode());
        Assertions.assertEquals(LicenseErrorCode.UNTRUSTED_KEY, Assertions.assertThrows(LicenseException.class,
                () -> Slot.verify(compact, 7, new LicenseVerifier(Collections.emptyMap()))).getErrorCode());
    }

    @Test
    void restorationRejectsSlotReceiptIdentityAndCommitVersionContradictions() throws Exception {
        LicenseImportState state = accept(empty, claims(1, 900, 2000), 1000);
        Slot slot = state.getActive();
        String fingerprint = slot.getDocument().getFingerprint();
        Receipt[] contradictory = {
                new Receipt(fingerprint, "license-1", 1, 2),
                new Receipt(fingerprint, "other-id", 1, 1),
                new Receipt(fingerprint, "license-1", 2, 1),
                new Receipt(String.format("%064x", 2), "license-1", 1, 1),
                new Receipt(String.format("%064x", 2), "license-2", 2, 1)
        };
        for (Receipt bad : contradictory) {
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> LicenseImportState.restore(DEPLOYMENT, slot, null, slot, 2, 2,
                            Collections.singletonList(bad)));
        }
        Slot wrongVersion = Slot.verify(slot.getCompact(), 2, verifier);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> LicenseImportState.restore(DEPLOYMENT, slot, null, wrongVersion, 1, 2,
                        Collections.emptyList()));
        Slot laterSequenceEarlierCommit = Slot.verify(sign(claims(2, 900, 3000)), 1, verifier);
        Slot earlierSequenceLaterCommit = Slot.verify(slot.getCompact(), 2, verifier);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> LicenseImportState.restore(DEPLOYMENT, earlierSequenceLaterCommit,
                        laterSequenceEarlierCommit, null, 2, 2, Collections.emptyList()));
    }

    @Test
    void restorationRejectsMixedBaseOrderAndOverlappingQuotaReductionWithoutInferringReplacement() throws Exception {
        Slot first = Slot.verify(sign(claims(1, 900, 2000)), 1, verifier);
        Slot second = Slot.verify(sign(claims(2, 1100, 3000)), 2, verifier);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> LicenseImportState.restore(DEPLOYMENT, first, null, second, 2, 2,
                        Collections.emptyList()));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> LicenseImportState.restore(DEPLOYMENT, null, second, second, 2, 2,
                        Collections.emptyList()));
        ObjectNode smaller = claims(2, 1100, 3000);
        smaller.with("limits").put("max_be_nodes", 7);
        Slot smallerPending = Slot.verify(sign(smaller), 2, verifier);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> LicenseImportState.restore(DEPLOYMENT, first, smallerPending, first, 2, 2,
                        Collections.emptyList()));
        // P2 can isolate a damaged base and retain the independently verified query slots.
        LicenseImportState isolated = LicenseImportState.restore(DEPLOYMENT, first, second, null,
                2, 2, Collections.emptyList());
        Assertions.assertNull(isolated.getEffectiveBase());
        Assertions.assertEquals(LicenseQueryStatus.EXPIRING, snapshot(isolated).queryStatus(1000));
        Assertions.assertNull(policy.prepareBaseActivation(isolated, now(1000)).getToPersist().getEffectiveBase());
    }

    @Test
    void restorationAllowsLowerPendingAtExpiryWithoutInferringAnActivatedBase() throws Exception {
        Slot first = Slot.verify(sign(claims(1, 900, 2000)), 1, verifier);
        for (String limit : new String[] {"max_fe_nodes", "max_be_nodes"}) {
            ObjectNode reduced = claims(2, 2000, 3000);
            reduced.with("limits").put(limit, 2);
            Slot next = Slot.verify(sign(reduced), 2, verifier);
            LicenseImportState restored = LicenseImportState.restore(DEPLOYMENT, first, next, first,
                    2, 2, Collections.emptyList());
            Assertions.assertSame(first, restored.getActive());
            Assertions.assertSame(first, restored.getEffectiveBase());
            Assertions.assertSame(next, restored.getPending());
            reduced.put("not_before", 1999);
            Slot overlapping = Slot.verify(sign(reduced), 2, verifier);
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> LicenseImportState.restore(DEPLOYMENT, first, overlapping, first,
                            2, 2, Collections.emptyList()));
            // A lower active with an older, larger base is not a committed renewal replacement.
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> LicenseImportState.restore(DEPLOYMENT, next, null, first,
                            2, 2, Collections.emptyList()));
        }
    }

    @Test
    void evictedReceiptStillConfirmsRetainedSlotUsingItsOriginalCommitVersion() throws Exception {
        Slot old = Slot.verify(sign(claims(1, 900, 2000)), 1, verifier);
        List<Receipt> recent = new ArrayList<>();
        for (int sequence = 2; sequence <= 1025; sequence++) {
            recent.add(new Receipt(String.format("%064x", sequence), "license-" + sequence,
                    sequence, sequence + 100));
        }
        LicenseImportState restored = LicenseImportState.restore(DEPLOYMENT, old, null, old,
                1025, 1125, recent);
        Prepared result = policy.prepare(old.getCompact(), restored, now(3000),
                new LicenseVerifier(Collections.emptyMap()));
        Assertions.assertTrue(result.isIdempotent());
        Assertions.assertEquals(1, result.getReceipt().getCommittedVersion());
        Assertions.assertEquals(102, restored.getEarliestRetainedVersion());
        Assertions.assertSame(restored, result.getToPersist());
    }

    @Test
    void activationRecheckUsesCurrentTimeReadinessAndMembershipBeforePersisting() throws Exception {
        LicenseImportState pending = accept(empty, claims(1, 1100, 1200), 1000);
        Prepared proposed = policy.prepareBaseActivation(pending, now(1100));
        Assertions.assertFalse(policy.recheckForCommit(proposed, pending, now(1099), verifier)
                .requiresPersistence());
        assertCommitFailure(LicenseErrorCode.IMPORT_NOT_READY, proposed, pending,
                new Context(1300, false, false, 3, 5, 0, 0, 1), verifier);
        assertCommitFailure(LicenseErrorCode.STALE_IMPORT_DECISION, proposed, pending,
                new Context(1300, false, true, 3, 5, 0, 0, 2), verifier);
        Prepared overdue = policy.recheckForCommit(proposed, pending, now(1300), verifier);
        Assertions.assertTrue(overdue.requiresPersistence());
        Assertions.assertEquals(1, overdue.getToPersist().getEffectiveBase().getDocument().getSequence());
        Assertions.assertNull(pending.getEffectiveBase());
    }

    private LicenseImportState accept(LicenseImportState state, ObjectNode claims, long at) throws Exception {
        // Simulate the caller publishing facts after durable success; no production journal is implied.
        return policy.prepare(sign(claims), state, now(at), verifier).getToPersist();
    }

    private void reject(LicenseErrorCode expected, LicenseImportState state, ObjectNode claims, Context context)
            throws Exception {
        String compact = sign(claims);
        Assertions.assertEquals(expected, Assertions.assertThrows(LicenseException.class,
                () -> policy.prepare(compact, state, context, verifier)).getErrorCode());
    }

    private void assertCommitFailure(LicenseErrorCode reason, Prepared prepared, LicenseImportState state,
            Context context, LicenseVerifier currentVerifier) {
        Assertions.assertEquals(reason, Assertions.assertThrows(LicenseException.class,
                () -> policy.recheckForCommit(prepared, state, context, currentVerifier)).getErrorCode());
    }

    private static Context now(long seconds) {
        return new Context(seconds, false, true, 3, 5, 0, 0, 1);
    }

    private static LicenseSnapshot snapshot(LicenseImportState state) {
        return new LicenseSnapshot(DEPLOYMENT, state.getActive() == null ? null : state.getActive().getDocument(),
                state.getPending() == null ? null : state.getPending().getDocument(),
                state.getEffectiveBase() == null ? null : state.getEffectiveBase().getDocument(),
                3, 5, true, false, false, state.getLicenseVersion(), 1);
    }

    private static ObjectNode claims(long sequence, long notBefore, long expiresAt) {
        ObjectNode result = JSON.createObjectNode();
        result.put("schema_version", 1).put("policy_version", 1).put("license_id", "license-" + sequence)
                .put("issuer", "Test Issuer").put("customer_id", "Test Customer").put("edition", "Test")
                .put("product", "MassDB SQL").put("deployment_id", DEPLOYMENT.toString())
                .put("issued_at", 900).put("not_before", notBefore).put("expires_at", expiresAt)
                .put("sequence", sequence);
        result.putArray("features").add("DATA_QUERY");
        result.putObject("limits").put("max_fe_nodes", 3).put("max_be_nodes", 8);
        return result;
    }

    private String sign(ObjectNode claims) throws Exception {
        String header = "{\"alg\":\"Ed25519\",\"typ\":\"massdb-license+jws\",\"kid\":\"issuer\"}";
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String message = encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(claims.toString().getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key.getPrivate());
        signer.update(message.getBytes(StandardCharsets.US_ASCII));
        return message + "." + encoder.encodeToString(signer.sign());
    }
}
