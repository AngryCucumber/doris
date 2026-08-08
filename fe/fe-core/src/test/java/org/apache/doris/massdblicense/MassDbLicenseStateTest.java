// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.doris.massdblicense;

import org.apache.doris.common.io.DataInputBuffer;
import org.apache.doris.common.io.DataOutputBuffer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

class MassDbLicenseStateTest {
    private static final String PLAN_SHA = repeat('a');
    private static final String REQUEST_SHA = repeat('b');

    @Test
    void newAndExistingClustersChooseDifferentSafeDefaults() {
        MassDbLicenseState fresh = MassDbLicenseState.empty().bootstrap(false, PLAN_SHA);
        MassDbLicenseState upgraded = MassDbLicenseState.empty().bootstrap(true, PLAN_SHA);

        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.ENFORCING,
                fresh.getEnforcementMode());
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.OBSERVE,
                upgraded.getEnforcementMode());
        Assertions.assertNotNull(fresh.getLicenseControlDeploymentUuid());
        Assertions.assertEquals(1, fresh.getBootstrapSealGeneration());
    }

    @Test
    void correctionBarrierBlocksAnyPreCorrectionEquivalentFile() {
        MassDbLicenseState state = initializedWithLicense(2_000);
        MassDbLicenseState.ActiveLicense shorter = license("short", repeat('c'), 200, 1_500);
        state = state.prepareLicense("op-2", "key-2", repeat('d'),
                MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER, shorter,
                "requester", "different-approver", 400, 500).commit("op-2", 400);

        Assertions.assertEquals(1, state.getLicenseCorrectionBarriers().size());
        final MassDbLicenseState corrected = state;
        MassDbLicenseException blocked = Assertions.assertThrows(MassDbLicenseException.class,
                () -> corrected.prepareLicense("op-3", "key-3", repeat('e'),
                        MassDbLicenseState.ImportIntent.NORMAL,
                        license("alternate-old-file", repeat('f'), 300, 2_000),
                        "tenant-admin", null, 410, 500));
        Assertions.assertEquals("MASSDB_LICENSE_SUPERSEDED", blocked.getCode());

        long allowedIssuedAt = state.getLicenseCorrectionBarriers().get(0)
                .getSupersededIssuedAtCutoff() + 1;
        MassDbLicenseState allowed = state.prepareLicense("op-4", "key-4", repeat('1'),
                MassDbLicenseState.ImportIntent.NORMAL,
                license("newly-signed", repeat('2'), allowedIssuedAt, 2_000),
                "tenant-admin", null, 410, 500);
        Assertions.assertNotNull(allowed.getMutation());
    }

    @Test
    void restrictiveKeysetPreemptsClockChallengeOnlyAfterCommit() {
        MassDbLicenseState state = initializedWithLicense(2_000)
                .createClockChallenge("challenge", repeat('3'), 300, 900);
        final MassDbLicenseState challenged = state;

        MassDbLicenseException blocked = Assertions.assertThrows(MassDbLicenseException.class,
                () -> challenged.prepareKeyset("add", "key-add", repeat('4'),
                        MassDbLicenseState.MutationKind.ADDITIVE_KEYSET,
                        keyset(2, '4'), 301, 500));
        Assertions.assertEquals("MASSDB_LICENSE_CLOCK_RECOVERY_CHALLENGE_ACTIVE", blocked.getCode());

        MassDbLicenseState prepared = state.prepareKeyset("recover", "key-recover", repeat('5'),
                MassDbLicenseState.MutationKind.RESTRICTIVE_KEYSET,
                keyset(2, '5'), 301, 500);
        Assertions.assertEquals(MassDbLicenseState.ClockChallengeState.ACTIVE,
                prepared.getClockChallenge().getState());
        MassDbLicenseState committed = prepared.commit("recover", 302);
        Assertions.assertEquals(MassDbLicenseState.ClockChallengeState.INVALIDATED_BY_KEYSET_RECOVERY,
                committed.getClockChallenge().getState());
        Assertions.assertEquals(2, committed.getKeysetVersion());
    }

    @Test
    void recoveryBundleAtomicallyCommitsKeysetAndLicense() {
        MassDbLicenseState challenged = initializedWithLicense(2_000)
                .createClockChallenge("challenge", repeat('3'), 300, 900);
        MassDbLicenseState.ActiveLicense replacement =
                license("replacement", repeat('a'), 250, 2_500);

        MassDbLicenseState prepared = challenged.prepareRecoveryBundle(
                "bundle", "key-bundle", repeat('f'), keyset(3, 'e'), replacement, 301, 500);
        MassDbLicenseState aborted = prepared.abort("bundle");
        Assertions.assertEquals(0, aborted.getKeysetVersion());
        Assertions.assertEquals("initial", aborted.getActiveLicense().getLicenseId());
        Assertions.assertEquals(MassDbLicenseState.ClockChallengeState.ACTIVE,
                aborted.getClockChallenge().getState());

        MassDbLicenseState committed = challenged.prepareRecoveryBundle(
                "bundle-2", "key-bundle-2", repeat('9'), keyset(3, 'd'), replacement, 301, 500)
                .commit("bundle-2", 302);
        Assertions.assertEquals(3, committed.getKeysetVersion());
        Assertions.assertEquals("replacement", committed.getActiveLicense().getLicenseId());
        Assertions.assertEquals(MassDbLicenseState.ClockChallengeState.INVALIDATED_BY_KEYSET_RECOVERY,
                committed.getClockChallenge().getState());
    }

    @Test
    void sameIdempotencyKeyReplaysAndDifferentHashConflicts() {
        MassDbLicenseState state = initializedWithLicense(2_000);
        MassDbLicenseState prepared = state.prepareLicense("op-idem", "idem", REQUEST_SHA,
                MassDbLicenseState.ImportIntent.NORMAL,
                license("next", repeat('6'), 200, 3_000), "admin", null, 300, 500);
        MassDbLicenseState replayed = prepared.prepareLicense("ignored", "idem", REQUEST_SHA,
                MassDbLicenseState.ImportIntent.NORMAL,
                license("other", repeat('7'), 200, 4_000), "admin", null, 301, 501);
        Assertions.assertEquals("op-idem", replayed.getMutation().getOperationId());

        MassDbLicenseException conflict = Assertions.assertThrows(MassDbLicenseException.class,
                () -> prepared.prepareLicense("new", "idem", repeat('8'),
                        MassDbLicenseState.ImportIntent.NORMAL,
                        license("other", repeat('9'), 200, 4_000), "admin", null, 301, 501));
        Assertions.assertEquals("MASSDB_LICENSE_IDEMPOTENCY_CONFLICT", conflict.getCode());
    }

    @Test
    void journalSnapshotRoundTripKeepsPermanentBarrier() throws IOException {
        MassDbLicenseState state = initializedWithLicense(2_000);
        state = state.prepareLicense("op-2", "key-2", repeat('c'),
                MassDbLicenseState.ImportIntent.REPLACE_WITH_SHORTER,
                license("short", repeat('d'), 200, 1_500),
                "requester", "approver", 400, 500).commit("op-2", 400);

        DataOutputBuffer output = new DataOutputBuffer(1024);
        state.write(output);
        DataInputBuffer input = new DataInputBuffer();
        input.reset(output.getData(), output.getLength());
        MassDbLicenseState restored = MassDbLicenseState.read(input);

        Assertions.assertEquals(1, restored.getLicenseCorrectionBarriers().size());
        Assertions.assertEquals(2_000,
                restored.getLicenseCorrectionBarriers().get(0).getSupersededExpiresAt());
    }

    @Test
    void managerJournalsBeforePublishingState() {
        AtomicInteger journals = new AtomicInteger();
        MassDbLicenseManager manager = new MassDbLicenseManager(
                MassDbLicenseState.empty(), ignored -> journals.incrementAndGet());
        manager.transition(state -> state.bootstrap(false, PLAN_SHA));
        Assertions.assertEquals(1, journals.get());
        Assertions.assertEquals(MassDbLicenseState.EnforcementMode.ENFORCING,
                manager.snapshot().getEnforcementMode());
    }

    private static MassDbLicenseState initializedWithLicense(long expiresAt) {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(false, PLAN_SHA);
        state = state.prepareLicense("op-1", "key-1", REQUEST_SHA,
                MassDbLicenseState.ImportIntent.NORMAL,
                license("initial", repeat('0'), 100, expiresAt),
                "admin", null, 200, 300);
        return state.commit("op-1", 201);
    }

    private static MassDbLicenseState.ActiveLicense license(
            String id, String sha, long issuedAt, long expiresAt) {
        return new MassDbLicenseState.ActiveLicense(
                id, sha, "license-kid", issuedAt, expiresAt, new byte[] {1, 2, 3});
    }

    private static MassDbLicenseState.ActiveKeyset keyset(long version, char shaCharacter) {
        return new MassDbLicenseState.ActiveKeyset(
                version, repeat(shaCharacter), new byte[] {4, 5, 6});
    }

    private static String repeat(char value) {
        StringBuilder result = new StringBuilder(64);
        for (int index = 0; index < 64; index++) {
            result.append(value);
        }
        return result.toString();
    }
}
