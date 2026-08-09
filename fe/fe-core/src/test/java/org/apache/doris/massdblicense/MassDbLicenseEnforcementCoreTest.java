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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

class MassDbLicenseEnforcementCoreTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void leaderRedriveAndRoleRestartConvergeThroughAuthoritativeDecision() {
        MassDbLicenseEnforcementCore core = new MassDbLicenseEnforcementCore();
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("commit"));
        String nodeUuid = store.getNodeUuid();
        MassDbLicenseState prepared = readyObserveState(nodeUuid).prepareEnforcementActivation(
                "enforce", "enforce-idem", repeat('7'), 300, 500);
        MassDbLicenseEnforcementCore.RedriveResult redrive =
                core.recover(prepared, "enforce", 301);
        Assertions.assertFalse(redrive.terminal);
        Assertions.assertEquals(Collections.singletonList(nodeUuid),
                redrive.plan.requiredAckNodeUuids);

        store.writeActive(new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                new byte[] {1, 2, 3}, activeSha256(), 2_000, 0, 250));
        MassDbLicenseState.ActivationAckEvidence evidence =
                core.prepareLocalAck(store, redrive.plan);
        Assertions.assertDoesNotThrow(
                () -> core.prepareLocalAck(store, redrive.plan));
        Assertions.assertEquals(MassDbLicenseEnforcementCore.Decision.PENDING,
                core.applyAuthoritativeDecision(store, prepared, 302));
        Assertions.assertNotNull(store.loadPending());

        MassDbLicenseState committed = prepared.commitEnforcementActivation(
                "enforce", Collections.singletonList(evidence), 303);
        MassDbLicenseLocalSnapshotStore restarted = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("commit"));
        Assertions.assertEquals(MassDbLicenseEnforcementCore.Decision.COMMIT,
                core.applyAuthoritativeDecision(restarted, committed, 304));
        Assertions.assertNull(restarted.loadPending());
        Assertions.assertEquals(1, restarted.loadActive().enforcementEpoch);
    }

    @Test
    void failedOrAbortedOperationClearsPendingButUnknownDecisionDoesNot() {
        MassDbLicenseEnforcementCore core = new MassDbLicenseEnforcementCore();
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("abort"));
        String nodeUuid = store.getNodeUuid();
        MassDbLicenseState prepared = readyObserveState(nodeUuid).prepareEnforcementActivation(
                "enforce-abort", "enforce-abort-idem", repeat('6'), 300, 500);
        MassDbLicenseEnforcementCore.RecoveryPlan plan =
                core.recover(prepared, "enforce-abort", 301).plan;
        store.writeActive(new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                new byte[] {1, 2, 3}, activeSha256(), 2_000, 0, 250));
        core.prepareLocalAck(store, plan);

        Assertions.assertEquals(MassDbLicenseEnforcementCore.Decision.UNKNOWN,
                core.applyAuthoritativeDecision(store, MassDbLicenseState.empty(), 302));
        Assertions.assertNotNull(store.loadPending());
        MassDbLicenseState aborted = prepared.abort("enforce-abort", 303);
        Assertions.assertEquals(MassDbLicenseEnforcementCore.Decision.ABORT,
                core.applyAuthoritativeDecision(store, aborted, 304));
        Assertions.assertNull(store.loadPending());

        MassDbLicenseState expiring = readyObserveState(nodeUuid).prepareEnforcementActivation(
                "enforce-expire", "enforce-expire-idem", repeat('5'), 300, 305);
        MassDbLicenseEnforcementCore.RedriveResult expired =
                core.recover(expiring, "enforce-expire", 305);
        Assertions.assertTrue(expired.terminal);
        Assertions.assertEquals("MASSDB_LICENSE_OPERATION_DEADLINE_EXCEEDED", expired.errorCode);
    }

    private static MassDbLicenseState readyObserveState(String nodeUuid) {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, repeat('a'));
        MassDbLicenseState.ActiveLicense active = new MassDbLicenseState.ActiveLicense(
                "initial", activeSha256(), "kid", 100, 2_000, new byte[] {1, 2, 3});
        state = state.prepareLicense("license", "license-idem", repeat('b'),
                MassDbLicenseState.ImportIntent.NORMAL, active,
                "admin", null, 200, 250).commit("license", 201);
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured(nodeUuid, "https://fe-1:8050", true);
        state = state.prepareIngressInventory("ingress", "ingress-idem", repeat('c'),
                inventory, 210, 250).commit("ingress", 211)
                .recordIngressHeartbeat(nodeUuid, true, 220, 1_000)
                .recordRoutingEvidence(nodeUuid,
                        MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                        MassDbLicenseIngressInventory.EvidenceSource.MACHINE, 220, 1_000);
        return state.recordIngressActiveAck(nodeUuid, activeSha256(), 2_000, 0);
    }

    private static String activeSha256() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(new byte[] {1, 2, 3});
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
                result.append(Character.forDigit(item & 0x0f, 16));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    private static String repeat(char value) {
        StringBuilder result = new StringBuilder(64);
        for (int index = 0; index < 64; index++) {
            result.append(value);
        }
        return result.toString();
    }
}
