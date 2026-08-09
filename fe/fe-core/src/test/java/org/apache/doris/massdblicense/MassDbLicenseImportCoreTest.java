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
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

class MassDbLicenseImportCoreTest {
    private static final long NOW = 1_767_225_600L;
    private static final long MAX_TERM = 31_536_000L;
    private static final String LICENSE_SHA =
            "b3f71e8f014c7eaf0f81db83a13803b34648617d3baf2e38b3e44ef0700e1745";

    @TempDir
    Path localDirectory;

    @Test
    void preparesWithOpaqueCasCommitsOnlyAfterAckAndReplaysByBodyHash() {
        MassDbLicenseLocalSnapshotStore localStore =
                new MassDbLicenseLocalSnapshotStore(localDirectory);
        String nodeUuid = localStore.getNodeUuid();
        Map<String, PublicKey> roots = Collections.singletonMap(
                "massdb-test-root-1", MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.ROOT_PUBLIC)));
        byte[] keysetBytes = MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.KEYSET);
        byte[] licenseBytes = MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.VALID_LICENSE);
        MassDbLicenseProtocolV1.VerifiedKeyset verifiedKeyset =
                MassDbLicenseProtocolV1.verifyKeyset(keysetBytes, roots, NOW, null);
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(false, repeat('a'))
                .prepareKeyset("keyset", "keyset-idem", repeat('b'),
                        MassDbLicenseState.MutationKind.ADDITIVE_KEYSET,
                        new MassDbLicenseState.ActiveKeyset(
                                verifiedKeyset.getPayload().getKeysetVersion(),
                                verifiedKeyset.getSha256(), keysetBytes), NOW, NOW + 60)
                .commit("keyset", NOW);
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured(nodeUuid, "https://fe-1:8050", true);
        state = state.prepareIngressInventory("ingress", "ingress-idem", repeat('c'),
                inventory, NOW, NOW + 60).commit("ingress", NOW)
                .recordIngressHeartbeat(nodeUuid, true, NOW, NOW + 120)
                .recordRoutingEvidence(nodeUuid,
                        MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                        MassDbLicenseIngressInventory.EvidenceSource.MACHINE,
                        NOW, NOW + 120);

        MassDbLicenseReadApiCore readCore = new MassDbLicenseReadApiCore(
                "4.0.5", MAX_TERM, roots);
        MassDbLicenseReadApiCore.ValidateResult validation =
                readCore.validateNormal(state, licenseBytes, NOW);
        MassDbLicenseImportCore importCore = new MassDbLicenseImportCore(MAX_TERM, roots);
        MassDbLicenseImportCore.Result prepared = importCore.prepareNormal(state, licenseBytes,
                LICENSE_SHA, validation.preconditionToken, "license-idem", "license-op",
                "admin-cert", NOW, NOW + 300);
        Assertions.assertFalse(prepared.terminal);
        Assertions.assertNull(prepared.state.getActiveLicense());
        Assertions.assertEquals("AWAITING_ACK",
                prepared.state.findOperation("license-op").apiState);
        Assertions.assertEquals("license-op",
                readCore.status(prepared.state, NOW, NOW).stagedOperationId);
        MassDbLicenseState aborted = prepared.state.abort("license-op").abort("license-op");
        Assertions.assertEquals("ABORTED", aborted.findOperation("license-op").apiState);
        MassDbLicenseImportCore.RedriveResult redrive = importCore.recoverNormal(
                prepared.state, "license-op", NOW + 1);
        Assertions.assertFalse(redrive.terminal);
        Assertions.assertEquals(Collections.singletonList(nodeUuid),
                redrive.plan.requiredAckNodeUuids);
        Assertions.assertEquals(LICENSE_SHA, redrive.plan.contentSha256);
        MassDbLicenseLocalSnapshotStore.LicenseAck localAck =
                importCore.prepareLocalAck(
                        localStore, redrive.plan, verifiedKeyset, NOW + 1);
        Assertions.assertEquals(LICENSE_SHA, localAck.contentSha256);
        Assertions.assertEquals(redrive.plan.licenseExpiresAt, localAck.licenseExpiresAt);
        Assertions.assertNull(localStore.loadActive());
        Assertions.assertNotNull(localStore.loadLicensePending());

        MassDbLicenseImportCore.RedriveResult unavailable = importCore.recoverNormal(
                prepared.state, "license-op", NOW + 121);
        Assertions.assertTrue(unavailable.terminal);
        Assertions.assertEquals("MASSDB_LICENSE_INGRESS_UNAVAILABLE", unavailable.errorCode);
        Assertions.assertNull(unavailable.state.getMutation());
        Assertions.assertEquals("MASSDB_LICENSE_INGRESS_UNAVAILABLE",
                importCore.recoverNormal(unavailable.state, "license-op", NOW + 122).errorCode);

        MassDbLicenseState expired = prepared.state.recoverOrExpireMutation(NOW + 301);
        Assertions.assertNull(expired.getMutation());
        Assertions.assertEquals("MASSDB_LICENSE_OPERATION_DEADLINE_EXCEEDED",
                expired.findOperationByIdempotencyKey("license-idem").errorCode);

        MassDbLicenseException incomplete = Assertions.assertThrows(MassDbLicenseException.class,
                () -> importCore.commitNormal(prepared.state, "license-op",
                        Collections.emptyList(), NOW + 1));
        Assertions.assertEquals("MASSDB_LICENSE_INGRESS_ACK_INCOMPLETE", incomplete.getCode());

        MassDbLicenseImportCore.Result committed = importCore.commitNormal(prepared.state,
                "license-op", Collections.singletonList(nodeUuid), NOW + 1);
        Assertions.assertTrue(committed.terminal);
        Assertions.assertEquals(LICENSE_SHA, committed.state.getActiveLicense().getSha256());
        Assertions.assertEquals(1,
                readCore.status(committed.state, NOW + 1, NOW + 1).coveredIngressNodes);
        Assertions.assertEquals(MassDbLicenseImportCore.LocalDecision.COMMIT,
                importCore.applyAuthoritativeDecision(
                        localStore, committed.state, NOW + 2));
        Assertions.assertNull(localStore.loadLicensePending());
        Assertions.assertEquals(LICENSE_SHA, localStore.loadActive().sha256);

        MassDbLicenseImportCore.Result replay = importCore.prepareNormal(committed.state,
                licenseBytes, LICENSE_SHA, "expired-or-irrelevant-token", "license-idem",
                "ignored", "admin-cert", NOW + 1, NOW + 60);
        Assertions.assertTrue(replay.replayed);
        Assertions.assertEquals("license-op", replay.operationId);
    }

    private static String repeat(char value) {
        return String.join("", Collections.nCopies(64, String.valueOf(value)));
    }
}
