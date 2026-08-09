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

import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

class MassDbLicenseReadApiCoreTest {
    private static final long NOW = 1_767_225_600L;
    private static final long MAX_TERM = 31_536_000L;

    @Test
    void reportsCapabilityAndRefusesImportReadinessWithoutIngressInventory() {
        Map<String, PublicKey> roots = Collections.singletonMap(
                "massdb-test-root-1",
                MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.ROOT_PUBLIC)));
        MassDbLicenseReadApiCore core = new MassDbLicenseReadApiCore("4.0.5", MAX_TERM, roots);
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(false, repeat('a'));

        MassDbLicenseReadApiCore.Capability capability = core.capability(state);
        Assertions.assertTrue(capability.supported);
        Assertions.assertEquals("massdb-sql", capability.componentType);
        Assertions.assertEquals("ENFORCING", capability.enforcementMode);
        Assertions.assertEquals("MISSING", core.status(state, NOW, NOW).state);

        MassDbLicenseProtocolV1.VerifiedKeyset verifiedKeyset =
                MassDbLicenseProtocolV1.verifyKeyset(
                        MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.KEYSET),
                        roots, NOW, null);
        MassDbLicenseState.ActiveKeyset keyset = new MassDbLicenseState.ActiveKeyset(
                verifiedKeyset.getPayload().getKeysetVersion(), verifiedKeyset.getSha256(),
                MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.KEYSET));
        state = state.prepareKeyset("keyset-op", "keyset-idem", repeat('b'),
                MassDbLicenseState.MutationKind.ADDITIVE_KEYSET, keyset, NOW, NOW + 60)
                .commit("keyset-op", NOW);
        MassDbLicenseState keysetOnlyState = state;

        MassDbLicenseReadApiCore.ValidateResult result = core.validateNormal(
                state, MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.VALID_LICENSE), NOW);
        Assertions.assertEquals("ACTIVATE", result.action);
        Assertions.assertFalse(result.readyForImport);
        Assertions.assertNull(result.preconditionToken);
        Assertions.assertEquals(
                Collections.singletonList("MASSDB_LICENSE_INGRESS_INVENTORY_EMPTY"), result.warnings);

        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured("fe-1", "https://fe-1:8050", true);
        state = state.prepareIngressInventory("ingress-op", "ingress-idem", repeat('e'),
                inventory, NOW, NOW + 60).commit("ingress-op", NOW);
        state = state.recordIngressHeartbeat("fe-1", true, NOW, NOW + 120)
                .recordRoutingEvidence("fe-1",
                        MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                        MassDbLicenseIngressInventory.EvidenceSource.MACHINE,
                        NOW, NOW + 120);
        result = core.validateNormal(
                state, MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.VALID_LICENSE), NOW);
        Assertions.assertTrue(result.readyForImport);
        Assertions.assertNotNull(result.preconditionToken);
        Assertions.assertEquals(1, result.expectedIngressNodes);
        Assertions.assertEquals(1, result.liveIngressNodes);
        MassDbLicensePreconditionToken.Claims token = MassDbLicensePreconditionToken.verify(
                state.getPreconditionHmacKey(), result.preconditionToken, NOW);
        Assertions.assertEquals(result.contentSha256, token.getCandidateSha256());
        Assertions.assertEquals(state.getTopologyRevision(), token.getTopologyRevision());

        MassDbLicenseProtocolV1.VerifiedLicense verifiedLicense =
                MassDbLicenseProtocolV1.verifyLicense(
                        MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.VALID_LICENSE),
                        verifiedKeyset, NOW, MAX_TERM, null);
        MassDbLicenseState.ActiveLicense active = new MassDbLicenseState.ActiveLicense(
                verifiedLicense.getPayload().getLicenseId(), verifiedLicense.getSha256(),
                verifiedLicense.getKid(), verifiedLicense.getPayload().getIssuedAt(),
                verifiedLicense.getPayload().getExpiresAt(),
                MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.VALID_LICENSE));
        state = state.prepareLicense("license-op", "license-idem", repeat('c'),
                MassDbLicenseState.ImportIntent.NORMAL, active, "admin", null, NOW, NOW + 60)
                .commit("license-op", NOW);
        state = state.recordIngressActiveAck(
                "fe-1", active.getSha256(), active.getExpiresAt(), state.getEnforcementEpoch());

        MassDbLicenseReadApiCore.Status validStatus = core.status(state, NOW, NOW);
        Assertions.assertEquals("EXPIRING", validStatus.state);
        Assertions.assertEquals(1, validStatus.coveredIngressNodes);
        Assertions.assertEquals("EXPIRED", core.status(
                state, active.getExpiresAt(), active.getExpiresAt()).state);

        MassDbLicenseState.ActiveLicense corruptMetadata = new MassDbLicenseState.ActiveLicense(
                active.getLicenseId(), active.getSha256(), "wrong-kid", active.getIssuedAt(),
                active.getExpiresAt(), active.getArtifact());
        MassDbLicenseState corruptState = keysetOnlyState.prepareLicense(
                "corrupt-op", "corrupt-idem", repeat('d'), MassDbLicenseState.ImportIntent.NORMAL,
                corruptMetadata, "admin", null, NOW, NOW + 60).commit("corrupt-op", NOW);
        Assertions.assertEquals("INVALID", core.status(
                corruptState, active.getExpiresAt(), active.getExpiresAt()).state);
    }

    @Test
    void capabilityAdvertisesSupportBeforeBootstrap() {
        Map<String, PublicKey> roots = Collections.singletonMap(
                "massdb-test-root-1",
                MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.decode(
                                MassDbLicenseProtocolV1Test.ROOT_PUBLIC)));
        MassDbLicenseReadApiCore.Capability capability =
                new MassDbLicenseReadApiCore("4.0.5", MAX_TERM, roots)
                        .capability(MassDbLicenseState.empty());
        Assertions.assertTrue(capability.supported);
        Assertions.assertEquals("UNINITIALIZED", capability.enforcementMode);
        Assertions.assertNull(capability.licenseControlDeploymentUuid);
    }

    private static String repeat(char value) {
        StringBuilder result = new StringBuilder(64);
        for (int index = 0; index < 64; index++) {
            result.append(value);
        }
        return result.toString();
    }
}
