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

import java.util.Collections;

class MassDbLicenseIngressControlCoreTest {
    @Test
    void machineObservationIsBoundToAuthenticatedAdapterType() {
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(
                false, repeat('a'));
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                .upsertConfigured("fe-1", "https://fe-1:8050", true);
        state = state.prepareIngressInventory("ingress", "ingress-idem", repeat('b'),
                inventory, 100, 200).commit("ingress", 101);
        final MassDbLicenseState preparedState = state;

        MassDbLicenseIngressControlCore.RoutingEvidenceRequest request =
                new MassDbLicenseIngressControlCore.RoutingEvidenceRequest();
        request.nodeUuid = "fe-1";
        request.adapterType = "keepalived";
        request.objectIdentity = "vip-1";
        request.objectRevision = 1;
        request.routingState = "REMOVED";
        request.evidenceDigest = repeat('c');
        request.observedAt = 300;

        MassDbLicenseIngressControlCore core = new MassDbLicenseIngressControlCore();
        MassDbLicenseException mismatch = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> core.observeMachine(preparedState, request, "haproxy", 300));
        Assertions.assertEquals("MASSDB_LICENSE_ROUTING_EVIDENCE_INVALID",
                mismatch.getCode());

        MassDbLicenseState observed = core.observeMachine(
                preparedState, request, "keepalived", 300);
        MassDbLicenseIngressInventory.IngressNode node =
                observed.getIngressInventory().getNodes().get("fe-1");
        Assertions.assertEquals("keepalived:vip-1", node.getRoutingObjectIdentity());
        Assertions.assertEquals(1, node.getRoutingObjectRevision());
        Assertions.assertEquals(1_200, node.getRoutingExpiresAt());
    }

    private static String repeat(char value) {
        return String.join("", Collections.nCopies(64, String.valueOf(value)));
    }
}
