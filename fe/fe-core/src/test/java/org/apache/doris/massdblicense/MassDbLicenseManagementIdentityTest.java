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
import org.mockito.Mockito;

import java.security.cert.X509Certificate;
import java.util.Collections;

class MassDbLicenseManagementIdentityTest {
    private static final String MANAGER_UUID = "550e8400-e29b-41d4-a716-446655440000";

    @Test
    void parsesFrozenManagerOperatorAndAdapterTemplates() throws Exception {
        MassDbLicenseManagementIdentity.Principal view =
                MassDbLicenseManagementIdentity.parse(
                        "spiffe://massdb.internal/license/manager/" + MANAGER_UUID
                                + "/view/manager-1");
        Assertions.assertEquals(MassDbLicenseManagementIdentity.Role.VIEW, view.role);
        Assertions.assertTrue(view.canRead());
        Assertions.assertFalse(view.canAdminister());
        Assertions.assertEquals(MANAGER_UUID, view.managerInstallationUuid);

        MassDbLicenseManagementIdentity.Principal admin =
                MassDbLicenseManagementIdentity.parse(
                        "spiffe://massdb.internal/license/operator/alice/admin");
        Assertions.assertEquals(MassDbLicenseManagementIdentity.Role.ADMIN, admin.role);
        Assertions.assertTrue(admin.canRead());
        Assertions.assertTrue(admin.canAdminister());

        MassDbLicenseManagementIdentity.Principal correction =
                MassDbLicenseManagementIdentity.parse(
                        "spiffe://massdb.internal/license/operator/approver-1/correction");
        Assertions.assertEquals(MassDbLicenseManagementIdentity.Role.CORRECTION,
                correction.role);
        Assertions.assertFalse(correction.canRead());
        Assertions.assertFalse(correction.canAdminister());

        MassDbLicenseManagementIdentity.Principal adapter =
                MassDbLicenseManagementIdentity.parse(
                        "spiffe://massdb.internal/license/routing-adapter/haproxy/adapter-1");
        Assertions.assertEquals(MassDbLicenseManagementIdentity.Role.ROUTING_ADAPTER,
                adapter.role);
        Assertions.assertFalse(adapter.canRead());
        Assertions.assertEquals("haproxy", adapter.routingAdapterType);

        X509Certificate managementLeaf = Mockito.mock(X509Certificate.class);
        Mockito.when(managementLeaf.getBasicConstraints()).thenReturn(-1);
        Mockito.when(managementLeaf.getKeyUsage()).thenReturn(new boolean[] {true});
        Mockito.when(managementLeaf.getExtendedKeyUsage()).thenReturn(
                Collections.singletonList("1.3.6.1.5.5.7.3.2"));
        MassDbLicenseIdentityKeyMaterial.requireLeafUsage(managementLeaf, false);
        MassDbLicenseException serverProfile = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseIdentityKeyMaterial.requireLeafUsage(
                        managementLeaf, true));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID",
                serverProfile.getCode());
    }

    @Test
    void rejectsAmbiguousOrNonCanonicalManagementIdentities() {
        assertInvalid("spiffe://massdb.internal/license/manager/"
                + MANAGER_UUID + "/admin/manager-1/extra");
        assertInvalid("spiffe://massdb.internal/license/manager/"
                + "550e8400-e29b-11d4-a716-446655440000/admin/manager-1");
        assertInvalid("spiffe://massdb.internal/license/operator/alice/owner");
        assertInvalid("spiffe://massdb.internal/license/operator/alice%2Fadmin/view");
        assertInvalid("spiffe://other.internal/license/operator/alice/view");
    }

    private static void assertInvalid(String value) {
        MassDbLicenseException failure = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseManagementIdentity.parse(value));
        Assertions.assertEquals("MASSDB_LICENSE_MTLS_IDENTITY_INVALID", failure.getCode());
    }
}
