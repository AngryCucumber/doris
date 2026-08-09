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

import java.util.Arrays;
import java.util.Collections;

class MassDbLicenseSpiffeIdentityTest {
    private static final String DEPLOYMENT = "22222222-2222-4222-8222-222222222222";
    private static final String NODE = "a1111111-b111-4c11-8d11-e11111111111";
    private static final String SQL_FE = "spiffe://massdb.internal/license/component/"
            + "massdb-sql/" + DEPLOYMENT + "/fe/" + NODE;

    @Test
    void acceptsOnlyExactSingleComponentUriSan() {
        MassDbLicenseSpiffeIdentity.Identity identity =
                MassDbLicenseSpiffeIdentity.requireNode(Collections.singletonList(SQL_FE),
                        "massdb-sql", DEPLOYMENT, "fe", NODE);
        Assertions.assertEquals(NODE, identity.nodeUuid);

        MassDbLicenseException multiple = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseSpiffeIdentity.parseUnique(Arrays.asList(SQL_FE, SQL_FE)));
        Assertions.assertEquals("MASSDB_LICENSE_MTLS_IDENTITY_INVALID", multiple.getCode());

        MassDbLicenseException mismatch = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseSpiffeIdentity.requireNode(Collections.singletonList(SQL_FE),
                        "massdb-sql", DEPLOYMENT, "fe",
                        "33333333-3333-4333-8333-333333333333"));
        Assertions.assertEquals("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH", mismatch.getCode());
    }

    @Test
    void rejectsWrongTrustDomainEscapesAndUnsupportedRoles() {
        assertInvalid(SQL_FE.replace("massdb.internal", "other.internal"));
        assertInvalid(SQL_FE.replace("/fe/", "/%66e/"));
        assertInvalid(SQL_FE.replace("/fe/", "/graphd/"));
        assertInvalid(SQL_FE.replace(NODE, NODE.toUpperCase()));
        assertInvalid(SQL_FE + "?role=fe");
    }

    private static void assertInvalid(String value) {
        MassDbLicenseException error = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseSpiffeIdentity.parseUnique(Collections.singletonList(value)));
        Assertions.assertEquals("MASSDB_LICENSE_MTLS_IDENTITY_INVALID", error.getCode());
    }
}
