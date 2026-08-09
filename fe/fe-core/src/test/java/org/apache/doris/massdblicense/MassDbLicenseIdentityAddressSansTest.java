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

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

class MassDbLicenseIdentityAddressSansTest {
    @Test
    void canonicalizesAndEmbedsExactAddressSansInCsr() {
        MassDbLicenseIdentityAddressSans.AddressSans sans =
                MassDbLicenseIdentityAddressSans.normalize(
                        Arrays.asList("SQL-2.EXAMPLE.INTERNAL", "sql-1.example.internal"),
                        Arrays.asList("2001:db8::1", "10.0.0.12"), true);

        Assertions.assertEquals(Arrays.asList(
                "sql-1.example.internal", "sql-2.example.internal"), sans.dnsNames());
        Assertions.assertEquals(Arrays.asList(
                "10.0.0.12", "2001:db8:0:0:0:0:0:1"), sans.ipAddresses());
        MassDbLicenseIdentityKeyMaterial.Generated generated =
                MassDbLicenseIdentityKeyMaterial.generate(
                        "spiffe://massdb.internal/license/component/massdb-sql/"
                                + "00000000-0000-4000-8000-000000000211/fe/"
                                + "00000000-0000-4000-8000-000000000212",
                        sans.dnsNames(), sans.ipAddresses(), 1_800_000_000L);
        Assertions.assertTrue(indexOf(generated.csr,
                "sql-1.example.internal".getBytes(StandardCharsets.US_ASCII)) >= 0);
        Assertions.assertTrue(indexOf(generated.csr,
                new byte[] {10, 0, 0, 12}) >= 0);
    }

    @Test
    void rejectsAmbiguousOrUnsafeAddressSans() {
        assertInvalid(Collections.singletonList("*.example.internal"),
                Collections.emptyList());
        assertInvalid(Arrays.asList("SQL.example.internal", "sql.example.internal"),
                Collections.emptyList());
        assertInvalid(Collections.singletonList("10.0.0.1"), Collections.emptyList());
        assertInvalid(Collections.emptyList(), Collections.singletonList("010.0.0.1"));
        assertInvalid(Collections.emptyList(), Collections.emptyList());
    }

    @Test
    @SuppressWarnings("unchecked")
    void requiresCertificateAddressSansToMatchExactly() throws Exception {
        MassDbLicenseIdentityAddressSans.AddressSans expected =
                MassDbLicenseIdentityAddressSans.normalize(
                        Collections.singletonList("sql.example.internal"),
                        Collections.singletonList("10.0.0.12"), true);
        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        Collection<List<?>> actual = Arrays.asList(
                Arrays.asList(6, "spiffe://massdb.internal/license/component/massdb-sql/"
                        + "00000000-0000-4000-8000-000000000211/fe/"
                        + "00000000-0000-4000-8000-000000000212"),
                Arrays.asList(2, "sql.example.internal"),
                Arrays.asList(7, "10.0.0.12"));
        Mockito.when(certificate.getSubjectAlternativeNames()).thenReturn(actual);

        MassDbLicenseIdentityAddressSans.requireCertificateMatches(certificate, expected);
        MassDbLicenseException mismatch = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseIdentityAddressSans.requireCertificateMatches(
                        certificate, MassDbLicenseIdentityAddressSans.normalize(
                                Collections.singletonList("other.example.internal"),
                                Collections.singletonList("10.0.0.12"), true)));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_ADDRESS_SAN_INVALID",
                mismatch.getCode());
    }

    private static void assertInvalid(List<String> dns, List<String> ips) {
        MassDbLicenseException failure = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseIdentityAddressSans.normalize(dns, ips, true));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_ADDRESS_SAN_INVALID",
                failure.getCode());
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int offset = 0; offset <= haystack.length - needle.length; offset++) {
            int index = 0;
            while (index < needle.length && haystack[offset + index] == needle[index]) {
                index++;
            }
            if (index == needle.length) {
                return offset;
            }
        }
        return -1;
    }
}
