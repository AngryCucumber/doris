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
import org.junit.jupiter.api.function.Executable;

import java.util.Arrays;

class MassDbLicensePreconditionTokenTest {
    @Test
    void authenticatesClaimsAndRejectsTamperingAndExpiry() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 7);
        MassDbLicensePreconditionToken.Claims claims =
                new MassDbLicensePreconditionToken.Claims(
                        "LICENSE_IMPORT", "ACTIVATE", null, null, 3, 8,
                        repeat('b'), repeat('c'), repeat('a'),
                        100, 2_000, 200, 500, "nonce-1");
        String token = MassDbLicensePreconditionToken.issue(key, claims);
        MassDbLicensePreconditionToken.Claims verified =
                MassDbLicensePreconditionToken.verify(key, token, 300);
        Assertions.assertEquals("ACTIVATE", verified.getAction());
        Assertions.assertEquals(repeat('a'), verified.getCandidateSha256());

        String tampered = token.substring(0, token.length() - 1)
                + (token.endsWith("A") ? "B" : "A");
        assertPreconditionFailure(() -> MassDbLicensePreconditionToken.verify(key, tampered, 300));
        assertPreconditionFailure(() -> MassDbLicensePreconditionToken.verify(key, token, 501));
    }

    private static void assertPreconditionFailure(Executable executable) {
        MassDbLicenseException error = Assertions.assertThrows(MassDbLicenseException.class, executable);
        Assertions.assertEquals("MASSDB_LICENSE_PRECONDITION_FAILED", error.getCode());
    }

    private static String repeat(char value) {
        char[] result = new char[64];
        Arrays.fill(result, value);
        return new String(result);
    }
}
