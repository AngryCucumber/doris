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
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

public class MassDbLicenseProtocolV1Test {
    @Test
    void verifiesTheSameP1GoldenArtifactsAsGoAndCpp() {
        PublicKey root = MassDbLicenseProtocolV1.parsePublicKeyPem(decode(ROOT_PUBLIC));
        Map<String, PublicKey> roots = Collections.singletonMap("massdb-test-root-1", root);
        MassDbLicenseProtocolV1.VerifiedKeyset keyset = MassDbLicenseProtocolV1.verifyKeyset(
                decode(KEYSET), roots, 1_767_225_600L, null);
        Assertions.assertEquals(
                "f3f32036e3e6746b2249fee11d62c19242b89169386153e5972cfbddc8fbe158",
                keyset.getSha256());

        MassDbLicenseProtocolV1.VerifiedLicense valid = MassDbLicenseProtocolV1.verifyLicense(
                decode(VALID_LICENSE), keyset, 1_767_225_600L, 31_536_000L, null);
        Assertions.assertEquals(
                "b3f71e8f014c7eaf0f81db83a13803b34648617d3baf2e38b3e44ef0700e1745",
                valid.getSha256());

        MassDbLicenseException expired = Assertions.assertThrows(MassDbLicenseException.class,
                () -> MassDbLicenseProtocolV1.verifyLicense(
                        decode(EXPIRED_LICENSE), keyset, 1_767_225_600L, 31_536_000L, null));
        Assertions.assertEquals("MASSDB_LICENSE_EXPIRED", expired.getCode());
        MassDbLicenseException tampered = Assertions.assertThrows(MassDbLicenseException.class,
                () -> MassDbLicenseProtocolV1.verifyLicense(
                        decode(TAMPERED_LICENSE), keyset, 1_767_225_600L, 31_536_000L, null));
        Assertions.assertEquals("MASSDB_LICENSE_SIGNATURE_INVALID", tampered.getCode());

        MassDbLicenseProtocolV1.ClockContext context = new MassDbLicenseProtocolV1.ClockContext(
                repeatedByte(0x11), "00000000-0000-4000-8000-000000000099",
                repeatedByte(0x22), 1_768_000_000L, 6, 1_767_225_600L);
        MassDbLicenseProtocolV1.VerifiedClockRecovery recovered =
                MassDbLicenseProtocolV1.verifyClockRecovery(decode(CLOCK_RECOVERY), keyset, context);
        Assertions.assertEquals(
                "8141149315e3ad158c52e55a85fb84f41d4ca3afb72ebb3f92664aaaade17a72",
                recovered.getSha256());

        MassDbLicenseProtocolV1.VerifiedLicense bundled =
                MassDbLicenseProtocolV1.verifyRecoveryBundle(
                        decode(RECOVERY_BUNDLE), roots, 1_767_225_600L, 31_536_000L, 0);
        Assertions.assertEquals(valid.getSha256(), bundled.getSha256());
    }

    static byte[] decode(String value) {
        return Base64.getDecoder().decode(value);
    }

    public static byte[] rootPublicBytes() {
        return decode(ROOT_PUBLIC);
    }

    public static byte[] keysetBytes() {
        return decode(KEYSET);
    }

    public static byte[] validLicenseBytes() {
        return decode(VALID_LICENSE);
    }

    private static byte[] repeatedByte(int value) {
        byte[] result = new byte[32];
        java.util.Arrays.fill(result, (byte) value);
        return result;
    }

    static final String ROOT_PUBLIC = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFYTBMQmN5UVhwU2VRVGJCMk1oMUR3aDQ0SXNNRQo3MWxuSnBQMUxoVXd3TlpuMVk3ODE4ekU3d2pwYTZ6UEkvLzVvTENBRnIvT05lQmV5cWJmaHRMZHZnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
    static final String KEYSET = "0oRXogEmBFJtYXNzZGItdGVzdC1yb290LTGgWQEJpwEBAnVNQVNTREJfVFJVU1RFRF9LRVlTRVQDZk1BU1NEQgQBBRppVbaoBoKkAXNtYXNzZGItdGVzdC1jbG9jay0xAm5DTE9DS19SRUNPVkVSWQNYIP8fNoE5UX2LxsOKmaXfc78PUJ5SAO2axxURZLFDzk9FBFggYCL9Y2T5q51le17Lagjc5r1xopjmLJmJDYvQ1mOxIRakAXVtYXNzZGItdGVzdC1saWNlbnNlLTECb0xJQ0VOU0VfU0lHTklORwNYIO4voGpbS4XrUulf3+MCgXo7SGij+SYd8gqS++AKwuezBFggM9NCgdu8ZD7UNVDxCKS2R5JAqu+hXXq/9WSe1KCNWG4HgFhAabq+wn7bS/h+bIpRSAFa7OpxnheLnkF8cy9d07CUa0ixPfvd2e6ejSnfZpDwsUpBtuPTh22/2zVhH2Uvh+WJ1A==";
    static final String VALID_LICENSE = "0oRYGqIBJgRVbWFzc2RiLXRlc3QtbGljZW5zZS0xoFg+pQEBAngkMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAxA2ZNQVNTREIEGmlVtqgFGml9RgBYQDXjfKtQyUqrAIbjJfqOxsASlFAYcwzqcCRdEjiyYXkHGNw8Pn3xsDiC8WKTw56yHYYDqtQNYYxMPjqhRlvdpSc=";
    private static final String EXPIRED_LICENSE = "0oRYGqIBJgRVbWFzc2RiLXRlc3QtbGljZW5zZS0xoFg+pQEBAngkMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAyA2ZNQVNTREIEGmlVtkQFGmlVuQBYQHYHARbBkRzHaHyePsUknIP1+xOtG5RovVTXzIjkRynpsroiQn71bBIMbMebnco1P/n5yrS8G9Oi1UBTlkkZZ7I=";
    private static final String TAMPERED_LICENSE = "0oRYGqIBJgRVbWFzc2RiLXRlc3QtbGljZW5zZS0xoFg+pQEBAngkMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAxA2ZNQVNTREIEGmlVtqgFGml9RgBYQDXjfKtQyUqrAIbjJfqOxsASlFAYcwzqcCRdEjiyYXkHGNw8Pn3xsDiC8WKTw56yHYYDqtQNYYxMPjqhRlvdpSY=";
    private static final String CLOCK_RECOVERY = "0oRYGKIBJgRTbWFzc2RiLXRlc3QtY2xvY2stMaBYqasBAQJ1TUFTU0RCX0NMT0NLX1JFQ09WRVJZA2ZNQVNTREIEBwVYIBERERERERERERERERERERERERERERERERERERERERERBngkMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDk5B1ggIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIIGmlhigAJGmlVuQAKGmlVtqgLGmlZqyhYQL37jOfWZpiRKieZoGItwAf8y4D2QlNibvTAOkyaT0POseVYTk9OOUCLzauJYjpEb1nTnUFzfeFt6P77G3jqIJ4=";
    private static final String RECOVERY_BUNDLE = "pAEBAnglTUFTU0RCX0tFWVNFVF9MSUNFTlNFX1JFQ09WRVJZX0JVTkRMRQNZAWnShFeiASYEUm1hc3NkYi10ZXN0LXJvb3QtMaBZAQmnAQECdU1BU1NEQl9UUlVTVEVEX0tFWVNFVANmTUFTU0RCBAEFGmlVtqgGgqQBc21hc3NkYi10ZXN0LWNsb2NrLTECbkNMT0NLX1JFQ09WRVJZA1gg/x82gTlRfYvGw4qZpd9zvw9QnlIA7ZrHFRFksUPOT0UEWCBgIv1jZPmrnWV7XstqCNzmvXGimOYsmYkNi9DWY7EhFqQBdW1hc3NkYi10ZXN0LWxpY2Vuc2UtMQJvTElDRU5TRV9TSUdOSU5HA1gg7i+galtLhetS6V/f4wKBejtIaKP5Jh3yCpL74ArC57MEWCAz00KB27xkPtQ1UPEIpLZHkkCq76Fder/1ZJ7UoI1YbgeAWEBpur7CfttL+H5silFIAVrs6nGeF4ueQXxzL13TsJRrSLE9+93Z7p6NKd9mkPCxSkG249OHbb/bNWEfZS+H5YnUBFih0oRYGqIBJgRVbWFzc2RiLXRlc3QtbGljZW5zZS0xoFg+pQEBAngkMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAxA2ZNQVNTREIEGmlVtqgFGml9RgBYQDXjfKtQyUqrAIbjJfqOxsASlFAYcwzqcCRdEjiyYXkHGNw8Pn3xsDiC8WKTw56yHYYDqtQNYYxMPjqhRlvdpSc=";
}
