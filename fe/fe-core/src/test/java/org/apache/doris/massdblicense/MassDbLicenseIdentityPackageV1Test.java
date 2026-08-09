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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;

class MassDbLicenseIdentityPackageV1Test {
    private static final String DEPLOYMENT_UUID = "00000000-0000-4000-8000-000000000101";
    private static final String NODE_UUID = "00000000-0000-4000-8000-000000000102";
    private static final String KID = "massdb-test-identity-artifact-1";

    @Test
    void verifiesExactIdentityAndCsrBinding() throws Exception {
        KeyPair root = p256();
        byte[] csrSha256 = repeated(0x31);
        byte[] artifact = identityArtifact(root, csrSha256, 2, 900, 900, 2_000);

        MassDbLicenseProtocolV1.VerifiedIdentityPackage verified =
                MassDbLicenseProtocolV1.verifyIdentityPackage(artifact,
                        Collections.singletonMap(KID, root.getPublic()), 1_000, 1L,
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, csrSha256);
        Assertions.assertEquals(2, verified.getPayload().getGeneration());
        Assertions.assertEquals("massdb-sql", verified.getPayload().getComponent());
        Assertions.assertEquals(64, verified.getSha256().length());

        MassDbLicenseException mismatch = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseProtocolV1.verifyIdentityPackage(artifact,
                        Collections.singletonMap(KID, root.getPublic()), 1_000, 1L,
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, repeated(0x32)));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_CSR_MISMATCH",
                mismatch.getCode());

        MassDbLicenseException rollback = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseProtocolV1.verifyIdentityPackage(artifact,
                        Collections.singletonMap(KID, root.getPublic()), 1_000, 2L,
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, csrSha256));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_GENERATION_ROLLBACK",
                rollback.getCode());
    }

    @Test
    void signedTrustBundleCannotBeReplacedAndTermIsBounded() throws Exception {
        KeyPair root = p256();
        byte[] csrSha256 = repeated(0x41);
        byte[] artifact = identityArtifact(root, csrSha256, 1, 900, 900, 2_000);
        byte[] tampered = artifact.clone();
        int trust = lastIndexOf(tampered, "ROOT".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertTrue(trust > 0);
        tampered[trust] = 'X';

        MassDbLicenseException invalidSignature = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseProtocolV1.verifyIdentityPackage(tampered,
                        Collections.singletonMap(KID, root.getPublic()), 1_000, null,
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, csrSha256));
        Assertions.assertEquals("MASSDB_LICENSE_SIGNATURE_INVALID", invalidSignature.getCode());

        byte[] overlong = identityArtifact(root, csrSha256, 1, 900, 900,
                900 + MassDbLicenseProtocolV1.MAX_IDENTITY_TERM_SECONDS + 1);
        MassDbLicenseException invalidTerm = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseProtocolV1.verifyIdentityPackage(overlong,
                        Collections.singletonMap(KID, root.getPublic()), 1_000, null,
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, csrSha256));
        Assertions.assertEquals("MASSDB_LICENSE_FILE_INVALID", invalidTerm.getCode());
    }

    @Test
    void signedRevocationsAcceptFrozenManagementIdentities() throws Exception {
        KeyPair root = p256();
        byte[] csrSha256 = repeated(0x51);
        String revoked = "spiffe://massdb.internal/license/operator/alice/admin";
        byte[] artifact = identityArtifact(
                root, csrSha256, 1, 900, 900, 2_000, revoked);
        MassDbLicenseProtocolV1.VerifiedIdentityPackage verified =
                MassDbLicenseProtocolV1.verifyIdentityPackage(artifact,
                        Collections.singletonMap(KID, root.getPublic()), 1_000, null,
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, csrSha256);
        Assertions.assertEquals(Collections.singletonList(revoked),
                verified.getPayload().getRevocations());

        byte[] malformed = identityArtifact(root, csrSha256, 1, 900, 900, 2_000,
                "spiffe://massdb.internal/license/operator/alice/owner");
        MassDbLicenseException rejected = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseProtocolV1.verifyIdentityPackage(malformed,
                        Collections.singletonMap(KID, root.getPublic()), 1_000, null,
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, csrSha256));
        Assertions.assertEquals("MASSDB_LICENSE_MTLS_IDENTITY_INVALID", rejected.getCode());
    }

    private static KeyPair p256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static byte[] identityArtifact(KeyPair root, byte[] csrSha256, long generation,
            long issuedAt, long notBefore, long notAfter) throws Exception {
        return identityArtifact(root, csrSha256, generation,
                issuedAt, notBefore, notAfter, new String[0]);
    }

    private static byte[] identityArtifact(KeyPair root, byte[] csrSha256, long generation,
            long issuedAt, long notBefore, long notAfter, String... revocations) throws Exception {
        byte[][] encodedRevocations = new byte[revocations.length][];
        for (int index = 0; index < revocations.length; index++) {
            encodedRevocations[index] = text(revocations[index]);
        }
        byte[] payload = map(
                uint(1), uint(1),
                uint(2), text(MassDbLicenseProtocolV1.IDENTITY_PACKAGE_TYPE),
                uint(3), text(MassDbLicenseProtocolV1.PRODUCT),
                uint(4), uint(generation),
                uint(5), uint(issuedAt),
                uint(6), uint(notBefore),
                uint(7), uint(notAfter),
                uint(8), text("massdb-sql"),
                uint(9), text(DEPLOYMENT_UUID),
                uint(10), text("fe"),
                uint(11), text(NODE_UUID),
                uint(12), bytes(csrSha256),
                uint(13), text("LEAF"),
                uint(14), array(),
                uint(15), array(text("ROOT")),
                uint(16), array(encodedRevocations));
        byte[] protectedHeader = map(uint(1), negative(7),
                uint(4), bytes(KID.getBytes(StandardCharsets.US_ASCII)));
        byte[] signatureStructure = array(text("Signature1"), bytes(protectedHeader),
                bytes(new byte[0]), bytes(payload));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(root.getPrivate());
        signer.update(signatureStructure);
        return concat(new byte[] {(byte) 0xd2}, array(bytes(protectedHeader),
                map(), bytes(payload), bytes(derToRaw(signer.sign()))));
    }

    private static byte[] map(byte[]... entries) {
        if ((entries.length & 1) != 0) {
            throw new IllegalArgumentException("map entries");
        }
        return aggregate(head(5, entries.length / 2), entries);
    }

    private static byte[] array(byte[]... entries) {
        return aggregate(head(4, entries.length), entries);
    }

    private static byte[] text(String value) {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        return concat(head(3, encoded.length), encoded);
    }

    private static byte[] bytes(byte[] value) {
        return concat(head(2, value.length), value);
    }

    private static byte[] uint(long value) {
        return head(0, value);
    }

    private static byte[] negative(long absolute) {
        return head(1, absolute - 1);
    }

    private static byte[] head(int major, long value) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        if (value < 24) {
            output.write((major << 5) | (int) value);
        } else if (value <= 0xff) {
            output.write((major << 5) | 24);
            output.write((int) value);
        } else if (value <= 0xffff) {
            output.write((major << 5) | 25);
            output.write((int) (value >>> 8));
            output.write((int) value);
        } else {
            output.write((major << 5) | 26);
            for (int shift = 24; shift >= 0; shift -= 8) {
                output.write((int) (value >>> shift));
            }
        }
        return output.toByteArray();
    }

    private static byte[] aggregate(byte[] prefix, byte[][] entries) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(prefix, 0, prefix.length);
        for (byte[] entry : entries) {
            output.write(entry, 0, entry.length);
        }
        return output.toByteArray();
    }

    private static byte[] concat(byte[]... values) {
        return aggregate(new byte[0], values);
    }

    private static byte[] derToRaw(byte[] der) {
        int offset = 2;
        if ((der[1] & 0x80) != 0) {
            offset = 2 + (der[1] & 0x7f);
        }
        if (der[offset++] != 0x02) {
            throw new IllegalArgumentException("ECDSA r missing");
        }
        int rLength = der[offset++] & 0xff;
        byte[] r = Arrays.copyOfRange(der, offset, offset + rLength);
        offset += rLength;
        if (der[offset++] != 0x02) {
            throw new IllegalArgumentException("ECDSA s missing");
        }
        int sLength = der[offset++] & 0xff;
        byte[] s = Arrays.copyOfRange(der, offset, offset + sLength);
        byte[] raw = new byte[64];
        copyInteger(r, raw, 0);
        copyInteger(s, raw, 32);
        return raw;
    }

    private static void copyInteger(byte[] source, byte[] target, int targetOffset) {
        int sourceOffset = source.length > 32 ? source.length - 32 : 0;
        int length = Math.min(32, source.length);
        System.arraycopy(source, sourceOffset, target, targetOffset + 32 - length, length);
    }

    private static int lastIndexOf(byte[] haystack, byte[] needle) {
        for (int index = haystack.length - needle.length; index >= 0; index--) {
            if (Arrays.equals(Arrays.copyOfRange(haystack, index, index + needle.length), needle)) {
                return index;
            }
        }
        return -1;
    }

    private static byte[] repeated(int value) {
        byte[] result = new byte[32];
        Arrays.fill(result, (byte) value);
        return result;
    }
}
