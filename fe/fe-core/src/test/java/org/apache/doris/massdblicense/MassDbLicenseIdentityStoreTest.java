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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

class MassDbLicenseIdentityStoreTest {
    private static final String DEPLOYMENT_UUID = "00000000-0000-4000-8000-000000000201";
    private static final String NODE_UUID = "00000000-0000-4000-8000-000000000202";
    private static final String KID = "massdb-test-identity-artifact-store-1";
    private static final char[] PASSWORD = "massdb-test-secret-2026".toCharArray();

    @TempDir
    Path temporaryDirectory;

    @Test
    void generatesCsrActivatesAndReloadsWithoutAnAgent() throws Exception {
        Fixture fixture = fixture();
        Path storeDirectory = temporaryDirectory.resolve("identity");
        MassDbLicenseIdentityStore store = store(storeDirectory, fixture, PASSWORD);
        long now = fixture.leaf.getNotBefore().toInstant().getEpochSecond() + 1;

        MassDbLicenseIdentityStore.Enrollment first = store.beginEnrollment(
                "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now);
        MassDbLicenseException notLegacy = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> store.replayPendingLegacyEnrollment(
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now + 1));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_ADDRESS_SAN_INVALID",
                notLegacy.getCode());
        MassDbLicenseIdentityStore.Enrollment replay = store.beginEnrollment(
                "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now + 1);
        Assertions.assertEquals(1, first.getGeneration());
        Assertions.assertArrayEquals(first.getCsrDer(), replay.getCsrDer());
        Assertions.assertTrue(first.getCsrPem().startsWith(
                "-----BEGIN CERTIFICATE REQUEST-----"));

        byte[] artifact = identityArtifact(fixture.artifactPrivateKey,
                first, fixture.leafPem, fixture.caPem,
                fixture.leaf.getNotBefore().toInstant().getEpochSecond(),
                fixture.leaf.getNotAfter().toInstant().getEpochSecond());
        String enrollmentToken = new String(Files.readAllBytes(
                storeDirectory.resolve("enrollment.pointer")),
                StandardCharsets.US_ASCII).trim();
        MassDbLicenseFeRoleIdentityProvider.Snapshot active =
                store.importAndActivate(artifact, now);
        Assertions.assertEquals(1, active.generation);
        Assertions.assertEquals("massdb-sql", active.identity.component);
        Assertions.assertEquals(NODE_UUID, active.identity.nodeUuid);
        active.requireAllowedServer(fixture.leaf, DEPLOYMENT_UUID);
        Assertions.assertEquals(NODE_UUID, active.requireAllowedClient(
                new X509Certificate[] {fixture.leaf}, now).nodeUuid);
        Path retiredEnrollment = storeDirectory.resolve(
                "retired-enrollment-" + enrollmentToken + ".marker");
        byte[] firstRetiredAt = Files.readAllBytes(retiredEnrollment);
        Path enrollmentPointer = storeDirectory.resolve("enrollment.pointer");
        Files.write(enrollmentPointer,
                (enrollmentToken + "\n").getBytes(StandardCharsets.US_ASCII));
        setPrivatePermissions(enrollmentPointer);
        store.importAndActivate(artifact, now + 1);
        Assertions.assertArrayEquals(firstRetiredAt, Files.readAllBytes(retiredEnrollment));
        Assertions.assertFalse(Files.exists(enrollmentPointer));
        MassDbLicenseException wrongDeployment = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> active.requireAllowedServer(fixture.leaf,
                        "00000000-0000-4000-8000-000000000299"));
        Assertions.assertEquals("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                wrongDeployment.getCode());
        String leafSpiffeId = "spiffe://massdb.internal/license/component/massdb-sql/"
                + DEPLOYMENT_UUID + "/fe/" + NODE_UUID;
        MassDbLicenseFeRoleIdentityProvider.Snapshot revoked =
                new MassDbLicenseFeRoleIdentityProvider.Snapshot(
                        1, active.clientSslContext, active.identity,
                        fixture.leaf.getNotBefore().toInstant().getEpochSecond(),
                        fixture.leaf.getNotAfter().toInstant().getEpochSecond(),
                        Collections.singleton(leafSpiffeId), active.trustRoots);
        MassDbLicenseException revokedPeer = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> revoked.requireAllowedServer(fixture.leaf, DEPLOYMENT_UUID));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_REVOKED",
                revokedPeer.getCode());
        MassDbLicenseException revokedClient = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> revoked.requireAllowedClient(
                        new X509Certificate[] {fixture.leaf}, now));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_REVOKED",
                revokedClient.getCode());
        assertPrivateKeyIsNotStoredInPlaintext(storeDirectory, fixture.leafPrivateKey);
        store.close();

        MassDbLicenseIdentityStore restarted = store(storeDirectory, fixture, PASSWORD);
        MassDbLicenseFeRoleIdentityProvider.Snapshot recovered = restarted.loadActive(now + 10);
        Assertions.assertEquals(1, recovered.generation);
        Assertions.assertEquals(1,
                restarted.importAndActivate(artifact, now + 11).generation);
        MassDbLicenseFeRoleIdentityProvider.StoreBacked liveProvider =
                MassDbLicenseFeRoleIdentityProvider.StoreBacked.open(
                        restarted, now + 11);
        String activeToken = new String(Files.readAllBytes(
                storeDirectory.resolve("active.pointer")), StandardCharsets.US_ASCII).trim();
        Path activeArtifact = storeDirectory.resolve(
                "identity-" + activeToken + ".midentity");
        byte[] originalArtifact = Files.readAllBytes(activeArtifact);
        byte[] damagedArtifact = originalArtifact.clone();
        damagedArtifact[damagedArtifact.length - 1] ^= 1;
        FileTime originalModifiedTime = Files.getLastModifiedTime(activeArtifact);
        Files.write(activeArtifact, damagedArtifact);
        Files.setLastModifiedTime(activeArtifact, originalModifiedTime);
        Assertions.assertThrows(MassDbLicenseException.class,
                () -> liveProvider.current(now + 12));
        Files.write(activeArtifact, originalArtifact);
        Files.setLastModifiedTime(activeArtifact, originalModifiedTime);
        Assertions.assertEquals(1, liveProvider.current(now + 12).generation);

        MassDbLicenseIdentityStore.Enrollment renewal = restarted.beginEnrollment(
                "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now + 12);
        Assertions.assertEquals(2, renewal.getGeneration());

        byte[] rollback = identityArtifact(fixture.artifactPrivateKey,
                renewal, fixture.leafPem, fixture.caPem,
                fixture.leaf.getNotBefore().toInstant().getEpochSecond(),
                fixture.leaf.getNotAfter().toInstant().getEpochSecond(), 1);
        MassDbLicenseException rejected = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> restarted.importAndActivate(rollback, now + 13));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_GENERATION_ROLLBACK",
                rejected.getCode());
        byte[] renewedArtifact = identityArtifact(fixture.artifactPrivateKey,
                renewal, fixture.leafPem, fixture.caPem,
                fixture.leaf.getNotBefore().toInstant().getEpochSecond(),
                fixture.leaf.getNotAfter().toInstant().getEpochSecond());
        restarted.importAndActivate(renewedArtifact, now + 14);
        Assertions.assertEquals(2, liveProvider.current(now + 15).generation);
        MassDbLicenseIdentityStore.CleanupResult cleanup =
                restarted.cleanupRetired(now + 16, 0);
        Assertions.assertTrue(cleanup.getRemovedGenerations() >= 2);
        Assertions.assertFalse(Files.exists(activeArtifact));
        Assertions.assertEquals(2, restarted.loadActive(now + 16).generation);
        liveProvider.close();
    }

    @Test
    void reportsMissingPendingActiveAndExpiredStatus() throws Exception {
        Fixture fixture = fixture();
        Path storeDirectory = temporaryDirectory.resolve("status");
        long now = fixture.leaf.getNotBefore().toInstant().getEpochSecond() + 1;
        MassDbLicenseIdentityStore store = store(storeDirectory, fixture, PASSWORD);
        Assertions.assertEquals(MassDbLicenseIdentityStore.IdentityState.MISSING,
                store.status(now).getState());

        MassDbLicenseIdentityStore.Enrollment enrollment = store.beginEnrollment(
                "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now);
        Assertions.assertEquals(MassDbLicenseIdentityStore.IdentityState.ENROLLMENT_PENDING,
                store.status(now).getState());
        byte[] artifact = identityArtifact(fixture.artifactPrivateKey,
                enrollment, fixture.leafPem, fixture.caPem,
                fixture.leaf.getNotBefore().toInstant().getEpochSecond(),
                fixture.leaf.getNotAfter().toInstant().getEpochSecond());
        store.importAndActivate(artifact, now);
        MassDbLicenseIdentityStore.IdentityStatus active = store.status(now);
        Assertions.assertEquals(MassDbLicenseIdentityStore.IdentityState.ACTIVE,
                active.getState());
        Assertions.assertEquals(enrollment.getGeneration(), active.getGeneration());
        Assertions.assertEquals(fixture.leaf.getNotAfter().toInstant().getEpochSecond(),
                active.getNotAfter());
        Assertions.assertEquals(MassDbLicenseIdentityStore.IdentityState.EXPIRED,
                store.status(active.getNotAfter()).getState());
        store.close();
    }

    @Test
    void serializesCliAndFeMutationsWithAnOsFileLock() throws Exception {
        Fixture fixture = fixture();
        Path storeDirectory = temporaryDirectory.resolve("locked");
        long now = fixture.leaf.getNotBefore().toInstant().getEpochSecond() + 1;
        MassDbLicenseIdentityStore store = store(storeDirectory, fixture, PASSWORD);
        try (FileChannel channel = FileChannel.open(
                storeDirectory.resolve(".identity-store.lock"), StandardOpenOption.WRITE);
                FileLock ignored = channel.lock()) {
            MassDbLicenseException busy = Assertions.assertThrows(
                    MassDbLicenseException.class,
                    () -> store.beginEnrollment(
                            "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now));
            Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_STORE_BUSY",
                    busy.getCode());
        }
        Assertions.assertEquals(1, store.beginEnrollment(
                "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now).getGeneration());
        store.close();
    }

    @Test
    void removesOnlyRecognizedCrashTemporaryFilesDuringLockedMaintenance() throws Exception {
        Fixture fixture = fixture();
        Path storeDirectory = temporaryDirectory.resolve("crash-temporary");
        long now = fixture.leaf.getNotBefore().toInstant().getEpochSecond() + 1;
        MassDbLicenseIdentityStore store = store(storeDirectory, fixture, PASSWORD);
        Path managedTemporary = storeDirectory.resolve(
                ".active.pointer.tmp-00000000-0000-4000-8000-000000000241");
        Path unrelatedHidden = storeDirectory.resolve(".operator-note");
        Path unrelatedTemporary = storeDirectory.resolve(
                ".identity-operator-note.tmp-00000000-0000-4000-8000-000000000242");
        Files.write(managedTemporary, "partial".getBytes(StandardCharsets.US_ASCII));
        Files.write(unrelatedHidden, "keep".getBytes(StandardCharsets.US_ASCII));
        Files.write(unrelatedTemporary, "keep".getBytes(StandardCharsets.US_ASCII));
        setPrivatePermissions(managedTemporary);

        MassDbLicenseIdentityStore.CleanupResult result =
                store.cleanupRetired(now, 0);

        Assertions.assertEquals(1, result.getRemovedFiles());
        Assertions.assertFalse(Files.exists(managedTemporary));
        Assertions.assertTrue(Files.exists(unrelatedHidden));
        Assertions.assertTrue(Files.exists(unrelatedTemporary));
        store.close();
    }

    @Test
    void bindsRequestedAddressSansToSignedCertificateActivation() throws Exception {
        Fixture fixture = fixture();
        Path storeDirectory = temporaryDirectory.resolve("address-sans");
        long now = fixture.leaf.getNotBefore().toInstant().getEpochSecond() + 1;
        MassDbLicenseIdentityStore store = store(storeDirectory, fixture, PASSWORD);
        MassDbLicenseIdentityStore.Enrollment enrollment = store.beginEnrollment(
                "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID,
                Collections.singletonList("sql.example.internal"),
                Collections.singletonList("10.0.0.12"), now);
        Assertions.assertEquals(Collections.singletonList("sql.example.internal"),
                enrollment.getDnsSans());
        byte[] artifact = identityArtifact(fixture.artifactPrivateKey,
                enrollment, fixture.leafPem, fixture.caPem,
                fixture.leaf.getNotBefore().toInstant().getEpochSecond(),
                fixture.leaf.getNotAfter().toInstant().getEpochSecond());
        MassDbLicenseException rejected = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> store.importAndActivate(artifact, now));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_ADDRESS_SAN_INVALID",
                rejected.getCode());
        Assertions.assertEquals(MassDbLicenseIdentityStore.IdentityState.ENROLLMENT_PENDING,
                store.status(now).getState());
        store.close();
    }

    @Test
    void readsAndUpgradesLegacyV1EnrollmentMetadata() throws Exception {
        Fixture fixture = fixture();
        Path storeDirectory = temporaryDirectory.resolve("legacy-v1");
        long now = fixture.leaf.getNotBefore().toInstant().getEpochSecond() + 1;
        MassDbLicenseIdentityStore store = store(storeDirectory, fixture, PASSWORD);
        MassDbLicenseIdentityStore.Enrollment enrollment = store.beginEnrollment(
                "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now);
        String token = new String(Files.readAllBytes(
                storeDirectory.resolve("enrollment.pointer")),
                StandardCharsets.US_ASCII).trim();
        Path metadata = storeDirectory.resolve("enrollment-" + token + ".bin");
        Files.write(metadata, toLegacyV1Metadata(Files.readAllBytes(metadata)));

        MassDbLicenseIdentityStore.Enrollment replay =
                store.replayPendingLegacyEnrollment(
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now + 1);
        Assertions.assertArrayEquals(enrollment.getCsrDer(), replay.getCsrDer());
        byte[] artifact = identityArtifact(fixture.artifactPrivateKey,
                replay, fixture.leafPem, fixture.caPem,
                fixture.leaf.getNotBefore().toInstant().getEpochSecond(),
                fixture.leaf.getNotAfter().toInstant().getEpochSecond());
        store.importAndActivate(artifact, now + 1);
        Assertions.assertEquals(MassDbLicenseIdentityStore.IdentityState.ACTIVE,
                store.status(now + 2).getState());
        store.close();
    }

    @Test
    void wrongCredentialAndClosedStoreFailClosed() throws Exception {
        Fixture fixture = fixture();
        Path storeDirectory = temporaryDirectory.resolve("credential");
        long now = fixture.leaf.getNotBefore().toInstant().getEpochSecond() + 1;
        MassDbLicenseIdentityStore store = store(storeDirectory, fixture, PASSWORD);
        MassDbLicenseIdentityStore.Enrollment enrollment = store.beginEnrollment(
                "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now);
        byte[] artifact = identityArtifact(fixture.artifactPrivateKey,
                enrollment, fixture.leafPem, fixture.caPem,
                fixture.leaf.getNotBefore().toInstant().getEpochSecond(),
                fixture.leaf.getNotAfter().toInstant().getEpochSecond());
        store.importAndActivate(artifact, now);
        store.close();

        Path activePointer = storeDirectory.resolve("active.pointer");
        if (Files.getFileStore(activePointer).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(activePointer,
                    PosixFilePermissions.fromString("rw-r-----"));
            MassDbLicenseIdentityStore exposed = store(storeDirectory, fixture, PASSWORD);
            MassDbLicenseException permissions = Assertions.assertThrows(
                    MassDbLicenseException.class, () -> exposed.loadActive(now + 1));
            Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                    permissions.getCode());
            exposed.close();
            Files.setPosixFilePermissions(activePointer,
                    PosixFilePermissions.fromString("rw-------"));
        }

        MassDbLicenseIdentityStore wrong = store(storeDirectory, fixture,
                "different-test-secret".toCharArray());
        MassDbLicenseException credential = Assertions.assertThrows(
                MassDbLicenseException.class, () -> wrong.loadActive(now + 1));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                credential.getCode());
        wrong.close();

        MassDbLicenseException closed = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> store.beginEnrollment(
                        "massdb-sql", DEPLOYMENT_UUID, "fe", NODE_UUID, now + 2));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_UNAVAILABLE", closed.getCode());
    }

    private static MassDbLicenseIdentityStore store(Path directory, Fixture fixture,
            char[] password) {
        return new MassDbLicenseIdentityStore(directory, password,
                Collections.singletonMap(KID, fixture.artifactPublicKey),
                new MassDbLicenseIdentityStore.KeyMaterialGenerator() {
                    @Override
                    public MassDbLicenseIdentityKeyMaterial.Generated generate(
                            String spiffeId, List<String> dnsSans, List<String> ipSans,
                            long nowEpochSecond) {
                        return MassDbLicenseIdentityKeyMaterial.generate(
                                fixture.leafKeyPair, spiffeId, dnsSans, ipSans,
                                nowEpochSecond);
                    }
                });
    }

    private static void setPrivatePermissions(Path path) throws Exception {
        try {
            Files.setPosixFilePermissions(path,
                    PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX test environments are accepted by the production fallback.
        }
    }

    private static byte[] toLegacyV1Metadata(byte[] encoded) throws Exception {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded));
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                DataOutputStream output = new DataOutputStream(bytes)) {
            byte[] magic = new byte[8];
            input.readFully(magic);
            Assertions.assertEquals(2, input.readInt());
            output.write(magic);
            output.writeInt(1);
            output.writeLong(input.readLong());
            output.writeLong(input.readLong());
            for (int index = 0; index < 4; index++) {
                writeSized(output, readSized(input));
            }
            skipStringList(input);
            skipStringList(input);
            writeSized(output, readSized(input));
            writeSized(output, readSized(input));
            writeSized(output, readSized(input));
            Assertions.assertEquals(-1, input.read());
            return bytes.toByteArray();
        }
    }

    private static void skipStringList(DataInputStream input) throws Exception {
        int count = input.readInt();
        for (int index = 0; index < count; index++) {
            readSized(input);
        }
    }

    private static byte[] readSized(DataInputStream input) throws Exception {
        byte[] value = new byte[input.readInt()];
        input.readFully(value);
        return value;
    }

    private static void writeSized(DataOutputStream output, byte[] value) throws Exception {
        output.writeInt(value.length);
        output.write(value);
    }

    private static void assertPrivateKeyIsNotStoredInPlaintext(Path directory,
            PrivateKey privateKey) throws Exception {
        byte[] privateDer = privateKey.getEncoded();
        try (Stream<Path> files = Files.list(directory)) {
            files.filter(Files::isRegularFile).forEach(path -> {
                try {
                    Assertions.assertEquals(-1, indexOf(Files.readAllBytes(path), privateDer),
                            "private key leaked in " + path.getFileName());
                } catch (java.io.IOException error) {
                    throw new IllegalStateException(error);
                }
            });
        }
    }

    private static Fixture fixture() throws Exception {
        PrivateKey leafPrivateKey = parsePrivateKey(decodePem(LEAF_PRIVATE_KEY));
        X509Certificate leaf = parseCertificate(decodePem(LEAF_CERTIFICATE));
        KeyPair leafKeyPair = new KeyPair(leaf.getPublicKey(), leafPrivateKey);
        PrivateKey artifactPrivateKey = parsePrivateKey(decodePem(ARTIFACT_PRIVATE_KEY));
        PublicKey artifactPublicKey = MassDbLicenseProtocolV1.parsePublicKeyPem(
                decodePem(ARTIFACT_PUBLIC_KEY));
        return new Fixture(leafPrivateKey, leafKeyPair, leaf,
                new String(decodePem(LEAF_CERTIFICATE), StandardCharsets.US_ASCII),
                new String(decodePem(CA_CERTIFICATE), StandardCharsets.US_ASCII),
                artifactPrivateKey, artifactPublicKey);
    }

    private static PrivateKey parsePrivateKey(byte[] pem) throws Exception {
        String value = new String(pem, StandardCharsets.US_ASCII).trim();
        String body = value.substring(value.indexOf('\n') + 1, value.lastIndexOf('\n'))
                .replaceAll("\\s", "");
        return KeyFactory.getInstance("EC").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
    }

    private static X509Certificate parseCertificate(byte[] pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    private static byte[] identityArtifact(PrivateKey signer,
            MassDbLicenseIdentityStore.Enrollment enrollment, String leafPem, String caPem,
            long notBefore, long notAfter) throws Exception {
        return identityArtifact(signer, enrollment, leafPem, caPem,
                notBefore, notAfter, enrollment.getGeneration());
    }

    private static byte[] identityArtifact(PrivateKey signer,
            MassDbLicenseIdentityStore.Enrollment enrollment, String leafPem, String caPem,
            long notBefore, long notAfter, long generation) throws Exception {
        byte[] payload = map(
                uint(1), uint(1),
                uint(2), text(MassDbLicenseProtocolV1.IDENTITY_PACKAGE_TYPE),
                uint(3), text(MassDbLicenseProtocolV1.PRODUCT),
                uint(4), uint(generation),
                uint(5), uint(notBefore),
                uint(6), uint(notBefore),
                uint(7), uint(notAfter),
                uint(8), text(enrollment.getComponent()),
                uint(9), text(enrollment.getDeploymentUuid()),
                uint(10), text(enrollment.getRole()),
                uint(11), text(enrollment.getNodeUuid()),
                uint(12), bytes(hex(enrollment.getCsrSha256())),
                uint(13), text(leafPem),
                uint(14), array(),
                uint(15), array(text(caPem)),
                uint(16), array());
        byte[] protectedHeader = map(uint(1), negative(7),
                uint(4), bytes(KID.getBytes(StandardCharsets.US_ASCII)));
        byte[] signatureStructure = array(text("Signature1"), bytes(protectedHeader),
                bytes(new byte[0]), bytes(payload));
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signer);
        signature.update(signatureStructure);
        return concat(new byte[] {(byte) 0xd2}, array(bytes(protectedHeader),
                map(), bytes(payload), bytes(derToRaw(signature.sign()))));
    }

    private static byte[] decodePem(String value) {
        return Base64.getDecoder().decode(value);
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(
                    value.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int index = 0; index <= haystack.length - needle.length; index++) {
            boolean match = true;
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[index + offset] != needle[offset]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return index;
            }
        }
        return -1;
    }

    private static byte[] map(byte[]... entries) {
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

    private static final class Fixture {
        private final PrivateKey leafPrivateKey;
        private final KeyPair leafKeyPair;
        private final X509Certificate leaf;
        private final String leafPem;
        private final String caPem;
        private final PrivateKey artifactPrivateKey;
        private final PublicKey artifactPublicKey;

        private Fixture(PrivateKey leafPrivateKey, KeyPair leafKeyPair,
                X509Certificate leaf, String leafPem, String caPem,
                PrivateKey artifactPrivateKey, PublicKey artifactPublicKey) {
            this.leafPrivateKey = leafPrivateKey;
            this.leafKeyPair = leafKeyPair;
            this.leaf = leaf;
            this.leafPem = leafPem;
            this.caPem = caPem;
            this.artifactPrivateKey = artifactPrivateKey;
            this.artifactPublicKey = artifactPublicKey;
        }
    }

    private static final String LEAF_PRIVATE_KEY =
            "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0ND"
            + "cUdTTTQ5QXdFSEJHMHdhd0lCQVFRZzRhcUhDVHdIRDlORldSY1IKaGRGdU9HV3M3dWNxa2ti"
            + "Rmo4ZzM1SG9DWXoyaFJBTkNBQVNxQ0lrc0tHYkFHZ091THlMcjRGaG5iRzBpN1JhMwovd25N"
            + "Q0w1NG1JOGZadDZ3RVVyMHZoWVVDVjUvMU9LY21qU1BNOTROaGtCendkbURhcXVtdFJUNQot"
            + "LS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==";
    private static final String LEAF_CERTIFICATE =
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNDekNDQWJDZ0F3SUJBZ0lKQVBMZElM"
            + "VFBFUVErTUFvR0NDcUdTTTQ5QkFNQ01DSXhJREFlQmdOVkJBTU0KRjAxaGMzTkVRaUJVWlhO"
            + "MElFbGtaVzUwYVhSNUlFTkJNQjRYRFRJMk1EZ3dPREUyTVRrek5Gb1hEVEkyTURrdwpOekUy"
            + "TVRrek5Gb3dIVEViTUJrR0ExVUVBd3dTVFdGemMwUkNJRk5SVENCR1JTQlVaWE4wTUZrd0V3"
            + "WUhLb1pJCnpqMENBUVlJS29aSXpqMERBUWNEUWdBRXFnaUpMQ2htd0JvRHJpOGk2K0JZWjJ4"
            + "dEl1MFd0LzhKekFpK2VKaVAKSDJiZXNCRks5TDRXRkFsZWY5VGluSm8wanpQZURZWkFjOEha"
            + "ZzJxcnByVVUrYU9CMHpDQjBEQU1CZ05WSFJNQgpBZjhFQWpBQU1BNEdBMVVkRHdFQi93UUVB"
            + "d0lIZ0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFnWUlLd1lCCkJRVUhBd0V3Z1pBR0Ex"
            + "VWRFUVNCaURDQmhZYUJnbk53YVdabVpUb3ZMMjFoYzNOa1lpNXBiblJsY201aGJDOXMKYVdO"
            + "bGJuTmxMMk52YlhCdmJtVnVkQzl0WVhOelpHSXRjM0ZzTHpBd01EQXdNREF3TFRBd01EQXRO"
            + "REF3TUMwNApNREF3TFRBd01EQXdNREF3TURJd01TOW1aUzh3TURBd01EQXdNQzB3TURBd0xU"
            + "UXdNREF0T0RBd01DMHdNREF3Ck1EQXdNREF5TURJd0NnWUlLb1pJemowRUF3SURTUUF3UmdJ"
            + "aEFPNFljTXhoUm43ZGdNcmxxTzVLb1B2b2JxbjUKV2lBOHNkVm5rRE5nNnhKdEFpRUFxYm04"
            + "VXlvSHh6T0RjY2U0WlFDc3JtMHJpclkyZGhrTUd4MnRsTjlSc0FrPQotLS0tLUVORCBDRVJU"
            + "SUZJQ0FURS0tLS0tCg==";
    private static final String CA_CERTIFICATE =
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJYekNDQVFTZ0F3SUJBZ0lKQUlNZ3Bw"
            + "UHJSUlc5TUFvR0NDcUdTTTQ5QkFNQ01DSXhJREFlQmdOVkJBTU0KRjAxaGMzTkVRaUJVWlhO"
            + "MElFbGtaVzUwYVhSNUlFTkJNQjRYRFRJMk1EZ3dPREUyTVRrek5Gb1hEVE0yTURndwpOVEUy"
            + "TVRrek5Gb3dJakVnTUI0R0ExVUVBd3dYVFdGemMwUkNJRlJsYzNRZ1NXUmxiblJwZEhrZ1Ew"
            + "RXdXVEFUCkJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVE4eWl1SkhSeEJYbkM1Tmhu"
            + "UXBzMkI2UVlUSmE0aXFySkYKbytkbjlrR0c2bkVYZTFPY3pUWlVKWFNlazJSTjF4RWp5Unln"
            + "UUFZUDhhMWdCZmNLQWNZWG95TXdJVEFQQmdOVgpIUk1CQWY4RUJUQURBUUgvTUE0R0ExVWRE"
            + "d0VCL3dRRUF3SUJCakFLQmdncWhrak9QUVFEQWdOSkFEQkdBaUVBCndQZW5ocVRESEMvQTk1"
            + "UURNNmdQWTRWY0J6TEVFK3VOclVmdXgvalZpSElDSVFDbndQZmxEdDF2byttVDFjRU0KRXpD"
            + "SEU3VFp6Rjl3bEhuMnV5MUlIVHd5c0E9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==";
    private static final String ARTIFACT_PRIVATE_KEY =
            "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0ND"
            + "cUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3Z3aFR4RDVJMWRlVjlhY3IKOUl5clQrUEt2ZTRqdzhh"
            + "VSszK0hYNlRaV2NLaFJBTkNBQVFqek5oeHRFbytPWlZUMUdaa1NyNXQ0eTJUeDR1bQpmbjQ2"
            + "enB1L2dOUzgvMG5VUjdRbFlMZmRMVTdVdWdRck9PRWY4OXNrZXQrQmlxUjVZbVZ3V0txWQot"
            + "LS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==";
    private static final String ARTIFACT_PUBLIC_KEY =
            "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemow"
            + "REFRY0RRZ0FFSTh6WWNiUktQam1WVTlSbVpFcStiZU10azhlTApwbjUrT3M2YnY0RFV2UDlK"
            + "MUVlMEpXQzMzUzFPMUxvRUt6amhIL1BiSkhyZmdZcWtlV0psY0ZpcW1BPT0KLS0tLS1FTkQg"
            + "UFVCTElDIEtFWS0tLS0tCg==";
}
