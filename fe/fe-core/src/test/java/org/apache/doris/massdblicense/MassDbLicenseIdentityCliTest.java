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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

class MassDbLicenseIdentityCliTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void createsDurableAddressBoundCsrAndReportsPendingStatus() throws Exception {
        Path roots = temporaryDirectory.resolve("roots");
        Files.createDirectory(roots);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair root = generator.generateKeyPair();
        Files.write(roots.resolve("massdb-test-identity-root.pem"),
                publicKeyPem(root).getBytes(StandardCharsets.US_ASCII));
        Path secret = temporaryDirectory.resolve("identity.secret");
        Files.write(secret, "massdb-cli-secret-2026\n".getBytes(StandardCharsets.UTF_8));
        try {
            Files.setPosixFilePermissions(secret,
                    PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX test environments are accepted by the production fallback.
        }
        Path store = temporaryDirectory.resolve("identity-store");
        Path meta = temporaryDirectory.resolve("meta");
        Files.createDirectory(meta);
        Path csr = temporaryDirectory.resolve("fe.csr.pem");
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        int exit = MassDbLicenseIdentityCli.run(new String[] {
                "identity-csr",
                "--store-dir", store.toString(),
                "--artifact-root-dir", roots.toString(),
                "--secret-file", secret.toString(),
                "--meta-dir", meta.toString(),
                "--deployment-uuid", "00000000-0000-4000-8000-000000000221",
                "--csr-out", csr.toString()
        }, stream(stdout), stream(stderr), 1_800_000_000L);
        Assertions.assertEquals(3, exit);
        Assertions.assertFalse(Files.exists(csr));
        Assertions.assertTrue(stderr.toString("UTF-8").contains(
                "\"code\":\"MASSDB_LICENSE_ROLE_IDENTITY_ADDRESS_SAN_INVALID\""));

        stdout.reset();
        stderr.reset();
        exit = MassDbLicenseIdentityCli.run(new String[] {
                "identity-csr",
                "--store-dir", store.toString(),
                "--artifact-root-dir", roots.toString(),
                "--secret-file", secret.toString(),
                "--meta-dir", meta.toString(),
                "--deployment-uuid", "00000000-0000-4000-8000-000000000221",
                "--csr-out", csr.toString(),
                "--dns-san", "SQL.EXAMPLE.INTERNAL",
                "--ip-san", "10.0.0.12"
        }, stream(stdout), stream(stderr), 1_800_000_000L);

        Assertions.assertEquals(0, exit, stderr.toString("UTF-8"));
        Assertions.assertTrue(new String(Files.readAllBytes(csr), StandardCharsets.US_ASCII)
                .startsWith("-----BEGIN CERTIFICATE REQUEST-----"));
        String csrResult = stdout.toString("UTF-8");
        Assertions.assertTrue(csrResult.contains("\"state\":\"ENROLLMENT_PENDING\""));
        Assertions.assertFalse(csrResult.contains("massdb-cli-secret-2026"));

        stdout.reset();
        stderr.reset();
        exit = MassDbLicenseIdentityCli.run(new String[] {
                "identity-status",
                "--store-dir", store.toString(),
                "--artifact-root-dir", roots.toString(),
                "--secret-file", secret.toString()
        }, stream(stdout), stream(stderr), 1_800_000_001L);
        Assertions.assertEquals(0, exit, stderr.toString("UTF-8"));
        Assertions.assertTrue(stdout.toString("UTF-8")
                .contains("\"state\":\"ENROLLMENT_PENDING\""));
    }

    @Test
    void rejectsIncompleteCommandsWithMachineReadableError() throws Exception {
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        int exit = MassDbLicenseIdentityCli.run(new String[0],
                stream(stdout), stream(stderr), 1_800_000_000L);

        Assertions.assertEquals(2, exit);
        Assertions.assertEquals("", stdout.toString("UTF-8"));
        Assertions.assertTrue(stderr.toString("UTF-8")
                .contains("\"code\":\"MASSDB_LICENSE_CLI_USAGE\""));
    }

    private static PrintStream stream(ByteArrayOutputStream output) throws Exception {
        return new PrintStream(output, true, "UTF-8");
    }

    private static String publicKeyPem(KeyPair pair) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'})
                .encodeToString(pair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n";
    }
}
