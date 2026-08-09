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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;

class MassDbLicenseIdentityRuntimeTest {
    private static final String SECRET = "massdb-runtime-secret-2026";

    @TempDir
    Path temporaryDirectory;

    @Test
    void readsPrivateUtf8SecretAndRemovesOnlyOneLineEnding() throws IOException {
        Path secret = privateFile("identity.secret", (SECRET + "\r\n")
                .getBytes(StandardCharsets.UTF_8));

        char[] loaded = MassDbLicenseIdentityRuntime.readSecret(secret);

        Assertions.assertArrayEquals(SECRET.toCharArray(), loaded);
        Arrays.fill(loaded, '\0');
    }

    @Test
    void rejectsExposedSymlinkAndMalformedSecretFiles() throws IOException {
        Path exposed = privateFile("exposed.secret", SECRET.getBytes(StandardCharsets.UTF_8));
        Files.setPosixFilePermissions(exposed,
                PosixFilePermissions.fromString("rw-r-----"));
        assertConfigInvalid(() -> MassDbLicenseIdentityRuntime.readSecret(exposed));

        Path malformed = privateFile("malformed.secret", new byte[] {(byte) 0xc3, 0x28});
        assertConfigInvalid(() -> MassDbLicenseIdentityRuntime.readSecret(malformed));

        Path target = privateFile("target.secret", SECRET.getBytes(StandardCharsets.UTF_8));
        Path link = temporaryDirectory.resolve("linked.secret");
        Files.createSymbolicLink(link, target);
        assertConfigInvalid(() -> MassDbLicenseIdentityRuntime.readSecret(link));
    }

    @Test
    void missingActiveIdentityBlocksRoleRequestsWithoutBlockingRuntimeConstruction()
            throws IOException {
        Path roots = Files.createDirectory(temporaryDirectory.resolve("roots"));
        Files.setPosixFilePermissions(roots,
                PosixFilePermissions.fromString("rwx------"));
        Path root = roots.resolve("identity-root-1.pem");
        Files.write(root, MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.ROOT_PUBLIC));
        Files.setPosixFilePermissions(root,
                PosixFilePermissions.fromString("rw-------"));
        Path secret = privateFile("startup.secret", SECRET.getBytes(StandardCharsets.UTF_8));
        Path store = temporaryDirectory.resolve("identity-store");

        MassDbLicenseFeRoleIdentityProvider provider =
                MassDbLicenseIdentityRuntime.open(store, roots, secret);
        MassDbLicenseException error = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> provider.current(1_767_225_600L));

        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                error.getCode());
        provider.close();
    }

    private Path privateFile(String name, byte[] content) throws IOException {
        Path path = temporaryDirectory.resolve(name);
        Files.write(path, content);
        Files.setPosixFilePermissions(path,
                PosixFilePermissions.fromString("rw-------"));
        return path;
    }

    private static void assertConfigInvalid(Runnable action) {
        MassDbLicenseException error = Assertions.assertThrows(
                MassDbLicenseException.class, action::run);
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_CONFIG_INVALID",
                error.getCode());
    }
}
