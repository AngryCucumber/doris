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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;

class MassDbLicenseRootTrustLoaderTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void loadsKidNamedImmutableP256Roots() throws IOException {
        Path roots = createRootsDirectory();
        writeRoot(roots.resolve("massdb-test-root-1.pem"));

        Map<String, java.security.PublicKey> loaded =
                MassDbLicenseRootTrustLoader.loadRootKeys(roots);

        Assertions.assertEquals(1, loaded.size());
        Assertions.assertTrue(loaded.containsKey("massdb-test-root-1"));
        Assertions.assertNotNull(MassDbLicenseRootTrustLoader.loadImportCoreIfConfigured(
                roots.toString(), 31_536_000L));
    }

    @Test
    void absentConfigurationPreservesLegacyCompatibilityButPartialConfigurationFails() {
        Assertions.assertNull(MassDbLicenseRootTrustLoader.loadImportCoreIfConfigured("", 0));
        assertRootTrustInvalid(() ->
                MassDbLicenseRootTrustLoader.loadImportCoreIfConfigured("", -1));
        assertRootTrustInvalid(() ->
                MassDbLicenseRootTrustLoader.loadImportCoreIfConfigured("", 31_536_000L));
        assertRootTrustInvalid(() ->
                MassDbLicenseRootTrustLoader.loadImportCoreIfConfigured(
                        temporaryDirectory.toString(), 0));
    }

    @Test
    void rejectsRelativeDirectoryAndUnexpectedEntries() throws IOException {
        assertRootTrustInvalid(() -> MassDbLicenseRootTrustLoader.loadRootKeys(
                temporaryDirectory.getFileName()));

        Path roots = createRootsDirectory();
        Files.write(roots.resolve("README"), new byte[] {1});
        assertRootTrustInvalid(() -> MassDbLicenseRootTrustLoader.loadRootKeys(roots));
    }

    @Test
    void rejectsWritableDirectoryAndSymlinkRoot() throws IOException {
        Path roots = createRootsDirectory();
        Files.setPosixFilePermissions(roots, PosixFilePermissions.fromString("rwxrwx---"));
        assertRootTrustInvalid(() -> MassDbLicenseRootTrustLoader.loadRootKeys(roots));

        Files.setPosixFilePermissions(roots, PosixFilePermissions.fromString("rwx------"));
        Path target = temporaryDirectory.resolve("actual.pem");
        writeRoot(target);
        Files.createSymbolicLink(roots.resolve("root-1.pem"), target);
        assertRootTrustInvalid(() -> MassDbLicenseRootTrustLoader.loadRootKeys(roots));
    }

    @Test
    void rejectsGroupWritableRootFile() throws IOException {
        Path roots = createRootsDirectory();
        Path root = roots.resolve("root-1.pem");
        writeRoot(root);
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rw-rw----"));
        assertRootTrustInvalid(() -> MassDbLicenseRootTrustLoader.loadRootKeys(roots));
    }

    private Path createRootsDirectory() throws IOException {
        Path roots = Files.createTempDirectory(temporaryDirectory, "roots-");
        Files.setPosixFilePermissions(roots, PosixFilePermissions.fromString("rwx------"));
        return roots;
    }

    private static void writeRoot(Path path) throws IOException {
        Files.write(path, MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.ROOT_PUBLIC));
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }

    private static void assertRootTrustInvalid(Runnable action) {
        MassDbLicenseException error = Assertions.assertThrows(
                MassDbLicenseException.class, action::run);
        Assertions.assertEquals("MASSDB_LICENSE_ROOT_TRUST_INVALID", error.getCode());
    }
}
