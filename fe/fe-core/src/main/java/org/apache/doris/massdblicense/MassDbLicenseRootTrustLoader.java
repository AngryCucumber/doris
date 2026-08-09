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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Loads immutable keyset-root trust anchors from a process-local directory. */
public final class MassDbLicenseRootTrustLoader {
    private static final String ERROR_CODE = "MASSDB_LICENSE_ROOT_TRUST_INVALID";
    private static final Pattern KID_PATTERN =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final long MAX_ROOT_PEM_BYTES = 16_384L;

    private MassDbLicenseRootTrustLoader() {
    }

    /**
     * Returns null only when both settings are intentionally absent, preserving legacy clusters.
     * A partial or invalid explicit configuration fails FE startup instead of silently disabling
     * License verification.
     */
    public static MassDbLicenseImportCore loadImportCoreIfConfigured(
            String rootTrustDirectory, long maxLicenseTermSeconds) {
        if (maxLicenseTermSeconds < 0) {
            fail("最大License期限不能是负数");
        }
        boolean hasDirectory = rootTrustDirectory != null
                && !rootTrustDirectory.trim().isEmpty();
        boolean hasMaximumTerm = maxLicenseTermSeconds > 0;
        if (!hasDirectory && !hasMaximumTerm) {
            return null;
        }
        if (!hasDirectory || !hasMaximumTerm) {
            fail("root trust目录和最大License期限必须同时显式配置");
        }
        try {
            return new MassDbLicenseImportCore(
                    maxLicenseTermSeconds, loadRootKeys(Paths.get(rootTrustDirectory.trim())));
        } catch (InvalidPathException | SecurityException error) {
            fail("无法安全读取root trust目录");
            return null;
        }
    }

    static Map<String, PublicKey> loadRootKeys(Path directory) {
        try {
            validateDirectory(directory);
            UserPrincipal directoryOwner = Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS);
            List<Path> entries = new ArrayList<>();
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
                for (Path entry : stream) {
                    entries.add(entry);
                }
            }
            entries.sort(Comparator.comparing(path -> path.getFileName().toString()));

            Map<String, PublicKey> roots = new LinkedHashMap<>();
            for (Path entry : entries) {
                String fileName = entry.getFileName().toString();
                if (!fileName.endsWith(".pem")) {
                    fail("root trust目录只能包含按kid命名的.pem文件");
                }
                String kid = fileName.substring(0, fileName.length() - 4);
                if (!KID_PATTERN.matcher(kid).matches()) {
                    fail("root trust文件名不是合法kid");
                }
                validateRootFile(entry, directoryOwner);
                byte[] pem = readBounded(entry);
                PublicKey key;
                try {
                    key = MassDbLicenseProtocolV1.parsePublicKeyPem(pem);
                } catch (MassDbLicenseException error) {
                    fail("root trust文件不是合法P-256 PUBLIC KEY PEM");
                    return Collections.emptyMap();
                }
                if (roots.put(kid, key) != null) {
                    fail("root trust kid重复");
                }
            }
            if (roots.isEmpty()) {
                fail("root trust目录不能为空");
            }
            return Collections.unmodifiableMap(roots);
        } catch (IOException | UnsupportedOperationException | SecurityException error) {
            fail("无法安全读取root trust目录");
            return Collections.emptyMap();
        }
    }

    private static void validateDirectory(Path directory) throws IOException {
        if (directory == null || !directory.isAbsolute()
                || Files.isSymbolicLink(directory)
                || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            fail("root trust目录必须是绝对路径且不能是符号链接");
        }
        rejectGroupOrOtherWrite(Files.getPosixFilePermissions(
                directory, LinkOption.NOFOLLOW_LINKS), "root trust目录不能被组或其他用户写入");
    }

    private static void validateRootFile(Path file, UserPrincipal directoryOwner)
            throws IOException {
        if (Files.isSymbolicLink(file)
                || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            fail("root trust条目必须是普通文件且不能是符号链接");
        }
        if (!directoryOwner.equals(Files.getOwner(file, LinkOption.NOFOLLOW_LINKS))) {
            fail("root trust目录和文件必须属于同一OS主体");
        }
        rejectGroupOrOtherWrite(Files.getPosixFilePermissions(
                file, LinkOption.NOFOLLOW_LINKS), "root trust文件不能被组或其他用户写入");
        long size = Files.size(file);
        if (size <= 0 || size > MAX_ROOT_PEM_BYTES) {
            fail("root trust文件为空或超过16384字节");
        }
    }

    private static void rejectGroupOrOtherWrite(Set<PosixFilePermission> permissions,
            String message) {
        if (permissions.contains(PosixFilePermission.GROUP_WRITE)
                || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
            fail(message);
        }
    }

    private static byte[] readBounded(Path file) throws IOException {
        try (InputStream input = Files.newInputStream(file);
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count == 0) {
                    continue;
                }
                if (output.size() + count > MAX_ROOT_PEM_BYTES) {
                    fail("root trust文件为空或超过16384字节");
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private static void fail(String message) {
        throw new MassDbLicenseException(ERROR_CODE, message);
    }
}
