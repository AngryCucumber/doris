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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Opens the component-native identity provider without putting its password in FE Config. */
final class MassDbLicenseIdentityRuntime {
    private static final String ERROR_CODE = "MASSDB_LICENSE_ROLE_IDENTITY_CONFIG_INVALID";
    private static final int MAX_SECRET_BYTES = 4096;
    private static final int MAX_SECRET_CHARS = 1024;

    private MassDbLicenseIdentityRuntime() {
    }

    static MassDbLicenseFeRoleIdentityProvider openConfigured(
            String configuredStoreDirectory, String artifactRootDirectory,
            String secretFile, String metaDirectory) {
        try {
            Path store = configuredStoreDirectory == null
                    || configuredStoreDirectory.trim().isEmpty()
                    ? Paths.get(metaDirectory, "massdb-license-identity")
                    : Paths.get(configuredStoreDirectory.trim());
            if (artifactRootDirectory == null || artifactRootDirectory.trim().isEmpty()
                    || secretFile == null || secretFile.trim().isEmpty()) {
                fail("Identity Artifact root目录和启动凭据文件必须显式配置");
            }
            return open(store, Paths.get(artifactRootDirectory.trim()),
                    Paths.get(secretFile.trim()));
        } catch (InvalidPathException | NullPointerException error) {
            fail("身份库配置路径无效");
            return null;
        }
    }

    static MassDbLicenseFeRoleIdentityProvider open(
            Path storeDirectory, Path artifactRootDirectory,
            Path secretFile) {
        if (storeDirectory == null || !storeDirectory.isAbsolute()) {
            fail("身份库目录必须是绝对路径");
        }
        Map<String, PublicKey> roots;
        try {
            roots = MassDbLicenseRootTrustLoader.loadRootKeys(artifactRootDirectory);
        } catch (MassDbLicenseException error) {
            fail("Identity Artifact root目录无效");
            return null;
        }
        char[] secret = readSecret(secretFile);
        MassDbLicenseIdentityStore store = null;
        try {
            store = new MassDbLicenseIdentityStore(storeDirectory, secret, roots);
            MassDbLicenseFeRoleIdentityProvider provider =
                    MassDbLicenseFeRoleIdentityProvider.StoreBacked.openDeferred(store);
            store = null;
            return provider;
        } finally {
            Arrays.fill(secret, '\0');
            if (store != null) {
                store.close();
            }
        }
    }

    static char[] readSecret(Path path) {
        if (path == null || !path.isAbsolute()) {
            fail("启动凭据必须是绝对路径下的非符号链接普通文件");
        }
        byte[] encoded = null;
        try {
            BasicFileAttributes before = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!before.isRegularFile() || Files.isSymbolicLink(path)) {
                fail("启动凭据必须是绝对路径下的非符号链接普通文件");
            }
            long size = before.size();
            if (size <= 0 || size > MAX_SECRET_BYTES) {
                fail("启动凭据文件为空或超过4096字节");
            }
            requirePrivatePermissions(path);
            encoded = readExact(path, (int) size);
            BasicFileAttributes after = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            requirePrivatePermissions(path);
            if (!after.isRegularFile() || before.size() != after.size()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || !Objects.equals(before.fileKey(), after.fileKey())) {
                fail("启动凭据文件在读取期间发生变化");
            }
            char[] value = decodeSecret(encoded);
            int length = value.length;
            if (length > 0 && value[length - 1] == '\n') {
                length--;
                if (length > 0 && value[length - 1] == '\r') {
                    length--;
                }
            }
            if (length < 16 || length > MAX_SECRET_CHARS) {
                Arrays.fill(value, '\0');
                fail("启动凭据去除单个行尾后必须为16至1024字符");
            }
            for (int index = 0; index < length; index++) {
                char item = value[index];
                if (Character.isISOControl(item)) {
                    Arrays.fill(value, '\0');
                    fail("启动凭据不能包含控制字符或内嵌换行");
                }
            }
            if (length == value.length) {
                return value;
            }
            char[] trimmed = Arrays.copyOf(value, length);
            Arrays.fill(value, '\0');
            return trimmed;
        } catch (CharacterCodingException error) {
            fail("启动凭据不是严格UTF-8文本");
            return null;
        } catch (IOException | UnsupportedOperationException | SecurityException error) {
            fail("无法安全读取启动凭据文件");
            return null;
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }

    private static char[] decodeSecret(byte[] encoded) throws CharacterCodingException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        CharBuffer decoded = CharBuffer.allocate(MAX_SECRET_BYTES);
        try {
            CoderResult result = decoder.decode(ByteBuffer.wrap(encoded), decoded, true);
            if (result.isError()) {
                result.throwException();
            }
            if (result.isOverflow()) {
                fail("启动凭据解码后超过4096字符");
            }
            result = decoder.flush(decoded);
            if (result.isError()) {
                result.throwException();
            }
            if (result.isOverflow()) {
                fail("启动凭据解码后超过4096字符");
            }
            decoded.flip();
            char[] value = new char[decoded.remaining()];
            decoded.get(value);
            return value;
        } finally {
            Arrays.fill(decoded.array(), '\0');
        }
    }

    private static byte[] readExact(Path path, int expectedSize) throws IOException {
        byte[] result = new byte[expectedSize];
        try (SeekableByteChannel input = Files.newByteChannel(path,
                StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer target = ByteBuffer.wrap(result);
            while (target.hasRemaining()) {
                int count = input.read(target);
                if (count < 0) {
                    Arrays.fill(result, (byte) 0);
                    fail("启动凭据文件在读取期间发生变化");
                }
            }
            if (input.read(ByteBuffer.allocate(1)) != -1) {
                Arrays.fill(result, (byte) 0);
                fail("启动凭据文件在读取期间发生变化或超过4096字节");
            }
            return result;
        }
    }

    private static void requirePrivatePermissions(Path path) throws IOException {
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                path, LinkOption.NOFOLLOW_LINKS);
        if (!permissions.contains(PosixFilePermission.OWNER_READ)
                || permissions.contains(PosixFilePermission.OWNER_EXECUTE)
                || permissions.contains(PosixFilePermission.GROUP_READ)
                || permissions.contains(PosixFilePermission.GROUP_WRITE)
                || permissions.contains(PosixFilePermission.GROUP_EXECUTE)
                || permissions.contains(PosixFilePermission.OTHERS_READ)
                || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                || permissions.contains(PosixFilePermission.OTHERS_EXECUTE)) {
            fail("启动凭据文件权限必须为0400或0600");
        }
    }

    private static void fail(String message) {
        throw new MassDbLicenseException(ERROR_CODE, message);
    }
}
