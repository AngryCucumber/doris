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

import org.apache.doris.common.Version;
import org.apache.doris.persist.OperationType;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Exact component-generated build evidence used by the existing-cluster upgrade fence. */
public final class MassDbLicenseBuildIdentity {
    public static final String CAPABILITY_VERSION = "1";
    public static final String SNAPSHOT_FORMAT = "massdb-license-state/v1";
    private static final int COPY_BUFFER_BYTES = 64 * 1024;
    private static final List<String> EXPLODED_RESOURCES = Collections.unmodifiableList(
            Arrays.asList(
                    "org/apache/doris/catalog/Env.class",
                    "org/apache/doris/journal/JournalEntity.class",
                    "org/apache/doris/massdblicense/MassDbLicenseBuildIdentity.class",
                    "org/apache/doris/massdblicense/MassDbLicenseState.class",
                    "org/apache/doris/massdblicense/MassDbLicenseUpgradeCore.class",
                    "org/apache/doris/persist/OperationType.class"));
    private static volatile MassDbLicenseBuildIdentity cached;

    public final String componentType;
    public final String componentVersion;
    public final String capabilityVersion;
    public final int stateFormatVersion;
    public final int journalOperationType;
    public final String snapshotFormat;
    public final String binarySha256;

    MassDbLicenseBuildIdentity(String componentVersion, String capabilityVersion,
            int stateFormatVersion, int journalOperationType, String snapshotFormat,
            String binarySha256) {
        this.componentType = "massdb-sql";
        this.componentVersion = requireText(componentVersion, "componentVersion");
        this.capabilityVersion = requireText(capabilityVersion, "capabilityVersion");
        if (stateFormatVersion <= 0 || journalOperationType <= 0) {
            fail("MASSDB_LICENSE_UPGRADE_BUILD_INVALID", "License状态格式或journal opcode无效");
        }
        this.stateFormatVersion = stateFormatVersion;
        this.journalOperationType = journalOperationType;
        this.snapshotFormat = requireText(snapshotFormat, "snapshotFormat");
        this.binarySha256 = requireSha256(binarySha256);
    }

    public static MassDbLicenseBuildIdentity current() {
        MassDbLicenseBuildIdentity existing = cached;
        if (existing != null) {
            return existing;
        }
        synchronized (MassDbLicenseBuildIdentity.class) {
            if (cached == null) {
                cached = new MassDbLicenseBuildIdentity(
                        Version.DORIS_BUILD_VERSION + "-" + Version.DORIS_BUILD_SHORT_HASH,
                        CAPABILITY_VERSION, MassDbLicenseState.FORMAT_VERSION,
                        OperationType.OP_MASSDB_LICENSE_STATE, SNAPSHOT_FORMAT,
                        computeBinarySha256());
            }
            return cached;
        }
    }

    boolean sameAs(MassDbLicenseBuildIdentity other) {
        return other != null && componentType.equals(other.componentType)
                && componentVersion.equals(other.componentVersion)
                && capabilityVersion.equals(other.capabilityVersion)
                && stateFormatVersion == other.stateFormatVersion
                && journalOperationType == other.journalOperationType
                && snapshotFormat.equals(other.snapshotFormat)
                && binarySha256.equals(other.binarySha256);
    }

    private static String computeBinarySha256() {
        try {
            URL location = MassDbLicenseBuildIdentity.class.getProtectionDomain()
                    .getCodeSource().getLocation();
            if (location != null && "file".equalsIgnoreCase(location.getProtocol())) {
                Path source = Paths.get(new URI(location.toString())).toAbsolutePath().normalize();
                BasicFileAttributes before = Files.readAttributes(
                        source, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!Files.isSymbolicLink(source) && before.isRegularFile()) {
                    MessageDigest digest = sha256Digest();
                    try (InputStream input = Files.newInputStream(source)) {
                        update(digest, input);
                    }
                    BasicFileAttributes after = Files.readAttributes(
                            source, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    if (before.size() != after.size()
                            || !before.lastModifiedTime().equals(after.lastModifiedTime())
                            || before.fileKey() != null && !before.fileKey().equals(after.fileKey())) {
                        fail("MASSDB_LICENSE_UPGRADE_BUILD_CHANGED", "运行中FE工件读取期间发生变化");
                    }
                    return hex(digest.digest());
                }
            }
            return explodedDigest();
        } catch (IOException | URISyntaxException | SecurityException failure) {
            fail("MASSDB_LICENSE_UPGRADE_BUILD_UNAVAILABLE", "无法计算当前FE二进制摘要");
            return null;
        }
    }

    private static String explodedDigest() throws IOException {
        MessageDigest digest = sha256Digest();
        ClassLoader loader = MassDbLicenseBuildIdentity.class.getClassLoader();
        for (String resource : EXPLODED_RESOURCES) {
            byte[] name = resource.getBytes(StandardCharsets.US_ASCII);
            digest.update((byte) (name.length >>> 8));
            digest.update((byte) name.length);
            digest.update(name);
            try (InputStream input = loader.getResourceAsStream(resource)) {
                if (input == null) {
                    fail("MASSDB_LICENSE_UPGRADE_BUILD_UNAVAILABLE",
                            "FE能力类缺失，不能生成可信构建摘要");
                }
                update(digest, input);
            }
        }
        return hex(digest.digest());
    }

    private static void update(MessageDigest digest, InputStream input) throws IOException {
        byte[] buffer = new byte[COPY_BUFFER_BYTES];
        int count;
        while ((count = input.read(buffer)) >= 0) {
            if (count > 0) {
                digest.update(buffer, 0, count);
            }
        }
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return result.toString();
    }

    private static String requireText(String value, String field) {
        if (value == null || value.trim().isEmpty() || value.length() > 256) {
            fail("MASSDB_LICENSE_UPGRADE_BUILD_INVALID", field + "为空或过长");
        }
        return value;
    }

    private static String requireSha256(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            fail("MASSDB_LICENSE_UPGRADE_BUILD_INVALID", "binarySha256格式无效");
        }
        return value;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }
}
