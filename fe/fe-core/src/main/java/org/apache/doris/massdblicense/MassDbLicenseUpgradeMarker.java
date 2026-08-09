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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

/** Private, component-local authorization marker for an existing FE's one-time upgrade. */
public final class MassDbLicenseUpgradeMarker {
    private static final int FORMAT_VERSION = 1;
    private static final int MAX_MARKER_BYTES = 16 * 1024;
    private static final long FUTURE_TOLERANCE_SECONDS = 300;
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Set<PosixFilePermission> FILE_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));

    public enum Status {
        READY,
        SEALED
    }

    public static final class Attestation {
        public final Status status;
        public final String reasonCode;
        public final String upgradeSessionId;
        public final String licenseControlDeploymentUuid;
        public final String upgradePlanSha256;
        public final String localNodeUuid;
        public final MassDbLicenseBuildIdentity buildIdentity;
        public final long createdAt;
        private final byte[] tokenKey;

        private Attestation(Status status, String reasonCode, Marker marker) {
            this.status = status;
            this.reasonCode = reasonCode;
            this.upgradeSessionId = marker == null ? null : marker.upgradeSessionId;
            this.licenseControlDeploymentUuid = marker == null
                    ? null : marker.licenseControlDeploymentUuid;
            this.upgradePlanSha256 = marker == null ? null : marker.upgradePlanSha256;
            this.localNodeUuid = marker == null ? null : marker.localNodeUuid;
            this.buildIdentity = marker == null ? null : marker.buildIdentity();
            this.createdAt = marker == null ? 0 : marker.createdAt;
            this.tokenKey = marker == null ? null
                    : Base64.getDecoder().decode(marker.preconditionHmacKeyBase64);
        }

        public boolean isEligible() {
            return status == Status.READY;
        }

        byte[] preconditionHmacKey() {
            return tokenKey == null ? null : tokenKey.clone();
        }
    }

    private MassDbLicenseUpgradeMarker() {
    }

    public static Attestation create(Path markerPath, Path metaDirectory,
            MassDbLicenseUpgradeCore.PlanSummary plan,
            MassDbLicenseBuildIdentity build, String upgradeSessionId,
            String deploymentUuid, long now) {
        Path marker = normalizedAbsolute(markerPath, "marker");
        Path meta = normalizedAbsolute(metaDirectory, "meta dir");
        if (plan == null || build == null || now <= 0) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker输入不完整");
        }
        if (!build.sameAs(plan.requiredBuild)) {
            fail("MASSDB_LICENSE_UPGRADE_BUILD_MISMATCH",
                    "当前FE精确构建与upgrade plan不一致");
        }
        requireExistingMeta(meta);
        String localNodeUuid = new MassDbLicenseLocalSnapshotStore(
                meta.resolve("massdb-license")).getNodeUuid();
        if (!plan.containsNodeUuid(localNodeUuid)) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_MISMATCH",
                    "当前FE node UUID不在upgrade plan中");
        }
        boolean idsOmitted = empty(upgradeSessionId) && empty(deploymentUuid);
        if (!idsOmitted && (empty(upgradeSessionId) || empty(deploymentUuid))) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID",
                    "upgrade session与deployment UUID必须同时提供或同时省略");
        }
        if (Files.exists(marker, LinkOption.NOFOLLOW_LINKS)) {
            Attestation existing = inspect(marker, meta, build, localNodeUuid, now);
            if (!existing.isEligible()
                    || !plan.planSha256.equals(existing.upgradePlanSha256)
                    || !idsOmitted && (!upgradeSessionId.equals(existing.upgradeSessionId)
                            || !deploymentUuid.equals(
                                    existing.licenseControlDeploymentUuid))) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_CONFLICT",
                        "既有upgrade marker绑定了不同会话或plan");
            }
            return existing;
        }
        String session = idsOmitted ? UUID.randomUUID().toString() : upgradeSessionId;
        String deployment = idsOmitted ? UUID.randomUUID().toString() : deploymentUuid;
        requireUuidV4(session, "upgradeSessionId");
        requireUuidV4(deployment, "licenseControlDeploymentUuid");
        requireSafeParent(marker);

        Marker value = new Marker();
        value.formatVersion = FORMAT_VERSION;
        value.upgradeSessionId = session;
        value.licenseControlDeploymentUuid = deployment;
        value.upgradePlanSha256 = plan.planSha256;
        value.localNodeUuid = localNodeUuid;
        value.componentType = build.componentType;
        value.componentVersion = build.componentVersion;
        value.capabilityVersion = build.capabilityVersion;
        value.stateFormatVersion = build.stateFormatVersion;
        value.journalOperationType = build.journalOperationType;
        value.snapshotFormat = build.snapshotFormat;
        value.binarySha256 = build.binarySha256;
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        value.preconditionHmacKeyBase64 = Base64.getEncoder().encodeToString(key);
        value.createdAt = now;
        try {
            byte[] encoded = MAPPER.writeValueAsBytes(value);
            if (encoded.length == 0 || encoded.length > MAX_MARKER_BYTES) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker编码过大");
            }
            atomicCreate(marker, encoded);
        } catch (FileAlreadyExistsException exists) {
            Attestation existing = inspect(marker, meta, build, localNodeUuid, now);
            if (!existing.isEligible()
                    || !plan.planSha256.equals(existing.upgradePlanSha256)
                    || !idsOmitted && (!session.equals(existing.upgradeSessionId)
                            || !deployment.equals(
                                    existing.licenseControlDeploymentUuid))) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_CONFLICT",
                        "既有upgrade marker绑定了不同会话或plan");
            }
            return existing;
        } catch (IOException failure) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "无法创建upgrade marker");
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
        }
        return inspect(marker, meta, build, localNodeUuid, now);
    }

    public static Attestation inspect(Path markerPath, Path metaDirectory,
            MassDbLicenseBuildIdentity build, String expectedNodeUuid, long now) {
        try {
            Path marker = normalizedAbsolute(markerPath, "marker");
            Path meta = normalizedAbsolute(metaDirectory, "meta dir");
            requireExistingMeta(meta);
            requireSafeParent(marker);
            Marker value = readMarker(marker);
            validate(value);
            if (now <= 0 || value.createdAt > saturatedAdd(now, FUTURE_TOLERANCE_SECONDS)) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker createdAt非法");
            }
            if (!value.localNodeUuid.equals(expectedNodeUuid)
                    || build == null || !build.sameAs(value.buildIdentity())) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_MISMATCH",
                        "upgrade marker与本FE node UUID或精确构建不匹配");
            }
            return new Attestation(Status.READY, null, value);
        } catch (MassDbLicenseException failure) {
            return new Attestation(Status.SEALED, failure.getCode(), null);
        }
    }

    private static Marker readMarker(Path marker) {
        byte[] encoded = readStable(marker);
        try {
            return MAPPER.readValue(encoded, Marker.class);
        } catch (IOException failure) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker JSON非法");
            return null;
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    private static byte[] readStable(Path marker) {
        try {
            BasicFileAttributes before = Files.readAttributes(
                    marker, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(marker) || !before.isRegularFile()
                    || before.size() <= 0 || before.size() > MAX_MARKER_BYTES) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker不是安全普通文件");
            }
            requirePrivateFile(marker);
            byte[] value = Files.readAllBytes(marker);
            BasicFileAttributes after = Files.readAttributes(
                    marker, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (before.size() != after.size()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || before.fileKey() != null && !before.fileKey().equals(after.fileKey())) {
                java.util.Arrays.fill(value, (byte) 0);
                fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker读取期间发生变化");
            }
            return value;
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "无法安全读取upgrade marker");
            return null;
        }
    }

    private static void requireExistingMeta(Path meta) {
        try {
            BasicFileAttributes attributes = Files.readAttributes(
                    meta, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(meta) || !attributes.isDirectory()) {
                fail("MASSDB_LICENSE_UPGRADE_NOT_EXISTING_CLUSTER", "FE meta dir不是安全目录");
            }
            boolean consistencyState = false;
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(meta)) {
                for (Path entry : entries) {
                    String name = entry.getFileName().toString();
                    if (!"bdb".equals(name) && !"image".equals(name)) {
                        continue;
                    }
                    BasicFileAttributes child = Files.readAttributes(
                            entry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    if (Files.isSymbolicLink(entry) || !child.isDirectory()) {
                        fail("MASSDB_LICENSE_UPGRADE_NOT_EXISTING_CLUSTER",
                                "FE一致性目录类型异常: " + name);
                    }
                    consistencyState = true;
                }
            }
            if (!consistencyState) {
                fail("MASSDB_LICENSE_UPGRADE_NOT_EXISTING_CLUSTER",
                        "没有发现既有FE image或BDB一致性状态");
            }
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            fail("MASSDB_LICENSE_UPGRADE_NOT_EXISTING_CLUSTER",
                    "无法证明FE属于既有集群");
        }
    }

    private static void validate(Marker value) {
        if (value == null || value.formatVersion != FORMAT_VERSION
                || !"massdb-sql".equals(value.componentType)) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker固定字段非法");
        }
        requireUuidV4(value.upgradeSessionId, "upgradeSessionId");
        requireUuidV4(value.licenseControlDeploymentUuid,
                "licenseControlDeploymentUuid");
        requireUuidV4(value.localNodeUuid, "localNodeUuid");
        requireSha256(value.upgradePlanSha256, "upgradePlanSha256");
        requireSha256(value.binarySha256, "binarySha256");
        if (value.createdAt <= 0 || value.stateFormatVersion <= 0
                || value.journalOperationType <= 0
                || empty(value.componentVersion) || empty(value.capabilityVersion)
                || empty(value.snapshotFormat)) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker构建字段非法");
        }
        try {
            byte[] key = Base64.getDecoder().decode(value.preconditionHmacKeyBase64);
            boolean valid = key.length == 32
                    && Base64.getEncoder().encodeToString(key)
                            .equals(value.preconditionHmacKeyBase64);
            java.util.Arrays.fill(key, (byte) 0);
            if (!valid) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker HMAC key非法");
            }
        } catch (IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker HMAC key非法");
        }
    }

    private static void atomicCreate(Path marker, byte[] encoded) throws IOException {
        Path temporary = marker.resolveSibling("." + marker.getFileName()
                + ".tmp-" + UUID.randomUUID());
        try {
            try (FileChannel channel = FileChannel.open(temporary,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS)) {
                setPrivatePermissions(temporary);
                ByteBuffer buffer = ByteBuffer.wrap(encoded);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            // Publish a fully fsynced inode with an exclusive hard link. ATOMIC_MOVE alone
            // may replace an existing target on Unix and therefore cannot implement a
            // one-time marker under concurrent installers.
            Files.createLink(marker, temporary);
            requirePrivateFile(marker);
            forceDirectory(marker.getParent());
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void requireSafeParent(Path marker) {
        Path parent = marker.getParent();
        if (parent == null) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker parent不存在");
        }
        try {
            BasicFileAttributes attributes = Files.readAttributes(
                    parent, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(parent) || !attributes.isDirectory()) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID",
                        "upgrade marker parent不是安全目录");
            }
            try {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                        parent, LinkOption.NOFOLLOW_LINKS);
                if (permissions.contains(PosixFilePermission.GROUP_WRITE)
                        || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                    fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID",
                            "upgrade marker parent不能被其他主体写入");
                }
            } catch (UnsupportedOperationException ignored) {
                // No portable equivalent. NOFOLLOW and exclusive-create still apply.
            }
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID",
                    "无法验证upgrade marker parent");
        }
    }

    private static void requirePrivateFile(Path marker) throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                    marker, LinkOption.NOFOLLOW_LINKS);
            if (!FILE_PERMISSIONS.equals(permissions)) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", "upgrade marker权限必须为0600");
            }
        } catch (UnsupportedOperationException ignored) {
            // No portable equivalent. Regular-file and NOFOLLOW checks remain mandatory.
        }
    }

    private static void setPrivatePermissions(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, FILE_PERMISSIONS);
        } catch (UnsupportedOperationException ignored) {
            // No portable equivalent.
        }
    }

    private static void forceDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException ignored) {
            // Best effort on filesystems that cannot fsync directories.
        }
    }

    private static Path normalizedAbsolute(Path value, String field) {
        if (value == null || !value.isAbsolute()) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", field + "必须是绝对路径");
        }
        return value.normalize();
    }

    private static void requireUuidV4(String value, String field) {
        try {
            UUID parsed = UUID.fromString(value);
            if (parsed.version() != 4 || parsed.variant() != 2
                    || !parsed.toString().equals(value)) {
                fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID",
                        field + "必须是canonical UUIDv4");
            }
        } catch (NullPointerException | IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID",
                    field + "必须是canonical UUIDv4");
        }
    }

    private static void requireSha256(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_INVALID", field + "必须是小写SHA-256");
        }
    }

    private static boolean empty(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    private static final class Marker {
        public int formatVersion;
        public String upgradeSessionId;
        public String licenseControlDeploymentUuid;
        public String upgradePlanSha256;
        public String localNodeUuid;
        public String componentType;
        public String componentVersion;
        public String capabilityVersion;
        public int stateFormatVersion;
        public int journalOperationType;
        public String snapshotFormat;
        public String binarySha256;
        public String preconditionHmacKeyBase64;
        public long createdAt;

        public Marker() {
        }

        private MassDbLicenseBuildIdentity buildIdentity() {
            return new MassDbLicenseBuildIdentity(componentVersion, capabilityVersion,
                    stateFormatVersion, journalOperationType, snapshotFormat, binarySha256);
        }
    }
}
