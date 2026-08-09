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
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/** One-time component-local proof that License bootstrap was requested on a fresh FE meta dir. */
public final class MassDbLicenseBootstrapMarker {
    public static final int FORMAT_VERSION = 1;
    public static final int MAX_MARKER_BYTES = 4096;
    public static final int MAX_CLAIM_BYTES = 4096;

    private static final String CLAIM_SUFFIX = ".first-start-claim";
    private static final String CLAIM_STATUS_CLAIMED = "CLAIMED";
    private static final String CLAIM_STATUS_OPEN_RECORDED = "OPEN_RECORDED";

    private static final Set<String> STARTUP_ALLOWED_META_ENTRIES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "process.lock", "massdb-license", "massdb-license-identity")));
    private static final Set<PosixFilePermission> FILE_PERMISSIONS =
            PosixFilePermissions.fromString("rw-------");
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);

    public enum Status {
        ELIGIBLE,
        ABSENT,
        SEALED
    }

    public static final class Attestation {
        public final Status status;
        public final String reasonCode;
        public final String bootstrapMarkerId;
        public final String licenseControlDeploymentUuid;
        public final String bootstrapPlanSha256;
        public final long createdAt;
        public final String bootstrapClaimId;
        public final String localClaimStatus;
        public final long claimedAt;
        public final long openRecordedAt;

        private Attestation(Status status, String reasonCode, Marker marker, Claim claim) {
            this.status = status;
            this.reasonCode = reasonCode;
            this.bootstrapMarkerId = marker == null ? null : marker.bootstrapMarkerId;
            this.licenseControlDeploymentUuid = marker == null
                    ? null : marker.licenseControlDeploymentUuid;
            this.bootstrapPlanSha256 = marker == null ? null : marker.bootstrapPlanSha256;
            this.createdAt = marker == null ? 0 : marker.createdAt;
            this.bootstrapClaimId = claim == null ? null : claim.bootstrapClaimId;
            this.localClaimStatus = claim == null ? "ABSENT" : claim.status;
            this.claimedAt = claim == null ? 0 : claim.claimedAt;
            this.openRecordedAt = claim == null ? 0 : claim.openRecordedAt;
        }

        public boolean isEligible() {
            return status == Status.ELIGIBLE;
        }
    }

    private MassDbLicenseBootstrapMarker() {
    }

    /** Creates exactly one marker; same-plan retries return the original deployment identity. */
    public static Attestation create(Path markerFile, Path metaDir,
            String planSha256, long createdAt) {
        Path marker = absolute(markerFile, "bootstrap marker");
        Path meta = absolute(metaDir, "FE meta dir");
        requireSha256(planSha256);
        if (createdAt <= 0) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker createdAt无效");
        }
        if (Files.exists(marker, LinkOption.NOFOLLOW_LINKS)) {
            Marker existing = readMarker(marker);
            if (!existing.bootstrapPlanSha256.equals(planSha256.toLowerCase(Locale.ROOT))) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_MISMATCH", "已存在marker绑定了不同bootstrap plan");
            }
            requireFreshMeta(meta, marker, false);
            return new Attestation(Status.ELIGIBLE, null, existing, null);
        }
        requireFreshMeta(meta, marker, true);
        requireSecureParent(marker.getParent());
        Marker payload = new Marker();
        payload.formatVersion = FORMAT_VERSION;
        payload.bootstrapMarkerId = UUID.randomUUID().toString();
        payload.licenseControlDeploymentUuid = UUID.randomUUID().toString();
        payload.bootstrapPlanSha256 = planSha256.toLowerCase(Locale.ROOT);
        payload.createdAt = createdAt;
        byte[] encoded;
        try {
            encoded = MAPPER.writeValueAsBytes(payload);
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
        atomicCreate(marker, encoded);
        Marker persisted = readMarker(marker);
        if (!payload.bootstrapMarkerId.equals(persisted.bootstrapMarkerId)
                || !payload.licenseControlDeploymentUuid.equals(
                        persisted.licenseControlDeploymentUuid)
                || !payload.bootstrapPlanSha256.equals(persisted.bootstrapPlanSha256)
                || payload.createdAt != persisted.createdAt) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker原子写入回读不一致");
        }
        return new Attestation(Status.ELIGIBLE, null, persisted, null);
    }

    /**
     * Captures a durable first-start claim before FE creates image/BDB consistency state.
     * A CLAIMED file is the only restart proof accepted after those directories appear.
     */
    public static Attestation inspect(Path markerFile, Path metaDir) {
        Path marker = absolute(markerFile, "bootstrap marker");
        Path meta = absolute(metaDir, "FE meta dir");
        if (!Files.exists(marker, LinkOption.NOFOLLOW_LINKS)) {
            return new Attestation(Status.ABSENT,
                    "MASSDB_LICENSE_BOOTSTRAP_MARKER_MISSING", null, null);
        }
        try {
            Marker payload = readMarker(marker);
            Path claimFile = claimFile(marker);
            Claim claim;
            if (Files.exists(claimFile, LinkOption.NOFOLLOW_LINKS)) {
                claim = readClaim(claimFile);
                requireClaimMatches(payload, claim);
                if (CLAIM_STATUS_CLAIMED.equals(claim.status)) {
                    requireRecoverableClaimMeta(meta, marker);
                }
            } else {
                requireFreshMeta(meta, marker, false);
                claim = createClaim(claimFile, payload);
            }
            if (!CLAIM_STATUS_CLAIMED.equals(claim.status)) {
                return new Attestation(Status.SEALED,
                        "MASSDB_LICENSE_BOOTSTRAP_CLAIM_ALREADY_OPENED", payload, claim);
            }
            return new Attestation(Status.ELIGIBLE, null, payload, claim);
        } catch (MassDbLicenseException failure) {
            return new Attestation(Status.SEALED, failure.getCode(), null, null);
        }
    }

    /** Marks the local claim after the OPEN journal record is durably accepted. */
    public static Attestation markOpenRecorded(Path markerFile, Path metaDir,
            Attestation attestation, long recordedAt) {
        Path marker = absolute(markerFile, "bootstrap marker");
        absolute(metaDir, "FE meta dir");
        if (attestation == null || !attestation.isEligible() || recordedAt <= 0) {
            fail("MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "OPEN claim提交参数无效");
        }
        Marker payload = readMarker(marker);
        Claim current = readClaim(claimFile(marker));
        requireClaimMatches(payload, current);
        if (!attestation.bootstrapClaimId.equals(current.bootstrapClaimId)) {
            fail("MASSDB_LICENSE_BOOTSTRAP_CLAIM_MISMATCH", "启动claim在OPEN期间发生变化");
        }
        if (CLAIM_STATUS_OPEN_RECORDED.equals(current.status)) {
            return new Attestation(Status.SEALED,
                    "MASSDB_LICENSE_BOOTSTRAP_CLAIM_ALREADY_OPENED", payload, current);
        }
        if (!CLAIM_STATUS_CLAIMED.equals(current.status)) {
            fail("MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "启动claim状态非法");
        }
        Claim recorded = current.copy();
        recorded.status = CLAIM_STATUS_OPEN_RECORDED;
        recorded.openRecordedAt = recordedAt;
        byte[] encoded = encode(recorded,
                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "无法编码启动claim");
        atomicReplace(claimFile(marker), encoded,
                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID");
        Claim persisted = readClaim(claimFile(marker));
        requireClaimMatches(payload, persisted);
        if (!CLAIM_STATUS_OPEN_RECORDED.equals(persisted.status)
                || persisted.openRecordedAt != recordedAt
                || !current.bootstrapClaimId.equals(persisted.bootstrapClaimId)) {
            fail("MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "OPEN claim原子写入回读不一致");
        }
        return new Attestation(Status.SEALED,
                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_ALREADY_OPENED", payload, persisted);
    }

    private static Claim createClaim(Path claimFile, Marker marker) {
        Claim claim = new Claim();
        claim.formatVersion = FORMAT_VERSION;
        claim.bootstrapClaimId = UUID.randomUUID().toString();
        claim.bootstrapMarkerId = marker.bootstrapMarkerId;
        claim.licenseControlDeploymentUuid = marker.licenseControlDeploymentUuid;
        claim.bootstrapPlanSha256 = marker.bootstrapPlanSha256;
        claim.markerCreatedAt = marker.createdAt;
        claim.status = CLAIM_STATUS_CLAIMED;
        // Bind to the marker's installation-time clock. Runtime wall clock is deliberately
        // not used here so a repaired host clock cannot make a later OPEN timestamp invalid.
        claim.claimedAt = marker.createdAt;
        byte[] encoded = encode(claim,
                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "无法编码启动claim");
        atomicCreate(claimFile, encoded,
                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "启动claim");
        Claim persisted = readClaim(claimFile);
        requireClaimMatches(marker, persisted);
        return persisted;
    }

    private static Claim readClaim(Path claimFile) {
        requireSecureParent(claimFile.getParent());
        byte[] encoded = readStable(claimFile, MAX_CLAIM_BYTES,
                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "启动claim");
        try {
            Claim claim = MAPPER.readValue(encoded, Claim.class);
            validate(claim);
            return claim;
        } catch (IOException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "启动claim JSON非法");
            return null;
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static void requireClaimMatches(Marker marker, Claim claim) {
        if (!marker.bootstrapMarkerId.equals(claim.bootstrapMarkerId)
                || !marker.licenseControlDeploymentUuid.equals(
                        claim.licenseControlDeploymentUuid)
                || !marker.bootstrapPlanSha256.equals(claim.bootstrapPlanSha256)
                || marker.createdAt != claim.markerCreatedAt) {
            fail("MASSDB_LICENSE_BOOTSTRAP_CLAIM_MISMATCH",
                    "启动claim与marker绑定不一致");
        }
    }

    private static Path claimFile(Path marker) {
        return marker.resolveSibling(marker.getFileName().toString() + CLAIM_SUFFIX);
    }

    private static Marker readMarker(Path marker) {
        requireSecureParent(marker.getParent());
        byte[] encoded = readStable(marker);
        try {
            Marker result = MAPPER.readValue(encoded, Marker.class);
            validate(result);
            return result;
        } catch (IOException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker JSON非法");
            return null;
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static byte[] readStable(Path marker) {
        return readStable(marker, MAX_MARKER_BYTES,
                "MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker");
    }

    private static byte[] readStable(Path marker, int maximum,
            String errorCode, String label) {
        try {
            BasicFileAttributes before = Files.readAttributes(
                    marker, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(marker) || !before.isRegularFile()
                    || before.size() <= 0 || before.size() > maximum) {
                fail(errorCode, label + "必须是有界普通文件");
            }
            requirePrivateFile(marker, errorCode, label);
            byte[] result = Files.readAllBytes(marker);
            BasicFileAttributes after = Files.readAttributes(
                    marker, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (result.length != before.size() || after.size() != before.size()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || !equalsNullable(before.fileKey(), after.fileKey())) {
                Arrays.fill(result, (byte) 0);
                fail(errorCode, label + "读取期间发生变化");
            }
            return result;
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            fail(errorCode, "无法安全读取" + label);
            return null;
        }
    }

    private static void requireFreshMeta(Path meta, Path marker, boolean markerMustBeAbsent) {
        try {
            BasicFileAttributes attributes = Files.readAttributes(
                    meta, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(meta) || !attributes.isDirectory()) {
                fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH", "FE meta dir不是安全目录");
            }
            Path normalizedMarker = marker.toAbsolutePath().normalize();
            Path normalizedClaim = claimFile(marker).toAbsolutePath().normalize();
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(meta)) {
                for (Path entry : entries) {
                    Path normalized = entry.toAbsolutePath().normalize();
                    if (normalized.equals(normalizedMarker)) {
                        if (markerMustBeAbsent) {
                            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker创建发生竞态");
                        }
                        continue;
                    }
                    if (normalized.equals(normalizedClaim)) {
                        BasicFileAttributes claimAttributes = Files.readAttributes(
                                entry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                        if (markerMustBeAbsent || Files.isSymbolicLink(entry)
                                || !claimAttributes.isRegularFile()) {
                            fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH",
                                    "启动claim不能出现在新marker创建前且必须是普通文件");
                        }
                        requirePrivateFile(entry,
                                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "启动claim");
                        continue;
                    }
                    String name = entry.getFileName().toString();
                    if (!STARTUP_ALLOWED_META_ENTRIES.contains(name)
                            || Files.isSymbolicLink(entry)) {
                        fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH",
                                "FE meta dir已有一致性或业务元数据: " + name);
                    }
                    requireAllowedEntryType(entry, name);
                }
            }
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH", "无法证明FE meta dir为fresh");
        }
    }

    /**
     * A durable claim may span creation of the FE consistency directories, but it never
     * authorizes arbitrary top-level files or a previously materialized License snapshot.
     */
    private static void requireRecoverableClaimMeta(Path meta, Path marker) {
        try {
            BasicFileAttributes attributes = Files.readAttributes(
                    meta, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(meta) || !attributes.isDirectory()) {
                fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH", "FE meta dir不是安全目录");
            }
            Path normalizedMarker = marker.toAbsolutePath().normalize();
            Path normalizedClaim = claimFile(marker).toAbsolutePath().normalize();
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(meta)) {
                for (Path entry : entries) {
                    Path normalized = entry.toAbsolutePath().normalize();
                    if (normalized.equals(normalizedMarker)) {
                        readMarker(entry);
                        continue;
                    }
                    if (normalized.equals(normalizedClaim)) {
                        readClaim(entry);
                        continue;
                    }
                    String name = entry.getFileName().toString();
                    if ("bdb".equals(name) || "image".equals(name)) {
                        BasicFileAttributes runtime = Files.readAttributes(
                                entry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                        if (Files.isSymbolicLink(entry) || !runtime.isDirectory()) {
                            fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH",
                                    "首次一致性目录类型异常: " + name);
                        }
                        continue;
                    }
                    if (!STARTUP_ALLOWED_META_ENTRIES.contains(name)
                            || Files.isSymbolicLink(entry)) {
                        fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH",
                                "启动claim之外出现未知FE状态: " + name);
                    }
                    requireAllowedEntryType(entry, name);
                }
            }
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH", "无法核验启动claim恢复边界");
        }
    }

    private static void requireAllowedEntryType(Path entry, String name) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(
                entry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if ("process.lock".equals(name)) {
            if (!attributes.isRegularFile()) {
                fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH", "process.lock不是普通文件");
            }
            return;
        }
        if (!attributes.isDirectory()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH", name + "不是目录");
        }
        if ("massdb-license".equals(name)) {
            requireNodeIdentityOnly(entry);
        }
    }

    /** A pre-created stable node UUID is allowed; any runtime snapshot proves prior use. */
    private static void requireNodeIdentityOnly(Path directory) throws IOException {
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
            for (Path child : entries) {
                BasicFileAttributes attributes = Files.readAttributes(
                        child, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!"node-uuid".equals(child.getFileName().toString())
                        || Files.isSymbolicLink(child) || !attributes.isRegularFile()
                        || attributes.size() != 36) {
                    fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH",
                            "本地License目录包含首启前不允许的运行态文件");
                }
            }
        }
    }

    private static void atomicCreate(Path marker, byte[] encoded) {
        atomicCreate(marker, encoded,
                "MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker");
    }

    private static void atomicCreate(Path marker, byte[] encoded,
            String errorCode, String label) {
        Path temporary = marker.resolveSibling("." + marker.getFileName()
                + ".tmp-" + UUID.randomUUID());
        try {
            try (FileChannel output = FileChannel.open(temporary,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                setPrivateFile(temporary);
                ByteBuffer source = ByteBuffer.wrap(encoded);
                while (source.hasRemaining()) {
                    output.write(source);
                }
                output.force(true);
            }
            try {
                // Publish a fully fsynced inode without rename-overwrite semantics. A hard
                // link is atomic and fails when another installer already owns the target.
                Files.createLink(marker, temporary);
            } catch (UnsupportedOperationException failure) {
                fail(errorCode, label + "目录不支持原子独占创建");
            } catch (FileAlreadyExistsException failure) {
                fail(errorCode, label + "创建发生竞态");
            }
            forceDirectory(marker.getParent());
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            fail(errorCode, "无法原子创建" + label);
        } finally {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException ignored) {
                // A private orphan temp link is fail-closed and can be removed by an operator.
            }
        }
    }

    private static void atomicReplace(Path target, byte[] encoded, String errorCode) {
        Path temporary = target.resolveSibling("." + target.getFileName()
                + ".tmp-" + UUID.randomUUID());
        boolean moved = false;
        try {
            try (FileChannel output = FileChannel.open(temporary,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                setPrivateFile(temporary);
                ByteBuffer source = ByteBuffer.wrap(encoded);
                while (source.hasRemaining()) {
                    output.write(source);
                }
                output.force(true);
            }
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException failure) {
                fail(errorCode, "启动claim目录不支持原子替换");
            }
            moved = true;
            forceDirectory(target.getParent());
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            fail(errorCode, "无法原子替换启动claim");
        } finally {
            if (!moved) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                    // A private orphan temp file is fail-closed and can be removed by an operator.
                }
            }
        }
    }

    private static byte[] encode(Object value, String errorCode, String message) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (IOException failure) {
            fail(errorCode, message);
            return null;
        }
    }

    private static void validate(Marker marker) {
        if (marker == null || marker.formatVersion != FORMAT_VERSION) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker formatVersion非法");
        }
        requireUuidV4(marker.bootstrapMarkerId, "bootstrapMarkerId");
        requireUuidV4(marker.licenseControlDeploymentUuid, "licenseControlDeploymentUuid");
        requireSha256(marker.bootstrapPlanSha256);
        if (!marker.bootstrapPlanSha256.equals(
                marker.bootstrapPlanSha256.toLowerCase(Locale.ROOT)) || marker.createdAt <= 0) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker摘要或createdAt非法");
        }
    }

    private static void validate(Claim claim) {
        if (claim == null || claim.formatVersion != FORMAT_VERSION) {
            fail("MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "启动claim formatVersion非法");
        }
        requireUuidV4(claim.bootstrapClaimId, "bootstrapClaimId",
                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID");
        requireUuidV4(claim.bootstrapMarkerId, "bootstrapMarkerId",
                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID");
        requireUuidV4(claim.licenseControlDeploymentUuid, "licenseControlDeploymentUuid",
                "MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID");
        requireSha256(claim.bootstrapPlanSha256);
        if (!claim.bootstrapPlanSha256.equals(
                claim.bootstrapPlanSha256.toLowerCase(Locale.ROOT))
                || claim.markerCreatedAt <= 0 || claim.claimedAt < claim.markerCreatedAt
                || (!CLAIM_STATUS_CLAIMED.equals(claim.status)
                        && !CLAIM_STATUS_OPEN_RECORDED.equals(claim.status))
                || (CLAIM_STATUS_CLAIMED.equals(claim.status) && claim.openRecordedAt != 0)
                || (CLAIM_STATUS_OPEN_RECORDED.equals(claim.status)
                        && claim.openRecordedAt < claim.claimedAt)) {
            fail("MASSDB_LICENSE_BOOTSTRAP_CLAIM_INVALID", "启动claim字段非法");
        }
    }

    private static Path absolute(Path value, String label) {
        if (value == null || !value.isAbsolute()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", label + "必须是绝对路径");
        }
        return value.normalize();
    }

    private static void requireSecureParent(Path parent) {
        if (parent == null) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker parent不存在");
        }
        try {
            BasicFileAttributes attributes = Files.readAttributes(
                    parent, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(parent) || !attributes.isDirectory()) {
                fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker parent不是安全目录");
            }
            try {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                        parent, LinkOption.NOFOLLOW_LINKS);
                if (permissions.contains(PosixFilePermission.GROUP_WRITE)
                        || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                    fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker parent不能被其他主体写入");
                }
            } catch (UnsupportedOperationException ignored) {
                // Stable no-symlink checks remain active on non-POSIX filesystems.
            }
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "无法验证marker parent");
        }
    }

    private static void requirePrivateFile(Path path) throws IOException {
        requirePrivateFile(path, "MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID", "marker");
    }

    private static void requirePrivateFile(Path path, String errorCode, String label)
            throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                    path, LinkOption.NOFOLLOW_LINKS);
            if (!permissions.equals(PosixFilePermissions.fromString("r--------"))
                    && !permissions.equals(FILE_PERMISSIONS)) {
                fail(errorCode, label + "权限必须为0400或0600");
            }
        } catch (UnsupportedOperationException ignored) {
            // Stable no-symlink checks remain active on non-POSIX filesystems.
        }
    }

    private static void setPrivateFile(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, FILE_PERMISSIONS);
        } catch (UnsupportedOperationException ignored) {
            // No portable equivalent; no-symlink and exclusive-create checks still apply.
        }
    }

    private static void forceDirectory(Path directory) throws IOException {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private static void requireUuidV4(String value, String field) {
        requireUuidV4(value, field, "MASSDB_LICENSE_BOOTSTRAP_MARKER_INVALID");
    }

    private static void requireUuidV4(String value, String field, String errorCode) {
        try {
            UUID uuid = UUID.fromString(value);
            if (uuid.version() != 4 || !uuid.toString().equals(value)) {
                fail(errorCode, field + "必须是canonical UUIDv4");
            }
        } catch (NullPointerException | IllegalArgumentException failure) {
            fail(errorCode, field + "必须是canonical UUIDv4");
        }
    }

    private static final class Claim {
        public int formatVersion;
        public String bootstrapClaimId;
        public String bootstrapMarkerId;
        public String licenseControlDeploymentUuid;
        public String bootstrapPlanSha256;
        public long markerCreatedAt;
        public String status;
        public long claimedAt;
        public long openRecordedAt;

        public Claim() {
        }

        private Claim copy() {
            Claim copy = new Claim();
            copy.formatVersion = formatVersion;
            copy.bootstrapClaimId = bootstrapClaimId;
            copy.bootstrapMarkerId = bootstrapMarkerId;
            copy.licenseControlDeploymentUuid = licenseControlDeploymentUuid;
            copy.bootstrapPlanSha256 = bootstrapPlanSha256;
            copy.markerCreatedAt = markerCreatedAt;
            copy.status = status;
            copy.claimedAt = claimedAt;
            copy.openRecordedAt = openRecordedAt;
            return copy;
        }
    }

    private static void requireSha256(String value) {
        if (value == null || !value.matches("[0-9a-fA-F]{64}")) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "bootstrap plan SHA-256非法");
        }
    }

    private static boolean equalsNullable(Object left, Object right) {
        return left == null ? right == null : left.equals(right);
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    public static final class Marker {
        public int formatVersion;
        public String bootstrapMarkerId;
        public String licenseControlDeploymentUuid;
        public String bootstrapPlanSha256;
        public long createdAt;

        public Marker() {
        }
    }
}
