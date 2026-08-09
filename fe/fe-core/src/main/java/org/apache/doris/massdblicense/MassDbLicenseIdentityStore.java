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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
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
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Component-native encrypted identity store. The private key is created on this FE and only ever
 * persisted inside password-protected PKCS12. Public metadata and signed .midentity bytes are
 * separate, atomically referenced records; they never contain the private key or its password.
 */
public final class MassDbLicenseIdentityStore implements AutoCloseable {
    private static final int FORMAT_VERSION = 2;
    private static final int LEGACY_FORMAT_VERSION = 1;
    private static final int MAX_METADATA_BYTES = 32 * 1024;
    private static final int MAX_PKCS12_BYTES = 256 * 1024;
    private static final int MAX_DIRECTORY_ENTRIES = 4096;
    static final long RETIRED_GENERATION_RETENTION_SECONDS = 7 * 24 * 60 * 60;
    private static final String ENROLLMENT_POINTER = "enrollment.pointer";
    private static final String ACTIVE_POINTER = "active.pointer";
    private static final String MUTATION_LOCK = ".identity-store.lock";
    private static final String RETIRED_IDENTITY_PREFIX = "retired-identity-";
    private static final String RETIRED_ENROLLMENT_PREFIX = "retired-enrollment-";
    private static final byte[] METADATA_MAGIC =
            "MDBID001".getBytes(StandardCharsets.US_ASCII);
    private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
    private static final Set<PosixFilePermission> FILE_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));

    private final Path directory;
    private final char[] password;
    private final Map<String, PublicKey> identityArtifactRoots;
    private final KeyMaterialGenerator keyMaterialGenerator;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    public MassDbLicenseIdentityStore(Path directory, char[] password,
            Map<String, PublicKey> identityArtifactRoots) {
        this(directory, password, identityArtifactRoots,
                new KeyMaterialGenerator() {
                    @Override
                    public MassDbLicenseIdentityKeyMaterial.Generated generate(
                            String spiffeId, List<String> dnsSans, List<String> ipSans,
                            long nowEpochSecond) {
                        return MassDbLicenseIdentityKeyMaterial.generate(
                                spiffeId, dnsSans, ipSans, nowEpochSecond);
                    }
                });
    }

    MassDbLicenseIdentityStore(Path directory, char[] password,
            Map<String, PublicKey> identityArtifactRoots,
            KeyMaterialGenerator keyMaterialGenerator) {
        if (directory == null || password == null || password.length < 16
                || identityArtifactRoots == null || identityArtifactRoots.isEmpty()
                || keyMaterialGenerator == null) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CONFIG_INVALID",
                    "身份库目录、至少16字符启动凭据和Identity Artifact root必须配置");
        }
        this.directory = directory.toAbsolutePath().normalize();
        this.password = password.clone();
        this.identityArtifactRoots = Collections.unmodifiableMap(
                new LinkedHashMap<>(identityArtifactRoots));
        this.keyMaterialGenerator = keyMaterialGenerator;
        initializeDirectory();
    }

    /** Generates a new P-256 key and CSR, or returns the same durable pending enrollment. */
    public synchronized Enrollment beginEnrollment(String component, String deploymentUuid,
            String role, String nodeUuid, long nowEpochSecond) {
        return beginEnrollment(component, deploymentUuid, role, nodeUuid,
                Collections.emptyList(), Collections.emptyList(), nowEpochSecond);
    }

    /** Generates a CSR whose exact canonical DNS/IP SAN request is durably bound to activation. */
    public synchronized Enrollment beginEnrollment(String component, String deploymentUuid,
            String role, String nodeUuid, List<String> dnsSans, List<String> ipSans,
            long nowEpochSecond) {
        requireOpen();
        MassDbLicenseIdentityAddressSans.AddressSans addressSans =
                MassDbLicenseIdentityAddressSans.normalize(dnsSans, ipSans, false);
        return withMutationLock(new Mutation<Enrollment>() {
            @Override
            public Enrollment run() {
                return beginEnrollmentLocked(component, deploymentUuid, role, nodeUuid,
                        addressSans, false, nowEpochSecond);
            }
        });
    }

    /** Replays only a durable legacy v1 URI-only enrollment; it never creates a new CSR. */
    synchronized Enrollment replayPendingLegacyEnrollment(String component,
            String deploymentUuid, String role, String nodeUuid, long nowEpochSecond) {
        requireOpen();
        MassDbLicenseIdentityAddressSans.AddressSans empty =
                MassDbLicenseIdentityAddressSans.normalize(
                        Collections.emptyList(), Collections.emptyList(), false);
        return withMutationLock(new Mutation<Enrollment>() {
            @Override
            public Enrollment run() {
                return beginEnrollmentLocked(component, deploymentUuid, role, nodeUuid,
                        empty, true, nowEpochSecond);
            }
        });
    }

    private Enrollment beginEnrollmentLocked(String component, String deploymentUuid,
            String role, String nodeUuid,
            MassDbLicenseIdentityAddressSans.AddressSans addressSans,
            boolean legacyReplayOnly, long nowEpochSecond) {
        requireIdentity(component, deploymentUuid, role, nodeUuid);
        cleanupRetiredLocked(nowEpochSecond, RETIRED_GENERATION_RETENTION_SECONDS);
        Metadata active = loadPointedMetadata(ACTIVE_POINTER, "identity-", false);
        if (active != null) {
            active.requireIdentity(component, deploymentUuid, role, nodeUuid);
        }
        long generation = active == null ? 1 : increment(active.generation);
        String existingToken = loadPointer(ENROLLMENT_POINTER, false);
        Metadata existing = existingToken == null ? null
                : readMetadata(enrollmentName(existingToken, ".bin"));
        if (existing != null && active != null && existing.generation <= active.generation) {
            existing = null;
        }
        if (existing != null) {
            existing.requireIdentity(component, deploymentUuid, role, nodeUuid);
            if (legacyReplayOnly && existing.addressSansBound) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_ADDRESS_SAN_INVALID",
                        "无SAN只允许导出已有v1 URI-only待签CSR");
            }
            existing.requireAddressSans(addressSans);
            if (existing.generation != generation) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_ENROLLMENT_CONFLICT",
                        "已有不同generation的待签CSR");
            }
            verifyEnrollmentKey(existing);
            return existing.toEnrollment();
        }
        if (legacyReplayOnly) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_ADDRESS_SAN_INVALID",
                    "新身份CSR至少需要一个DNS或IP SAN；无SAN只允许导出已有v1待签CSR");
        }

        String spiffeId = spiffeId(component, deploymentUuid, role, nodeUuid);
        MassDbLicenseIdentityKeyMaterial.Generated generated =
                keyMaterialGenerator.generate(spiffeId, addressSans.dnsNames(),
                        addressSans.ipAddresses(), nowEpochSecond);
        String publicKeySha256 = MassDbLicenseIdentityKeyMaterial.sha256Hex(
                generated.publicKey.getEncoded());
        Metadata metadata = new Metadata(generation, nowEpochSecond, component,
                deploymentUuid, role, nodeUuid, addressSans, true,
                generated.csr, publicKeySha256, "");
        String token = UUID.randomUUID().toString();
        byte[] pkcs12 = MassDbLicenseIdentityKeyMaterial.encodePkcs12(
                generated.privateKey, new Certificate[] {generated.placeholderCertificate},
                password);
        try {
            atomicWrite(enrollmentName(token, ".p12"), pkcs12);
        } finally {
            Arrays.fill(pkcs12, (byte) 0);
        }
        atomicWrite(enrollmentName(token, ".bin"), encodeMetadata(metadata));
        if (existingToken != null) {
            ensureRetiredMarker(retiredEnrollmentName(existingToken), nowEpochSecond);
        }
        atomicWrite(ENROLLMENT_POINTER, pointerBytes(token));
        Metadata readBack = loadPointedMetadata(ENROLLMENT_POINTER, "enrollment-", true);
        if (!metadata.equals(readBack)) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "CSR落盘回读不一致");
        }
        verifyEnrollmentKey(readBack);
        return readBack.toEnrollment();
    }

    /**
     * Verifies and activates one no-private-key .midentity package. Inactive bytes are fsynced and
     * used to build a working TLS context before the active pointer is atomically replaced.
     */
    public synchronized MassDbLicenseFeRoleIdentityProvider.Snapshot importAndActivate(
            byte[] artifact, long nowEpochSecond) {
        requireOpen();
        if (artifact == null || artifact.length == 0
                || artifact.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES) {
            fail("MASSDB_LICENSE_FILE_INVALID", "身份包为空或超过协议上限");
        }
        byte[] candidate = artifact.clone();
        try {
            return withMutationLock(
                    new Mutation<MassDbLicenseFeRoleIdentityProvider.Snapshot>() {
                        @Override
                        public MassDbLicenseFeRoleIdentityProvider.Snapshot run() {
                            return importAndActivateLocked(candidate, nowEpochSecond);
                        }
                    });
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }

    private MassDbLicenseFeRoleIdentityProvider.Snapshot importAndActivateLocked(
            byte[] artifact, long nowEpochSecond) {
        cleanupRetiredLocked(nowEpochSecond, RETIRED_GENERATION_RETENTION_SECONDS);
        String artifactSha256 = MassDbLicenseIdentityKeyMaterial.sha256Hex(artifact);
        String activeToken = loadPointer(ACTIVE_POINTER, false);
        Metadata active = loadPointedMetadata(ACTIVE_POINTER, "identity-", false);
        if (active != null && artifactSha256.equals(active.artifactSha256)) {
            retireCommittedEnrollmentBestEffort(active, nowEpochSecond);
            return loadActive(nowEpochSecond);
        }
        String enrollmentToken = loadPointer(ENROLLMENT_POINTER, true);
        Metadata enrollment = loadPointedMetadata(ENROLLMENT_POINTER, "enrollment-", true);
        if (enrollment == null) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_ENROLLMENT_REQUIRED", "本节点没有待签CSR");
        }
        Long currentGeneration = active == null ? null : active.generation;
        MassDbLicenseProtocolV1.VerifiedIdentityPackage verified =
                MassDbLicenseProtocolV1.verifyIdentityPackage(artifact,
                        identityArtifactRoots, nowEpochSecond, currentGeneration,
                        enrollment.component, enrollment.deploymentUuid, enrollment.role,
                        enrollment.nodeUuid, sha256(enrollment.csr));
        if (verified.getPayload().getGeneration() != enrollment.generation) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_ENROLLMENT_CONFLICT",
                    "身份包generation与本地待签CSR不一致");
        }
        MassDbLicenseIdentityKeyMaterial.Loaded localKey = loadEnrollmentKey(enrollment);
        MassDbLicenseIdentityKeyMaterial.ActiveMaterial activated =
                MassDbLicenseIdentityKeyMaterial.activate(
                        verified, localKey, password, enrollment.addressSans,
                        true, nowEpochSecond);
        try {
            Metadata committed = enrollment.withArtifactSha256(artifactSha256);
            String token = UUID.randomUUID().toString();
            atomicWrite(identityName(token, ".p12"), activated.pkcs12);
            atomicWrite(identityName(token, ".midentity"), artifact);
            atomicWrite(identityName(token, ".bin"), encodeMetadata(committed));
            if (activeToken != null) {
                ensureRetiredMarker(retiredIdentityName(activeToken), nowEpochSecond);
            }
            ensureRetiredMarker(retiredEnrollmentName(enrollmentToken), nowEpochSecond);
            atomicWrite(ACTIVE_POINTER, pointerBytes(token));
            MassDbLicenseFeRoleIdentityProvider.Snapshot readBack = loadActive(nowEpochSecond);
            removeEnrollmentPointerBestEffort();
            return readBack;
        } finally {
            Arrays.fill(activated.pkcs12, (byte) 0);
        }
    }

    private void retireCommittedEnrollmentBestEffort(Metadata active, long nowEpochSecond) {
        try {
            String token = loadPointer(ENROLLMENT_POINTER, false);
            if (token == null) {
                return;
            }
            Metadata enrollment = readMetadata(enrollmentName(token, ".bin"));
            if (enrollment.generation > active.generation) {
                return;
            }
            ensureRetiredMarker(retiredEnrollmentName(token), nowEpochSecond);
            removeEnrollmentPointerBestEffort();
        } catch (MassDbLicenseException ignored) {
            // Active identity was already committed and is re-verified below. A stale pending
            // generation is retried by the next maintenance or enrollment operation.
        }
    }

    /** Loads and re-verifies the signed artifact, private-key match, chain and TLS context. */
    public synchronized MassDbLicenseFeRoleIdentityProvider.Snapshot loadActive(
            long nowEpochSecond) {
        requireOpen();
        String token = loadPointer(ACTIVE_POINTER, true);
        Metadata metadata = readMetadata(identityName(token, ".bin"));
        byte[] artifact = readRequired(identityName(token, ".midentity"),
                MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES);
        if (!metadata.artifactSha256.equals(
                MassDbLicenseIdentityKeyMaterial.sha256Hex(artifact))) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                    "active身份包摘要与元数据不一致");
        }
        MassDbLicenseProtocolV1.VerifiedIdentityPackage verified =
                MassDbLicenseProtocolV1.verifyIdentityPackage(artifact,
                        identityArtifactRoots, nowEpochSecond, null,
                        metadata.component, metadata.deploymentUuid, metadata.role,
                        metadata.nodeUuid, sha256(metadata.csr));
        if (verified.getPayload().getGeneration() != metadata.generation
                || !verified.getSha256().equals(metadata.artifactSha256)) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                    "active身份generation或摘要回读不一致");
        }
        MassDbLicenseIdentityKeyMaterial.Loaded localKey =
                loadPkcs12(identityName(token, ".p12"));
        if (!metadata.publicKeySha256.equals(
                MassDbLicenseIdentityKeyMaterial.sha256Hex(localKey.publicKey.getEncoded()))) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "active身份公钥摘要不一致");
        }
        return MassDbLicenseIdentityKeyMaterial.activate(
                verified, localKey, password, metadata.addressSans,
                true, nowEpochSecond).snapshot;
    }

    /**
     * Returns a bounded content revision for the atomically selected active generation. Hashing
     * every referenced file prevents same-size or timestamp-preserving in-place corruption from
     * silently leaving a previously loaded in-memory identity usable.
     */
    public synchronized String activeRevision() {
        requireOpen();
        String token = loadPointer(ACTIVE_POINTER, true);
        return token + ":" + fileRevision(identityName(token, ".p12"), MAX_PKCS12_BYTES)
                + ":" + fileRevision(identityName(token, ".midentity"),
                        MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES)
                + ":" + fileRevision(identityName(token, ".bin"), MAX_METADATA_BYTES);
    }

    /** Returns signed, key-matched local identity status even when the identity is expired. */
    public synchronized IdentityStatus status(long nowEpochSecond) {
        requireOpen();
        if (nowEpochSecond < 0) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CONFIG_INVALID", "当前时间不能为负数");
        }
        String token = loadPointer(ACTIVE_POINTER, false);
        if (token == null) {
            Metadata enrollment = loadPointedMetadata(
                    ENROLLMENT_POINTER, "enrollment-", false);
            if (enrollment == null) {
                return IdentityStatus.missing();
            }
            return IdentityStatus.pending(enrollment);
        }
        Metadata metadata = readMetadata(identityName(token, ".bin"));
        byte[] artifact = readRequired(identityName(token, ".midentity"),
                MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES);
        if (!metadata.artifactSha256.equals(
                MassDbLicenseIdentityKeyMaterial.sha256Hex(artifact))) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                    "active身份包摘要与元数据不一致");
        }
        MassDbLicenseProtocolV1.VerifiedIdentityPackage verified =
                MassDbLicenseProtocolV1.inspectIdentityPackage(artifact,
                        identityArtifactRoots, metadata.component, metadata.deploymentUuid,
                        metadata.role, metadata.nodeUuid, sha256(metadata.csr));
        if (verified.getPayload().getGeneration() != metadata.generation
                || !verified.getSha256().equals(metadata.artifactSha256)) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                    "active身份generation或摘要回读不一致");
        }
        MassDbLicenseIdentityKeyMaterial.Loaded localKey =
                loadPkcs12(identityName(token, ".p12"));
        if (!metadata.publicKeySha256.equals(
                MassDbLicenseIdentityKeyMaterial.sha256Hex(localKey.publicKey.getEncoded()))) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "active身份公钥摘要不一致");
        }
        IdentityState state;
        long validationTime = nowEpochSecond;
        if (nowEpochSecond < verified.getPayload().getNotBefore()) {
            state = IdentityState.NOT_YET_VALID;
            validationTime = verified.getPayload().getNotBefore();
        } else if (nowEpochSecond >= verified.getPayload().getNotAfter()) {
            state = IdentityState.EXPIRED;
            validationTime = verified.getPayload().getNotAfter() - 1;
        } else {
            state = IdentityState.ACTIVE;
        }
        MassDbLicenseIdentityKeyMaterial.ActiveMaterial checked =
                MassDbLicenseIdentityKeyMaterial.activate(verified, localKey, password,
                        metadata.addressSans, true, validationTime);
        Arrays.fill(checked.pkcs12, (byte) 0);
        return IdentityStatus.active(metadata, verified, state);
    }

    /** Marks and removes unreferenced generations after the fixed recovery retention window. */
    public synchronized CleanupResult cleanupRetired(long nowEpochSecond) {
        requireOpen();
        return withMutationLock(new Mutation<CleanupResult>() {
            @Override
            public CleanupResult run() {
                return cleanupRetiredLocked(
                        nowEpochSecond, RETIRED_GENERATION_RETENTION_SECONDS);
            }
        });
    }

    CleanupResult cleanupRetired(long nowEpochSecond, long retentionSeconds) {
        requireOpen();
        return withMutationLock(new Mutation<CleanupResult>() {
            @Override
            public CleanupResult run() {
                return cleanupRetiredLocked(nowEpochSecond, retentionSeconds);
            }
        });
    }

    @Override
    public synchronized void close() {
        if (closed.compareAndSet(false, true)) {
            Arrays.fill(password, '\0');
        }
    }

    private void verifyEnrollmentKey(Metadata metadata) {
        MassDbLicenseIdentityKeyMaterial.Loaded loaded = loadEnrollmentKey(metadata);
        if (!metadata.publicKeySha256.equals(
                MassDbLicenseIdentityKeyMaterial.sha256Hex(loaded.publicKey.getEncoded()))) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "待签CSR公钥摘要不一致");
        }
    }

    private MassDbLicenseIdentityKeyMaterial.Loaded loadEnrollmentKey(Metadata metadata) {
        String token = loadPointer(ENROLLMENT_POINTER, true);
        Metadata pointed = readMetadata(enrollmentName(token, ".bin"));
        if (!metadata.equals(pointed)) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "待签CSR指针发生变化");
        }
        return loadPkcs12(enrollmentName(token, ".p12"));
    }

    private MassDbLicenseIdentityKeyMaterial.Loaded loadPkcs12(String name) {
        byte[] encoded = readRequired(name, MAX_PKCS12_BYTES);
        try {
            return MassDbLicenseIdentityKeyMaterial.loadPkcs12(encoded, password);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private Metadata loadPointedMetadata(String pointer, String prefix, boolean required) {
        String token = loadPointer(pointer, required);
        if (token == null) {
            return null;
        }
        return readMetadata(prefix + token + ".bin");
    }

    private String loadPointer(String name, boolean required) {
        Path path = directory.resolve(name);
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (required) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", name + "不存在");
            }
            return null;
        }
        byte[] encoded = readRequired(name, 128);
        String token = new String(encoded, StandardCharsets.US_ASCII).trim();
        try {
            UUID parsed = UUID.fromString(token);
            if (parsed.version() != 4 || parsed.variant() != 2
                    || !parsed.toString().equals(token)) {
                throw new IllegalArgumentException("not canonical v4");
            }
        } catch (IllegalArgumentException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", name + "内容无效");
        }
        return token;
    }

    private void removeEnrollmentPointerBestEffort() {
        try {
            Files.deleteIfExists(directory.resolve(ENROLLMENT_POINTER));
            fsyncDirectory();
        } catch (IOException ignored) {
            // The committed active pointer is authoritative. A stale enrollment generation is
            // ignored by beginEnrollment and can be removed during a later maintenance window.
        }
    }

    private void initializeDirectory() {
        try {
            if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(directory)
                        || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                    fail("MASSDB_LICENSE_ROLE_IDENTITY_CONFIG_INVALID",
                            "身份库路径必须是非符号链接目录");
                }
            } else {
                Files.createDirectories(directory);
            }
            setPermissions(directory, DIRECTORY_PERMISSIONS);
            initializeMutationLock();
            fsyncDirectory();
        } catch (IOException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CONFIG_INVALID", "无法初始化身份库目录");
        }
    }

    private void initializeMutationLock() throws IOException {
        Path path = directory.resolve(MUTATION_LOCK);
        try {
            Files.write(path, new byte[] {'\n'}, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
        } catch (FileAlreadyExistsException ignored) {
            // A concurrent process may have initialized the shared lock first.
        }
        BasicFileAttributes attributes = Files.readAttributes(
                path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (Files.isSymbolicLink(path) || !attributes.isRegularFile()) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CONFIG_INVALID",
                    "身份库进程锁必须是非符号链接普通文件");
        }
        setPermissions(path, FILE_PERMISSIONS);
        requirePrivateFilePermissions(path, MUTATION_LOCK);
    }

    private <T> T withMutationLock(Mutation<T> mutation) {
        Path path = directory.resolve(MUTATION_LOCK);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS)) {
            BasicFileAttributes before = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            requireLockFile(before, path);
            requirePrivateFilePermissions(path, MUTATION_LOCK);
            FileLock acquired;
            try {
                acquired = channel.tryLock();
            } catch (OverlappingFileLockException error) {
                acquired = null;
            }
            if (acquired == null) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_BUSY",
                        "另一个组件进程正在修改身份库，请稍后重试");
            }
            try (FileLock ignored = acquired) {
                BasicFileAttributes after = Files.readAttributes(
                        path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                requireLockFile(after, path);
                requirePrivateFilePermissions(path, MUTATION_LOCK);
                if (!Objects.equals(before.fileKey(), after.fileKey())) {
                    fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                            "身份库进程锁在加锁期间被替换");
                }
                return mutation.run();
            }
        } catch (MassDbLicenseException error) {
            throw error;
        } catch (IOException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "无法获取身份库进程锁");
            return null;
        }
    }

    private static void requireLockFile(BasicFileAttributes attributes, Path path) {
        if (Files.isSymbolicLink(path) || !attributes.isRegularFile()) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                    "身份库进程锁不存在或类型错误");
        }
    }

    private CleanupResult cleanupRetiredLocked(long nowEpochSecond, long retentionSeconds) {
        if (nowEpochSecond < 0 || retentionSeconds < 0) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CONFIG_INVALID",
                    "退役清理时间参数不能为负数");
        }
        String activeToken = loadPointer(ACTIVE_POINTER, false);
        String enrollmentToken = loadPointer(ENROLLMENT_POINTER, false);
        Set<String> identityTokens = new HashSet<>();
        Set<String> enrollmentTokens = new HashSet<>();
        List<String> temporaryFiles = new ArrayList<>();
        int entries = 0;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
            for (Path path : stream) {
                if (++entries > MAX_DIRECTORY_ENTRIES) {
                    fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                            "身份库目录文件数量超过安全上限");
                }
                String name = path.getFileName().toString();
                if (isManagedTemporaryFile(name)) {
                    temporaryFiles.add(name);
                    continue;
                }
                collectToken(name, "identity-",
                        new String[] {".p12", ".midentity", ".bin"}, identityTokens);
                collectToken(name, "enrollment-",
                        new String[] {".p12", ".bin"}, enrollmentTokens);
                collectToken(name, RETIRED_IDENTITY_PREFIX,
                        new String[] {".marker"}, identityTokens);
                collectToken(name, RETIRED_ENROLLMENT_PREFIX,
                        new String[] {".marker"}, enrollmentTokens);
            }
        } catch (IOException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "无法枚举身份库目录");
        }

        int marked = 0;
        int removedGenerations = 0;
        int removedFiles = 0;
        if (!temporaryFiles.isEmpty()) {
            try {
                for (String name : temporaryFiles) {
                    if (deleteTemporaryFileIfExists(name)) {
                        removedFiles++;
                    }
                }
                fsyncDirectory();
            } catch (IOException error) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                        "无法删除身份库原子写入临时文件");
            }
        }
        for (String token : identityTokens) {
            if (!token.equals(activeToken)) {
                CleanupCounts counts = cleanupToken(token, true,
                        nowEpochSecond, retentionSeconds);
                marked += counts.marked;
                removedGenerations += counts.removedGenerations;
                removedFiles += counts.removedFiles;
            }
        }
        for (String token : enrollmentTokens) {
            if (!token.equals(enrollmentToken)) {
                CleanupCounts counts = cleanupToken(token, false,
                        nowEpochSecond, retentionSeconds);
                marked += counts.marked;
                removedGenerations += counts.removedGenerations;
                removedFiles += counts.removedFiles;
            }
        }
        return new CleanupResult(marked, removedGenerations, removedFiles);
    }

    private CleanupCounts cleanupToken(String token, boolean identity,
            long nowEpochSecond, long retentionSeconds) {
        String marker = identity ? retiredIdentityName(token) : retiredEnrollmentName(token);
        Path markerPath = directory.resolve(marker);
        if (!Files.exists(markerPath, LinkOption.NOFOLLOW_LINKS)) {
            ensureRetiredMarker(marker, nowEpochSecond);
            return new CleanupCounts(1, 0, 0);
        }
        long retiredAt = readRetiredAt(marker);
        if (nowEpochSecond < retiredAt
                || nowEpochSecond - retiredAt < retentionSeconds) {
            return CleanupCounts.NONE;
        }
        String[] files = identity
                ? new String[] {identityName(token, ".p12"),
                        identityName(token, ".midentity"), identityName(token, ".bin")}
                : new String[] {enrollmentName(token, ".p12"),
                        enrollmentName(token, ".bin")};
        int removed = 0;
        try {
            for (String name : files) {
                if (deleteRegularFileIfExists(name)) {
                    removed++;
                }
            }
            if (deleteRegularFileIfExists(marker)) {
                removed++;
            }
            fsyncDirectory();
        } catch (IOException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "无法删除退役身份generation");
        }
        return new CleanupCounts(0, 1, removed);
    }

    private boolean deleteRegularFileIfExists(String name) throws IOException {
        Path path = directory.resolve(name);
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        BasicFileAttributes attributes = Files.readAttributes(
                path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (Files.isSymbolicLink(path) || !attributes.isRegularFile()) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                    "退役身份文件类型错误: " + name);
        }
        requirePrivateFilePermissions(path, name);
        return Files.deleteIfExists(path);
    }

    private boolean deleteTemporaryFileIfExists(String name) throws IOException {
        Path path = directory.resolve(name);
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        BasicFileAttributes attributes = Files.readAttributes(
                path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (Files.isSymbolicLink(path) || !attributes.isRegularFile()) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                    "身份库原子写入临时文件类型错误: " + name);
        }
        // A process may have stopped after CREATE_NEW but before chmod. The containing directory
        // is 0700, so remove this recognized, unreferenced temporary without requiring mode 0600.
        return Files.deleteIfExists(path);
    }

    private void ensureRetiredMarker(String marker, long nowEpochSecond) {
        Path path = directory.resolve(marker);
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            readRetiredAt(marker);
            return;
        }
        atomicWrite(marker, retiredAtBytes(nowEpochSecond));
    }

    private static boolean isManagedTemporaryFile(String name) {
        if (!name.startsWith(".")) {
            return false;
        }
        int separator = name.lastIndexOf(".tmp-");
        if (separator <= 1 || separator + 5 >= name.length()) {
            return false;
        }
        String target = name.substring(1, separator);
        if (!isManagedAtomicTarget(target)) {
            return false;
        }
        return isCanonicalUuidToken(name.substring(separator + 5));
    }

    private static boolean isManagedAtomicTarget(String target) {
        if (ACTIVE_POINTER.equals(target) || ENROLLMENT_POINTER.equals(target)) {
            return true;
        }
        return isManagedGenerationName(target, "identity-",
                new String[] {".p12", ".midentity", ".bin"})
                || isManagedGenerationName(target, "enrollment-",
                        new String[] {".p12", ".bin"})
                || isManagedGenerationName(target, RETIRED_IDENTITY_PREFIX,
                        new String[] {".marker"})
                || isManagedGenerationName(target, RETIRED_ENROLLMENT_PREFIX,
                        new String[] {".marker"});
    }

    private static boolean isManagedGenerationName(String name, String prefix,
            String[] suffixes) {
        if (!name.startsWith(prefix)) {
            return false;
        }
        for (String suffix : suffixes) {
            if (name.endsWith(suffix)) {
                return isCanonicalUuidToken(name.substring(
                        prefix.length(), name.length() - suffix.length()));
            }
        }
        return false;
    }

    private static void collectToken(String name, String prefix,
            String[] suffixes, Set<String> output) {
        if (!name.startsWith(prefix)) {
            return;
        }
        for (String suffix : suffixes) {
            if (name.endsWith(suffix)) {
                String token = name.substring(prefix.length(), name.length() - suffix.length());
                requireUuidToken(token, name);
                output.add(token);
                return;
            }
        }
        fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                "身份库包含未知generation文件: " + name);
    }

    private static void requireUuidToken(String token, String label) {
        if (!isCanonicalUuidToken(token)) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                    "身份库generation标识无效: " + label);
        }
    }

    private static boolean isCanonicalUuidToken(String token) {
        try {
            UUID parsed = UUID.fromString(token);
            return parsed.version() == 4 && parsed.variant() == 2
                    && parsed.toString().equals(token);
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    private long readRetiredAt(String marker) {
        byte[] encoded = readRequired(marker, 32);
        String value = new String(encoded, StandardCharsets.US_ASCII).trim();
        try {
            long result = Long.parseLong(value);
            if (result < 0 || !(result + "\n").equals(
                    new String(encoded, StandardCharsets.US_ASCII))) {
                throw new NumberFormatException("not canonical");
            }
            return result;
        } catch (NumberFormatException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "退役时间标记无效");
            return 0;
        }
    }

    private void atomicWrite(String name, byte[] encoded) {
        Path target = directory.resolve(name);
        Path temporary = directory.resolve("." + name + ".tmp-" + UUID.randomUUID());
        try {
            Files.write(temporary, encoded, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
            setPermissions(temporary, FILE_PERMISSIONS);
            try (FileChannel file = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                file.force(true);
            }
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException error) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                        "身份库所在文件系统不支持原子切换");
            }
            fsyncDirectory();
        } catch (IOException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "无法原子写入身份库文件");
        } finally {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException ignored) {
                // Best-effort cleanup of an unreferenced temporary file.
            }
        }
    }

    private byte[] readRequired(String name, int maximum) {
        Path path = directory.resolve(name);
        byte[] result = null;
        try {
            BasicFileAttributes before = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(path) || !before.isRegularFile()) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                        "身份库文件不存在或类型错误: " + name);
            }
            long size = before.size();
            if (size <= 0 || size > maximum) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                        "身份库文件大小错误: " + name);
            }
            requirePrivateFilePermissions(path, name);
            result = new byte[(int) size];
            try (SeekableByteChannel input = Files.newByteChannel(path,
                    StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer target = ByteBuffer.wrap(result);
                while (target.hasRemaining()) {
                    if (input.read(target) < 0) {
                        fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                                "身份库文件在读取期间被截断: " + name);
                    }
                }
                if (input.read(ByteBuffer.allocate(1)) != -1) {
                    fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                            "身份库文件在读取期间增长: " + name);
                }
            }
            BasicFileAttributes after = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            requirePrivateFilePermissions(path, name);
            if (!after.isRegularFile() || before.size() != after.size()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || !Objects.equals(before.fileKey(), after.fileKey())) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                        "身份库文件在读取期间发生变化: " + name);
            }
            byte[] complete = result;
            result = null;
            return complete;
        } catch (IOException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "无法读取身份库文件: " + name);
            return null;
        } finally {
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
        }
    }

    private String fileRevision(String name, int maximum) {
        byte[] content = readRequired(name, maximum);
        try {
            return content.length + "-"
                    + MassDbLicenseIdentityKeyMaterial.sha256Hex(content);
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    private Metadata readMetadata(String name) {
        byte[] encoded = readRequired(name, MAX_METADATA_BYTES);
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            byte[] magic = new byte[METADATA_MAGIC.length];
            input.readFully(magic);
            int version = input.readInt();
            if (!Arrays.equals(magic, METADATA_MAGIC)
                    || version != LEGACY_FORMAT_VERSION && version != FORMAT_VERSION) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "身份元数据格式错误");
            }
            long generation = input.readLong();
            long createdAt = input.readLong();
            String component = readString(input, 64);
            String deploymentUuid = readString(input, 64);
            String role = readString(input, 64);
            String nodeUuid = readString(input, 64);
            List<String> dnsSans = version == FORMAT_VERSION
                    ? readStringList(input, 253) : Collections.emptyList();
            List<String> ipSans = version == FORMAT_VERSION
                    ? readStringList(input, 64) : Collections.emptyList();
            MassDbLicenseIdentityAddressSans.AddressSans addressSans =
                    MassDbLicenseIdentityAddressSans.normalize(dnsSans, ipSans, false);
            byte[] csr = readBytes(input, 16_384);
            String publicKeySha256 = readString(input, 64);
            String artifactSha256 = readString(input, 64);
            if (input.read() != -1) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "身份元数据格式错误");
            }
            return new Metadata(generation, createdAt, component, deploymentUuid,
                    role, nodeUuid, addressSans, version == FORMAT_VERSION,
                    csr, publicKeySha256, artifactSha256);
        } catch (EOFException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "身份元数据被截断");
            return null;
        } catch (IOException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "无法解析身份元数据");
            return null;
        }
    }

    private static byte[] encodeMetadata(Metadata metadata) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.write(METADATA_MAGIC);
                output.writeInt(FORMAT_VERSION);
                output.writeLong(metadata.generation);
                output.writeLong(metadata.createdAt);
                writeString(output, metadata.component);
                writeString(output, metadata.deploymentUuid);
                writeString(output, metadata.role);
                writeString(output, metadata.nodeUuid);
                writeStringList(output, metadata.addressSans.dnsNames());
                writeStringList(output, metadata.addressSans.ipAddresses());
                writeBytes(output, metadata.csr);
                writeString(output, metadata.publicKeySha256);
                writeString(output, metadata.artifactSha256);
            }
            return bytes.toByteArray();
        } catch (IOException error) {
            throw new IllegalStateException(error);
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        writeBytes(output, value.getBytes(StandardCharsets.UTF_8));
    }

    private static String readString(DataInputStream input, int maximum) throws IOException {
        return new String(readBytes(input, maximum), StandardCharsets.UTF_8);
    }

    private static void writeStringList(DataOutputStream output, List<String> values)
            throws IOException {
        output.writeInt(values.size());
        for (String value : values) {
            writeString(output, value);
        }
    }

    private static List<String> readStringList(DataInputStream input, int itemMaximum)
            throws IOException {
        int count = input.readInt();
        if (count < 0 || count > 16) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "身份SAN数量错误");
        }
        List<String> result = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            result.add(readString(input, itemMaximum));
        }
        return result;
    }

    private static void writeBytes(DataOutputStream output, byte[] value) throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }

    private static byte[] readBytes(DataInputStream input, int maximum) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > maximum) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "身份元数据字段长度错误");
        }
        byte[] value = new byte[length];
        input.readFully(value);
        return value;
    }

    private void fsyncDirectory() throws IOException {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private static void setPermissions(Path path, Set<PosixFilePermission> permissions)
            throws IOException {
        try {
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException ignored) {
            // Windows/non-POSIX packaging still gets non-symlink and regular-file validation.
        }
    }

    private static void requirePrivateFilePermissions(Path path, String name)
            throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                    path, LinkOption.NOFOLLOW_LINKS);
            if (permissions.contains(PosixFilePermission.GROUP_READ)
                    || permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.GROUP_EXECUTE)
                    || permissions.contains(PosixFilePermission.OTHERS_READ)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                        "身份库文件权限必须为0600: " + name);
            }
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX packaging cannot expose POSIX permission bits.
        }
    }

    private void requireOpen() {
        if (closed.get()) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_UNAVAILABLE", "身份库已关闭");
        }
    }

    private static void requireIdentity(String component, String deploymentUuid,
            String role, String nodeUuid) {
        MassDbLicenseSpiffeIdentity.parse(spiffeId(component, deploymentUuid, role, nodeUuid));
    }

    private static String spiffeId(String component, String deploymentUuid,
            String role, String nodeUuid) {
        return "spiffe://" + MassDbLicenseSpiffeIdentity.TRUST_DOMAIN
                + "/license/component/" + component + "/" + deploymentUuid
                + "/" + role + "/" + nodeUuid;
    }

    private static String enrollmentName(String token, String suffix) {
        return "enrollment-" + token + suffix;
    }

    private static String identityName(String token, String suffix) {
        return "identity-" + token + suffix;
    }

    private static String retiredIdentityName(String token) {
        return RETIRED_IDENTITY_PREFIX + token + ".marker";
    }

    private static String retiredEnrollmentName(String token) {
        return RETIRED_ENROLLMENT_PREFIX + token + ".marker";
    }

    private static byte[] retiredAtBytes(long nowEpochSecond) {
        if (nowEpochSecond < 0) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CONFIG_INVALID",
                    "退役时间不能为负数");
        }
        return (nowEpochSecond + "\n").getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] pointerBytes(String token) {
        return (token + "\n").getBytes(StandardCharsets.US_ASCII);
    }

    private static long increment(long value) {
        if (value <= 0 || value == Long.MAX_VALUE) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "身份generation无法递增");
        }
        return value + 1;
    }

    private static byte[] sha256(byte[] value) {
        String hex = MassDbLicenseIdentityKeyMaterial.sha256Hex(value);
        byte[] result = new byte[32];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(
                    hex.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    private static boolean sha256Hex(String value, boolean allowEmpty) {
        if (allowEmpty && value.isEmpty()) {
            return true;
        }
        if (value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (!(item >= '0' && item <= '9') && !(item >= 'a' && item <= 'f')) {
                return false;
            }
        }
        return true;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    interface KeyMaterialGenerator {
        MassDbLicenseIdentityKeyMaterial.Generated generate(
                String spiffeId, List<String> dnsSans, List<String> ipSans,
                long nowEpochSecond);
    }

    private interface Mutation<T> {
        T run();
    }

    public static final class Enrollment {
        private final long generation;
        private final String component;
        private final String deploymentUuid;
        private final String role;
        private final String nodeUuid;
        private final List<String> dnsSans;
        private final List<String> ipSans;
        private final byte[] csr;
        private final String csrSha256;

        private Enrollment(Metadata metadata) {
            this.generation = metadata.generation;
            this.component = metadata.component;
            this.deploymentUuid = metadata.deploymentUuid;
            this.role = metadata.role;
            this.nodeUuid = metadata.nodeUuid;
            this.dnsSans = metadata.addressSans.dnsNames();
            this.ipSans = metadata.addressSans.ipAddresses();
            this.csr = metadata.csr.clone();
            this.csrSha256 = MassDbLicenseIdentityKeyMaterial.sha256Hex(csr);
        }

        public long getGeneration() {
            return generation;
        }

        public String getComponent() {
            return component;
        }

        public String getDeploymentUuid() {
            return deploymentUuid;
        }

        public String getRole() {
            return role;
        }

        public String getNodeUuid() {
            return nodeUuid;
        }

        public List<String> getDnsSans() {
            return dnsSans;
        }

        public List<String> getIpSans() {
            return ipSans;
        }

        public byte[] getCsrDer() {
            return csr.clone();
        }

        public String getCsrPem() {
            return MassDbLicenseIdentityKeyMaterial.csrPem(csr);
        }

        public String getCsrSha256() {
            return csrSha256;
        }
    }

    public enum IdentityState {
        MISSING,
        ENROLLMENT_PENDING,
        NOT_YET_VALID,
        ACTIVE,
        EXPIRED
    }

    public static final class IdentityStatus {
        private final IdentityState state;
        private final long generation;
        private final String component;
        private final String deploymentUuid;
        private final String role;
        private final String nodeUuid;
        private final long notBefore;
        private final long notAfter;
        private final String artifactSha256;

        private IdentityStatus(IdentityState state, long generation, String component,
                String deploymentUuid, String role, String nodeUuid,
                long notBefore, long notAfter, String artifactSha256) {
            this.state = state;
            this.generation = generation;
            this.component = component;
            this.deploymentUuid = deploymentUuid;
            this.role = role;
            this.nodeUuid = nodeUuid;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.artifactSha256 = artifactSha256;
        }

        private static IdentityStatus missing() {
            return new IdentityStatus(IdentityState.MISSING, 0,
                    "", "", "", "", 0, 0, "");
        }

        private static IdentityStatus pending(Metadata metadata) {
            return new IdentityStatus(IdentityState.ENROLLMENT_PENDING,
                    metadata.generation, metadata.component, metadata.deploymentUuid,
                    metadata.role, metadata.nodeUuid, 0, 0, "");
        }

        private static IdentityStatus active(Metadata metadata,
                MassDbLicenseProtocolV1.VerifiedIdentityPackage verified,
                IdentityState state) {
            return new IdentityStatus(state, metadata.generation,
                    metadata.component, metadata.deploymentUuid, metadata.role,
                    metadata.nodeUuid, verified.getPayload().getNotBefore(),
                    verified.getPayload().getNotAfter(), metadata.artifactSha256);
        }

        public IdentityState getState() {
            return state;
        }

        public long getGeneration() {
            return generation;
        }

        public String getComponent() {
            return component;
        }

        public String getDeploymentUuid() {
            return deploymentUuid;
        }

        public String getRole() {
            return role;
        }

        public String getNodeUuid() {
            return nodeUuid;
        }

        public long getNotBefore() {
            return notBefore;
        }

        public long getNotAfter() {
            return notAfter;
        }

        public String getArtifactSha256() {
            return artifactSha256;
        }
    }

    public static final class CleanupResult {
        private final int markedGenerations;
        private final int removedGenerations;
        private final int removedFiles;

        private CleanupResult(int markedGenerations, int removedGenerations,
                int removedFiles) {
            this.markedGenerations = markedGenerations;
            this.removedGenerations = removedGenerations;
            this.removedFiles = removedFiles;
        }

        public int getMarkedGenerations() {
            return markedGenerations;
        }

        public int getRemovedGenerations() {
            return removedGenerations;
        }

        public int getRemovedFiles() {
            return removedFiles;
        }
    }

    private static final class CleanupCounts {
        private static final CleanupCounts NONE = new CleanupCounts(0, 0, 0);

        private final int marked;
        private final int removedGenerations;
        private final int removedFiles;

        private CleanupCounts(int marked, int removedGenerations, int removedFiles) {
            this.marked = marked;
            this.removedGenerations = removedGenerations;
            this.removedFiles = removedFiles;
        }
    }

    private static final class Metadata {
        private final long generation;
        private final long createdAt;
        private final String component;
        private final String deploymentUuid;
        private final String role;
        private final String nodeUuid;
        private final MassDbLicenseIdentityAddressSans.AddressSans addressSans;
        private final boolean addressSansBound;
        private final byte[] csr;
        private final String publicKeySha256;
        private final String artifactSha256;

        private Metadata(long generation, long createdAt, String component,
                String deploymentUuid, String role, String nodeUuid,
                MassDbLicenseIdentityAddressSans.AddressSans addressSans,
                boolean addressSansBound, byte[] csr, String publicKeySha256,
                String artifactSha256) {
            if (generation <= 0 || createdAt < 0 || csr == null || csr.length == 0
                    || addressSans == null
                    || !sha256Hex(publicKeySha256, false)
                    || !sha256Hex(artifactSha256, true)) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "身份元数据字段无效");
            }
            MassDbLicenseIdentityStore.requireIdentity(
                    component, deploymentUuid, role, nodeUuid);
            this.generation = generation;
            this.createdAt = createdAt;
            this.component = component;
            this.deploymentUuid = deploymentUuid;
            this.role = role;
            this.nodeUuid = nodeUuid;
            this.addressSans = addressSans;
            this.addressSansBound = addressSansBound;
            this.csr = csr.clone();
            this.publicKeySha256 = publicKeySha256.toLowerCase(Locale.ROOT);
            this.artifactSha256 = artifactSha256.toLowerCase(Locale.ROOT);
        }

        private void requireIdentity(String expectedComponent, String expectedDeploymentUuid,
                String expectedRole, String expectedNodeUuid) {
            if (!component.equals(expectedComponent)
                    || !deploymentUuid.equals(expectedDeploymentUuid)
                    || !role.equals(expectedRole) || !nodeUuid.equals(expectedNodeUuid)) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_ENROLLMENT_CONFLICT",
                        "身份库已有其他组件、部署、角色或节点记录");
            }
        }

        private void requireAddressSans(
                MassDbLicenseIdentityAddressSans.AddressSans expected) {
            if (addressSansBound && !addressSans.equals(expected)
                    || !addressSansBound && (!expected.dnsNames().isEmpty()
                    || !expected.ipAddresses().isEmpty())) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_ENROLLMENT_CONFLICT",
                        "已有待签CSR的DNS/IP SAN集合不同");
            }
        }

        private Metadata withArtifactSha256(String value) {
            return new Metadata(generation, createdAt, component, deploymentUuid,
                    role, nodeUuid, addressSans, addressSansBound,
                    csr, publicKeySha256, value);
        }

        private Enrollment toEnrollment() {
            return new Enrollment(this);
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof Metadata)) {
                return false;
            }
            Metadata that = (Metadata) other;
            return generation == that.generation && createdAt == that.createdAt
                    && component.equals(that.component)
                    && deploymentUuid.equals(that.deploymentUuid)
                    && role.equals(that.role) && nodeUuid.equals(that.nodeUuid)
                    && addressSans.equals(that.addressSans)
                    && addressSansBound == that.addressSansBound
                    && Arrays.equals(csr, that.csr)
                    && publicKeySha256.equals(that.publicKeySha256)
                    && artifactSha256.equals(that.artifactSha256);
        }

        @Override
        public int hashCode() {
            int result = Long.hashCode(generation);
            result = 31 * result + Long.hashCode(createdAt);
            result = 31 * result + component.hashCode();
            result = 31 * result + deploymentUuid.hashCode();
            result = 31 * result + role.hashCode();
            result = 31 * result + nodeUuid.hashCode();
            result = 31 * result + addressSans.hashCode();
            result = 31 * result + Boolean.hashCode(addressSansBound);
            result = 31 * result + Arrays.hashCode(csr);
            result = 31 * result + publicKeySha256.hashCode();
            return 31 * result + artifactSha256.hashCode();
        }
    }
}
