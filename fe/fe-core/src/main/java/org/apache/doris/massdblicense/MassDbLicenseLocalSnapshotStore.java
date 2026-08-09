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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Role-local active License and activation-pending persistence.
 *
 * <p>The fixed binary format matches the Go/C++ stores. Every replacement uses same-directory
 * temporary file, file fsync, atomic rename and directory fsync. Pending is persisted and read back
 * before an ingress may ACK an enforcement activation.</p>
 */
public final class MassDbLicenseLocalSnapshotStore {
    private static final int FORMAT_VERSION = 1;
    private static final String ACTIVE_NAME = "active.snapshot";
    private static final String PENDING_NAME = "activation.pending";
    private static final String LICENSE_PENDING_NAME = "license.pending";
    private static final String CONTROL_PENDING_NAME = "control.pending";
    private static final String IDENTITY_CONFLICT_NAME = "identity-conflict.snapshot";
    private static final String CONTROL_NAME = "control.snapshot";
    private static final String NODE_UUID_NAME = "node-uuid";
    private static final byte[] ACTIVE_MAGIC = "MDBLA001".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PENDING_MAGIC = "MDBLP001".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LICENSE_PENDING_MAGIC =
            "MDBLN001".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CONTROL_PENDING_MAGIC =
            "MDBLK001".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] IDENTITY_CONFLICT_MAGIC =
            "MDBLI001".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CONTROL_MAGIC = "MDBLC001".getBytes(StandardCharsets.US_ASCII);
    private static final int MAX_LOCAL_RECORD_BYTES = 256 * 1024;
    private static final ObjectMapper CONTROL_MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);
    private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS = Collections.unmodifiableSet(
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
    private static final Set<PosixFilePermission> FILE_PERMISSIONS = Collections.unmodifiableSet(
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));

    private final Path directory;
    private final String nodeUuid;

    public MassDbLicenseLocalSnapshotStore(Path directory) {
        if (directory == null) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "本地License目录不能为空");
        }
        this.directory = directory.toAbsolutePath().normalize();
        initializeDirectory();
        this.nodeUuid = loadOrCreateNodeUuid();
    }

    /** Stable role-local identity. It is generated once and must match the mTLS URI SAN. */
    public String getNodeUuid() {
        return nodeUuid;
    }

    public synchronized void writeActive(ActiveSnapshot snapshot) {
        if (loadPending() != null || loadLicensePending() != null
                || loadControlPending() != null) {
            fail("MASSDB_LICENSE_OPERATION_IN_PROGRESS",
                    "本地pending期间不能直接替换active snapshot");
        }
        atomicWrite(ACTIVE_NAME, encodeActive(snapshot));
    }

    public synchronized ActiveSnapshot loadActive() {
        byte[] encoded = readOptional(ACTIVE_NAME);
        return encoded == null ? null : decodeActive(encoded);
    }

    public synchronized ActivationPending loadPending() {
        byte[] encoded = readOptional(PENDING_NAME);
        return encoded == null ? null : decodePending(encoded);
    }

    public synchronized LicensePending loadLicensePending() {
        byte[] encoded = readOptional(LICENSE_PENDING_NAME);
        return encoded == null ? null : decodeLicensePending(encoded);
    }

    public synchronized ControlPending loadControlPending() {
        byte[] encoded = readOptional(CONTROL_PENDING_NAME);
        return encoded == null ? null : decodeControlPending(encoded);
    }

    public synchronized IdentityConflictSnapshot loadIdentityConflict() {
        byte[] encoded = readOptional(IDENTITY_CONFLICT_NAME);
        return encoded == null ? null : decodeIdentityConflict(encoded);
    }

    public synchronized ControlPlaneCheckpoint loadControlPlaneCheckpoint() {
        byte[] encoded = readOptional(CONTROL_NAME);
        return encoded == null ? null : decodeControlPlaneCheckpoint(encoded);
    }

    /** Reads every local file influencing a query decision under one role-local lock. */
    public synchronized RoleRuntimeSnapshot loadRoleRuntimeSnapshot() {
        return new RoleRuntimeSnapshot(loadActive(), loadPending(), loadLicensePending(),
                loadControlPending(), loadControlPlaneCheckpoint(), loadIdentityConflict());
    }

    /**
     * Applies the verified active cache first and its authority manifest last. A crash between the
     * two files is therefore a detectable mismatch and can never create a falsely verified state.
     */
    public synchronized void applyControlPlaneCheckpoint(ControlPlaneCheckpoint checkpoint,
            ActiveSnapshot authoritativeActive) {
        validateControlPlaneCheckpoint(checkpoint);
        boolean checkpointHasActive = checkpoint.activeLicenseSha256 != null;
        if ((authoritativeActive != null) != checkpointHasActive
                || authoritativeActive != null
                        && (!authoritativeActive.sha256.equals(checkpoint.activeLicenseSha256)
                                || authoritativeActive.expiresAt
                                        != checkpoint.activeLicenseExpiresAt
                                || authoritativeActive.enforcementEpoch
                                        != checkpoint.enforcementEpoch)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID",
                    "控制面检查点与authoritative active不一致");
        }
        byte[] encodedCheckpoint = encodeControlPlaneCheckpoint(checkpoint);
        byte[] encodedActive = authoritativeActive == null
                ? null : encodeActive(authoritativeActive);

        ActiveSnapshot current = null;
        boolean activeCorrupt = false;
        try {
            current = loadActive();
        } catch (MassDbLicenseException error) {
            if (!"MASSDB_LICENSE_LOCAL_STATE_CORRUPT".equals(error.getCode())) {
                throw error;
            }
            activeCorrupt = true;
        }
        boolean needsActiveChange = activeCorrupt
                || (current == null) != (authoritativeActive == null)
                || current != null && (!current.sha256.equals(authoritativeActive.sha256)
                        || current.expiresAt != authoritativeActive.expiresAt
                        || current.enforcementEpoch != authoritativeActive.enforcementEpoch
                        || !Arrays.equals(current.artifact, authoritativeActive.artifact));
        if (needsActiveChange && (loadPending() != null || loadLicensePending() != null)) {
            fail("MASSDB_LICENSE_OPERATION_IN_PROGRESS",
                    "本地pending收敛前不能修复active控制面快照");
        }
        if (needsActiveChange) {
            if (authoritativeActive == null) {
                removeSnapshot(ACTIVE_NAME, "无法删除非权威active snapshot");
            } else {
                atomicWrite(ACTIVE_NAME, encodedActive);
            }
        }
        atomicWrite(CONTROL_NAME, encodedCheckpoint);
        ControlPlaneCheckpoint readBack = loadControlPlaneCheckpoint();
        if (!checkpoint.equals(readBack)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "控制面检查点落盘回读不一致");
        }
    }

    /** Applies only a revision-bound Leader command; disconnect or restart never clears the file. */
    public synchronized void applyIdentityConflict(IdentityConflictSnapshot value) {
        validateIdentityConflict(value);
        if (!nodeUuid.equals(value.nodeUuid)) {
            fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                    "重复node UUID标记与本地持久身份不一致");
        }
        IdentityConflictSnapshot existing = null;
        try {
            existing = loadIdentityConflict();
        } catch (MassDbLicenseException error) {
            if (!"MASSDB_LICENSE_LOCAL_STATE_CORRUPT".equals(error.getCode())) {
                throw error;
            }
            // A strictly validated newer authority command may repair a corrupt local marker.
        }
        if (existing != null) {
            if (!existing.deploymentUuid.equals(value.deploymentUuid)
                    || !existing.role.equals(value.role)
                    || !existing.nodeUuid.equals(value.nodeUuid)) {
                fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                        "重复node UUID标记身份发生变化");
            }
            if (value.controlPlaneRevision < existing.controlPlaneRevision) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                        "重复node UUID标记revision发生回退");
            }
            if (value.controlPlaneRevision == existing.controlPlaneRevision) {
                if (value.equals(existing)) {
                    return;
                }
                fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                        "相同revision携带不同重复node UUID状态");
            }
            if (existing.active && !value.active
                    && value.resolvedAt < existing.clearEligibleAt) {
                fail("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                        "重复node UUID尚未达到安全解除时间");
            }
        }
        atomicWrite(IDENTITY_CONFLICT_NAME, encodeIdentityConflict(value));
        if (!value.equals(loadIdentityConflict())) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "重复node UUID标记落盘回读不一致");
        }
    }

    /** Re-verifies the raw local active artifact during ingress startup. */
    public synchronized MassDbLicenseProtocolV1.VerifiedLicense verifyActive(
            MassDbLicenseProtocolV1.VerifiedKeyset keyset,
            long effectiveNow, long maxLicenseTermSeconds) {
        ActiveSnapshot active;
        try {
            active = loadActive();
        } catch (MassDbLicenseException error) {
            fail("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT", "本地active snapshot损坏");
            return null;
        }
        if (active == null) {
            fail("MASSDB_LICENSE_REQUIRED", "本地active License不存在");
        }
        if (keyset == null || active.expiresAt <= 0) {
            fail("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT", "本地active验签上下文错误");
        }
        long validationNow = Math.min(effectiveNow, active.expiresAt - 1);
        try {
            MassDbLicenseProtocolV1.VerifiedLicense verified =
                    MassDbLicenseProtocolV1.verifyLicense(active.artifact, keyset,
                            validationNow, maxLicenseTermSeconds, null);
            if (!verified.getSha256().equals(active.sha256)
                    || verified.getPayload().getExpiresAt() != active.expiresAt) {
                fail("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT",
                        "本地active元数据与工件不一致");
            }
            return verified;
        } catch (MassDbLicenseException error) {
            if ("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT".equals(error.getCode())) {
                throw error;
            }
            fail("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT", "本地active License验签失败");
            return null;
        }
    }

    /** Returns only after the pending record is durable and read back byte-semantically. */
    public synchronized void beginActivationPending(ActivationPending pending) {
        requireIdentityConflictClear();
        if (loadLicensePending() != null || loadControlPending() != null) {
            fail("MASSDB_LICENSE_OPERATION_IN_PROGRESS", "已有License控制pending");
        }
        ActiveSnapshot active = loadActive();
        if (active == null || !active.sha256.equals(normalizeSha256(pending.activeSha256))
                || pending.targetEnforcementEpoch <= active.enforcementEpoch) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                    "pending目标与本地active摘要或epoch不匹配");
        }
        ActivationPending existing = loadPending();
        if (existing != null) {
            if (existing.equals(pending)) {
                return;
            }
            fail("MASSDB_LICENSE_OPERATION_IN_PROGRESS", "已有其他activation pending");
        }
        atomicWrite(PENDING_NAME, encodePending(pending));
        ActivationPending readBack = loadPending();
        if (!pending.equals(readBack)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "activation pending落盘回读不一致");
        }
    }

    /** Builds ACK evidence only from the pending file read after durable persistence. */
    public synchronized ActivationAck prepareActivationAck(ActivationPending pending) {
        beginActivationPending(pending);
        ActivationAck ack = loadActivationAck();
        if (ack == null) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "ACK前无法回读activation pending");
        }
        return ack;
    }

    /** Rebuilds the same ACK after process or Leader restart, only from durable pending bytes. */
    public synchronized ActivationAck loadActivationAck() {
        byte[] encoded = readOptional(PENDING_NAME);
        if (encoded == null) {
            return null;
        }
        ActivationPending readBack = decodePending(encoded);
        return new ActivationAck(nodeUuid, readBack.operationId,
                readBack.targetEnforcementEpoch, readBack.activeSha256,
                encodeHex(sha256(encoded)));
    }

    /** Persists NORMAL staged bytes separately from active and returns only after read-back. */
    public synchronized void beginLicensePending(LicensePending pending) {
        requireIdentityConflictClear();
        if (loadPending() != null || loadControlPending() != null) {
            fail("MASSDB_LICENSE_OPERATION_IN_PROGRESS", "已有License控制pending");
        }
        LicensePending existing = loadLicensePending();
        if (existing != null) {
            if (existing.equals(pending)) {
                return;
            }
            fail("MASSDB_LICENSE_OPERATION_IN_PROGRESS", "已有其他NORMAL License pending");
        }
        atomicWrite(LICENSE_PENDING_NAME, encodeLicensePending(pending));
        LicensePending readBack = loadLicensePending();
        if (!pending.equals(readBack)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "license pending落盘回读不一致");
        }
    }

    /** Builds an identity-bound transport payload only from the durably read-back pending file. */
    public synchronized LicenseAck prepareLicenseAck(LicensePending pending) {
        beginLicensePending(pending);
        LicenseAck ack = loadLicenseAck();
        if (ack == null) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "ACK前无法回读license pending");
        }
        return ack;
    }

    /** Rebuilds the same NORMAL ACK after restart, only from durable pending bytes. */
    public synchronized LicenseAck loadLicenseAck() {
        byte[] encoded = readOptional(LICENSE_PENDING_NAME);
        if (encoded == null) {
            return null;
        }
        LicensePending readBack = decodeLicensePending(encoded);
        return new LicenseAck(nodeUuid, readBack.operationId, readBack.contentSha256,
                readBack.expiresAt, readBack.enforcementEpoch, encodeHex(sha256(encoded)));
    }

    /** Persists a role-side keyset validation barrier before emitting an ACK. */
    public synchronized void beginControlPending(ControlPending pending) {
        requireIdentityConflictClear();
        validateControlPending(pending, false);
        if (loadPending() != null || loadLicensePending() != null) {
            fail("MASSDB_LICENSE_OPERATION_IN_PROGRESS", "已有License或enforcement pending");
        }
        ControlPending existing = loadControlPending();
        if (existing != null) {
            if (existing.equals(pending)) {
                return;
            }
            fail("MASSDB_LICENSE_OPERATION_IN_PROGRESS", "已有其他keyset pending");
        }
        atomicWrite(CONTROL_PENDING_NAME, encodeControlPending(pending));
        if (!pending.equals(loadControlPending())) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "keyset pending落盘回读不一致");
        }
    }

    public synchronized ControlAck prepareControlAck(ControlPending pending) {
        beginControlPending(pending);
        ControlAck ack = loadControlAck();
        if (ack == null) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "ACK前无法回读keyset pending");
        }
        return ack;
    }

    /** Rebuilds the same keyset ACK after a role or Leader restart. */
    public synchronized ControlAck loadControlAck() {
        byte[] encoded = readOptional(CONTROL_PENDING_NAME);
        if (encoded == null) {
            return null;
        }
        ControlPending pending = decodeControlPending(encoded);
        return new ControlAck(nodeUuid, pending.operationId, pending.keysetSha256,
                pending.keysetVersion, pending.licenseSha256,
                pending.licenseExpiresAt, encodeHex(sha256(encoded)));
    }

    /** A successful decision is clearable only after the new authority snapshot is durable. */
    public synchronized void finishControlPending(String operationId, boolean committed) {
        ControlPending pending = loadControlPending();
        if (pending == null) {
            return;
        }
        if (!pending.operationId.equals(operationId)) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "keyset终态与pending不匹配");
        }
        if (committed) {
            ControlPlaneCheckpoint checkpoint = loadControlPlaneCheckpoint();
            boolean bundle = pending.kind
                    == MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE;
            if (checkpoint == null || checkpoint.activeKeysetVersion != pending.keysetVersion
                    || !pending.keysetSha256.equals(checkpoint.activeKeysetSha256)
                    || bundle && (!pending.licenseSha256.equals(
                                    checkpoint.activeLicenseSha256)
                            || pending.licenseExpiresAt
                                    != checkpoint.activeLicenseExpiresAt)) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED",
                        "权威control snapshot尚未原子应用，不能清除keyset pending");
            }
        }
        removePending(CONTROL_PENDING_NAME, "无法删除keyset pending");
    }

    public synchronized void commitActivation(String operationId,
            long targetEnforcementEpoch, long now) {
        ActivationPending pending = loadPending();
        if (pending == null || !pending.operationId.equals(operationId)
                || pending.targetEnforcementEpoch != targetEnforcementEpoch) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "commit决议与pending不匹配");
        }
        ActiveSnapshot active = loadActive();
        if (active == null || !active.sha256.equals(pending.activeSha256)
                || now >= active.expiresAt) {
            fail("MASSDB_LICENSE_EXPIRED", "本地active在activation commit前无效");
        }
        atomicWrite(ACTIVE_NAME, encodeActive(new ActiveSnapshot(
                active.artifact, active.sha256, active.expiresAt,
                targetEnforcementEpoch, now)));
        removePending(PENDING_NAME, "无法删除activation pending");
    }

    public synchronized void abortActivation(String operationId) {
        ActivationPending pending = loadPending();
        if (pending == null) {
            return;
        }
        if (!pending.operationId.equals(operationId)) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "abort决议与pending不匹配");
        }
        removePending(PENDING_NAME, "无法删除activation pending");
    }

    /** Applies a successful authoritative NORMAL decision; staged never self-activates. */
    public synchronized void commitLicense(String operationId, String contentSha256, long now) {
        LicensePending pending = loadLicensePending();
        if (pending == null || !pending.operationId.equals(operationId)
                || !pending.contentSha256.equals(normalizeSha256(contentSha256))) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "License commit决议与pending不匹配");
        }
        if (now >= pending.expiresAt) {
            fail("MASSDB_LICENSE_EXPIRED", "pending License在commit前已经到期");
        }
        atomicWrite(ACTIVE_NAME, encodeActive(new ActiveSnapshot(
                pending.artifact, pending.contentSha256, pending.expiresAt,
                pending.enforcementEpoch, now)));
        removePending(LICENSE_PENDING_NAME, "无法删除license pending");
    }

    public synchronized void abortLicense(String operationId) {
        LicensePending pending = loadLicensePending();
        if (pending == null) {
            return;
        }
        if (!pending.operationId.equals(operationId)) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "License abort决议与pending不匹配");
        }
        removePending(LICENSE_PENDING_NAME, "无法删除license pending");
    }

    /** The component query classifier still decides whether the request is a business read. */
    public synchronized QueryDecision evaluateQuery(
            MassDbLicenseState.EnforcementMode mode, long effectiveNow) {
        try {
            IdentityConflictSnapshot conflict = loadIdentityConflict();
            if (conflict != null && conflict.active) {
                return QueryDecision.deny("MASSDB_LICENSE_DUPLICATE_NODE_UUID");
            }
        } catch (MassDbLicenseException error) {
            return QueryDecision.deny("MASSDB_LICENSE_LOCAL_STATE_CORRUPT");
        }
        try {
            if (loadPending() != null) {
                return QueryDecision.deny("MASSDB_LICENSE_ACTIVATION_PENDING");
            }
            ControlPending controlPending = loadControlPending();
            if (controlPending != null && controlPending.failClosed()) {
                return QueryDecision.deny("MASSDB_LICENSE_KEYSET_RECOVERY_PENDING");
            }
        } catch (MassDbLicenseException error) {
            return QueryDecision.deny("MASSDB_LICENSE_LOCAL_STATE_CORRUPT");
        }
        if (mode != MassDbLicenseState.EnforcementMode.ENFORCING) {
            return QueryDecision.allow();
        }
        ActiveSnapshot active;
        try {
            active = loadActive();
        } catch (MassDbLicenseException error) {
            return QueryDecision.deny("MASSDB_LICENSE_ACTIVE_FILE_CORRUPT");
        }
        if (active == null) {
            return QueryDecision.deny("MASSDB_LICENSE_REQUIRED");
        }
        return effectiveNow >= active.expiresAt
                ? QueryDecision.deny("MASSDB_LICENSE_EXPIRED") : QueryDecision.allow();
    }

    private void requireIdentityConflictClear() {
        IdentityConflictSnapshot conflict = loadIdentityConflict();
        if (conflict != null && conflict.active) {
            fail("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                    "重复node UUID未解除，不能生成本地ACK");
        }
    }

    private void initializeDirectory() {
        boolean created = false;
        try {
            try {
                Files.createDirectory(directory,
                        PosixFilePermissions.asFileAttribute(DIRECTORY_PERMISSIONS));
                created = true;
            } catch (FileAlreadyExistsException existing) {
                // Validate the existing role directory below; never silently repair it.
            }
            if (Files.isSymbolicLink(directory)
                    || !Files.readAttributes(directory, BasicFileAttributes.class,
                            LinkOption.NOFOLLOW_LINKS).isDirectory()) {
                fail("MASSDB_LICENSE_LOCAL_STATE_INVALID",
                        "本地License路径必须是非符号链接目录");
            }
            if (created) {
                Files.setPosixFilePermissions(directory, DIRECTORY_PERMISSIONS);
            } else if (!Files.getPosixFilePermissions(directory).equals(DIRECTORY_PERMISSIONS)) {
                fail("MASSDB_LICENSE_NODE_IDENTITY_INVALID",
                        "既有本地License目录权限必须为0700");
            }
        } catch (IOException | UnsupportedOperationException error) {
            fail("MASSDB_LICENSE_LOCAL_STATE_IO", "无法初始化本地License目录");
        }
    }

    private String loadOrCreateNodeUuid() {
        byte[] existing;
        try {
            existing = readOptional(NODE_UUID_NAME);
        } catch (MassDbLicenseException error) {
            fail("MASSDB_LICENSE_NODE_IDENTITY_INVALID", "无法读取持久node UUID");
            return null;
        }
        if (existing == null) {
            createNodeUuid(UUID.randomUUID().toString());
            try {
                existing = readOptional(NODE_UUID_NAME);
            } catch (MassDbLicenseException error) {
                fail("MASSDB_LICENSE_NODE_IDENTITY_INVALID", "无法回读持久node UUID");
                return null;
            }
        }
        if (existing == null) {
            fail("MASSDB_LICENSE_NODE_IDENTITY_INVALID", "无法回读持久node UUID");
        }
        Path path = directory.resolve(NODE_UUID_NAME);
        try {
            if (!Files.getPosixFilePermissions(path).equals(FILE_PERMISSIONS)) {
                fail("MASSDB_LICENSE_NODE_IDENTITY_INVALID", "node UUID文件权限必须为0600");
            }
        } catch (IOException | UnsupportedOperationException error) {
            fail("MASSDB_LICENSE_NODE_IDENTITY_INVALID", "无法检查node UUID文件权限");
        }
        String value = new String(existing, StandardCharsets.US_ASCII);
        if (!isCanonicalVersion4Uuid(value)) {
            fail("MASSDB_LICENSE_NODE_IDENTITY_INVALID", "node UUID文件内容非法");
        }
        return value;
    }

    /** CREATE_NEW prevents two processes sharing a role directory from silently replacing identity. */
    private void createNodeUuid(String value) {
        Path target = directory.resolve(NODE_UUID_NAME);
        byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
        try (FileChannel channel = FileChannel.open(target,
                EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS))) {
            ByteBuffer source = ByteBuffer.wrap(encoded);
            while (source.hasRemaining()) {
                channel.write(source);
            }
            channel.force(true);
            Files.setPosixFilePermissions(target, FILE_PERMISSIONS);
            syncDirectory();
        } catch (FileAlreadyExistsException concurrentCreator) {
            // The winner is validated and used by loadOrCreateNodeUuid().
        } catch (IOException | UnsupportedOperationException error) {
            fail("MASSDB_LICENSE_NODE_IDENTITY_INVALID", "无法持久化node UUID");
        }
    }

    private static boolean isCanonicalVersion4Uuid(String value) {
        if (value == null || value.length() != 36) {
            return false;
        }
        try {
            UUID parsed = UUID.fromString(value);
            return parsed.version() == 4 && parsed.variant() == 2
                    && parsed.toString().equals(value);
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    private void atomicWrite(String name, byte[] encoded) {
        Path temporary = directory.resolve("." + name + "." + UUID.randomUUID() + ".tmp");
        Path target = directory.resolve(name);
        boolean moved = false;
        try {
            try (FileChannel channel = FileChannel.open(temporary,
                    EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                    PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS))) {
                ByteBuffer source = ByteBuffer.wrap(encoded);
                while (source.hasRemaining()) {
                    channel.write(source);
                }
                channel.force(true);
            }
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            moved = true;
            Files.setPosixFilePermissions(target, FILE_PERMISSIONS);
            syncDirectory();
        } catch (AtomicMoveNotSupportedException error) {
            fail("MASSDB_LICENSE_LOCAL_STATE_IO", "本地文件系统不支持原子rename");
        } catch (IOException | UnsupportedOperationException error) {
            fail("MASSDB_LICENSE_LOCAL_STATE_IO", "无法原子持久化本地License文件");
        } finally {
            if (!moved) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                    // The fixed target remains untouched; a stale hidden temp is never read.
                }
            }
        }
    }

    private void removePending(String name, String errorMessage) {
        removeSnapshot(name, errorMessage);
    }

    private void removeSnapshot(String name, String errorMessage) {
        try {
            Files.deleteIfExists(directory.resolve(name));
            syncDirectory();
        } catch (IOException error) {
            fail("MASSDB_LICENSE_LOCAL_STATE_IO", errorMessage);
        }
    }

    private void syncDirectory() throws IOException {
        try (FileChannel directoryChannel = FileChannel.open(directory, StandardOpenOption.READ)) {
            directoryChannel.force(true);
        }
    }

    private byte[] readOptional(String name) {
        Path path = directory.resolve(name);
        try {
            if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                return null;
            }
            BasicFileAttributes attributes = Files.readAttributes(path,
                    BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile() || Files.isSymbolicLink(path)
                    || attributes.size() <= 0
                    || attributes.size() > MAX_LOCAL_RECORD_BYTES) {
                fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "本地License文件类型或长度错误");
            }
            if (!Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
                    .equals(FILE_PERMISSIONS)) {
                fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "本地License文件权限必须为0600");
            }
            return Files.readAllBytes(path);
        } catch (IOException | UnsupportedOperationException error) {
            fail("MASSDB_LICENSE_LOCAL_STATE_IO", "无法读取本地License文件");
            return null;
        }
    }

    private static byte[] encodeActive(ActiveSnapshot value) {
        if (value == null || value.artifact.length == 0
                || value.artifact.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                || value.expiresAt <= value.writtenAt || !isSha256(value.sha256)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "active snapshot字段错误");
        }
        byte[] actualSha = sha256(value.artifact);
        byte[] suppliedSha = decodeHex(value.sha256);
        if (!MessageDigest.isEqual(actualSha, suppliedSha)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "active snapshot摘要不匹配");
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(ACTIVE_MAGIC);
            output.writeInt(FORMAT_VERSION);
            output.writeLong(value.enforcementEpoch);
            output.writeLong(value.writtenAt);
            output.writeLong(value.expiresAt);
            output.write(suppliedSha);
            output.writeInt(value.artifact.length);
            output.write(value.artifact);
            output.flush();
            byte[] payload = bytes.toByteArray();
            output.write(sha256(payload));
            output.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory encoding failed", impossible);
        }
    }

    private static ActiveSnapshot decodeActive(byte[] encoded) {
        final int fixedLength = 8 + 4 + 8 * 3 + 32 + 4 + 32;
        if (encoded.length < fixedLength || !startsWith(encoded, ACTIVE_MAGIC)
                || ByteBuffer.wrap(encoded, 8, 4).getInt() != FORMAT_VERSION
                || !validRecordDigest(encoded)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "active snapshot格式错误");
        }
        ByteBuffer source = ByteBuffer.wrap(encoded);
        source.position(12);
        long epoch = source.getLong();
        long writtenAt = source.getLong();
        long expiresAt = source.getLong();
        byte[] sha = new byte[32];
        source.get(sha);
        int artifactLength = source.getInt();
        if (artifactLength <= 0 || artifactLength > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                || encoded.length != fixedLength + artifactLength) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "active snapshot工件长度错误");
        }
        byte[] artifact = new byte[artifactLength];
        source.get(artifact);
        if (!MessageDigest.isEqual(sha256(artifact), sha) || expiresAt <= writtenAt) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "active snapshot摘要或时间错误");
        }
        return new ActiveSnapshot(artifact, encodeHex(sha), expiresAt, epoch, writtenAt);
    }

    private static byte[] encodePending(ActivationPending value) {
        byte[] operation = value == null || value.operationId == null ? new byte[0]
                : value.operationId.getBytes(StandardCharsets.US_ASCII);
        if (value == null || operation.length == 0
                || operation.length > MassDbLicenseState.MAX_IDEMPOTENCY_KEY_BYTES
                || !isPrintableAscii(operation) || value.targetEnforcementEpoch <= 0
                || value.createdAt <= 0 || !isSha256(value.activeSha256)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "activation pending字段错误");
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(PENDING_MAGIC);
            output.writeInt(FORMAT_VERSION);
            output.writeLong(value.targetEnforcementEpoch);
            output.writeLong(value.createdAt);
            output.writeShort(operation.length);
            output.write(operation);
            output.write(decodeHex(value.activeSha256));
            output.flush();
            byte[] payload = bytes.toByteArray();
            output.write(sha256(payload));
            output.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory encoding failed", impossible);
        }
    }

    private static ActivationPending decodePending(byte[] encoded) {
        final int fixedLength = 8 + 4 + 8 * 2 + 2 + 32 + 32;
        if (encoded.length < fixedLength || !startsWith(encoded, PENDING_MAGIC)
                || ByteBuffer.wrap(encoded, 8, 4).getInt() != FORMAT_VERSION
                || !validRecordDigest(encoded)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "activation pending格式错误");
        }
        ByteBuffer source = ByteBuffer.wrap(encoded);
        source.position(12);
        long epoch = source.getLong();
        long createdAt = source.getLong();
        int operationLength = source.getShort() & 0xffff;
        if (operationLength <= 0 || operationLength > MassDbLicenseState.MAX_IDEMPOTENCY_KEY_BYTES
                || encoded.length != fixedLength + operationLength) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "activation pending长度错误");
        }
        byte[] operation = new byte[operationLength];
        source.get(operation);
        byte[] sha = new byte[32];
        source.get(sha);
        if (!isPrintableAscii(operation) || epoch <= 0 || createdAt <= 0) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "activation pending字段错误");
        }
        return new ActivationPending(new String(operation, StandardCharsets.US_ASCII),
                epoch, encodeHex(sha), createdAt);
    }

    private static byte[] encodeLicensePending(LicensePending value) {
        byte[] operation = value == null || value.operationId == null ? new byte[0]
                : value.operationId.getBytes(StandardCharsets.US_ASCII);
        if (value == null || operation.length == 0
                || operation.length > MassDbLicenseState.MAX_IDEMPOTENCY_KEY_BYTES
                || !isPrintableAscii(operation) || value.createdAt <= 0
                || value.expiresAt <= value.createdAt || value.enforcementEpoch < 0
                || value.artifact.length == 0
                || value.artifact.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                || !isSha256(value.contentSha256)
                || !MessageDigest.isEqual(sha256(value.artifact),
                        decodeHex(value.contentSha256))) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "license pending字段错误");
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(LICENSE_PENDING_MAGIC);
            output.writeInt(FORMAT_VERSION);
            output.writeLong(value.enforcementEpoch);
            output.writeLong(value.createdAt);
            output.writeLong(value.expiresAt);
            output.writeShort(operation.length);
            output.write(operation);
            output.write(decodeHex(value.contentSha256));
            output.writeInt(value.artifact.length);
            output.write(value.artifact);
            output.flush();
            byte[] payload = bytes.toByteArray();
            output.write(sha256(payload));
            output.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory encoding failed", impossible);
        }
    }

    private static LicensePending decodeLicensePending(byte[] encoded) {
        final int fixedLength = 8 + 4 + 8 * 3 + 2 + 32 + 4 + 32;
        if (encoded.length < fixedLength || !startsWith(encoded, LICENSE_PENDING_MAGIC)
                || ByteBuffer.wrap(encoded, 8, 4).getInt() != FORMAT_VERSION
                || !validRecordDigest(encoded)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "license pending格式错误");
        }
        ByteBuffer source = ByteBuffer.wrap(encoded);
        source.position(12);
        long epoch = source.getLong();
        long createdAt = source.getLong();
        long expiresAt = source.getLong();
        int operationLength = source.getShort() & 0xffff;
        if (operationLength <= 0
                || operationLength > MassDbLicenseState.MAX_IDEMPOTENCY_KEY_BYTES
                || encoded.length <= fixedLength + operationLength) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "license pending operation长度错误");
        }
        byte[] operation = new byte[operationLength];
        source.get(operation);
        byte[] sha = new byte[32];
        source.get(sha);
        int artifactLength = source.getInt();
        if (artifactLength <= 0 || artifactLength > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                || encoded.length != fixedLength + operationLength + artifactLength) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "license pending工件长度错误");
        }
        byte[] artifact = new byte[artifactLength];
        source.get(artifact);
        if (!isPrintableAscii(operation) || epoch < 0 || createdAt <= 0
                || expiresAt <= createdAt
                || !MessageDigest.isEqual(sha256(artifact), sha)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "license pending字段错误");
        }
        return new LicensePending(new String(operation, StandardCharsets.US_ASCII),
                artifact, encodeHex(sha), expiresAt, epoch, createdAt);
    }

    private static byte[] encodeControlPending(ControlPending value) {
        validateControlPending(value, false);
        try {
            byte[] payload = CONTROL_MAPPER.writeValueAsBytes(value);
            if (payload.length == 0 || payload.length > MAX_LOCAL_RECORD_BYTES - 48) {
                fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "keyset pending JSON编码过大");
            }
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(CONTROL_PENDING_MAGIC);
            output.writeInt(FORMAT_VERSION);
            output.writeInt(payload.length);
            output.write(payload);
            output.flush();
            byte[] unsigned = bytes.toByteArray();
            output.write(sha256(unsigned));
            output.flush();
            return bytes.toByteArray();
        } catch (IOException error) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "keyset pending JSON编码失败");
            return null;
        }
    }

    private static ControlPending decodeControlPending(byte[] encoded) {
        final int fixedLength = 8 + 4 + 4 + 32;
        if (encoded.length < fixedLength || !startsWith(encoded, CONTROL_PENDING_MAGIC)
                || ByteBuffer.wrap(encoded, 8, 4).getInt() != FORMAT_VERSION
                || !validRecordDigest(encoded)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "keyset pending格式错误");
        }
        int payloadLength = ByteBuffer.wrap(encoded, 12, 4).getInt();
        if (payloadLength <= 0 || payloadLength > MAX_LOCAL_RECORD_BYTES - fixedLength
                || encoded.length != fixedLength + payloadLength) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "keyset pending长度错误");
        }
        try {
            ControlPending value = CONTROL_MAPPER.readValue(
                    encoded, 16, payloadLength, ControlPending.class);
            validateControlPending(value, true);
            return value.normalizedCopy();
        } catch (IOException | MassDbLicenseException error) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "keyset pending字段错误");
            return null;
        }
    }

    private static void validateControlPending(ControlPending value, boolean fromDisk) {
        byte[] operation = value == null || value.operationId == null ? new byte[0]
                : value.operationId.getBytes(StandardCharsets.US_ASCII);
        boolean bundle = value != null && value.kind
                == MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE;
        boolean kindValid = value != null && (value.kind
                == MassDbLicenseState.MutationKind.ADDITIVE_KEYSET
                || value.kind == MassDbLicenseState.MutationKind.RESTRICTIVE_KEYSET
                || bundle);
        boolean licenseAbsent = value != null
                && (value.licenseArtifact == null || value.licenseArtifact.length == 0)
                && value.licenseSha256 == null && value.licenseExpiresAt == 0;
        boolean licenseValid = value != null && value.licenseArtifact != null
                && value.licenseArtifact.length > 0
                && value.licenseArtifact.length <= MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                && isSha256(value.licenseSha256)
                && MessageDigest.isEqual(sha256(value.licenseArtifact),
                        decodeHex(value.licenseSha256))
                && value.licenseExpiresAt > value.createdAt;
        if (value == null || !kindValid || operation.length == 0
                || operation.length > MassDbLicenseState.MAX_IDEMPOTENCY_KEY_BYTES
                || !isPrintableAscii(operation) || value.createdAt <= 0
                || value.keysetVersion <= 0 || value.enforcementEpoch < 0
                || value.keysetArtifact == null || value.keysetArtifact.length == 0
                || value.keysetArtifact.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                || !isSha256(value.keysetSha256)
                || !MessageDigest.isEqual(sha256(value.keysetArtifact),
                        decodeHex(value.keysetSha256))
                || bundle && !licenseValid || !bundle && !licenseAbsent) {
            fail(fromDisk ? "MASSDB_LICENSE_LOCAL_STATE_CORRUPT"
                    : "MASSDB_LICENSE_LOCAL_STATE_INVALID", "keyset pending字段非法");
        }
    }

    private static byte[] encodeIdentityConflict(IdentityConflictSnapshot value) {
        validateIdentityConflict(value);
        byte[] deployment = value.deploymentUuid.getBytes(StandardCharsets.US_ASCII);
        byte[] role = value.role.getBytes(StandardCharsets.US_ASCII);
        byte[] node = value.nodeUuid.getBytes(StandardCharsets.US_ASCII);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(IDENTITY_CONFLICT_MAGIC);
            output.writeInt(FORMAT_VERSION);
            output.writeByte(value.active ? 1 : 0);
            output.writeLong(value.controlPlaneRevision);
            writeShortAscii(output, deployment);
            writeShortAscii(output, role);
            writeShortAscii(output, node);
            output.writeLong(value.detectedAt);
            output.writeLong(value.lastObservedAt);
            output.writeLong(value.clearEligibleAt);
            output.writeLong(value.resolvedAt);
            output.flush();
            byte[] payload = bytes.toByteArray();
            output.write(sha256(payload));
            output.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory encoding failed", impossible);
        }
    }

    private static IdentityConflictSnapshot decodeIdentityConflict(byte[] encoded) {
        final int minimumLength = 8 + 4 + 1 + 8 + 2 * 3 + 36 * 2 + 2 + 8 * 4 + 32;
        if (encoded.length < minimumLength || !startsWith(encoded, IDENTITY_CONFLICT_MAGIC)
                || ByteBuffer.wrap(encoded, 8, 4).getInt() != FORMAT_VERSION
                || !validRecordDigest(encoded)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "重复node UUID标记格式错误");
        }
        try {
            ByteBuffer source = ByteBuffer.wrap(encoded, 0, encoded.length - 32);
            source.position(12);
            byte active = source.get();
            if (active != 0 && active != 1) {
                fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "重复node UUID标记状态错误");
            }
            long revision = source.getLong();
            String deployment = readShortAscii(source);
            String role = readShortAscii(source);
            String node = readShortAscii(source);
            long detectedAt = source.getLong();
            long lastObservedAt = source.getLong();
            long clearEligibleAt = source.getLong();
            long resolvedAt = source.getLong();
            if (source.hasRemaining()) {
                fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "重复node UUID标记包含尾随字段");
            }
            IdentityConflictSnapshot result = new IdentityConflictSnapshot(active == 1,
                    revision, deployment, role, node, detectedAt, lastObservedAt,
                    clearEligibleAt, resolvedAt);
            validateIdentityConflict(result);
            return result;
        } catch (RuntimeException error) {
            if (error instanceof MassDbLicenseException
                    && "MASSDB_LICENSE_LOCAL_STATE_CORRUPT".equals(
                            ((MassDbLicenseException) error).getCode())) {
                throw error;
            }
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "重复node UUID标记字段错误");
            return null;
        }
    }

    private static byte[] encodeControlPlaneCheckpoint(ControlPlaneCheckpoint value) {
        validateControlPlaneCheckpoint(value);
        try {
            byte[] payload = CONTROL_MAPPER.writeValueAsBytes(value);
            if (payload.length == 0 || payload.length > MAX_LOCAL_RECORD_BYTES - 80) {
                fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "控制面检查点JSON编码过大");
            }
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(CONTROL_MAGIC);
            output.writeInt(FORMAT_VERSION);
            output.writeInt(payload.length);
            output.write(payload);
            output.flush();
            byte[] unsigned = bytes.toByteArray();
            output.write(sha256(unsigned));
            output.flush();
            return bytes.toByteArray();
        } catch (IOException error) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "控制面检查点JSON编码失败");
            return null;
        }
    }

    private static ControlPlaneCheckpoint decodeControlPlaneCheckpoint(byte[] encoded) {
        final int fixedLength = 8 + 4 + 4 + 32;
        if (encoded.length < fixedLength || !startsWith(encoded, CONTROL_MAGIC)
                || ByteBuffer.wrap(encoded, 8, 4).getInt() != FORMAT_VERSION
                || !validRecordDigest(encoded)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "控制面检查点格式错误");
        }
        int payloadLength = ByteBuffer.wrap(encoded, 12, 4).getInt();
        if (payloadLength <= 0 || payloadLength > MAX_LOCAL_RECORD_BYTES - fixedLength
                || encoded.length != fixedLength + payloadLength) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "控制面检查点长度错误");
        }
        try {
            ControlPlaneCheckpoint value = CONTROL_MAPPER.readValue(
                    encoded, 16, payloadLength, ControlPlaneCheckpoint.class);
            validateControlPlaneCheckpoint(value);
            return value;
        } catch (IOException | MassDbLicenseException error) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "控制面检查点字段错误");
            return null;
        }
    }

    private static void validateControlPlaneCheckpoint(ControlPlaneCheckpoint value) {
        boolean keysetPresent = value != null && (value.activeKeysetVersion != 0
                || value.activeKeysetSha256 != null
                || value.activeKeysetArtifact != null && value.activeKeysetArtifact.length != 0);
        boolean licensePresent = value != null && (value.activeLicenseSha256 != null
                || value.activeLicenseExpiresAt != 0);
        if (value == null || !isCanonicalVersion4Uuid(value.deploymentUuid)
                || value.controlPlaneRevision <= 0 || !"fe".equals(value.role)
                || !isCanonicalVersion4Uuid(value.nodeUuid)
                || value.enforcementMode == null
                || value.enforcementMode == MassDbLicenseState.EnforcementMode.UNINITIALIZED
                || value.enforcementEpoch < 0 || value.clockRecoveryEpoch < 0
                || value.clockRecoveryEpoch != value.recoverySequence
                || value.authenticatedAtWallClock <= 0 || value.leaderObservedAt <= 0
                || value.committedMaxSeenWallClock < 0
                || value.lastVerifiedEffectiveNow < value.committedMaxSeenWallClock
                || value.lastVerifiedEffectiveNow < value.authenticatedAtWallClock
                || value.lastVerifiedEffectiveNow < value.leaderObservedAt
                || value.maxControlPlaneStalenessSeconds
                        != MassDbLicenseState.DEFAULT_CONTROL_PLANE_STALENESS_SECONDS
                || keysetPresent && (value.activeKeysetVersion <= 0
                        || !isSha256(value.activeKeysetSha256)
                        || value.activeKeysetArtifact == null
                        || value.activeKeysetArtifact.length == 0
                        || value.activeKeysetArtifact.length
                                > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES)
                || !keysetPresent && licensePresent
                || licensePresent && (!isSha256(value.activeLicenseSha256)
                        || value.activeLicenseExpiresAt <= 0)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "控制面检查点字段非法");
        }
        if (keysetPresent && !MessageDigest.isEqual(sha256(value.activeKeysetArtifact),
                decodeHex(value.activeKeysetSha256))) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "控制面keyset摘要不匹配");
        }
    }

    private static void validateIdentityConflict(IdentityConflictSnapshot value) {
        boolean activeValid = value != null && value.active && value.detectedAt > 0
                && value.lastObservedAt >= value.detectedAt
                && value.clearEligibleAt == saturatedAdd(value.lastObservedAt,
                        MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS)
                && value.resolvedAt == 0;
        boolean resolvedValid = value != null && !value.active && value.detectedAt > 0
                && value.lastObservedAt >= value.detectedAt
                && value.clearEligibleAt == saturatedAdd(value.lastObservedAt,
                        MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS)
                && value.resolvedAt >= value.clearEligibleAt;
        if (value == null || value.controlPlaneRevision <= 0
                || !isCanonicalVersion4Uuid(value.deploymentUuid)
                || !"fe".equals(value.role)
                || !isCanonicalVersion4Uuid(value.nodeUuid)
                || !activeValid && !resolvedValid) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "重复node UUID标记字段非法");
        }
    }

    private static void writeShortAscii(DataOutputStream output, byte[] value) throws IOException {
        if (value.length == 0 || value.length > 128 || !isPrintableAscii(value)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "重复node UUID标记文本字段非法");
        }
        output.writeShort(value.length);
        output.write(value);
    }

    private static String readShortAscii(ByteBuffer source) {
        int length = source.getShort() & 0xffff;
        if (length <= 0 || length > 128 || source.remaining() < length) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "重复node UUID标记文本长度错误");
        }
        byte[] value = new byte[length];
        source.get(value);
        if (!isPrintableAscii(value)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_CORRUPT", "重复node UUID标记文本字段错误");
        }
        return new String(value, StandardCharsets.US_ASCII);
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static boolean validRecordDigest(byte[] encoded) {
        int digestOffset = encoded.length - 32;
        return digestOffset > 0 && MessageDigest.isEqual(
                sha256(Arrays.copyOf(encoded, digestOffset)),
                Arrays.copyOfRange(encoded, digestOffset, encoded.length));
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    private static boolean startsWith(byte[] value, byte[] prefix) {
        return value.length >= prefix.length
                && MessageDigest.isEqual(Arrays.copyOf(value, prefix.length), prefix);
    }

    private static boolean isPrintableAscii(byte[] value) {
        for (byte item : value) {
            if ((item & 0xff) < 0x21 || (item & 0xff) > 0x7e) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSha256(String value) {
        return value != null && value.matches("[0-9a-fA-F]{64}");
    }

    private static String normalizeSha256(String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    private static byte[] decodeHex(String value) {
        if (!isSha256(value)) {
            fail("MASSDB_LICENSE_LOCAL_STATE_INVALID", "SHA-256格式错误");
        }
        byte[] result = new byte[32];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    private static String encodeHex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return result.toString();
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    /** Last chain-authenticated FE Master authority used for offline query decisions. */
    public static final class ControlPlaneCheckpoint {
        public String deploymentUuid;
        public long controlPlaneRevision;
        public String role;
        public String nodeUuid;
        public long activeKeysetVersion;
        public String activeKeysetSha256;
        public byte[] activeKeysetArtifact;
        public String activeLicenseSha256;
        public long activeLicenseExpiresAt;
        public MassDbLicenseState.EnforcementMode enforcementMode;
        public long enforcementEpoch;
        public long clockRecoveryEpoch;
        public long recoverySequence;
        public long committedMaxSeenWallClock;
        public long lastVerifiedEffectiveNow;
        public long authenticatedAtWallClock;
        public long leaderObservedAt;
        public long maxControlPlaneStalenessSeconds;

        public ControlPlaneCheckpoint() {
        }

        public ControlPlaneCheckpoint(String deploymentUuid, long controlPlaneRevision,
                String role, String nodeUuid, long activeKeysetVersion,
                String activeKeysetSha256, byte[] activeKeysetArtifact,
                String activeLicenseSha256, long activeLicenseExpiresAt,
                MassDbLicenseState.EnforcementMode enforcementMode, long enforcementEpoch,
                long clockRecoveryEpoch, long recoverySequence,
                long committedMaxSeenWallClock, long lastVerifiedEffectiveNow,
                long authenticatedAtWallClock, long leaderObservedAt,
                long maxControlPlaneStalenessSeconds) {
            this.deploymentUuid = deploymentUuid;
            this.controlPlaneRevision = controlPlaneRevision;
            this.role = role;
            this.nodeUuid = nodeUuid;
            this.activeKeysetVersion = activeKeysetVersion;
            this.activeKeysetSha256 = normalizeSha256(activeKeysetSha256);
            this.activeKeysetArtifact = activeKeysetArtifact == null
                    ? new byte[0] : activeKeysetArtifact.clone();
            this.activeLicenseSha256 = normalizeSha256(activeLicenseSha256);
            this.activeLicenseExpiresAt = activeLicenseExpiresAt;
            this.enforcementMode = enforcementMode;
            this.enforcementEpoch = enforcementEpoch;
            this.clockRecoveryEpoch = clockRecoveryEpoch;
            this.recoverySequence = recoverySequence;
            this.committedMaxSeenWallClock = committedMaxSeenWallClock;
            this.lastVerifiedEffectiveNow = lastVerifiedEffectiveNow;
            this.authenticatedAtWallClock = authenticatedAtWallClock;
            this.leaderObservedAt = leaderObservedAt;
            this.maxControlPlaneStalenessSeconds = maxControlPlaneStalenessSeconds;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof ControlPlaneCheckpoint)) {
                return false;
            }
            ControlPlaneCheckpoint value = (ControlPlaneCheckpoint) other;
            return controlPlaneRevision == value.controlPlaneRevision
                    && activeKeysetVersion == value.activeKeysetVersion
                    && activeLicenseExpiresAt == value.activeLicenseExpiresAt
                    && enforcementEpoch == value.enforcementEpoch
                    && clockRecoveryEpoch == value.clockRecoveryEpoch
                    && recoverySequence == value.recoverySequence
                    && committedMaxSeenWallClock == value.committedMaxSeenWallClock
                    && lastVerifiedEffectiveNow == value.lastVerifiedEffectiveNow
                    && authenticatedAtWallClock == value.authenticatedAtWallClock
                    && leaderObservedAt == value.leaderObservedAt
                    && maxControlPlaneStalenessSeconds
                            == value.maxControlPlaneStalenessSeconds
                    && Objects.equals(deploymentUuid, value.deploymentUuid)
                    && Objects.equals(role, value.role)
                    && Objects.equals(nodeUuid, value.nodeUuid)
                    && Objects.equals(activeKeysetSha256, value.activeKeysetSha256)
                    && Arrays.equals(activeKeysetArtifact, value.activeKeysetArtifact)
                    && Objects.equals(activeLicenseSha256, value.activeLicenseSha256)
                    && enforcementMode == value.enforcementMode;
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(deploymentUuid, controlPlaneRevision, role, nodeUuid,
                    activeKeysetVersion, activeKeysetSha256, activeLicenseSha256,
                    activeLicenseExpiresAt, enforcementMode, enforcementEpoch,
                    clockRecoveryEpoch, recoverySequence, committedMaxSeenWallClock,
                    lastVerifiedEffectiveNow, authenticatedAtWallClock, leaderObservedAt,
                    maxControlPlaneStalenessSeconds);
            return 31 * result + Arrays.hashCode(activeKeysetArtifact);
        }
    }

    public static final class RoleRuntimeSnapshot {
        public final ActiveSnapshot active;
        public final ActivationPending activationPending;
        public final LicensePending licensePending;
        public final ControlPending controlPending;
        public final ControlPlaneCheckpoint checkpoint;
        public final IdentityConflictSnapshot identityConflict;

        private RoleRuntimeSnapshot(ActiveSnapshot active, ActivationPending activationPending,
                LicensePending licensePending, ControlPending controlPending,
                ControlPlaneCheckpoint checkpoint,
                IdentityConflictSnapshot identityConflict) {
            this.active = active;
            this.activationPending = activationPending;
            this.licensePending = licensePending;
            this.controlPending = controlPending;
            this.checkpoint = checkpoint;
            this.identityConflict = identityConflict;
        }
    }

    public static final class ActiveSnapshot {
        public final byte[] artifact;
        public final String sha256;
        public final long expiresAt;
        public final long enforcementEpoch;
        public final long writtenAt;

        public ActiveSnapshot(byte[] artifact, String sha256, long expiresAt,
                long enforcementEpoch, long writtenAt) {
            this.artifact = artifact == null ? new byte[0] : artifact.clone();
            this.sha256 = normalizeSha256(sha256);
            this.expiresAt = expiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.writtenAt = writtenAt;
        }
    }

    public static final class ActivationPending {
        public final String operationId;
        public final long targetEnforcementEpoch;
        public final String activeSha256;
        public final long createdAt;

        public ActivationPending(String operationId, long targetEnforcementEpoch,
                String activeSha256, long createdAt) {
            this.operationId = operationId;
            this.targetEnforcementEpoch = targetEnforcementEpoch;
            this.activeSha256 = normalizeSha256(activeSha256);
            this.createdAt = createdAt;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof ActivationPending)) {
                return false;
            }
            ActivationPending value = (ActivationPending) other;
            return Objects.equals(operationId, value.operationId)
                    && targetEnforcementEpoch == value.targetEnforcementEpoch
                    && Objects.equals(activeSha256, value.activeSha256) && createdAt == value.createdAt;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(new Object[] {
                    operationId, targetEnforcementEpoch, activeSha256, createdAt});
        }
    }

    public static final class LicensePending {
        public final String operationId;
        public final byte[] artifact;
        public final String contentSha256;
        public final long expiresAt;
        public final long enforcementEpoch;
        public final long createdAt;

        public LicensePending(String operationId, byte[] artifact, String contentSha256,
                long expiresAt, long enforcementEpoch, long createdAt) {
            this.operationId = operationId;
            this.artifact = artifact == null ? new byte[0] : artifact.clone();
            this.contentSha256 = normalizeSha256(contentSha256);
            this.expiresAt = expiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.createdAt = createdAt;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof LicensePending)) {
                return false;
            }
            LicensePending value = (LicensePending) other;
            return Objects.equals(operationId, value.operationId)
                    && Arrays.equals(artifact, value.artifact)
                    && Objects.equals(contentSha256, value.contentSha256)
                    && expiresAt == value.expiresAt
                    && enforcementEpoch == value.enforcementEpoch
                    && createdAt == value.createdAt;
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(operationId, contentSha256, expiresAt,
                    enforcementEpoch, createdAt);
            return 31 * result + Arrays.hashCode(artifact);
        }
    }

    /** Durable role-side validation record for keyset and recovery-bundle operations. */
    public static final class ControlPending {
        public String operationId;
        public MassDbLicenseState.MutationKind kind;
        public byte[] keysetArtifact;
        public String keysetSha256;
        public long keysetVersion;
        public byte[] licenseArtifact;
        public String licenseSha256;
        public long licenseExpiresAt;
        public long enforcementEpoch;
        public long createdAt;

        public ControlPending() {
        }

        public ControlPending(String operationId, MassDbLicenseState.MutationKind kind,
                byte[] keysetArtifact, String keysetSha256, long keysetVersion,
                byte[] licenseArtifact, String licenseSha256, long licenseExpiresAt,
                long enforcementEpoch, long createdAt) {
            this.operationId = operationId;
            this.kind = kind;
            this.keysetArtifact = keysetArtifact == null ? new byte[0] : keysetArtifact.clone();
            this.keysetSha256 = normalizeSha256(keysetSha256);
            this.keysetVersion = keysetVersion;
            this.licenseArtifact = licenseArtifact == null
                    ? new byte[0] : licenseArtifact.clone();
            this.licenseSha256 = normalizeSha256(licenseSha256);
            this.licenseExpiresAt = licenseExpiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.createdAt = createdAt;
        }

        private ControlPending normalizedCopy() {
            return new ControlPending(operationId, kind, keysetArtifact, keysetSha256,
                    keysetVersion, licenseArtifact, licenseSha256, licenseExpiresAt,
                    enforcementEpoch, createdAt);
        }

        public boolean failClosed() {
            return kind == MassDbLicenseState.MutationKind.RESTRICTIVE_KEYSET
                    || kind == MassDbLicenseState.MutationKind.KEYSET_LICENSE_RECOVERY_BUNDLE;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof ControlPending)) {
                return false;
            }
            ControlPending value = (ControlPending) other;
            return Objects.equals(operationId, value.operationId) && kind == value.kind
                    && Arrays.equals(keysetArtifact, value.keysetArtifact)
                    && Objects.equals(keysetSha256, value.keysetSha256)
                    && keysetVersion == value.keysetVersion
                    && Arrays.equals(licenseArtifact, value.licenseArtifact)
                    && Objects.equals(licenseSha256, value.licenseSha256)
                    && licenseExpiresAt == value.licenseExpiresAt
                    && enforcementEpoch == value.enforcementEpoch
                    && createdAt == value.createdAt;
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(operationId, kind, keysetSha256, keysetVersion,
                    licenseSha256, licenseExpiresAt, enforcementEpoch, createdAt);
            result = 31 * result + Arrays.hashCode(keysetArtifact);
            return 31 * result + Arrays.hashCode(licenseArtifact);
        }
    }

    public static final class IdentityConflictSnapshot {
        public final boolean active;
        public final long controlPlaneRevision;
        public final String deploymentUuid;
        public final String role;
        public final String nodeUuid;
        public final long detectedAt;
        public final long lastObservedAt;
        public final long clearEligibleAt;
        public final long resolvedAt;

        public IdentityConflictSnapshot(boolean active, long controlPlaneRevision,
                String deploymentUuid, String role, String nodeUuid, long detectedAt,
                long lastObservedAt, long clearEligibleAt, long resolvedAt) {
            this.active = active;
            this.controlPlaneRevision = controlPlaneRevision;
            this.deploymentUuid = deploymentUuid;
            this.role = role;
            this.nodeUuid = nodeUuid;
            this.detectedAt = detectedAt;
            this.lastObservedAt = lastObservedAt;
            this.clearEligibleAt = clearEligibleAt;
            this.resolvedAt = resolvedAt;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof IdentityConflictSnapshot)) {
                return false;
            }
            IdentityConflictSnapshot value = (IdentityConflictSnapshot) other;
            return active == value.active
                    && controlPlaneRevision == value.controlPlaneRevision
                    && Objects.equals(deploymentUuid, value.deploymentUuid)
                    && Objects.equals(role, value.role)
                    && Objects.equals(nodeUuid, value.nodeUuid)
                    && detectedAt == value.detectedAt
                    && lastObservedAt == value.lastObservedAt
                    && clearEligibleAt == value.clearEligibleAt
                    && resolvedAt == value.resolvedAt;
        }

        @Override
        public int hashCode() {
            return Objects.hash(active, controlPlaneRevision, deploymentUuid, role, nodeUuid,
                    detectedAt, lastObservedAt, clearEligibleAt, resolvedAt);
        }
    }

    public static final class QueryDecision {
        public final boolean allowed;
        public final String errorCode;

        private QueryDecision(boolean allowed, String errorCode) {
            this.allowed = allowed;
            this.errorCode = errorCode;
        }

        public static QueryDecision allow() {
            return new QueryDecision(true, null);
        }

        public static QueryDecision deny(String errorCode) {
            return new QueryDecision(false, errorCode);
        }
    }

    public static final class ActivationAck {
        public final String nodeUuid;
        public final String operationId;
        public final long targetEnforcementEpoch;
        public final String activeSha256;
        public final String pendingSnapshotSha256;

        private ActivationAck(String nodeUuid, String operationId,
                long targetEnforcementEpoch, String activeSha256,
                String pendingSnapshotSha256) {
            this.nodeUuid = nodeUuid;
            this.operationId = operationId;
            this.targetEnforcementEpoch = targetEnforcementEpoch;
            this.activeSha256 = activeSha256;
            this.pendingSnapshotSha256 = pendingSnapshotSha256;
        }
    }

    public static final class LicenseAck {
        public final String nodeUuid;
        public final String operationId;
        public final String contentSha256;
        public final long licenseExpiresAt;
        public final long enforcementEpoch;
        public final String pendingSnapshotSha256;

        private LicenseAck(String nodeUuid, String operationId,
                String contentSha256, long licenseExpiresAt, long enforcementEpoch,
                String pendingSnapshotSha256) {
            this.nodeUuid = nodeUuid;
            this.operationId = operationId;
            this.contentSha256 = contentSha256;
            this.licenseExpiresAt = licenseExpiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.pendingSnapshotSha256 = pendingSnapshotSha256;
        }
    }

    public static final class ControlAck {
        public final String nodeUuid;
        public final String operationId;
        public final String keysetSha256;
        public final long keysetVersion;
        public final String licenseSha256;
        public final long licenseExpiresAt;
        public final String pendingSnapshotSha256;

        private ControlAck(String nodeUuid, String operationId, String keysetSha256,
                long keysetVersion, String licenseSha256, long licenseExpiresAt,
                String pendingSnapshotSha256) {
            this.nodeUuid = nodeUuid;
            this.operationId = operationId;
            this.keysetSha256 = keysetSha256;
            this.keysetVersion = keysetVersion;
            this.licenseSha256 = licenseSha256;
            this.licenseExpiresAt = licenseExpiresAt;
            this.pendingSnapshotSha256 = pendingSnapshotSha256;
        }
    }
}
