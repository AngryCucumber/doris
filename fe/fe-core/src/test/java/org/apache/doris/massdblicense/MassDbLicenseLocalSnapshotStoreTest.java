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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Map;

class MassDbLicenseLocalSnapshotStoreTest {
    private static final long NOW = 1_767_225_600L;

    @TempDir
    Path directory;

    @Test
    void pendingSurvivesRestartAndRequiresMatchingDecision() throws Exception {
        byte[] artifact = "signed-license-artifact".getBytes(StandardCharsets.US_ASCII);
        String sha256 = encodeHex(MessageDigest.getInstance("SHA-256").digest(artifact));
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(directory);
        store.writeActive(new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                artifact, sha256, NOW + 3600, 4, NOW));
        MassDbLicenseLocalSnapshotStore.ActivationPending pending =
                new MassDbLicenseLocalSnapshotStore.ActivationPending(
                        "activation-operation", 5, sha256, NOW + 1);
        MassDbLicenseLocalSnapshotStore.ActivationAck ack =
                store.prepareActivationAck(pending);
        Assertions.assertEquals(store.getNodeUuid(), ack.nodeUuid);
        Assertions.assertEquals(pending.operationId, ack.operationId);
        Assertions.assertEquals(pending.targetEnforcementEpoch, ack.targetEnforcementEpoch);
        Assertions.assertEquals(sha256, ack.activeSha256);
        Assertions.assertEquals(64, ack.pendingSnapshotSha256.length());
        Assertions.assertEquals("MASSDB_LICENSE_ACTIVATION_PENDING",
                store.evaluateQuery(MassDbLicenseState.EnforcementMode.OBSERVE, NOW + 2).errorCode);
        MassDbLicenseException replace = Assertions.assertThrows(MassDbLicenseException.class,
                () -> store.writeActive(new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                        artifact, sha256, NOW + 7200, 4, NOW + 2)));
        Assertions.assertEquals("MASSDB_LICENSE_OPERATION_IN_PROGRESS", replace.getCode());

        MassDbLicenseLocalSnapshotStore restarted =
                new MassDbLicenseLocalSnapshotStore(directory);
        Assertions.assertEquals(store.getNodeUuid(), restarted.getNodeUuid());
        Assertions.assertEquals("MASSDB_LICENSE_ACTIVATION_PENDING",
                restarted.evaluateQuery(
                        MassDbLicenseState.EnforcementMode.OBSERVE, NOW + 2).errorCode);
        MassDbLicenseException wrong = Assertions.assertThrows(MassDbLicenseException.class,
                () -> restarted.abortActivation("wrong-operation"));
        Assertions.assertEquals("MASSDB_LICENSE_PRECONDITION_FAILED", wrong.getCode());

        restarted.commitActivation("activation-operation", 5, NOW + 3);
        Assertions.assertNull(restarted.loadPending());
        Assertions.assertEquals(5, restarted.loadActive().enforcementEpoch);
        Assertions.assertTrue(restarted.evaluateQuery(
                MassDbLicenseState.EnforcementMode.ENFORCING, NOW + 4).allowed);

        restarted.beginActivationPending(
                new MassDbLicenseLocalSnapshotStore.ActivationPending(
                        "activation-abort", 6, sha256, NOW + 5));
        restarted.abortActivation("activation-abort");
        Assertions.assertEquals(5, restarted.loadActive().enforcementEpoch);
        Assertions.assertEquals(EnumSet.of(PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE),
                Files.getPosixFilePermissions(directory.resolve("active.snapshot")));
        Assertions.assertEquals(EnumSet.of(PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
                Files.getPosixFilePermissions(directory));
    }

    @Test
    void corruptPendingFailsClosedEvenInObserve() throws Exception {
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(directory);
        Files.write(directory.resolve("activation.pending"),
                "corrupt".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertEquals("MASSDB_LICENSE_LOCAL_STATE_CORRUPT",
                store.evaluateQuery(MassDbLicenseState.EnforcementMode.OBSERVE, NOW).errorCode);
    }

    @Test
    void normalPendingNeverSelfActivatesAndSurvivesRestart() throws Exception {
        byte[] oldArtifact = "old-signed-license".getBytes(StandardCharsets.US_ASCII);
        String oldSha = encodeHex(MessageDigest.getInstance("SHA-256").digest(oldArtifact));
        byte[] candidate = "new-signed-license".getBytes(StandardCharsets.US_ASCII);
        String candidateSha = encodeHex(MessageDigest.getInstance("SHA-256").digest(candidate));
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(directory);
        store.writeActive(new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                oldArtifact, oldSha, NOW + 3600, 4, NOW));
        MassDbLicenseLocalSnapshotStore.LicensePending pending =
                new MassDbLicenseLocalSnapshotStore.LicensePending(
                        "normal-operation", candidate, candidateSha,
                        NOW + 7200, 4, NOW + 1);
        MassDbLicenseLocalSnapshotStore.LicenseAck ack =
                store.prepareLicenseAck(pending);
        Assertions.assertEquals(store.getNodeUuid(), ack.nodeUuid);
        Assertions.assertEquals("normal-operation", ack.operationId);
        Assertions.assertEquals(candidateSha, ack.contentSha256);
        Assertions.assertEquals(64, ack.pendingSnapshotSha256.length());
        Assertions.assertEquals(oldSha, store.loadActive().sha256);
        Assertions.assertTrue(store.evaluateQuery(
                MassDbLicenseState.EnforcementMode.ENFORCING, NOW + 2).allowed);

        MassDbLicenseLocalSnapshotStore restarted =
                new MassDbLicenseLocalSnapshotStore(directory);
        Assertions.assertEquals(candidateSha,
                restarted.loadLicensePending().contentSha256);
        MassDbLicenseException conflicting = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> restarted.beginActivationPending(
                        new MassDbLicenseLocalSnapshotStore.ActivationPending(
                                "enforce", 5, oldSha, NOW + 2)));
        Assertions.assertEquals("MASSDB_LICENSE_OPERATION_IN_PROGRESS", conflicting.getCode());
        restarted.commitLicense("normal-operation", candidateSha, NOW + 3);
        Assertions.assertNull(restarted.loadLicensePending());
        Assertions.assertEquals(candidateSha, restarted.loadActive().sha256);
        Assertions.assertEquals(4, restarted.loadActive().enforcementEpoch);

        MassDbLicenseLocalSnapshotStore.LicensePending aborted =
                new MassDbLicenseLocalSnapshotStore.LicensePending(
                        "normal-abort", oldArtifact, oldSha, NOW + 9000, 4, NOW + 4);
        restarted.beginLicensePending(aborted);
        restarted.abortLicense("normal-abort");
        Assertions.assertNull(restarted.loadLicensePending());
        Assertions.assertEquals(candidateSha, restarted.loadActive().sha256);

        byte[] goldenArtifact = new byte[] {1, 2, 3};
        String goldenSha = encodeHex(MessageDigest.getInstance("SHA-256")
                .digest(goldenArtifact));
        MassDbLicenseLocalSnapshotStore goldenStore =
                new MassDbLicenseLocalSnapshotStore(directory.resolve("golden"));
        MassDbLicenseLocalSnapshotStore.LicenseAck goldenAck = goldenStore.prepareLicenseAck(
                new MassDbLicenseLocalSnapshotStore.LicensePending(
                        "normal-op", goldenArtifact, goldenSha, 2_000, 4, 1_000));
        Assertions.assertEquals(
                "188ce51ece3096154a304c3ba397847df172937aff8ca768d235137e60e7e235",
                goldenAck.pendingSnapshotSha256);
    }

    @Test
    void nodeIdentityIsStableAndCannotBeSuppliedByAckPayload() throws Exception {
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(directory);
        String nodeUuid = store.getNodeUuid();
        Assertions.assertEquals(nodeUuid,
                new MassDbLicenseLocalSnapshotStore(directory).getNodeUuid());
        Assertions.assertEquals(EnumSet.of(PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE),
                Files.getPosixFilePermissions(directory.resolve("node-uuid")));

        byte[] artifact = new byte[] {1, 2, 3};
        String sha256 = encodeHex(MessageDigest.getInstance("SHA-256").digest(artifact));
        store.writeActive(new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                artifact, sha256, NOW + 3600, 0, NOW));
        MassDbLicenseLocalSnapshotStore.ActivationAck ack = store.prepareActivationAck(
                new MassDbLicenseLocalSnapshotStore.ActivationPending(
                        "activation", 1, sha256, NOW + 1));
        Assertions.assertEquals(nodeUuid, ack.nodeUuid);

        Files.write(directory.resolve("node-uuid"), "not-a-uuid".getBytes(StandardCharsets.US_ASCII));
        MassDbLicenseException corrupt = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> new MassDbLicenseLocalSnapshotStore(directory));
        Assertions.assertEquals("MASSDB_LICENSE_NODE_IDENTITY_INVALID", corrupt.getCode());
    }

    @Test
    void existingInsecureDirectoryFailsClosedInsteadOfBeingRepaired() throws Exception {
        Path insecureDirectory = Files.createDirectory(directory.resolve("insecure-directory"));
        Files.setPosixFilePermissions(insecureDirectory,
                PosixFilePermissions.fromString("rwxr-xr-x"));

        MassDbLicenseException error = Assertions.assertThrows(MassDbLicenseException.class,
                () -> new MassDbLicenseLocalSnapshotStore(insecureDirectory));
        Assertions.assertEquals("MASSDB_LICENSE_NODE_IDENTITY_INVALID", error.getCode());
        Assertions.assertEquals(PosixFilePermissions.fromString("rwxr-xr-x"),
                Files.getPosixFilePermissions(insecureDirectory));
    }

    @Test
    void startupReverifiesRawActiveArtifact() {
        Map<String, PublicKey> roots = Collections.singletonMap(
                "massdb-test-root-1", MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.ROOT_PUBLIC)));
        MassDbLicenseProtocolV1.VerifiedKeyset keyset = MassDbLicenseProtocolV1.verifyKeyset(
                MassDbLicenseProtocolV1Test.decode(MassDbLicenseProtocolV1Test.KEYSET),
                roots, NOW, null);
        byte[] license = MassDbLicenseProtocolV1Test.decode(
                MassDbLicenseProtocolV1Test.VALID_LICENSE);
        MassDbLicenseProtocolV1.VerifiedLicense verified =
                MassDbLicenseProtocolV1.verifyLicense(license, keyset, NOW, 31_536_000L, null);
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(directory);
        store.writeActive(new MassDbLicenseLocalSnapshotStore.ActiveSnapshot(
                license, verified.getSha256(), verified.getPayload().getExpiresAt(), 1, NOW));
        Assertions.assertEquals(verified.getSha256(),
                store.verifyActive(keyset, NOW, 31_536_000L).getSha256());
    }

    @Test
    void identityConflictPersistsAcrossRestartAndRequiresNewerSafeClear() throws Exception {
        String deploymentUuid = "00000000-0000-4000-8000-000000000041";
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(directory);
        MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot active =
                new MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot(
                        true, 3, deploymentUuid, "fe", store.getNodeUuid(), NOW, NOW,
                        NOW + MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS, 0);
        store.applyIdentityConflict(active);
        Assertions.assertEquals(active, store.loadIdentityConflict());
        Assertions.assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(directory.resolve("identity-conflict.snapshot")));
        Assertions.assertEquals("MASSDB_LICENSE_DUPLICATE_NODE_UUID",
                store.evaluateQuery(MassDbLicenseState.EnforcementMode.OBSERVE, NOW).errorCode);

        byte[] candidate = new byte[] {1, 2, 3};
        String candidateSha = encodeHex(MessageDigest.getInstance("SHA-256").digest(candidate));
        MassDbLicenseException blocked = Assertions.assertThrows(MassDbLicenseException.class,
                () -> store.prepareLicenseAck(
                        new MassDbLicenseLocalSnapshotStore.LicensePending(
                                "blocked", candidate, candidateSha, NOW + 3_600, 0, NOW)));
        Assertions.assertEquals("MASSDB_LICENSE_DUPLICATE_NODE_UUID", blocked.getCode());

        MassDbLicenseLocalSnapshotStore restarted =
                new MassDbLicenseLocalSnapshotStore(directory);
        Assertions.assertEquals(active, restarted.loadIdentityConflict());
        MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot early =
                new MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot(
                        false, 4, deploymentUuid, "fe", store.getNodeUuid(), NOW, NOW,
                        NOW + MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS,
                        NOW + MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS - 1);
        MassDbLicenseException invalid = Assertions.assertThrows(MassDbLicenseException.class,
                () -> restarted.applyIdentityConflict(early));
        Assertions.assertEquals("MASSDB_LICENSE_LOCAL_STATE_INVALID", invalid.getCode());

        MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot resolved =
                new MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot(
                        false, 4, deploymentUuid, "fe", store.getNodeUuid(), NOW, NOW,
                        NOW + MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS,
                        NOW + MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS);
        restarted.applyIdentityConflict(resolved);
        Assertions.assertTrue(restarted.evaluateQuery(
                MassDbLicenseState.EnforcementMode.OBSERVE, NOW).allowed);
        MassDbLicenseException stale = Assertions.assertThrows(MassDbLicenseException.class,
                () -> restarted.applyIdentityConflict(active));
        Assertions.assertEquals("MASSDB_LICENSE_PRECONDITION_FAILED", stale.getCode());

        Files.write(directory.resolve("identity-conflict.snapshot"),
                "corrupt".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertEquals("MASSDB_LICENSE_LOCAL_STATE_CORRUPT",
                restarted.evaluateQuery(
                        MassDbLicenseState.EnforcementMode.OBSERVE, NOW).errorCode);
        MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot repaired =
                new MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot(
                        true, 5, deploymentUuid, "fe", store.getNodeUuid(), NOW + 100,
                        NOW + 100,
                        NOW + 100 + MassDbLicenseState.DEFAULT_ROLE_LIVE_LEASE_SECONDS, 0);
        restarted.applyIdentityConflict(repaired);
        Assertions.assertEquals(repaired, restarted.loadIdentityConflict());
    }

    @Test
    void restrictiveKeysetPendingSurvivesRestartAndClearsOnlyAfterAuthoritySync()
            throws Exception {
        byte[] keyset = "root-signed-keyset-v2".getBytes(StandardCharsets.US_ASCII);
        String keysetSha = encodeHex(MessageDigest.getInstance("SHA-256").digest(keyset));
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(directory);
        MassDbLicenseLocalSnapshotStore.ControlPending pending =
                new MassDbLicenseLocalSnapshotStore.ControlPending(
                        "keyset-operation",
                        MassDbLicenseState.MutationKind.RESTRICTIVE_KEYSET,
                        keyset, keysetSha, 2, null, null, 0, 4, NOW + 1);
        MassDbLicenseLocalSnapshotStore.ControlAck ack = store.prepareControlAck(pending);
        Assertions.assertEquals(store.getNodeUuid(), ack.nodeUuid);
        Assertions.assertEquals(keysetSha, ack.keysetSha256);
        Assertions.assertEquals(2, ack.keysetVersion);
        Assertions.assertEquals("MASSDB_LICENSE_KEYSET_RECOVERY_PENDING",
                store.evaluateQuery(MassDbLicenseState.EnforcementMode.OBSERVE,
                        NOW + 2).errorCode);

        MassDbLicenseLocalSnapshotStore restarted =
                new MassDbLicenseLocalSnapshotStore(directory);
        Assertions.assertEquals(ack.pendingSnapshotSha256,
                restarted.loadControlAck().pendingSnapshotSha256);
        MassDbLicenseException early = Assertions.assertThrows(MassDbLicenseException.class,
                () -> restarted.finishControlPending("keyset-operation", true));
        Assertions.assertEquals("MASSDB_LICENSE_PRECONDITION_FAILED", early.getCode());

        String deploymentUuid = "00000000-0000-4000-8000-000000000051";
        restarted.applyControlPlaneCheckpoint(
                new MassDbLicenseLocalSnapshotStore.ControlPlaneCheckpoint(
                        deploymentUuid, 2, "fe", restarted.getNodeUuid(), 2,
                        keysetSha, keyset, null, 0,
                        MassDbLicenseState.EnforcementMode.OBSERVE, 4, 0, 0,
                        NOW, NOW + 2, NOW + 2, NOW + 2,
                        MassDbLicenseState.DEFAULT_CONTROL_PLANE_STALENESS_SECONDS),
                null);
        restarted.finishControlPending("keyset-operation", true);
        Assertions.assertNull(restarted.loadControlPending());
        Assertions.assertTrue(restarted.evaluateQuery(
                MassDbLicenseState.EnforcementMode.OBSERVE, NOW + 3).allowed);
    }

    private static String encodeHex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return result.toString();
    }
}
