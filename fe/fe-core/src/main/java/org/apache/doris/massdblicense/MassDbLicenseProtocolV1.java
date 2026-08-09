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
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Dependency-free Java 8 verifier for the frozen MassDB License protocol v1.
 *
 * <p>This is component runtime code, not an issuer. It accepts deterministic CBOR only, requires
 * COSE_Sign1 tag 18 with protected ES256/kid headers, validates the sealed root-signed keyset, and
 * verifies .mlic, .mclock and atomic keyset+License recovery bundles.</p>
 */
public final class MassDbLicenseProtocolV1 {
    public static final long FORMAT_VERSION = 1;
    public static final String PRODUCT = "MASSDB";
    public static final String KEYSET_TYPE = "MASSDB_TRUSTED_KEYSET";
    public static final String CLOCK_RECOVERY_TYPE = "MASSDB_CLOCK_RECOVERY";
    public static final String RECOVERY_BUNDLE_TYPE = "MASSDB_KEYSET_LICENSE_RECOVERY_BUNDLE";
    public static final String IDENTITY_PACKAGE_TYPE = "MASSDB_IDENTITY_PACKAGE";
    public static final long ISSUED_AT_FUTURE_TOLERANCE_SECONDS = 300;
    public static final long MAX_CLOCK_RECOVERY_TERM_SECONDS = 259_200;
    public static final long MAX_IDENTITY_TERM_SECONDS = 2_592_000;
    public static final int MAX_ARTIFACT_BYTES = 65_536;

    private static final int KIND_UNSIGNED = 0;
    private static final int KIND_NEGATIVE = 1;
    private static final int KIND_BYTES = 2;
    private static final int KIND_TEXT = 3;
    private static final int KIND_ARRAY = 4;
    private static final int KIND_MAP = 5;
    private static final int KIND_TAG = 6;

    private MassDbLicenseProtocolV1() {
    }

    public enum KeyUse {
        LICENSE_SIGNING,
        CLOCK_RECOVERY
    }

    public static final class License {
        private final long formatVersion;
        private final String licenseId;
        private final String product;
        private final long issuedAt;
        private final long expiresAt;

        private License(long formatVersion, String licenseId, String product,
                long issuedAt, long expiresAt) {
            this.formatVersion = formatVersion;
            this.licenseId = licenseId;
            this.product = product;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
        }

        public long getFormatVersion() {
            return formatVersion;
        }

        public String getLicenseId() {
            return licenseId;
        }

        public String getProduct() {
            return product;
        }

        public long getIssuedAt() {
            return issuedAt;
        }

        public long getExpiresAt() {
            return expiresAt;
        }
    }

    public static final class TrustedKey {
        private final String kid;
        private final KeyUse use;
        private final PublicKey publicKey;
        private final byte[] x;
        private final byte[] y;

        private TrustedKey(String kid, KeyUse use, PublicKey publicKey, byte[] x, byte[] y) {
            this.kid = kid;
            this.use = use;
            this.publicKey = publicKey;
            this.x = x.clone();
            this.y = y.clone();
        }

        public String getKid() {
            return kid;
        }

        public KeyUse getUse() {
            return use;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public byte[] getX() {
            return x.clone();
        }

        public byte[] getY() {
            return y.clone();
        }
    }

    public static final class TrustedKeyset {
        private final long keysetVersion;
        private final long issuedAt;
        private final Map<String, TrustedKey> keys;
        private final Set<String> revokedKids;

        private TrustedKeyset(long keysetVersion, long issuedAt,
                Map<String, TrustedKey> keys, Set<String> revokedKids) {
            this.keysetVersion = keysetVersion;
            this.issuedAt = issuedAt;
            this.keys = Collections.unmodifiableMap(new LinkedHashMap<>(keys));
            this.revokedKids = Collections.unmodifiableSet(new HashSet<>(revokedKids));
        }

        public long getKeysetVersion() {
            return keysetVersion;
        }

        public long getIssuedAt() {
            return issuedAt;
        }

        public Map<String, TrustedKey> getKeys() {
            return keys;
        }

        public Set<String> getRevokedKids() {
            return revokedKids;
        }
    }

    public static final class VerifiedKeyset {
        private final TrustedKeyset payload;
        private final String rootKid;
        private final String sha256;

        private VerifiedKeyset(TrustedKeyset payload, String rootKid, String sha256) {
            this.payload = payload;
            this.rootKid = rootKid;
            this.sha256 = sha256;
        }

        public TrustedKeyset getPayload() {
            return payload;
        }

        public String getRootKid() {
            return rootKid;
        }

        public String getSha256() {
            return sha256;
        }

        private TrustedKey requireKey(String kid, KeyUse use) {
            if (payload.revokedKids.contains(kid)) {
                fail("MASSDB_LICENSE_SIGNATURE_INVALID", "kid已被keyset吊销");
            }
            TrustedKey key = payload.keys.get(kid);
            if (key == null || key.use != use) {
                fail("MASSDB_LICENSE_SIGNATURE_INVALID", "kid不存在或用途不匹配");
            }
            return key;
        }
    }

    public static final class VerifiedLicense {
        private final License payload;
        private final String kid;
        private final String sha256;

        private VerifiedLicense(License payload, String kid, String sha256) {
            this.payload = payload;
            this.kid = kid;
            this.sha256 = sha256;
        }

        public License getPayload() {
            return payload;
        }

        public String getKid() {
            return kid;
        }

        public String getSha256() {
            return sha256;
        }
    }

    public static final class ClockRecovery {
        private final long recoverySequence;
        private final byte[] challenge;
        private final String deploymentUuid;
        private final byte[] activeLicenseSha256;
        private final long observedMaxSeenWallClock;
        private final long resetMaxSeenWallClockTo;
        private final long issuedAt;
        private final long artifactExpiresAt;

        private ClockRecovery(long recoverySequence, byte[] challenge, String deploymentUuid,
                byte[] activeLicenseSha256, long observedMaxSeenWallClock,
                long resetMaxSeenWallClockTo, long issuedAt, long artifactExpiresAt) {
            this.recoverySequence = recoverySequence;
            this.challenge = challenge.clone();
            this.deploymentUuid = deploymentUuid;
            this.activeLicenseSha256 = activeLicenseSha256.clone();
            this.observedMaxSeenWallClock = observedMaxSeenWallClock;
            this.resetMaxSeenWallClockTo = resetMaxSeenWallClockTo;
            this.issuedAt = issuedAt;
            this.artifactExpiresAt = artifactExpiresAt;
        }

        public long getRecoverySequence() {
            return recoverySequence;
        }

        public long getObservedMaxSeenWallClock() {
            return observedMaxSeenWallClock;
        }

        public long getResetMaxSeenWallClockTo() {
            return resetMaxSeenWallClockTo;
        }

        public long getIssuedAt() {
            return issuedAt;
        }

        public long getArtifactExpiresAt() {
            return artifactExpiresAt;
        }
    }

    public static final class ClockContext {
        private final byte[] challenge;
        private final String deploymentUuid;
        private final byte[] activeLicenseSha256;
        private final long observedMaxSeenWallClock;
        private final long maxAcceptedSequence;
        private final long currentWallClock;

        public ClockContext(byte[] challenge, String deploymentUuid, byte[] activeLicenseSha256,
                long observedMaxSeenWallClock, long maxAcceptedSequence, long currentWallClock) {
            if (challenge == null || activeLicenseSha256 == null || deploymentUuid == null) {
                fail("MASSDB_LICENSE_FILE_INVALID", "Clock recovery上下文不能为空");
            }
            this.challenge = challenge.clone();
            this.deploymentUuid = deploymentUuid;
            this.activeLicenseSha256 = activeLicenseSha256.clone();
            this.observedMaxSeenWallClock = observedMaxSeenWallClock;
            this.maxAcceptedSequence = maxAcceptedSequence;
            this.currentWallClock = currentWallClock;
        }
    }

    public static final class VerifiedClockRecovery {
        private final ClockRecovery payload;
        private final String kid;
        private final String sha256;

        private VerifiedClockRecovery(ClockRecovery payload, String kid, String sha256) {
            this.payload = payload;
            this.kid = kid;
            this.sha256 = sha256;
        }

        public ClockRecovery getPayload() {
            return payload;
        }

        public String getKid() {
            return kid;
        }

        public String getSha256() {
            return sha256;
        }
    }

    public static final class VerifiedRecoveryBundle {
        private final VerifiedKeyset keyset;
        private final VerifiedLicense license;
        private final byte[] keysetArtifact;
        private final byte[] licenseArtifact;
        private final String sha256;

        private VerifiedRecoveryBundle(VerifiedKeyset keyset, VerifiedLicense license,
                byte[] keysetArtifact, byte[] licenseArtifact, String sha256) {
            this.keyset = keyset;
            this.license = license;
            this.keysetArtifact = keysetArtifact.clone();
            this.licenseArtifact = licenseArtifact.clone();
            this.sha256 = sha256;
        }

        public VerifiedKeyset getKeyset() {
            return keyset;
        }

        public VerifiedLicense getLicense() {
            return license;
        }

        public byte[] getKeysetArtifact() {
            return keysetArtifact.clone();
        }

        public byte[] getLicenseArtifact() {
            return licenseArtifact.clone();
        }

        public String getSha256() {
            return sha256;
        }
    }

    /** Signed transport identity package. It never contains the node private key. */
    public static final class IdentityPackage {
        private final long generation;
        private final long issuedAt;
        private final long notBefore;
        private final long notAfter;
        private final String component;
        private final String deploymentUuid;
        private final String role;
        private final String nodeUuid;
        private final byte[] csrSha256;
        private final String leafCertificatePem;
        private final List<String> chainPem;
        private final List<String> trustBundles;
        private final List<String> revocations;

        private IdentityPackage(long generation, long issuedAt, long notBefore, long notAfter,
                String component, String deploymentUuid, String role, String nodeUuid,
                byte[] csrSha256, String leafCertificatePem, List<String> chainPem,
                List<String> trustBundles, List<String> revocations) {
            this.generation = generation;
            this.issuedAt = issuedAt;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.component = component;
            this.deploymentUuid = deploymentUuid;
            this.role = role;
            this.nodeUuid = nodeUuid;
            this.csrSha256 = csrSha256.clone();
            this.leafCertificatePem = leafCertificatePem;
            this.chainPem = Collections.unmodifiableList(new ArrayList<>(chainPem));
            this.trustBundles = Collections.unmodifiableList(new ArrayList<>(trustBundles));
            this.revocations = Collections.unmodifiableList(new ArrayList<>(revocations));
        }

        public long getGeneration() {
            return generation;
        }

        public long getIssuedAt() {
            return issuedAt;
        }

        public long getNotBefore() {
            return notBefore;
        }

        public long getNotAfter() {
            return notAfter;
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

        public byte[] getCsrSha256() {
            return csrSha256.clone();
        }

        public String getLeafCertificatePem() {
            return leafCertificatePem;
        }

        public List<String> getChainPem() {
            return chainPem;
        }

        public List<String> getTrustBundles() {
            return trustBundles;
        }

        public List<String> getRevocations() {
            return revocations;
        }
    }

    public static final class VerifiedIdentityPackage {
        private final IdentityPackage payload;
        private final String kid;
        private final String sha256;

        private VerifiedIdentityPackage(IdentityPackage payload, String kid, String sha256) {
            this.payload = payload;
            this.kid = kid;
            this.sha256 = sha256;
        }

        public IdentityPackage getPayload() {
            return payload;
        }

        public String getKid() {
            return kid;
        }

        public String getSha256() {
            return sha256;
        }
    }

    public static PublicKey parsePublicKeyPem(byte[] pem) {
        if (pem == null || pem.length == 0 || pem.length > 16_384) {
            fail("MASSDB_LICENSE_FILE_INVALID", "root公钥PEM为空或超过16384字节");
        }
        String text = new String(pem, StandardCharsets.US_ASCII).trim();
        String begin = "-----BEGIN PUBLIC KEY-----";
        String end = "-----END PUBLIC KEY-----";
        if (!text.startsWith(begin) || !text.endsWith(end)
                || text.indexOf(begin, begin.length()) >= 0) {
            fail("MASSDB_LICENSE_FILE_INVALID", "root公钥必须是单个PUBLIC KEY PEM");
        }
        String body = text.substring(begin.length(), text.length() - end.length())
                .replaceAll("\\s", "");
        try {
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(body)));
            requireP256(key);
            return key;
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            fail("MASSDB_LICENSE_FILE_INVALID", "root公钥无法解析");
            return null;
        }
    }

    public static VerifiedKeyset verifyKeyset(byte[] artifact, Map<String, PublicKey> roots,
            long effectiveNow, Long currentVersion) {
        if (roots == null) {
            fail("MASSDB_LICENSE_FILE_INVALID", "必须显式提供keyset root");
        }
        CoseMessage message = parseCose(artifact);
        PublicKey root = roots.get(message.kid);
        if (root == null) {
            fail("MASSDB_LICENSE_SIGNATURE_INVALID", "未知keyset root kid");
        }
        verifyCose(message, root);
        TrustedKeyset payload = decodeKeyset(message.payload);
        byte[] rootCoordinates = publicKeyCoordinates(root);
        for (TrustedKey key : payload.keys.values()) {
            if (Arrays.equals(rootCoordinates, concat(key.x, key.y))) {
                fail("MASSDB_LICENSE_FILE_INVALID", "keyset离线root不能复用为签发key");
            }
        }
        if (payload.issuedAt > saturatedAdd(effectiveNow, ISSUED_AT_FUTURE_TOLERANCE_SECONDS)) {
            fail("MASSDB_LICENSE_ISSUED_AT_IN_FUTURE", "keyset issuedAt超过未来容差");
        }
        if (currentVersion != null && payload.keysetVersion <= currentVersion) {
            fail("MASSDB_LICENSE_KEYSET_VERSION_NOT_INCREASED", "keysetVersion必须严格递增");
        }
        return new VerifiedKeyset(payload, message.kid, sha256Hex(artifact));
    }

    public static VerifiedLicense verifyLicense(byte[] artifact, VerifiedKeyset keyset,
            long effectiveNow, long maxTerm, Long currentExpiresAt) {
        if (keyset == null || maxTerm <= 0) {
            fail("MASSDB_LICENSE_FILE_INVALID", "必须提供keyset和显式最大期限");
        }
        CoseMessage message = parseCose(artifact);
        TrustedKey key = keyset.requireKey(message.kid, KeyUse.LICENSE_SIGNING);
        verifyCose(message, key.publicKey);
        License payload = decodeLicense(message.payload);
        if (payload.issuedAt > saturatedAdd(effectiveNow, ISSUED_AT_FUTURE_TOLERANCE_SECONDS)) {
            fail("MASSDB_LICENSE_ISSUED_AT_IN_FUTURE", "issuedAt超过未来容差");
        }
        if (payload.expiresAt - payload.issuedAt > maxTerm) {
            fail("MASSDB_LICENSE_TERM_EXCEEDED", "License期限超过目标上限");
        }
        if (effectiveNow >= payload.expiresAt) {
            fail("MASSDB_LICENSE_EXPIRED", "License已到期");
        }
        if (currentExpiresAt != null && payload.expiresAt <= currentExpiresAt) {
            fail("MASSDB_LICENSE_EXPIRY_NOT_EXTENDED", "NORMAL续期未严格延长");
        }
        return new VerifiedLicense(payload, message.kid, sha256Hex(artifact));
    }

    public static VerifiedClockRecovery verifyClockRecovery(byte[] artifact,
            VerifiedKeyset keyset, ClockContext context) {
        if (keyset == null || context == null) {
            fail("MASSDB_LICENSE_FILE_INVALID", "必须提供keyset和clock context");
        }
        CoseMessage message = parseCose(artifact);
        TrustedKey key = keyset.requireKey(message.kid, KeyUse.CLOCK_RECOVERY);
        verifyCose(message, key.publicKey);
        ClockRecovery payload = decodeClock(message.payload);
        if (context.currentWallClock < payload.issuedAt
                || context.currentWallClock > payload.artifactExpiresAt
                || payload.artifactExpiresAt - payload.issuedAt > MAX_CLOCK_RECOVERY_TERM_SECONDS) {
            fail("MASSDB_LICENSE_EXPIRED", "clock recovery工件不在有效窗口");
        }
        if (payload.recoverySequence <= context.maxAcceptedSequence) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_REPLAY", "recoverySequence已使用");
        }
        if (!Arrays.equals(payload.challenge, context.challenge)
                || !payload.deploymentUuid.equals(context.deploymentUuid)
                || !Arrays.equals(payload.activeLicenseSha256, context.activeLicenseSha256)
                || payload.observedMaxSeenWallClock != context.observedMaxSeenWallClock) {
            fail("MASSDB_LICENSE_CLOCK_RECOVERY_CONTEXT_MISMATCH", "clock recovery上下文不匹配");
        }
        return new VerifiedClockRecovery(payload, message.kid, sha256Hex(artifact));
    }

    public static VerifiedLicense verifyRecoveryBundle(byte[] artifact,
            Map<String, PublicKey> roots, long effectiveNow, long maxTerm, long currentVersion) {
        return verifyRecoveryBundleFull(artifact, roots, effectiveNow,
                maxTerm, currentVersion).getLicense();
    }

    public static VerifiedRecoveryBundle verifyRecoveryBundleFull(byte[] artifact,
            Map<String, PublicKey> roots, long effectiveNow, long maxTerm, long currentVersion) {
        Value root = decodeAll(artifact);
        Map<Long, Value> fields = exactMap(root, 1, 2, 3, 4);
        requireKind(fields.get(1L), KIND_UNSIGNED, "bundle version");
        requireKind(fields.get(2L), KIND_TEXT, "bundle type");
        requireKind(fields.get(3L), KIND_BYTES, "bundle keyset");
        requireKind(fields.get(4L), KIND_BYTES, "bundle License");
        if (fields.get(1L).number != FORMAT_VERSION
                || !RECOVERY_BUNDLE_TYPE.equals(fields.get(2L).text)) {
            fail("MASSDB_LICENSE_FILE_INVALID", "recovery bundle字段错误");
        }
        byte[] keysetArtifact = fields.get(3L).bytes;
        byte[] licenseArtifact = fields.get(4L).bytes;
        VerifiedKeyset keyset = verifyKeyset(
                keysetArtifact, roots, effectiveNow, currentVersion);
        VerifiedLicense license = verifyLicense(
                licenseArtifact, keyset, effectiveNow, maxTerm, null);
        return new VerifiedRecoveryBundle(keyset, license, keysetArtifact,
                licenseArtifact, sha256Hex(artifact));
    }

    /**
     * Verifies the dedicated Identity Artifact signature and its exact node/CSR binding.
     * Certificate-chain and local-private-key checks are intentionally performed by the
     * component identity store immediately before atomic activation.
     */
    public static VerifiedIdentityPackage verifyIdentityPackage(byte[] artifact,
            Map<String, PublicKey> identityArtifactRoots, long effectiveNow,
            Long currentGeneration, String expectedComponent, String expectedDeploymentUuid,
            String expectedRole, String expectedNodeUuid, byte[] expectedCsrSha256) {
        return verifyIdentityPackageInternal(artifact, identityArtifactRoots, effectiveNow,
                currentGeneration, expectedComponent, expectedDeploymentUuid, expectedRole,
                expectedNodeUuid, expectedCsrSha256, true);
    }

    /** Verifies signed local identity metadata for status even after its validity window ends. */
    static VerifiedIdentityPackage inspectIdentityPackage(byte[] artifact,
            Map<String, PublicKey> identityArtifactRoots,
            String expectedComponent, String expectedDeploymentUuid,
            String expectedRole, String expectedNodeUuid, byte[] expectedCsrSha256) {
        return verifyIdentityPackageInternal(artifact, identityArtifactRoots, 0, null,
                expectedComponent, expectedDeploymentUuid, expectedRole,
                expectedNodeUuid, expectedCsrSha256, false);
    }

    private static VerifiedIdentityPackage verifyIdentityPackageInternal(byte[] artifact,
            Map<String, PublicKey> identityArtifactRoots, long effectiveNow,
            Long currentGeneration, String expectedComponent, String expectedDeploymentUuid,
            String expectedRole, String expectedNodeUuid, byte[] expectedCsrSha256,
            boolean requireUsable) {
        if (identityArtifactRoots == null || identityArtifactRoots.isEmpty()
                || expectedCsrSha256 == null || expectedCsrSha256.length != 32) {
            fail("MASSDB_LICENSE_FILE_INVALID", "Identity Artifact root或CSR摘要未配置");
        }
        CoseMessage message = parseCose(artifact);
        PublicKey root = identityArtifactRoots.get(message.kid);
        if (root == null) {
            fail("MASSDB_LICENSE_SIGNATURE_INVALID", "未知Identity Artifact root kid");
        }
        verifyCose(message, root);
        IdentityPackage payload = decodeIdentityPackage(message.payload);
        if (!payload.component.equals(expectedComponent)
                || !payload.deploymentUuid.equals(expectedDeploymentUuid)
                || !payload.role.equals(expectedRole)
                || !payload.nodeUuid.equals(expectedNodeUuid)) {
            fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH", "身份包与组件本地CSR目标不匹配");
        }
        if (!Arrays.equals(payload.csrSha256, expectedCsrSha256)) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CSR_MISMATCH", "身份包CSR摘要与本地待激活CSR不匹配");
        }
        if (requireUsable) {
            if (payload.issuedAt > saturatedAdd(effectiveNow,
                    ISSUED_AT_FUTURE_TOLERANCE_SECONDS)
                    || payload.notBefore > saturatedAdd(
                            effectiveNow, ISSUED_AT_FUTURE_TOLERANCE_SECONDS)) {
                fail("MASSDB_LICENSE_ISSUED_AT_IN_FUTURE",
                        "身份包签发或生效时间超过未来容差");
            }
            if (effectiveNow >= payload.notAfter) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_EXPIRED", "身份包已过期");
            }
            if (currentGeneration != null && payload.generation <= currentGeneration) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_GENERATION_ROLLBACK",
                        "身份包generation必须严格递增");
            }
        }
        return new VerifiedIdentityPackage(payload, message.kid, sha256Hex(artifact));
    }

    private static License decodeLicense(byte[] payloadBytes) {
        Map<Long, Value> fields = exactMap(decodeAll(payloadBytes), 1, 2, 3, 4, 5);
        requireKind(fields.get(1L), KIND_UNSIGNED, "formatVersion");
        requireKind(fields.get(2L), KIND_TEXT, "licenseId");
        requireKind(fields.get(3L), KIND_TEXT, "product");
        requireKind(fields.get(4L), KIND_UNSIGNED, "issuedAt");
        requireKind(fields.get(5L), KIND_UNSIGNED, "expiresAt");
        License value = new License(fields.get(1L).number, fields.get(2L).text,
                fields.get(3L).text, fields.get(4L).number, fields.get(5L).number);
        if (value.formatVersion != FORMAT_VERSION || !canonicalUuid(value.licenseId)) {
            fail("MASSDB_LICENSE_FILE_INVALID", "License版本或licenseId错误");
        }
        if (!PRODUCT.equals(value.product)) {
            fail("MASSDB_LICENSE_PRODUCT_MISMATCH", "License product必须为MASSDB");
        }
        if (value.issuedAt >= value.expiresAt) {
            fail("MASSDB_LICENSE_FILE_INVALID", "必须满足issuedAt < expiresAt");
        }
        return value;
    }

    private static TrustedKeyset decodeKeyset(byte[] payloadBytes) {
        Map<Long, Value> fields = exactMap(decodeAll(payloadBytes), 1, 2, 3, 4, 5, 6, 7);
        requireKind(fields.get(1L), KIND_UNSIGNED, "keyset formatVersion");
        requireKind(fields.get(2L), KIND_TEXT, "keyset artifactType");
        requireKind(fields.get(3L), KIND_TEXT, "keyset product");
        requireKind(fields.get(4L), KIND_UNSIGNED, "keyset version");
        requireKind(fields.get(5L), KIND_UNSIGNED, "keyset issuedAt");
        requireKind(fields.get(6L), KIND_ARRAY, "keyset keys");
        requireKind(fields.get(7L), KIND_ARRAY, "keyset revokedKids");
        if (fields.get(1L).number != FORMAT_VERSION
                || !KEYSET_TYPE.equals(fields.get(2L).text)
                || !PRODUCT.equals(fields.get(3L).text)
                || fields.get(4L).number == 0 || fields.get(6L).array.isEmpty()) {
            fail("MASSDB_LICENSE_FILE_INVALID", "keyset固定字段错误");
        }
        Map<String, TrustedKey> keys = new LinkedHashMap<>();
        Set<String> revoked = new HashSet<>();
        Set<String> coordinates = new HashSet<>();
        String previousKid = "";
        for (Value row : fields.get(6L).array) {
            Map<Long, Value> keyFields = exactMap(row, 1, 2, 3, 4);
            requireKind(keyFields.get(1L), KIND_TEXT, "trusted key kid");
            requireKind(keyFields.get(2L), KIND_TEXT, "trusted key use");
            requireKind(keyFields.get(3L), KIND_BYTES, "trusted key x");
            requireKind(keyFields.get(4L), KIND_BYTES, "trusted key y");
            String kid = keyFields.get(1L).text;
            KeyUse use;
            try {
                use = KeyUse.valueOf(keyFields.get(2L).text);
            } catch (IllegalArgumentException e) {
                fail("MASSDB_LICENSE_FILE_INVALID", "trusted key用途错误");
                return null;
            }
            byte[] x = keyFields.get(3L).bytes;
            byte[] y = keyFields.get(4L).bytes;
            if (!printableAscii(kid) || kid.compareTo(previousKid) <= 0
                    || x.length != 32 || y.length != 32) {
                fail("MASSDB_LICENSE_FILE_INVALID", "trusted key顺序、kid或坐标错误");
            }
            String coordinateKey = hex(x) + hex(y);
            if (!coordinates.add(coordinateKey)) {
                fail("MASSDB_LICENSE_FILE_INVALID", "同一P-256公钥不能复用为不同kid或用途");
            }
            PublicKey publicKey = fromCoordinates(x, y);
            keys.put(kid, new TrustedKey(kid, use, publicKey, x, y));
            previousKid = kid;
        }
        previousKid = "";
        for (Value row : fields.get(7L).array) {
            requireKind(row, KIND_TEXT, "revoked kid");
            if (!printableAscii(row.text) || row.text.compareTo(previousKid) <= 0
                    || keys.containsKey(row.text)) {
                fail("MASSDB_LICENSE_FILE_INVALID", "revokedKids顺序或值错误");
            }
            revoked.add(row.text);
            previousKid = row.text;
        }
        return new TrustedKeyset(fields.get(4L).number, fields.get(5L).number, keys, revoked);
    }

    private static ClockRecovery decodeClock(byte[] payloadBytes) {
        Map<Long, Value> fields = exactMap(
                decodeAll(payloadBytes), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
        int[] uintKeys = {1, 4, 8, 9, 10, 11};
        for (int key : uintKeys) {
            requireKind(fields.get((long) key), KIND_UNSIGNED, "clock uint");
        }
        requireKind(fields.get(2L), KIND_TEXT, "clock type");
        requireKind(fields.get(3L), KIND_TEXT, "clock product");
        requireKind(fields.get(5L), KIND_BYTES, "clock challenge");
        requireKind(fields.get(6L), KIND_TEXT, "clock deployment");
        requireKind(fields.get(7L), KIND_BYTES, "clock active SHA");
        ClockRecovery value = new ClockRecovery(fields.get(4L).number, fields.get(5L).bytes,
                fields.get(6L).text, fields.get(7L).bytes, fields.get(8L).number,
                fields.get(9L).number, fields.get(10L).number, fields.get(11L).number);
        if (fields.get(1L).number != FORMAT_VERSION
                || !CLOCK_RECOVERY_TYPE.equals(fields.get(2L).text)
                || !PRODUCT.equals(fields.get(3L).text)
                || value.recoverySequence == 0 || value.challenge.length != 32
                || value.activeLicenseSha256.length != 32 || !canonicalUuid(value.deploymentUuid)
                || value.artifactExpiresAt <= value.issuedAt
                || value.resetMaxSeenWallClockTo < value.issuedAt
                || value.resetMaxSeenWallClockTo > value.artifactExpiresAt
                || value.resetMaxSeenWallClockTo >= value.observedMaxSeenWallClock) {
            fail("MASSDB_LICENSE_FILE_INVALID", "clock固定字段或时间边界错误");
        }
        return value;
    }

    private static IdentityPackage decodeIdentityPackage(byte[] payloadBytes) {
        Map<Long, Value> fields = exactMap(decodeAll(payloadBytes),
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
        int[] uintKeys = {1, 4, 5, 6, 7};
        for (int key : uintKeys) {
            requireKind(fields.get((long) key), KIND_UNSIGNED, "identity uint");
        }
        int[] textKeys = {2, 3, 8, 9, 10, 11, 13};
        for (int key : textKeys) {
            requireKind(fields.get((long) key), KIND_TEXT, "identity text");
        }
        requireKind(fields.get(12L), KIND_BYTES, "identity csrSha256");
        requireKind(fields.get(14L), KIND_ARRAY, "identity chainPem");
        requireKind(fields.get(15L), KIND_ARRAY, "identity trustBundles");
        requireKind(fields.get(16L), KIND_ARRAY, "identity revocations");
        List<String> chain = textArray(fields.get(14L), "identity chainPem", 8, false);
        List<String> trust = textArray(fields.get(15L), "identity trustBundles", 4, true);
        List<String> revocations = textArray(fields.get(16L), "identity revocations", 128, false);
        IdentityPackage value = new IdentityPackage(fields.get(4L).number,
                fields.get(5L).number, fields.get(6L).number, fields.get(7L).number,
                fields.get(8L).text, fields.get(9L).text, fields.get(10L).text,
                fields.get(11L).text, fields.get(12L).bytes, fields.get(13L).text,
                chain, trust, revocations);
        if (fields.get(1L).number != FORMAT_VERSION
                || !IDENTITY_PACKAGE_TYPE.equals(fields.get(2L).text)
                || !PRODUCT.equals(fields.get(3L).text)
                || value.generation == 0 || value.csrSha256.length != 32
                || value.issuedAt >= value.notAfter || value.notBefore >= value.notAfter
                || value.notAfter - value.notBefore > MAX_IDENTITY_TERM_SECONDS
                || value.leafCertificatePem.isEmpty()) {
            fail("MASSDB_LICENSE_FILE_INVALID", "身份包固定字段、期限或CSR摘要错误");
        }
        MassDbLicenseSpiffeIdentity.Identity identity = MassDbLicenseSpiffeIdentity.parse(
                "spiffe://" + MassDbLicenseSpiffeIdentity.TRUST_DOMAIN
                        + "/license/component/" + value.component + "/"
                        + value.deploymentUuid + "/" + value.role + "/" + value.nodeUuid);
        if (!identity.component.equals(value.component)
                || !identity.deploymentUuid.equals(value.deploymentUuid)
                || !identity.role.equals(value.role) || !identity.nodeUuid.equals(value.nodeUuid)) {
            fail("MASSDB_LICENSE_MTLS_IDENTITY_INVALID", "身份包SPIFFE字段错误");
        }
        String previous = "";
        for (String revoked : value.revocations) {
            if (revoked.compareTo(previous) <= 0) {
                fail("MASSDB_LICENSE_FILE_INVALID", "身份包revocations必须严格排序且不重复");
            }
            MassDbLicenseManagementIdentity.validateKnownIdentity(revoked);
            previous = revoked;
        }
        return value;
    }

    private static List<String> textArray(Value value, String label, int maximum,
            boolean requireNonEmpty) {
        if (value.array.size() > maximum || requireNonEmpty && value.array.isEmpty()) {
            fail("MASSDB_LICENSE_FILE_INVALID", label + "数量错误");
        }
        List<String> result = new ArrayList<>(value.array.size());
        for (Value item : value.array) {
            requireKind(item, KIND_TEXT, label);
            if (item.text.isEmpty()) {
                fail("MASSDB_LICENSE_FILE_INVALID", label + "包含空值");
            }
            result.add(item.text);
        }
        return result;
    }

    private static final class CoseMessage {
        private final String kid;
        private final byte[] protectedHeader;
        private final byte[] payload;
        private final byte[] signature;

        private CoseMessage(String kid, byte[] protectedHeader, byte[] payload, byte[] signature) {
            this.kid = kid;
            this.protectedHeader = protectedHeader;
            this.payload = payload;
            this.signature = signature;
        }
    }

    private static CoseMessage parseCose(byte[] artifact) {
        Value root = decodeAll(artifact);
        if (root.kind != KIND_TAG || root.number != 18 || root.child == null
                || root.child.kind != KIND_ARRAY || root.child.array.size() != 4) {
            fail("MASSDB_LICENSE_FILE_INVALID", "工件不是tag 18 COSE_Sign1");
        }
        List<Value> values = root.child.array;
        requireKind(values.get(0), KIND_BYTES, "protected header");
        requireKind(values.get(1), KIND_MAP, "unprotected header");
        requireKind(values.get(2), KIND_BYTES, "payload");
        requireKind(values.get(3), KIND_BYTES, "signature");
        if (!values.get(1).map.isEmpty() || values.get(3).bytes.length != 64) {
            fail("MASSDB_LICENSE_FILE_INVALID", "COSE_Sign1字段错误");
        }
        Map<Long, Value> protectedFields = exactMap(decodeAll(values.get(0).bytes), 1, 4);
        requireKind(protectedFields.get(1L), KIND_NEGATIVE, "COSE alg");
        requireKind(protectedFields.get(4L), KIND_BYTES, "COSE kid");
        String kid = strictUtf8(protectedFields.get(4L).bytes);
        if (protectedFields.get(1L).number != -7 || !printableAscii(kid) || kid.length() > 128) {
            fail("MASSDB_LICENSE_FILE_INVALID", "protected header必须包含alg=-7和kid");
        }
        return new CoseMessage(kid, values.get(0).bytes, values.get(2).bytes, values.get(3).bytes);
    }

    private static void verifyCose(CoseMessage message, PublicKey publicKey) {
        requireP256(publicKey);
        Value signatureStructure = Value.array(Arrays.asList(
                Value.text("Signature1"), Value.bytes(message.protectedHeader),
                Value.bytes(new byte[0]), Value.bytes(message.payload)));
        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(encode(signatureStructure));
            if (!verifier.verify(rawToDer(message.signature))) {
                fail("MASSDB_LICENSE_SIGNATURE_INVALID", "ES256签名验证失败");
            }
        } catch (MassDbLicenseException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            fail("MASSDB_LICENSE_SIGNATURE_INVALID", "ES256签名验证失败");
        }
    }

    private static final class Entry {
        private final Value key;
        private final Value value;

        private Entry(Value key, Value value) {
            this.key = key;
            this.value = value;
        }
    }

    private static final class Value {
        private int kind;
        private long number;
        private byte[] bytes;
        private String text;
        private List<Value> array;
        private List<Entry> map;
        private Value child;

        private static Value number(int kind, long number) {
            Value value = new Value();
            value.kind = kind;
            value.number = number;
            return value;
        }

        private static Value bytes(byte[] bytes) {
            Value value = new Value();
            value.kind = KIND_BYTES;
            value.bytes = bytes.clone();
            return value;
        }

        private static Value text(String text) {
            Value value = new Value();
            value.kind = KIND_TEXT;
            value.text = text;
            return value;
        }

        private static Value array(List<Value> values) {
            Value value = new Value();
            value.kind = KIND_ARRAY;
            value.array = values;
            return value;
        }
    }

    private static final class Decoder {
        private final byte[] data;
        private int offset;

        private Decoder(byte[] data) {
            this.data = data;
        }

        private Value read(int depth) {
            if (depth > 8 || offset >= data.length) {
                fail("MASSDB_LICENSE_FILE_INVALID", "CBOR深度超限或被截断");
            }
            int initial = data[offset++] & 0xff;
            int major = initial >>> 5;
            long argument = readArgument(initial & 0x1f);
            if (major == 0) {
                return Value.number(KIND_UNSIGNED, argument);
            }
            if (major == 1) {
                return Value.number(KIND_NEGATIVE, -1 - argument);
            }
            if (major == 2 || major == 3) {
                int maximum = major == 2 ? MAX_ARTIFACT_BYTES : 4096;
                if (argument > maximum || argument > data.length - offset) {
                    fail("MASSDB_LICENSE_FILE_INVALID", "CBOR字符串长度错误");
                }
                byte[] content = Arrays.copyOfRange(data, offset, offset + (int) argument);
                offset += (int) argument;
                if (major == 2) {
                    return Value.bytes(content);
                }
                return Value.text(strictUtf8(content));
            }
            if (major == 4) {
                if (argument > 128) {
                    fail("MASSDB_LICENSE_FILE_INVALID", "CBOR数组过长");
                }
                List<Value> items = new ArrayList<>((int) argument);
                for (int index = 0; index < argument; index++) {
                    items.add(read(depth + 1));
                }
                return Value.array(items);
            }
            if (major == 5) {
                if (argument > 128) {
                    fail("MASSDB_LICENSE_FILE_INVALID", "CBOR map过长");
                }
                Value value = new Value();
                value.kind = KIND_MAP;
                value.map = new ArrayList<>((int) argument);
                byte[] previous = null;
                for (int index = 0; index < argument; index++) {
                    int start = offset;
                    Value key = read(depth + 1);
                    byte[] encodedKey = Arrays.copyOfRange(data, start, offset);
                    if (previous != null && (previous.length > encodedKey.length
                            || (previous.length == encodedKey.length
                            && compareUnsigned(previous, encodedKey) >= 0))) {
                        fail("MASSDB_LICENSE_FILE_INVALID", "CBOR map key顺序或重复错误");
                    }
                    value.map.add(new Entry(key, read(depth + 1)));
                    previous = encodedKey;
                }
                return value;
            }
            if (major == 6) {
                Value value = Value.number(KIND_TAG, argument);
                value.child = read(depth + 1);
                return value;
            }
            fail("MASSDB_LICENSE_FILE_INVALID", "协议不允许该CBOR major type");
            return null;
        }

        private long readArgument(int additional) {
            if (additional < 24) {
                return additional;
            }
            int count;
            if (additional == 24) {
                count = 1;
            } else if (additional == 25) {
                count = 2;
            } else if (additional == 26) {
                count = 4;
            } else if (additional == 27) {
                count = 8;
            } else {
                fail("MASSDB_LICENSE_FILE_INVALID", "不允许indefinite CBOR");
                return 0;
            }
            if (offset + count > data.length || (count == 8 && (data[offset] & 0x80) != 0)) {
                fail("MASSDB_LICENSE_FILE_INVALID", "CBOR长度被截断或整数超出实现上限");
            }
            long result = 0;
            for (int index = 0; index < count; index++) {
                result = (result << 8) | (data[offset++] & 0xffL);
            }
            long minimum = count == 1 ? 24 : count == 2 ? 256
                    : count == 4 ? 65_536 : 4_294_967_296L;
            if (result < minimum) {
                fail("MASSDB_LICENSE_FILE_INVALID", "CBOR参数不是最短编码");
            }
            return result;
        }
    }

    private static Value decodeAll(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            fail("MASSDB_LICENSE_FILE_INVALID", "CBOR为空");
        }
        if (encoded.length > MAX_ARTIFACT_BYTES) {
            fail("MASSDB_LICENSE_FILE_TOO_LARGE", "工件超过65536字节");
        }
        Decoder decoder = new Decoder(encoded);
        Value value = decoder.read(0);
        if (decoder.offset != encoded.length || !Arrays.equals(encoded, encode(value))) {
            fail("MASSDB_LICENSE_FILE_INVALID", "CBOR存在尾随字节或不是deterministic编码");
        }
        return value;
    }

    private static byte[] encode(Value value) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        writeValue(output, value);
        return output.toByteArray();
    }

    private static void writeValue(ByteArrayOutputStream output, Value value) {
        if (value.kind == KIND_UNSIGNED) {
            writeHead(output, 0, value.number);
        } else if (value.kind == KIND_NEGATIVE) {
            writeHead(output, 1, -1 - value.number);
        } else if (value.kind == KIND_BYTES) {
            writeHead(output, 2, value.bytes.length);
            output.write(value.bytes, 0, value.bytes.length);
        } else if (value.kind == KIND_TEXT) {
            byte[] bytes = value.text.getBytes(StandardCharsets.UTF_8);
            writeHead(output, 3, bytes.length);
            output.write(bytes, 0, bytes.length);
        } else if (value.kind == KIND_ARRAY) {
            writeHead(output, 4, value.array.size());
            for (Value child : value.array) {
                writeValue(output, child);
            }
        } else if (value.kind == KIND_MAP) {
            List<Entry> entries = new ArrayList<>(value.map);
            Collections.sort(entries, new Comparator<Entry>() {
                @Override
                public int compare(Entry left, Entry right) {
                    byte[] leftBytes = encode(left.key);
                    byte[] rightBytes = encode(right.key);
                    if (leftBytes.length != rightBytes.length) {
                        return Integer.compare(leftBytes.length, rightBytes.length);
                    }
                    return compareUnsigned(leftBytes, rightBytes);
                }
            });
            writeHead(output, 5, entries.size());
            for (Entry entry : entries) {
                writeValue(output, entry.key);
                writeValue(output, entry.value);
            }
        } else if (value.kind == KIND_TAG) {
            writeHead(output, 6, value.number);
            writeValue(output, value.child);
        }
    }

    private static void writeHead(ByteArrayOutputStream output, int major, long argument) {
        if (argument < 24) {
            output.write((major << 5) | (int) argument);
        } else if (argument <= 0xffL) {
            output.write((major << 5) | 24);
            output.write((int) argument);
        } else if (argument <= 0xffffL) {
            output.write((major << 5) | 25);
            output.write((int) (argument >>> 8));
            output.write((int) argument);
        } else if (argument <= 0xffffffffL) {
            output.write((major << 5) | 26);
            for (int shift = 24; shift >= 0; shift -= 8) {
                output.write((int) (argument >>> shift));
            }
        } else {
            output.write((major << 5) | 27);
            for (int shift = 56; shift >= 0; shift -= 8) {
                output.write((int) (argument >>> shift));
            }
        }
    }

    private static Map<Long, Value> exactMap(Value value, long... keys) {
        if (value.kind != KIND_MAP || value.map.size() != keys.length) {
            fail("MASSDB_LICENSE_FILE_INVALID", "payload字段数量错误");
        }
        Set<Long> expected = new HashSet<>();
        for (long key : keys) {
            expected.add(key);
        }
        Map<Long, Value> result = new HashMap<>();
        for (Entry entry : value.map) {
            if (entry.key.kind != KIND_UNSIGNED || !expected.contains(entry.key.number)) {
                fail("MASSDB_LICENSE_FILE_INVALID", "payload key未知或类型错误");
            }
            result.put(entry.key.number, entry.value);
        }
        return result;
    }

    private static void requireKind(Value value, int kind, String field) {
        if (value == null || value.kind != kind) {
            fail("MASSDB_LICENSE_FILE_INVALID", field + "字段类型错误");
        }
    }

    private static PublicKey fromCoordinates(byte[] x, byte[] y) {
        try {
            ECParameterSpec parameters = p256Parameters();
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                    new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), parameters));
            requireP256(key);
            return key;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            fail("MASSDB_LICENSE_FILE_INVALID", "trusted key坐标不在P-256曲线");
            return null;
        }
    }

    private static void requireP256(PublicKey key) {
        if (!(key instanceof ECKey)) {
            fail("MASSDB_LICENSE_SIGNATURE_INVALID", "公钥不是有效P-256");
        }
        ECParameterSpec actual = ((ECKey) key).getParams();
        try {
            ECParameterSpec expected = p256Parameters();
            if (!actual.getCurve().equals(expected.getCurve())
                    || !actual.getGenerator().equals(expected.getGenerator())
                    || !actual.getOrder().equals(expected.getOrder())
                    || actual.getCofactor() != expected.getCofactor()) {
                fail("MASSDB_LICENSE_SIGNATURE_INVALID", "公钥不是有效P-256");
            }
        } catch (GeneralSecurityException e) {
            fail("MASSDB_LICENSE_SIGNATURE_INVALID", "无法确认P-256参数");
        }
    }

    private static ECParameterSpec p256Parameters() throws GeneralSecurityException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] publicKeyCoordinates(PublicKey key) {
        if (!(key instanceof java.security.interfaces.ECPublicKey)) {
            fail("MASSDB_LICENSE_FILE_INVALID", "root公钥必须是P-256");
        }
        java.security.interfaces.ECPublicKey ec = (java.security.interfaces.ECPublicKey) key;
        return concat(fixed32(ec.getW().getAffineX()), fixed32(ec.getW().getAffineY()));
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] encoded = value.toByteArray();
        int first = encoded.length == 33 && encoded[0] == 0 ? 1 : 0;
        if (encoded.length - first > 32) {
            fail("MASSDB_LICENSE_FILE_INVALID", "P-256坐标超长");
        }
        byte[] result = new byte[32];
        System.arraycopy(encoded, first, result, 32 - (encoded.length - first), encoded.length - first);
        return result;
    }

    private static byte[] rawToDer(byte[] raw) {
        if (raw.length != 64) {
            fail("MASSDB_LICENSE_SIGNATURE_INVALID", "ES256签名必须是64字节raw R||S");
        }
        byte[] r = derInteger(Arrays.copyOfRange(raw, 0, 32));
        byte[] s = derInteger(Arrays.copyOfRange(raw, 32, 64));
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        content.write(0x02);
        content.write(r.length);
        content.write(r, 0, r.length);
        content.write(0x02);
        content.write(s.length);
        content.write(s, 0, s.length);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x30);
        result.write(content.size());
        byte[] contentBytes = content.toByteArray();
        result.write(contentBytes, 0, contentBytes.length);
        return result.toByteArray();
    }

    private static byte[] derInteger(byte[] fixed) {
        int first = 0;
        while (first < fixed.length - 1 && fixed[first] == 0) {
            first++;
        }
        byte[] value = Arrays.copyOfRange(fixed, first, fixed.length);
        if ((value[0] & 0x80) != 0) {
            byte[] positive = new byte[value.length + 1];
            System.arraycopy(value, 0, positive, 1, value.length);
            return positive;
        }
        return value;
    }

    private static String strictUtf8(byte[] bytes) {
        try {
            CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes));
            return decoded.toString();
        } catch (CharacterCodingException e) {
            fail("MASSDB_LICENSE_FILE_INVALID", "CBOR文本不是UTF-8");
            return null;
        }
    }

    private static int compareUnsigned(byte[] left, byte[] right) {
        for (int index = 0; index < left.length; index++) {
            int result = Integer.compare(left[index] & 0xff, right[index] & 0xff);
            if (result != 0) {
                return result;
            }
        }
        return 0;
    }

    private static boolean printableAscii(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        if (!value.equals(new String(bytes, StandardCharsets.US_ASCII))) {
            return false;
        }
        for (byte item : bytes) {
            if (item < 0x21 || item > 0x7e) {
                return false;
            }
        }
        return true;
    }

    private static boolean canonicalUuid(String value) {
        if (value == null || value.length() != 36 || !value.equals(value.toLowerCase())) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (index == 8 || index == 13 || index == 18 || index == 23) {
                if (item != '-') {
                    return false;
                }
            } else if ("0123456789abcdef".indexOf(item) < 0) {
                return false;
            }
        }
        return true;
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static String sha256Hex(byte[] value) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String hex(byte[] value) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] result = new char[value.length * 2];
        for (int index = 0; index < value.length; index++) {
            int item = value[index] & 0xff;
            result[index * 2] = digits[item >>> 4];
            result[index * 2 + 1] = digits[item & 0x0f];
        }
        return new String(result);
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] result = Arrays.copyOf(left, left.length + right.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }
}
