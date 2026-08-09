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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

/** Dependency-free P-256 CSR, encrypted PKCS12, certificate, and TLS-context operations. */
final class MassDbLicenseIdentityKeyMaterial {
    private static final String KEY_ALIAS = "massdb-license-identity";
    private static final String CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";
    private static final String SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";
    private static final byte[] ECDSA_SHA256_ALGORITHM = new byte[] {
            0x30, 0x0a, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce,
            0x3d, 0x04, 0x03, 0x02
    };
    private static final byte[] EXTENSION_REQUEST_OID = new byte[] {
            0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7,
            0x0d, 0x01, 0x09, 0x0e
    };
    private static final byte[] SUBJECT_ALT_NAME_OID = new byte[] {
            0x06, 0x03, 0x55, 0x1d, 0x11
    };
    private static final SecureRandom RANDOM = new SecureRandom();

    private MassDbLicenseIdentityKeyMaterial() {
    }

    static Generated generate(String spiffeUri, long nowEpochSecond) {
        return generate(spiffeUri, java.util.Collections.emptyList(),
                java.util.Collections.emptyList(), nowEpochSecond);
    }

    static Generated generate(String spiffeUri, List<String> dnsSans,
            List<String> ipSans, long nowEpochSecond) {
        try {
            MassDbLicenseIdentityAddressSans.AddressSans addressSans =
                    MassDbLicenseIdentityAddressSans.normalize(dnsSans, ipSans, false);
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            return generate(generator.generateKeyPair(), spiffeUri, addressSans,
                    nowEpochSecond);
        } catch (GeneralSecurityException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_KEY_GENERATION_FAILED",
                    "无法生成组件身份私钥或CSR");
            return null;
        }
    }

    static Generated generate(KeyPair keyPair, String spiffeUri, long nowEpochSecond) {
        return generate(keyPair, spiffeUri,
                MassDbLicenseIdentityAddressSans.normalize(
                        java.util.Collections.emptyList(), java.util.Collections.emptyList(), false),
                nowEpochSecond);
    }

    static Generated generate(KeyPair keyPair, String spiffeUri, List<String> dnsSans,
            List<String> ipSans, long nowEpochSecond) {
        return generate(keyPair, spiffeUri,
                MassDbLicenseIdentityAddressSans.normalize(dnsSans, ipSans, false),
                nowEpochSecond);
    }

    private static Generated generate(KeyPair keyPair, String spiffeUri,
            MassDbLicenseIdentityAddressSans.AddressSans addressSans,
            long nowEpochSecond) {
        try {
            byte[] csr = createCsr(keyPair, spiffeUri, addressSans);
            X509Certificate placeholder = createPlaceholderCertificate(
                    keyPair, spiffeUri, addressSans, nowEpochSecond);
            return new Generated(keyPair.getPrivate(), keyPair.getPublic(), csr, placeholder);
        } catch (GeneralSecurityException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_KEY_GENERATION_FAILED",
                    "无法生成组件身份私钥或CSR");
            return null;
        }
    }

    static byte[] encodePkcs12(PrivateKey privateKey, Certificate[] chain, char[] password) {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, password);
            store.setKeyEntry(KEY_ALIAS, privateKey, password, chain);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            store.store(output, password);
            return output.toByteArray();
        } catch (GeneralSecurityException | java.io.IOException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "无法生成加密PKCS12身份库");
            return null;
        }
    }

    static Loaded loadPkcs12(byte[] encoded, char[] password) {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new ByteArrayInputStream(encoded), password);
            if (!store.isKeyEntry(KEY_ALIAS)) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "PKCS12缺少唯一身份私钥");
            }
            PrivateKey privateKey = (PrivateKey) store.getKey(KEY_ALIAS, password);
            Certificate certificate = store.getCertificate(KEY_ALIAS);
            if (privateKey == null || !(certificate instanceof X509Certificate)) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "PKCS12身份私钥条目无效");
            }
            return new Loaded(privateKey, certificate.getPublicKey());
        } catch (MassDbLicenseException error) {
            throw error;
        } catch (GeneralSecurityException | java.io.IOException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "无法解密或读取PKCS12身份库");
            return null;
        }
    }

    static ActiveMaterial activate(MassDbLicenseProtocolV1.VerifiedIdentityPackage verified,
            Loaded localKey, char[] password, long nowEpochSecond) {
        return activate(verified, localKey, password,
                MassDbLicenseIdentityAddressSans.normalize(
                        java.util.Collections.emptyList(), java.util.Collections.emptyList(), false),
                false, nowEpochSecond);
    }

    static ActiveMaterial activate(MassDbLicenseProtocolV1.VerifiedIdentityPackage verified,
            Loaded localKey, char[] password,
            MassDbLicenseIdentityAddressSans.AddressSans expectedAddressSans,
            boolean enforceAddressSans, long nowEpochSecond) {
        MassDbLicenseProtocolV1.IdentityPackage payload = verified.getPayload();
        try {
            X509Certificate leaf = parseCertificate(payload.getLeafCertificatePem());
            List<X509Certificate> intermediates = parseCertificates(payload.getChainPem());
            List<X509Certificate> roots = parseCertificates(payload.getTrustBundles());
            if (!Arrays.equals(leaf.getPublicKey().getEncoded(), localKey.publicKey.getEncoded())) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_KEY_MISMATCH",
                        "身份包leaf公钥与本地待激活私钥不匹配");
            }
            long certificateNotBefore = leaf.getNotBefore().toInstant().getEpochSecond();
            long certificateNotAfter = leaf.getNotAfter().toInstant().getEpochSecond();
            if (certificateNotBefore != payload.getNotBefore()
                    || certificateNotAfter != payload.getNotAfter()) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID",
                        "身份包时间与leaf证书有效期不一致");
            }
            leaf.checkValidity(Date.from(Instant.ofEpochSecond(nowEpochSecond)));
            requireLeafUsage(leaf, true);
            MassDbLicenseSpiffeIdentity.Identity identity =
                    MassDbLicenseSpiffeIdentity.parsePeerCertificate(leaf);
            requireIdentity(payload, identity);
            if (enforceAddressSans) {
                MassDbLicenseIdentityAddressSans.requireCertificateMatches(
                        leaf, expectedAddressSans);
            }
            String spiffeId = spiffeId(identity);
            if (payload.getRevocations().contains(spiffeId)) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_REVOKED", "本节点身份已在签名吊销表中");
            }
            validateChain(leaf, intermediates, roots, nowEpochSecond);
            X509Certificate[] keyChain = new X509Certificate[intermediates.size() + 1];
            keyChain[0] = leaf;
            for (int index = 0; index < intermediates.size(); index++) {
                keyChain[index + 1] = intermediates.get(index);
            }
            byte[] pkcs12 = encodePkcs12(localKey.privateKey, keyChain, password);
            SSLContext context = buildSslContext(localKey.privateKey, keyChain,
                    roots, password);
            MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot =
                    new MassDbLicenseFeRoleIdentityProvider.Snapshot(
                            payload.getGeneration(), context, identity,
                            payload.getNotBefore(), payload.getNotAfter(),
                            new HashSet<>(payload.getRevocations()), roots);
            snapshot.requireUsable(nowEpochSecond);
            return new ActiveMaterial(snapshot, pkcs12);
        } catch (MassDbLicenseException error) {
            throw error;
        } catch (GeneralSecurityException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID",
                    "身份包证书链、用途或有效期验证失败");
            return null;
        }
    }

    static String csrPem(byte[] csr) {
        return pem("CERTIFICATE REQUEST", csr);
    }

    static String sha256Hex(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder output = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                output.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return output.toString();
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException(error);
        }
    }

    private static byte[] createCsr(KeyPair keyPair, String spiffeUri,
            MassDbLicenseIdentityAddressSans.AddressSans addressSans)
            throws GeneralSecurityException {
        List<byte[]> requestedNames = new ArrayList<>();
        requestedNames.add(tagged(0x86, spiffeUri.getBytes(StandardCharsets.US_ASCII)));
        for (String dns : addressSans.dnsNames()) {
            requestedNames.add(tagged(0x82, dns.getBytes(StandardCharsets.US_ASCII)));
        }
        for (String ip : addressSans.ipAddresses()) {
            requestedNames.add(tagged(0x87, MassDbLicenseIdentityAddressSans.ipBytes(ip)));
        }
        byte[] generalNames = sequence(requestedNames.toArray(new byte[0][]));
        byte[] extension = sequence(SUBJECT_ALT_NAME_OID, octetString(generalNames));
        byte[] extensions = sequence(extension);
        byte[] attribute = sequence(EXTENSION_REQUEST_OID, set(extensions));
        byte[] attributes = tagged(0xa0, attribute);
        byte[] requestInfo = sequence(integer(BigInteger.ZERO),
                new X500Principal("CN=MassDB Identity Enrollment").getEncoded(),
                keyPair.getPublic().getEncoded(), attributes);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate(), RANDOM);
        signer.update(requestInfo);
        return sequence(requestInfo, ECDSA_SHA256_ALGORITHM, bitString(signer.sign()));
    }

    private static X509Certificate createPlaceholderCertificate(KeyPair keyPair,
            String spiffeUri, MassDbLicenseIdentityAddressSans.AddressSans addressSans,
            long nowEpochSecond) throws GeneralSecurityException {
        X500Principal name = new X500Principal("CN=MassDB Identity Enrollment Placeholder");
        BigInteger serial = new BigInteger(127, RANDOM).add(BigInteger.ONE);
        Date notBefore = Date.from(Instant.ofEpochSecond(Math.max(0, nowEpochSecond - 60)));
        Date notAfter = Date.from(Instant.ofEpochSecond(nowEpochSecond + 604_800));
        List<byte[]> requestedNames = new ArrayList<>();
        requestedNames.add(tagged(0x86, spiffeUri.getBytes(StandardCharsets.US_ASCII)));
        for (String dns : addressSans.dnsNames()) {
            requestedNames.add(tagged(0x82, dns.getBytes(StandardCharsets.US_ASCII)));
        }
        for (String ip : addressSans.ipAddresses()) {
            requestedNames.add(tagged(0x87, MassDbLicenseIdentityAddressSans.ipBytes(ip)));
        }
        byte[] generalNames = sequence(requestedNames.toArray(new byte[0][]));
        byte[] extensions = sequence(sequence(
                SUBJECT_ALT_NAME_OID, octetString(generalNames)));
        byte[] version = tagged(0xa0, integer(BigInteger.valueOf(2)));
        byte[] tbs = sequence(version, integer(serial), ECDSA_SHA256_ALGORITHM,
                name.getEncoded(), sequence(utcTime(notBefore), utcTime(notAfter)),
                name.getEncoded(), keyPair.getPublic().getEncoded(), tagged(0xa3, extensions));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate(), RANDOM);
        signer.update(tbs);
        byte[] certificate = sequence(tbs, ECDSA_SHA256_ALGORITHM, bitString(signer.sign()));
        try {
            X509Certificate parsed = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certificate));
            parsed.verify(keyPair.getPublic());
            return parsed;
        } catch (java.security.cert.CertificateException error) {
            throw new GeneralSecurityException(error);
        }
    }

    private static X509Certificate parseCertificate(String pem) throws GeneralSecurityException {
        if (pem == null || pem.length() > 16_384) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID", "身份包证书为空或过大");
        }
        String begin = "-----BEGIN CERTIFICATE-----";
        String end = "-----END CERTIFICATE-----";
        String trimmed = pem.trim();
        if (!trimmed.startsWith(begin) || !trimmed.endsWith(end)
                || trimmed.indexOf(begin, begin.length()) >= 0) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID", "身份包必须包含单个PEM证书");
        }
        String body = trimmed.substring(begin.length(), trimmed.length() - end.length())
                .replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(body);
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (IllegalArgumentException | java.security.cert.CertificateException error) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID", "身份包PEM证书无法解析");
            return null;
        }
    }

    private static List<X509Certificate> parseCertificates(List<String> pem)
            throws GeneralSecurityException {
        List<X509Certificate> result = new ArrayList<>(pem.size());
        Set<String> seen = new HashSet<>();
        for (String value : pem) {
            X509Certificate certificate = parseCertificate(value);
            if (!seen.add(sha256Hex(certificate.getEncoded()))) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID", "身份包包含重复证书");
            }
            result.add(certificate);
        }
        return result;
    }

    static void requireLeafUsage(X509Certificate leaf, boolean requireServerAuth)
            throws GeneralSecurityException {
        if (leaf.getBasicConstraints() >= 0) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID", "身份leaf不能是CA证书");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage == null || keyUsage.length == 0 || !keyUsage[0]) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID",
                    "身份leaf必须允许digitalSignature");
        }
        List<String> extended = leaf.getExtendedKeyUsage();
        if (extended == null || !extended.contains(CLIENT_AUTH_OID)
                || requireServerAuth && !extended.contains(SERVER_AUTH_OID)) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID",
                    requireServerAuth
                            ? "FE身份leaf必须同时包含clientAuth和serverAuth EKU"
                            : "License管理身份leaf必须包含clientAuth EKU");
        }
    }

    private static void requireIdentity(MassDbLicenseProtocolV1.IdentityPackage payload,
            MassDbLicenseSpiffeIdentity.Identity identity) {
        if (!payload.getComponent().equals(identity.component)
                || !payload.getDeploymentUuid().equals(identity.deploymentUuid)
                || !payload.getRole().equals(identity.role)
                || !payload.getNodeUuid().equals(identity.nodeUuid)) {
            fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH", "leaf URI SAN与签名身份包不一致");
        }
    }

    private static void validateChain(X509Certificate leaf,
            List<X509Certificate> intermediates, List<X509Certificate> roots,
            long nowEpochSecond) throws GeneralSecurityException {
        if (roots.isEmpty()) {
            fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID", "身份包trust bundle不能为空");
        }
        List<X509Certificate> pathCertificates = new ArrayList<>();
        pathCertificates.add(leaf);
        pathCertificates.addAll(intermediates);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath path = factory.generateCertPath(pathCertificates);
        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate root : roots) {
            if (root.getBasicConstraints() < 0) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_CERTIFICATE_INVALID",
                        "trust bundle包含非CA证书");
            }
            anchors.add(new TrustAnchor(root, null));
        }
        PKIXParameters parameters = new PKIXParameters(anchors);
        parameters.setRevocationEnabled(false);
        parameters.setDate(Date.from(Instant.ofEpochSecond(nowEpochSecond)));
        CertPathValidator.getInstance("PKIX").validate(path, parameters);
    }

    /** Revalidates a servlet peer chain against the currently signed trust bundle. */
    static void validatePeerChain(X509Certificate[] chain,
            List<X509Certificate> roots, long nowEpochSecond) {
        validatePeerChain(chain, roots, nowEpochSecond, true);
    }

    /** Management clients are never server identities and therefore require clientAuth only. */
    static void validateManagementPeerChain(X509Certificate[] chain,
            List<X509Certificate> roots, long nowEpochSecond) {
        validatePeerChain(chain, roots, nowEpochSecond, false);
    }

    private static void validatePeerChain(X509Certificate[] chain,
            List<X509Certificate> roots, long nowEpochSecond, boolean requireServerAuth) {
        try {
            if (chain == null || chain.length == 0 || chain.length > 8
                    || roots == null || roots.isEmpty()) {
                fail("MASSDB_LICENSE_MTLS_IDENTITY_INVALID",
                        "mTLS客户端证书链为空、过长或缺少当前trust bundle");
            }
            Set<String> seen = new HashSet<>();
            for (X509Certificate certificate : chain) {
                if (certificate == null || !seen.add(sha256Hex(certificate.getEncoded()))) {
                    fail("MASSDB_LICENSE_MTLS_IDENTITY_INVALID",
                            "mTLS客户端证书链包含空值或重复证书");
                }
            }
            requireLeafUsage(chain[0], requireServerAuth);
            int pathLength = chain.length;
            if (pathLength > 1 && isCurrentTrustRoot(chain[pathLength - 1], roots)) {
                pathLength--;
            }
            List<X509Certificate> intermediates = new ArrayList<>();
            for (int index = 1; index < pathLength; index++) {
                intermediates.add(chain[index]);
            }
            validateChain(chain[0], intermediates, roots, nowEpochSecond);
        } catch (GeneralSecurityException | MassDbLicenseException error) {
            fail("MASSDB_LICENSE_MTLS_IDENTITY_INVALID",
                    "mTLS客户端证书链不受当前签名trust bundle信任");
        }
    }

    private static boolean isCurrentTrustRoot(X509Certificate certificate,
            List<X509Certificate> roots) throws GeneralSecurityException {
        String digest = sha256Hex(certificate.getEncoded());
        for (X509Certificate root : roots) {
            if (digest.equals(sha256Hex(root.getEncoded()))) {
                return true;
            }
        }
        return false;
    }

    private static SSLContext buildSslContext(PrivateKey privateKey,
            X509Certificate[] keyChain, List<X509Certificate> roots, char[] password)
            throws GeneralSecurityException {
        try {
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(null, password);
            keys.setKeyEntry(KEY_ALIAS, privateKey, password, keyChain);
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keys, password);

            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, password);
            for (int index = 0; index < roots.size(); index++) {
                trust.setCertificateEntry("massdb-license-identity-root-" + index,
                        roots.get(index));
            }
            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), RANDOM);
            return context;
        } catch (java.io.IOException error) {
            throw new GeneralSecurityException(error);
        }
    }

    private static String spiffeId(MassDbLicenseSpiffeIdentity.Identity identity) {
        return "spiffe://" + MassDbLicenseSpiffeIdentity.TRUST_DOMAIN
                + "/license/component/" + identity.component + "/" + identity.deploymentUuid
                + "/" + identity.role + "/" + identity.nodeUuid;
    }

    private static String pem(String type, byte[] value) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(value)
                + "\n-----END " + type + "-----\n";
    }

    private static byte[] sequence(byte[]... values) {
        return constructed(0x30, values);
    }

    private static byte[] set(byte[]... values) {
        return constructed(0x31, values);
    }

    private static byte[] constructed(int tag, byte[]... values) {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        for (byte[] value : values) {
            content.write(value, 0, value.length);
        }
        return tagged(tag, content.toByteArray());
    }

    private static byte[] integer(BigInteger value) {
        return tagged(0x02, value.toByteArray());
    }

    private static byte[] bitString(byte[] value) {
        byte[] content = new byte[value.length + 1];
        System.arraycopy(value, 0, content, 1, value.length);
        return tagged(0x03, content);
    }

    private static byte[] octetString(byte[] value) {
        return tagged(0x04, value);
    }

    private static byte[] utcTime(Date value) {
        SimpleDateFormat format = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.ROOT);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return tagged(0x17, format.format(value).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] tagged(int tag, byte[] content) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(tag);
        writeDerLength(output, content.length);
        output.write(content, 0, content.length);
        return output.toByteArray();
    }

    private static void writeDerLength(ByteArrayOutputStream output, int length) {
        if (length < 128) {
            output.write(length);
            return;
        }
        int bytes = length <= 0xff ? 1 : length <= 0xffff ? 2 : 3;
        output.write(0x80 | bytes);
        for (int shift = (bytes - 1) * 8; shift >= 0; shift -= 8) {
            output.write(length >>> shift);
        }
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    static final class Generated {
        final PrivateKey privateKey;
        final PublicKey publicKey;
        final byte[] csr;
        final X509Certificate placeholderCertificate;

        private Generated(PrivateKey privateKey, PublicKey publicKey, byte[] csr,
                X509Certificate placeholderCertificate) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.csr = csr.clone();
            this.placeholderCertificate = placeholderCertificate;
        }
    }

    static final class Loaded {
        final PrivateKey privateKey;
        final PublicKey publicKey;

        private Loaded(PrivateKey privateKey, PublicKey publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }

    static final class ActiveMaterial {
        final MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot;
        final byte[] pkcs12;

        private ActiveMaterial(MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot,
                byte[] pkcs12) {
            this.snapshot = snapshot;
            this.pkcs12 = pkcs12;
        }
    }
}
