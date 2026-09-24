// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

class LicenseVerifierTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String HEADER = "{\"typ\":\"massdb-license+jws\",\"alg\":\"Ed25519\",\"kid\":\"test-key\"}";
    private static final String DEPLOYMENT = "003aaf16-b828-455a-8ce2-1bd393572102";
    private KeyPair keys;
    private LicenseVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        verifier = new LicenseVerifier(Collections.singletonMap("test-key", keys.getPublic()));
    }

    @Test
    void verifiesSignedClaimsAndFingerprintWithoutConsultingCurrentState() throws Exception {
        ObjectNode claims = claims();
        claims.putArray("features").add("DATA_QUERY").add("FUTURE_FEATURE");
        String compact = sign(HEADER, claims.toString());
        LicenseDocument document = verifier.verify(compact);
        Assertions.assertEquals(UUID.fromString(DEPLOYMENT), document.getDeploymentId());
        Assertions.assertEquals("license-1", document.getLicenseId());
        Assertions.assertEquals("MassDB Test Issuer", document.getIssuer());
        Assertions.assertEquals("test-customer", document.getCustomerId());
        Assertions.assertEquals("Enterprise", document.getEdition());
        Assertions.assertEquals("test-key", document.getKeyId());
        Assertions.assertEquals(0, document.getIssuedAt());
        Assertions.assertEquals(1, document.getNotBefore());
        Assertions.assertEquals(100, document.getExpiresAt());
        Assertions.assertEquals(1, document.getSequence());
        Assertions.assertEquals(3, document.getMaxFeNodes());
        Assertions.assertEquals(8, document.getMaxBeNodes());
        Assertions.assertTrue(document.hasFeature("DATA_QUERY"));
        Assertions.assertTrue(document.hasFeature("FUTURE_FEATURE"));
        Assertions.assertFalse(document.hasFeature("UNKNOWN"));
        Assertions.assertThrows(UnsupportedOperationException.class, () -> document.getFeatures().clear());
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(compact.getBytes(StandardCharsets.UTF_8));
        Assertions.assertEquals(String.format("%064x", new BigInteger(1, hash)), document.getFingerprint());
        Assertions.assertFalse(document.toString().contains("license-1"));
    }

    @Test
    void acceptsFutureCertificateAndMissingQueryFeatureForLaterPolicyEvaluation() throws Exception {
        ObjectNode claims = claims();
        claims.put("issued_at", LicenseVerifier.MAX_EPOCH_SECOND - 2);
        claims.put("not_before", LicenseVerifier.MAX_EPOCH_SECOND - 1);
        claims.put("expires_at", LicenseVerifier.MAX_EPOCH_SECOND);
        claims.putArray("features");
        Assertions.assertFalse(verifier.verify(sign(HEADER, claims.toString())).hasFeature("DATA_QUERY"));
    }

    @Test
    void verifiesOriginalBytesRatherThanReserializingJson() throws Exception {
        String compact = sign(" { \"kid\":\"test-key\", \"alg\":\"Ed25519\","
                + " \"typ\":\"massdb-license+jws\" } ", " \n" + claims() + " \t");
        LicenseDocument document = verifier.verify(compact);
        Assertions.assertEquals("license-1", document.getLicenseId());
        Assertions.assertNotEquals(document.getFingerprint(),
                verifier.verify(sign(HEADER, claims().toString())).getFingerprint());
        String[] segments = compact.split("\\.");
        reject(LicenseErrorCode.INVALID_SIGNATURE,
                segments[0] + "." + encode(claims().toString().getBytes(StandardCharsets.UTF_8)) + "." + segments[2]);
    }

    @Test
    void rejectsAlteredQuotaExpiryAndWrongSigningKey() throws Exception {
        String compact = sign(HEADER, claims().toString());
        String[] segments = compact.split("\\.");
        ObjectNode changed = claims();
        ((ObjectNode) changed.get("limits")).put("max_be_nodes", 100);
        reject(LicenseErrorCode.INVALID_SIGNATURE,
                segments[0] + "." + encode(changed.toString().getBytes(StandardCharsets.UTF_8)) + "." + segments[2]);
        changed = claims();
        changed.put("expires_at", 99999);
        reject(LicenseErrorCode.INVALID_SIGNATURE,
                segments[0] + "." + encode(changed.toString().getBytes(StandardCharsets.UTF_8)) + "." + segments[2]);
        LicenseVerifier otherVerifier = new LicenseVerifier(Collections.singletonMap("test-key",
                KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic()));
        Assertions.assertEquals(LicenseErrorCode.INVALID_SIGNATURE,
                Assertions.assertThrows(LicenseException.class, () -> otherVerifier.verify(compact)).getErrorCode());
    }

    @Test
    void copiesTrustConfigurationAndRejectsUntrustedOrWrongAlgorithmKeys() throws Exception {
        Map<String, PublicKey> trusted = new HashMap<>();
        trusted.put("test-key", keys.getPublic());
        LicenseVerifier copied = new LicenseVerifier(trusted);
        trusted.clear();
        Assertions.assertEquals("test-key", copied.verify(sign(HEADER, claims().toString())).getKeyId());
        reject(LicenseErrorCode.UNTRUSTED_KEY, sign(HEADER.replace("test-key", "not-trusted"), claims().toString()));
        PublicKey ed448 = KeyPairGenerator.getInstance("Ed448").generateKeyPair().getPublic();
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new LicenseVerifier(Collections.singletonMap("wrong-curve", ed448)));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new LicenseVerifier(null));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new LicenseVerifier(Collections.singletonMap("test-key", null)));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new LicenseVerifier(Collections.singletonMap("bad key", keys.getPublic())));
    }

    @Test
    void rejectsHeaderSubstitutionAndUnsupportedJwsExtensions() throws Exception {
        for (String field : new String[] {"jwk", "jku", "x5u", "crit", "b64", "zip", "extra"}) {
            ObjectNode header = (ObjectNode) JSON.readTree(HEADER);
            header.put(field, "untrusted");
            reject(LicenseErrorCode.INVALID_HEADER, sign(header.toString(), claims().toString()));
        }
        for (String algorithm : new String[] {"none", "EdDSA", "HS256", "RS256"}) {
            reject(LicenseErrorCode.INVALID_HEADER,
                    sign(HEADER.replace("Ed25519", algorithm), claims().toString()));
        }
        reject(LicenseErrorCode.INVALID_HEADER, sign(HEADER.replace("massdb-license+jws", "JWT"), claims().toString()));
        ObjectNode header = (ObjectNode) JSON.readTree(HEADER);
        header.remove("kid");
        reject(LicenseErrorCode.INVALID_HEADER, sign(header.toString(), claims().toString()));
        header.put("kid", "");
        reject(LicenseErrorCode.INVALID_HEADER, sign(header.toString(), claims().toString()));
    }

    @Test
    void rejectsDuplicateFieldsAtEveryObjectLevel() throws Exception {
        reject(LicenseErrorCode.INVALID_JSON,
                sign(HEADER.replace("{", "{\"kid\":\"test-key\","), claims().toString()));
        reject(LicenseErrorCode.INVALID_JSON,
                sign(HEADER, claims().toString().replace("{", "{\"sequence\":1,")));
        reject(LicenseErrorCode.INVALID_JSON, sign(HEADER,
                claims().toString().replace("\"max_fe_nodes\":3", "\"max_fe_nodes\":3,\"max_fe_nodes\":3")));
        reject(LicenseErrorCode.INVALID_JSON, sign(HEADER,
                claims().toString().replace("\"sequence\":1", "\"sequence\":1,\"sequen\\u0063e\":1")));
    }

    @Test
    void rejectsTrailingDocumentsNonObjectRootsAndDeepJson() throws Exception {
        reject(LicenseErrorCode.INVALID_JSON, sign(HEADER + " {}", claims().toString()));
        for (String payload : new String[] {claims() + " {}", "[]", "null", "1", "\"text\"", "", "{"}) {
            reject(payload.isEmpty() ? LicenseErrorCode.INVALID_COMPACT : LicenseErrorCode.INVALID_JSON,
                    sign(HEADER, payload));
        }
        reject(LicenseErrorCode.INVALID_JSON, sign(HEADER,
                "{\"extra\":" + repeat("[", 20) + "0" + repeat("]", 20) + "}"));
        reject(LicenseErrorCode.INVALID_JSON, sign(HEADER, "{\"extra\":\"" + repeat("a", 5000) + "\"}"));
        reject(LicenseErrorCode.INVALID_JSON, sign(HEADER, "{/* comment */}"));
    }

    @Test
    void rejectsNonUtf8PayloadsAndMalformedUtf8() throws Exception {
        reject(LicenseErrorCode.INVALID_JSON, signBytes(HEADER.getBytes(StandardCharsets.UTF_8),
                claims().toString().getBytes(StandardCharsets.UTF_16)));
        reject(LicenseErrorCode.INVALID_JSON, signBytes(HEADER.getBytes(StandardCharsets.UTF_8),
                new byte[] {'{', '"', 'x', '"', ':', '"', (byte) 0xc3, (byte) 0x28, '"', '}'}));
    }

    @Test
    void rejectsMalformedCompactAndPaddedOrNoncanonicalBase64() throws Exception {
        for (String compact : new String[] {"", "a", "a.b", "a.b.c.d", ".b.c", "a..c", "a.b.", "é.b.c"}) {
            reject(LicenseErrorCode.INVALID_COMPACT, compact);
        }
        reject(LicenseErrorCode.INVALID_COMPACT, null);
        String compact = sign(HEADER, claims().toString());
        String[] segments = compact.split("\\.");
        reject(LicenseErrorCode.INVALID_BASE64URL, segments[0] + "=." + segments[1] + "." + segments[2]);
        reject(LicenseErrorCode.INVALID_BASE64URL, " " + compact);
        reject(LicenseErrorCode.INVALID_BASE64URL, compact + "\n");
        reject(LicenseErrorCode.INVALID_BASE64URL, "a." + segments[1] + "." + segments[2]);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        String signature = segments[2];
        char last = signature.charAt(signature.length() - 1);
        char noncanonical = alphabet.charAt(alphabet.indexOf(last) + 1);
        String changed = signature.substring(0, signature.length() - 1) + noncanonical;
        Assertions.assertTrue(java.util.Arrays.equals(
                Base64.getUrlDecoder().decode(signature), Base64.getUrlDecoder().decode(changed)));
        reject(LicenseErrorCode.INVALID_BASE64URL, segments[0] + "." + segments[1] + "." + changed);
        reject(LicenseErrorCode.INVALID_SIGNATURE, segments[0] + "." + segments[1] + "." + encode(new byte[63]));
    }

    @Test
    void enforcesCompactSizeBeforeParsingAndAcceptsBoundary() throws Exception {
        reject(LicenseErrorCode.INPUT_TOO_LARGE, repeat("a", LicenseVerifier.MAX_COMPACT_LENGTH + 1));
        String payload = claims().toString();
        int overhead = encode(HEADER.getBytes(StandardCharsets.UTF_8)).length() + 88;
        int length = (LicenseVerifier.MAX_COMPACT_LENGTH - overhead) * 3 / 4;
        String compact = sign(HEADER, payload + repeat(" ", length - payload.length()));
        Assertions.assertTrue(compact.length() <= LicenseVerifier.MAX_COMPACT_LENGTH);
        Assertions.assertTrue(compact.length() >= LicenseVerifier.MAX_COMPACT_LENGTH - 1);
        verifier.verify(compact);
        reject(LicenseErrorCode.INPUT_TOO_LARGE,
                sign(HEADER, payload + repeat(" ", length - payload.length() + 2)));
    }

    @Test
    void rejectsUnknownMissingOrNullClaimsAndLimits() throws Exception {
        ObjectNode claims = claims();
        claims.put("unknown", 1);
        rejectClaims(claims);
        claims = claims();
        claims.remove("issuer");
        rejectClaims(claims);
        claims = claims();
        claims.putNull("features");
        rejectClaims(claims);
        claims = claims();
        ((ObjectNode) claims.get("limits")).put("cpu", 8);
        rejectClaims(claims);
        claims = claims();
        claims.putNull("limits");
        rejectClaims(claims);
    }

    @Test
    void rejectsUnsupportedVersionsAndWrongProduct() throws Exception {
        ObjectNode claims = claims();
        claims.put("schema_version", 2);
        reject(LicenseErrorCode.UNSUPPORTED_SCHEMA, sign(HEADER, claims.toString()));
        claims = claims();
        claims.put("policy_version", 2);
        reject(LicenseErrorCode.UNSUPPORTED_POLICY, sign(HEADER, claims.toString()));
        claims = claims();
        claims.put("product", "Other Product");
        rejectClaims(claims);
    }

    @Test
    void rejectsImplicitNumericConversionAndOverflow() throws Exception {
        for (String field : new String[] {"sequence", "issued_at", "not_before", "expires_at", "schema_version"}) {
            for (String literal : new String[] {"1.0", "1e0", "\"1\"", "true", "null", "9223372036854775808"}) {
                ObjectNode claims = claims();
                claims.set(field, JSON.readTree(literal));
                rejectClaims(claims);
            }
        }
        for (String field : new String[] {"max_fe_nodes", "max_be_nodes"}) {
            for (String literal : new String[] {"0", "-1", "1.0", "\"1\"", "2147483648", "null"}) {
                ObjectNode claims = claims();
                ((ObjectNode) claims.get("limits")).set(field, JSON.readTree(literal));
                rejectClaims(claims);
            }
        }
        reject(LicenseErrorCode.INVALID_JSON, sign(HEADER,
                claims().toString().replace("\"sequence\":1", "\"sequence\":" + repeat("9", 50))));
    }

    @Test
    void validatesTimeSequenceAndQuotaBoundaries() throws Exception {
        ObjectNode claims = claims();
        claims.put("issued_at", LicenseVerifier.MAX_EPOCH_SECOND);
        claims.put("not_before", 0);
        claims.put("expires_at", LicenseVerifier.MAX_EPOCH_SECOND);
        claims.put("sequence", Long.MAX_VALUE);
        ((ObjectNode) claims.get("limits")).put("max_fe_nodes", Integer.MAX_VALUE).put("max_be_nodes", 1);
        Assertions.assertEquals(Long.MAX_VALUE, verifier.verify(sign(HEADER, claims.toString())).getSequence());
        for (String field : new String[] {"issued_at", "not_before", "expires_at"}) {
            ObjectNode invalid = claims();
            invalid.put(field, -1);
            rejectClaims(invalid);
            invalid.put(field, LicenseVerifier.MAX_EPOCH_SECOND + 1);
            rejectClaims(invalid);
        }
        for (long sequence : new long[] {0, -1}) {
            ObjectNode invalid = claims();
            invalid.put("sequence", sequence);
            rejectClaims(invalid);
        }
        claims = claims();
        claims.put("issued_at", 101);
        rejectClaims(claims);
        claims = claims();
        claims.put("not_before", 100);
        rejectClaims(claims);
    }

    @Test
    void requiresCanonicalUuidAndBoundedText() throws Exception {
        for (String uuid : new String[] {"1-1-1-1-1", DEPLOYMENT.toUpperCase(), "not-a-uuid"}) {
            ObjectNode claims = claims();
            claims.put("deployment_id", uuid);
            rejectClaims(claims);
        }
        for (String value : new String[] {"", " ", " leading", "trailing ", "x\n", "x\u0000", "x\u200b",
                repeat("x", 257)}) {
            ObjectNode claims = claims();
            claims.put("issuer", value);
            rejectClaims(claims);
        }
        ObjectNode claims = claims();
        claims.put("license_id", "id with space");
        rejectClaims(claims);
        claims = claims();
        claims.put("issuer", repeat("x", 256));
        verifier.verify(sign(HEADER, claims.toString()));
        claims.put("issuer", repeat("😀", 129));
        rejectClaims(claims);
        reject(LicenseErrorCode.INVALID_CLAIMS, sign(HEADER,
                claims().toString().replace("MassDB Test Issuer", "x\\ud800")));
    }

    @Test
    void boundsFeaturesRejectsDuplicatesAndPreservesUnknownValues() throws Exception {
        ObjectNode claims = claims();
        ArrayNode features = claims.putArray("features");
        for (int i = 0; i < 128; i++) {
            features.add("FUTURE_" + i);
        }
        Assertions.assertEquals(128, verifier.verify(sign(HEADER, claims.toString())).getFeatures().size());
        features.add("EXCESS");
        rejectClaims(claims);
        for (String feature : new String[] {"", " ", "with space", "\u0000", repeat("F", 129)}) {
            claims = claims();
            claims.putArray("features").add(feature);
            rejectClaims(claims);
        }
        claims = claims();
        claims.putArray("features").add("DATA_QUERY").add("DATA_QUERY");
        rejectClaims(claims);
        claims = claims();
        claims.putArray("features").add(1);
        rejectClaims(claims);
    }

    private void rejectClaims(ObjectNode claims) throws Exception {
        reject(LicenseErrorCode.INVALID_CLAIMS, sign(HEADER, claims.toString()));
    }

    private void reject(LicenseErrorCode expected, String compact) {
        LicenseException exception = Assertions.assertThrows(LicenseException.class, () -> verifier.verify(compact));
        Assertions.assertEquals(expected, exception.getErrorCode());
        Assertions.assertEquals("License certificate rejected: " + expected.name(), exception.getMessage());
        Assertions.assertNull(exception.getCause());
    }

    private String sign(String header, String payload) throws Exception {
        return signBytes(header.getBytes(StandardCharsets.UTF_8), payload.getBytes(StandardCharsets.UTF_8));
    }

    private String signBytes(byte[] header, byte[] payload) throws Exception {
        String input = encode(header) + "." + encode(payload);
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keys.getPrivate());
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + encode(signature.sign());
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static String repeat(String value, int count) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < count; i++) {
            result.append(value);
        }
        return result.toString();
    }

    private static ObjectNode claims() {
        ObjectNode claims = JSON.createObjectNode();
        claims.put("schema_version", 1).put("policy_version", 1).put("product", "MassDB SQL");
        claims.put("deployment_id", DEPLOYMENT).put("license_id", "license-1");
        claims.put("issuer", "MassDB Test Issuer").put("customer_id", "test-customer").put("edition", "Enterprise");
        claims.put("issued_at", 0).put("not_before", 1).put("expires_at", 100).put("sequence", 1);
        claims.putArray("features").add("DATA_QUERY");
        claims.putObject("limits").put("max_fe_nodes", 3).put("max_be_nodes", 8);
        return claims;
    }
}
