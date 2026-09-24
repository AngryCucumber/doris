// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Import/recovery boundary. This class must never be invoked on the query admission path. */
public final class LicenseVerifier {
    public static final int MAX_COMPACT_LENGTH = 64 * 1024;
    public static final long MAX_EPOCH_SECOND = 253402300799L;

    private static final int MAX_CLAIM_LENGTH = 256;
    private static final int MAX_KEY_ID_LENGTH = 128;
    private static final int MAX_FEATURE_LENGTH = 128;
    private static final int MAX_FEATURES = 128;
    private static final Set<String> HEADER_FIELDS = fields("typ", "alg", "kid");
    private static final Set<String> CLAIM_FIELDS = fields("schema_version", "policy_version", "product",
            "deployment_id", "license_id", "issuer", "customer_id", "edition", "issued_at", "not_before",
            "expires_at", "sequence", "features", "limits");
    private static final Set<String> LIMIT_FIELDS = fields("max_fe_nodes", "max_be_nodes");
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(8).maxDocumentLength(MAX_COMPACT_LENGTH)
                    .maxNumberLength(20).maxStringLength(4096).maxNameLength(128).build())
            .build());

    private final Map<String, PublicKey> trustedKeys;

    /** Copies keys into JCA keys, so later caller mutations cannot change the trust set. */
    public LicenseVerifier(Map<String, PublicKey> trustedKeys) {
        if (trustedKeys == null) {
            throw new IllegalArgumentException("Trusted license keys must be provided");
        }
        Map<String, PublicKey> copy = new HashMap<>();
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
            for (Map.Entry<String, PublicKey> entry : trustedKeys.entrySet()) {
                if (!isBoundedText(entry.getKey(), MAX_KEY_ID_LENGTH, true) || entry.getValue() == null
                        || entry.getValue().getEncoded() == null) {
                    throw new IllegalArgumentException("Invalid trusted license key configuration");
                }
                PublicKey key = keyFactory.generatePublic(new X509EncodedKeySpec(entry.getValue().getEncoded()));
                copy.put(entry.getKey(), key);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid trusted license key configuration");
        }
        this.trustedKeys = Collections.unmodifiableMap(copy);
    }

    /** Verifies signed claims without consulting wall time, deployment identity, or mutable state. */
    public LicenseDocument verify(String compact) throws LicenseException {
        if (compact == null || compact.isEmpty()) {
            throw new LicenseException(LicenseErrorCode.INVALID_COMPACT);
        }
        if (compact.length() > MAX_COMPACT_LENGTH) {
            throw new LicenseException(LicenseErrorCode.INPUT_TOO_LARGE);
        }
        for (int i = 0; i < compact.length(); i++) {
            if (compact.charAt(i) > 127) {
                throw new LicenseException(LicenseErrorCode.INVALID_COMPACT);
            }
        }
        String[] segments = compact.split("\\.", -1);
        if (segments.length != 3 || segments[0].isEmpty() || segments[1].isEmpty() || segments[2].isEmpty()) {
            throw new LicenseException(LicenseErrorCode.INVALID_COMPACT);
        }
        byte[] headerBytes = decode(segments[0]);
        byte[] payloadBytes = decode(segments[1]);
        byte[] signatureBytes = decode(segments[2]);
        if (signatureBytes.length != 64) {
            throw new LicenseException(LicenseErrorCode.INVALID_SIGNATURE);
        }
        JsonNode header = parseObject(headerBytes);
        requireFields(header, HEADER_FIELDS, LicenseErrorCode.INVALID_HEADER);
        if (!"massdb-license+jws".equals(header.path("typ").textValue())
                || !"Ed25519".equals(header.path("alg").textValue())) {
            throw new LicenseException(LicenseErrorCode.INVALID_HEADER);
        }
        String keyId = text(header, "kid", MAX_KEY_ID_LENGTH, LicenseErrorCode.INVALID_HEADER);
        PublicKey key = trustedKeys.get(keyId);
        if (key == null) {
            throw new LicenseException(LicenseErrorCode.UNTRUSTED_KEY);
        }
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update((segments[0] + "." + segments[1]).getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(signatureBytes)) {
                throw new LicenseException(LicenseErrorCode.INVALID_SIGNATURE);
            }
        } catch (SignatureException e) {
            throw new LicenseException(LicenseErrorCode.INVALID_SIGNATURE);
        } catch (GeneralSecurityException e) {
            throw new LicenseException(LicenseErrorCode.VERIFICATION_UNAVAILABLE);
        }
        return readClaims(parseObject(payloadBytes), keyId, fingerprint(compact));
    }

    private static LicenseDocument readClaims(JsonNode claims, String keyId, String fingerprint)
            throws LicenseException {
        requireFields(claims, CLAIM_FIELDS, LicenseErrorCode.INVALID_CLAIMS);
        if (number(claims, "schema_version", 0, Long.MAX_VALUE) != 1) {
            throw new LicenseException(LicenseErrorCode.UNSUPPORTED_SCHEMA);
        }
        if (number(claims, "policy_version", 0, Long.MAX_VALUE) != 1) {
            throw new LicenseException(LicenseErrorCode.UNSUPPORTED_POLICY);
        }
        if (!"MassDB SQL".equals(text(claims, "product", MAX_CLAIM_LENGTH, LicenseErrorCode.INVALID_CLAIMS))) {
            throw new LicenseException(LicenseErrorCode.INVALID_CLAIMS);
        }
        String deployment = text(claims, "deployment_id", 36, LicenseErrorCode.INVALID_CLAIMS);
        UUID deploymentId;
        try {
            deploymentId = UUID.fromString(deployment);
        } catch (IllegalArgumentException e) {
            throw new LicenseException(LicenseErrorCode.INVALID_CLAIMS);
        }
        if (!deploymentId.toString().equals(deployment)) {
            throw new LicenseException(LicenseErrorCode.INVALID_CLAIMS);
        }
        long issuedAt = number(claims, "issued_at", 0, MAX_EPOCH_SECOND);
        long notBefore = number(claims, "not_before", 0, MAX_EPOCH_SECOND);
        long expiresAt = number(claims, "expires_at", 0, MAX_EPOCH_SECOND);
        if (issuedAt > expiresAt || notBefore >= expiresAt) {
            throw new LicenseException(LicenseErrorCode.INVALID_CLAIMS);
        }
        long sequence = number(claims, "sequence", 1, Long.MAX_VALUE);
        JsonNode limits = claims.get("limits");
        requireFields(limits, LIMIT_FIELDS, LicenseErrorCode.INVALID_CLAIMS);
        int maxFeNodes = (int) number(limits, "max_fe_nodes", 1, Integer.MAX_VALUE);
        int maxBeNodes = (int) number(limits, "max_be_nodes", 1, Integer.MAX_VALUE);
        JsonNode featureList = claims.get("features");
        if (!featureList.isArray() || featureList.size() > MAX_FEATURES) {
            throw new LicenseException(LicenseErrorCode.INVALID_CLAIMS);
        }
        Set<String> features = new LinkedHashSet<>();
        for (JsonNode feature : featureList) {
            if (!feature.isTextual() || !isBoundedText(feature.textValue(), MAX_FEATURE_LENGTH, true)
                    || !features.add(feature.textValue())) {
                throw new LicenseException(LicenseErrorCode.INVALID_CLAIMS);
            }
        }
        return new LicenseDocument(deploymentId,
                text(claims, "license_id", MAX_CLAIM_LENGTH, LicenseErrorCode.INVALID_CLAIMS),
                text(claims, "issuer", MAX_CLAIM_LENGTH, LicenseErrorCode.INVALID_CLAIMS),
                text(claims, "customer_id", MAX_CLAIM_LENGTH, LicenseErrorCode.INVALID_CLAIMS),
                text(claims, "edition", MAX_CLAIM_LENGTH, LicenseErrorCode.INVALID_CLAIMS),
                keyId, fingerprint, issuedAt, notBefore, expiresAt, sequence, maxFeNodes, maxBeNodes, features);
    }

    private static byte[] decode(String segment) throws LicenseException {
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9')
                    && c != '-' && c != '_') {
                throw new LicenseException(LicenseErrorCode.INVALID_BASE64URL);
            }
        }
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(segment);
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(segment)) {
                throw new LicenseException(LicenseErrorCode.INVALID_BASE64URL);
            }
            return bytes;
        } catch (IllegalArgumentException e) {
            throw new LicenseException(LicenseErrorCode.INVALID_BASE64URL);
        }
    }

    private static JsonNode parseObject(byte[] bytes) throws LicenseException {
        String json;
        try {
            json = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new LicenseException(LicenseErrorCode.INVALID_JSON);
        }
        try (JsonParser parser = JSON.createParser(json)) {
            JsonNode node = JSON.readTree(parser);
            if (node == null || !node.isObject() || parser.nextToken() != null) {
                throw new LicenseException(LicenseErrorCode.INVALID_JSON);
            }
            return node;
        } catch (IOException e) {
            throw new LicenseException(LicenseErrorCode.INVALID_JSON);
        }
    }

    private static void requireFields(JsonNode object, Set<String> expected, LicenseErrorCode errorCode)
            throws LicenseException {
        if (object == null || !object.isObject() || object.size() != expected.size()) {
            throw new LicenseException(errorCode);
        }
        Iterator<String> names = object.fieldNames();
        while (names.hasNext()) {
            if (!expected.contains(names.next())) {
                throw new LicenseException(errorCode);
            }
        }
    }

    private static long number(JsonNode object, String name, long minimum, long maximum) throws LicenseException {
        JsonNode value = object.get(name);
        if (value == null || !value.isIntegralNumber() || !value.canConvertToLong()) {
            throw new LicenseException(LicenseErrorCode.INVALID_CLAIMS);
        }
        long result = value.longValue();
        if (result < minimum || result > maximum) {
            throw new LicenseException(LicenseErrorCode.INVALID_CLAIMS);
        }
        return result;
    }

    private static String text(JsonNode object, String name, int maximum, LicenseErrorCode errorCode)
            throws LicenseException {
        JsonNode value = object.get(name);
        boolean identifier = "kid".equals(name) || "license_id".equals(name);
        if (value == null || !value.isTextual() || !isBoundedText(value.textValue(), maximum, identifier)) {
            throw new LicenseException(errorCode);
        }
        return value.textValue();
    }

    private static boolean isBoundedText(String value, int maximum, boolean identifier) {
        return LicenseText.matches(value, maximum, identifier);
    }

    /** Raw-byte identity for already committed receipts; it does not establish authenticity. */
    public static String fingerprint(String compact) throws LicenseException {
        if (compact == null || compact.isEmpty()) {
            throw new LicenseException(LicenseErrorCode.INVALID_COMPACT);
        }
        if (compact.length() > MAX_COMPACT_LENGTH) {
            throw new LicenseException(LicenseErrorCode.INPUT_TOO_LARGE);
        }
        for (int i = 0; i < compact.length(); i++) {
            if (compact.charAt(i) > 127) {
                throw new LicenseException(LicenseErrorCode.INVALID_COMPACT);
            }
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(compact.getBytes(StandardCharsets.US_ASCII));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                result.append(Character.forDigit((value & 0xff) >>> 4, 16));
                result.append(Character.forDigit(value & 0x0f, 16));
            }
            return result.toString();
        } catch (GeneralSecurityException e) {
            throw new LicenseException(LicenseErrorCode.VERIFICATION_UNAVAILABLE);
        }
    }

    private static Set<String> fields(String... names) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(names)));
    }
}
