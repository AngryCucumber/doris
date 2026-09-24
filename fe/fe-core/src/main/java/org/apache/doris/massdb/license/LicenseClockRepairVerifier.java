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
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Separate purpose and parser boundary for offline, one-time clock repair authorizations. */
public final class LicenseClockRepairVerifier {
    public static final String TYPE = "massdb-license-clock-repair+jws";
    public static final int MAX_COMPACT_LENGTH = 16 * 1024;
    public static final long MAX_WINDOW_SECONDS = 86400L;
    private static final Set<String> HEADER_FIELDS = fields("typ", "alg", "kid");
    private static final Set<String> CLAIM_FIELDS = fields("schema_version", "product", "deployment_id", "repair_id",
            "nonce", "clock_epoch", "repair_authorization_version", "leader_term", "issued_at", "not_before",
            "expires_at");
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(4).maxDocumentLength(MAX_COMPACT_LENGTH)
                    .maxNumberLength(20).maxStringLength(1024).maxNameLength(128).build()).build());
    private final Map<String, PublicKey> repairKeys;

    /** The caller supplies only purpose=time_repair keys, never the general license key set. */
    public LicenseClockRepairVerifier(Map<String, PublicKey> repairKeys) {
        if (repairKeys == null) {
            throw new IllegalArgumentException("Repair-purpose key set required");
        }
        Map<String, PublicKey> copy = new HashMap<>();
        try {
            KeyFactory factory = KeyFactory.getInstance("Ed25519");
            for (Map.Entry<String, PublicKey> entry : repairKeys.entrySet()) {
                if (!LicenseText.matches(entry.getKey(), 128, true) || entry.getValue() == null
                        || entry.getValue().getEncoded() == null) {
                    throw new IllegalArgumentException("Invalid repair-purpose key");
                }
                copy.put(entry.getKey(), factory.generatePublic(new X509EncodedKeySpec(entry.getValue().getEncoded())));
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid repair-purpose key");
        }
        this.repairKeys = Collections.unmodifiableMap(copy);
    }

    /** Does not consult either the polluted watermark or wall time. */
    public Ticket verify(String compact) throws LicenseRepairException {
        if (compact == null || compact.isEmpty() || compact.length() > MAX_COMPACT_LENGTH) {
            throw invalid();
        }
        for (int i = 0; i < compact.length(); i++) {
            if (compact.charAt(i) > 127) {
                throw invalid();
            }
        }
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 3) {
            throw invalid();
        }
        JsonNode header = object(decode(parts[0]));
        requireFields(header, HEADER_FIELDS);
        if (!TYPE.equals(header.path("typ").textValue()) || !"Ed25519".equals(header.path("alg").textValue())) {
            throw invalid();
        }
        String kid = text(header, "kid", 128);
        PublicKey key = repairKeys.get(kid);
        if (key == null) {
            throw new LicenseRepairException(LicenseRepairException.Code.UNTRUSTED_REPAIR_KEY);
        }
        byte[] signature = decode(parts[2]);
        if (signature.length != 64) {
            throw invalid();
        }
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(signature)) {
                throw invalid();
            }
        } catch (SignatureException e) {
            throw invalid();
        } catch (GeneralSecurityException e) {
            throw new LicenseRepairException(LicenseRepairException.Code.VERIFICATION_UNAVAILABLE);
        }
        JsonNode claims = object(decode(parts[1]));
        requireFields(claims, CLAIM_FIELDS);
        if (number(claims, "schema_version", 1, 1) != 1
                || !"MassDB SQL".equals(claims.path("product").textValue())) {
            throw invalid();
        }
        UUID deployment = uuid(claims, "deployment_id");
        UUID repairId = uuid(claims, "repair_id");
        UUID term = uuid(claims, "leader_term");
        String nonce = text(claims, "nonce", 43);
        if (decode(nonce).length != 32) {
            throw invalid();
        }
        long epoch = number(claims, "clock_epoch", 0, Long.MAX_VALUE - 1);
        long authorization = number(claims, "repair_authorization_version", 1, Long.MAX_VALUE - 1);
        long issued = number(claims, "issued_at", 0, LicenseVerifier.MAX_EPOCH_SECOND);
        long from = number(claims, "not_before", 0, LicenseVerifier.MAX_EPOCH_SECOND);
        long until = number(claims, "expires_at", 0, LicenseVerifier.MAX_EPOCH_SECOND);
        if (from >= until || until - from > MAX_WINDOW_SECONDS || issued > until) {
            throw invalid();
        }
        return new Ticket(deployment, repairId, term, nonce, epoch, authorization, issued, from, until, kid,
                fingerprint(compact));
    }

    public static final class Ticket {
        private final UUID deploymentId;
        private final UUID repairId;
        private final UUID leaderTerm;
        private final String nonce;
        private final long clockEpoch;
        private final long repairAuthorizationVersion;
        private final long issuedAt;
        private final long notBefore;
        private final long expiresAt;
        private final String keyId;
        private final String fingerprint;

        private Ticket(UUID deploymentId, UUID repairId, UUID leaderTerm, String nonce, long clockEpoch,
                long repairAuthorizationVersion, long issuedAt, long notBefore, long expiresAt, String keyId,
                String fingerprint) {
            this.deploymentId = deploymentId;
            this.repairId = repairId;
            this.leaderTerm = leaderTerm;
            this.nonce = nonce;
            this.clockEpoch = clockEpoch;
            this.repairAuthorizationVersion = repairAuthorizationVersion;
            this.issuedAt = issuedAt;
            this.notBefore = notBefore;
            this.expiresAt = expiresAt;
            this.keyId = keyId;
            this.fingerprint = fingerprint;
        }

        public UUID getDeploymentId() {
            return deploymentId;
        }

        public UUID getRepairId() {
            return repairId;
        }

        public UUID getLeaderTerm() {
            return leaderTerm;
        }

        public String getNonce() {
            return nonce;
        }

        public long getClockEpoch() {
            return clockEpoch;
        }

        public long getRepairAuthorizationVersion() {
            return repairAuthorizationVersion;
        }

        public long getIssuedAt() {
            return issuedAt;
        }

        public long getNotBefore() {
            return notBefore;
        }

        public long getExpiresAt() {
            return expiresAt;
        }

        public String getKeyId() {
            return keyId;
        }

        public String getFingerprint() {
            return fingerprint;
        }
    }

    private static String fingerprint(String compact) throws LicenseRepairException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(compact.getBytes(StandardCharsets.US_ASCII));
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest) {
                result.append(String.format("%02x", value & 255));
            }
            return result.toString();
        } catch (GeneralSecurityException e) {
            throw new LicenseRepairException(LicenseRepairException.Code.VERIFICATION_UNAVAILABLE);
        }
    }

    private static Set<String> fields(String... fields) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(fields)));
    }

    private static void requireFields(JsonNode value, Set<String> expected) throws LicenseRepairException {
        if (!value.isObject() || value.size() != expected.size()) {
            throw invalid();
        }
        Iterator<String> names = value.fieldNames();
        while (names.hasNext()) {
            if (!expected.contains(names.next())) {
                throw invalid();
            }
        }
    }

    private static String text(JsonNode node, String name, int max) throws LicenseRepairException {
        JsonNode value = node.get(name);
        if (value == null || !value.isTextual() || !LicenseText.matches(value.textValue(), max, true)) {
            throw invalid();
        }
        return value.textValue();
    }

    private static long number(JsonNode node, String name, long min, long max) throws LicenseRepairException {
        JsonNode value = node.get(name);
        if (value == null || !value.isIntegralNumber() || !value.canConvertToLong()
                || value.longValue() < min || value.longValue() > max) {
            throw invalid();
        }
        return value.longValue();
    }

    private static UUID uuid(JsonNode node, String name) throws LicenseRepairException {
        String value = text(node, name, 36);
        try {
            UUID result = UUID.fromString(value);
            if (!result.toString().equals(value)) {
                throw invalid();
            }
            return result;
        } catch (IllegalArgumentException e) {
            throw invalid();
        }
    }

    private static byte[] decode(String text) throws LicenseRepairException {
        if (text.isEmpty()) {
            throw invalid();
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9')
                    && c != '-' && c != '_') {
                throw invalid();
            }
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(text);
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(text)) {
                throw invalid();
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            throw invalid();
        }
    }

    private static JsonNode object(byte[] bytes) throws LicenseRepairException {
        String input;
        try {
            input = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw invalid();
        }
        try (JsonParser parser = JSON.createParser(input)) {
            JsonNode value = JSON.readTree(parser);
            if (value == null || !value.isObject() || parser.nextToken() != null) {
                throw invalid();
            }
            return value;
        } catch (IOException e) {
            throw invalid();
        }
    }

    private static LicenseRepairException invalid() {
        return new LicenseRepairException(LicenseRepairException.Code.INVALID_TICKET);
    }
}
