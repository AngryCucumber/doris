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
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Public keys pinned into doris-fe.jar plus optional operator-installed keys; never fetches a
 * certificate-supplied trust root. The built-in keys are Java constants, so a same-named file placed
 * ahead of the jar on the classpath cannot replace them. The classpath resource of the same bytes is
 * kept only as the source of the package's conf/massdb-license-trust.json, which earlier FE versions
 * still read after a downgrade; a test pins the two together.
 */
public final class LicenseTrustStore {
    public enum Purpose {
        LICENSE("license"),
        TIME_REPAIR("time_repair"),
        /** Signs trust manifests that add operator-installed keys; never signs certificates or repair tickets. */
        TRUST("trust");

        private final String wireName;

        Purpose(String wireName) {
            this.wireName = wireName;
        }
    }

    static final String BUILT_IN_RESOURCE = "/massdb/license/builtin-trust.json";
    static final String BUILT_IN_LICENSE_KID = "self-use-license-20260929";
    static final String BUILT_IN_LICENSE_SPKI = "MCowBQYDK2VwAyEA296WLuNZLjs6LA9W0zT9v7-GdARgBW6_3tH5S7IiGJM";
    static final String BUILT_IN_TIME_REPAIR_KID = "self-use-time-repair-20260929";
    static final String BUILT_IN_TIME_REPAIR_SPKI = "MCowBQYDK2VwAyEAeYQAth424gsdEXXECoWO_l0cbFbazelUYDRZsXv4IPQ";
    static final String BUILT_IN_TRUST_KID = "self-use-trust-20261023";
    static final String BUILT_IN_TRUST_SPKI = "MCowBQYDK2VwAyEADDXdmbbtopojcR0sua1IX_4AujVELAchcYO5PfnSHxY";
    /** Compact JWS type of a signed trust manifest. */
    public static final String SIGNED_MANIFEST_TYPE = "massdb-trust+jws";
    private static final int MAX_MANIFEST_BYTES = 65536;
    private static final byte[] ED25519_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
            0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(5)
                    .maxDocumentLength(65536).maxNumberLength(20).maxStringLength(256)
                    .maxNameLength(32).build()).build());

    private final Map<Purpose, Map<String, PublicKey>> keys;

    private LicenseTrustStore(Map<Purpose, Map<String, PublicKey>> keys) {
        Map<Purpose, Map<String, PublicKey>> copy = new EnumMap<>(Purpose.class);
        for (Purpose purpose : Purpose.values()) {
            copy.put(purpose, Collections.unmodifiableMap(new HashMap<>(keys.get(purpose))));
        }
        this.keys = Collections.unmodifiableMap(copy);
    }

    /** Bounded UTF-8 manifest; malformed configuration exposes no input or provider exception. */
    public static LicenseTrustStore parse(byte[] manifest) throws LicenseException {
        if (manifest == null || manifest.length == 0 || manifest.length > 65536) {
            throw invalid();
        }
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(manifest)).toString();
            JsonNode root;
            try (JsonParser parser = JSON.createParser(text)) {
                root = JSON.readTree(parser);
                if (parser.nextToken() != null) {
                    throw invalid();
                }
            }
            fields(root, "schema_version", "keys");
            if (!root.get("schema_version").isIntegralNumber() || !root.get("schema_version").canConvertToInt()
                    || root.get("schema_version").intValue() != 1) {
                throw invalid();
            }
            JsonNode entries = root.get("keys");
            if (!entries.isArray() || entries.isEmpty() || entries.size() > 32) {
                throw invalid();
            }
            Map<Purpose, Map<String, PublicKey>> keys = new EnumMap<>(Purpose.class);
            for (Purpose purpose : Purpose.values()) {
                keys.put(purpose, new HashMap<>());
            }
            Set<String> ids = new HashSet<>();
            Map<String, Purpose> keyPurposes = new HashMap<>();
            KeyFactory factory = KeyFactory.getInstance("Ed25519");
            for (JsonNode entry : entries) {
                fields(entry, "kid", "purpose", "public_key_spki");
                String id = entry.get("kid").textValue();
                if (!LicenseText.matches(id, 128, true) || !ids.add(id)) {
                    throw invalid();
                }
                Purpose purpose = purpose(entry.get("purpose").textValue());
                String encoded = entry.get("public_key_spki").textValue();
                if (encoded == null || !encoded.matches("[A-Za-z0-9_-]{59}")) {
                    throw invalid();
                }
                byte[] bytes = Base64.getUrlDecoder().decode(encoded);
                if (bytes.length != 44 || !Arrays.equals(ED25519_PREFIX, Arrays.copyOf(bytes, 12))
                        || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(encoded)) {
                    throw invalid();
                }
                Purpose previous = keyPurposes.put(encoded, purpose);
                if (previous != null && previous != purpose) {
                    throw invalid();
                }
                keys.get(purpose).put(id, factory.generatePublic(new X509EncodedKeySpec(bytes)));
            }
            return new LicenseTrustStore(keys);
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw invalid();
        }
    }

    /**
     * The keys compiled into doris-fe.jar; no classpath lookup, so conf/ cannot shadow them. The trust key is not
     * part of the shipped plain manifest because earlier FEs reject a purpose they do not know.
     */
    public static LicenseTrustStore builtIn() throws LicenseException {
        String trustEntry = "{\"kid\":\"" + BUILT_IN_TRUST_KID + "\",\"public_key_spki\":\"" + BUILT_IN_TRUST_SPKI
                + "\",\"purpose\":\"trust\"}";
        return parse(("{\"keys\":[" + builtInEntries() + "," + trustEntry + "],\"schema_version\":1}")
                .getBytes(StandardCharsets.UTF_8));
    }

    /** The pinned plain manifest, byte for byte the shipped conf/massdb-license-trust.json that earlier FEs read. */
    static byte[] builtInManifest() {
        return ("{\"keys\":[" + builtInEntries() + "],\"schema_version\":1}").getBytes(StandardCharsets.UTF_8);
    }

    private static String builtInEntries() {
        return "{\"kid\":\"" + BUILT_IN_LICENSE_KID + "\",\"public_key_spki\":\"" + BUILT_IN_LICENSE_SPKI
                + "\",\"purpose\":\"license\"},{\"kid\":\"" + BUILT_IN_TIME_REPAIR_KID + "\",\"public_key_spki\":\""
                + BUILT_IN_TIME_REPAIR_SPKI + "\",\"purpose\":\"time_repair\"}";
    }

    /**
     * Verify a signed trust manifest (compact JWS, type massdb-trust+jws) against this store's trust keys and
     * return the keys it carries. The payload is {schema_version, issued_at, sequence, keys}; issued_at and
     * sequence are the issuer's bookkeeping and are only type-checked here. Every failure is an exception without
     * input or provider details; nothing is trusted on failure.
     */
    public LicenseTrustStore verifySigned(byte[] compact) throws LicenseException {
        if (compact == null || compact.length == 0 || compact.length > MAX_MANIFEST_BYTES) {
            throw invalid();
        }
        String text;
        try {
            text = StandardCharsets.US_ASCII.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(compact)).toString().trim();
        } catch (java.nio.charset.CharacterCodingException e) {
            throw invalid();
        }
        String[] segments = text.split("\\.", -1);
        if (segments.length != 3) {
            throw invalid();
        }
        byte[] header = decodeSegment(segments[0]);
        byte[] payload = decodeSegment(segments[1]);
        byte[] signature = decodeSegment(segments[2]);
        if (signature.length != 64) {
            throw new LicenseException(LicenseErrorCode.INVALID_SIGNATURE);
        }
        try {
            JsonNode headerNode = readObject(header);
            fields(headerNode, "alg", "typ", "kid");
            if (!"Ed25519".equals(headerNode.get("alg").textValue())
                    || !SIGNED_MANIFEST_TYPE.equals(headerNode.get("typ").textValue())) {
                throw invalid();
            }
            String kid = headerNode.get("kid").textValue();
            if (!LicenseText.matches(kid, 128, true)) {
                throw invalid();
            }
            PublicKey signer = getKeys(Purpose.TRUST).get(kid);
            if (signer == null) {
                throw new LicenseException(LicenseErrorCode.UNTRUSTED_KEY);
            }
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(signer);
            verifier.update((segments[0] + "." + segments[1]).getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(signature)) {
                throw new LicenseException(LicenseErrorCode.INVALID_SIGNATURE);
            }
            JsonNode claims = readObject(payload);
            fields(claims, "schema_version", "issued_at", "sequence", "keys");
            for (String name : new String[] {"schema_version", "issued_at", "sequence"}) {
                JsonNode value = claims.get(name);
                if (!value.isIntegralNumber() || !value.canConvertToLong() || value.longValue() < 0) {
                    throw invalid();
                }
            }
            if (claims.get("schema_version").intValue() != 1 || claims.get("sequence").longValue() < 1) {
                throw invalid();
            }
            ObjectNode manifest = JSON.createObjectNode();
            manifest.put("schema_version", 1);
            manifest.set("keys", claims.get("keys"));
            return parse(JSON.writeValueAsBytes(manifest));
        } catch (LicenseException e) {
            throw e;
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw invalid();
        }
    }

    /** Entries of another store that this store does not already hold with the same purpose and key bytes. */
    public List<String> extraKeys(LicenseTrustStore other) {
        List<String> extra = new ArrayList<>();
        for (Purpose purpose : Purpose.values()) {
            for (Map.Entry<String, PublicKey> entry : other.getKeys(purpose).entrySet()) {
                PublicKey held = getKeys(purpose).get(entry.getKey());
                if (held == null || !Arrays.equals(held.getEncoded(), entry.getValue().getEncoded())) {
                    extra.add(purpose.wireName + ":" + entry.getKey());
                }
            }
        }
        Collections.sort(extra);
        return extra;
    }

    private static byte[] decodeSegment(String segment) throws LicenseException {
        if (segment.isEmpty() || !segment.matches("[A-Za-z0-9_-]+")) {
            throw invalid();
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(segment);
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(segment)) {
                throw invalid();
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            throw invalid();
        }
    }

    private static JsonNode readObject(byte[] bytes) throws IOException, LicenseException {
        String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        try (JsonParser parser = JSON.createParser(text)) {
            JsonNode node = JSON.readTree(parser);
            if (node == null || !node.isObject() || parser.nextToken() != null) {
                throw invalid();
            }
            return node;
        }
    }

    /**
     * Add operator-installed keys. A key ID or key value never changes meaning: one ID carries one key and purpose,
     * and one key is never trusted for two purposes. A conflict rejects the added keys as a whole.
     */
    public LicenseTrustStore merge(LicenseTrustStore added) throws LicenseException {
        if (added == null) {
            throw invalid();
        }
        Map<Purpose, Map<String, PublicKey>> merged = new EnumMap<>(Purpose.class);
        for (Purpose purpose : Purpose.values()) {
            merged.put(purpose, new HashMap<>());
        }
        Map<String, Purpose> keyPurposes = new HashMap<>();
        for (LicenseTrustStore store : new LicenseTrustStore[] {this, added}) {
            for (Purpose purpose : Purpose.values()) {
                for (Map.Entry<String, PublicKey> entry : store.getKeys(purpose).entrySet()) {
                    for (Purpose other : Purpose.values()) {
                        if (other != purpose && merged.get(other).containsKey(entry.getKey())) {
                            throw invalid();
                        }
                    }
                    PublicKey existing = merged.get(purpose).get(entry.getKey());
                    if (existing != null && !Arrays.equals(existing.getEncoded(), entry.getValue().getEncoded())) {
                        throw invalid();
                    }
                    Purpose previous = keyPurposes.put(encode(entry.getValue()), purpose);
                    if (previous != null && previous != purpose) {
                        throw invalid();
                    }
                    merged.get(purpose).put(entry.getKey(), entry.getValue());
                }
            }
        }
        return new LicenseTrustStore(merged);
    }

    /** SHA-256 of the effective key set, independent of manifest formatting, field order or key order. */
    public String digest() {
        List<String> entries = new ArrayList<>();
        for (Purpose purpose : Purpose.values()) {
            for (Map.Entry<String, PublicKey> entry : getKeys(purpose).entrySet()) {
                entries.add(purpose.wireName + "\n" + entry.getKey() + "\n" + encode(entry.getValue()));
            }
        }
        Collections.sort(entries);
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (String entry : entries) {
                sha.update(entry.getBytes(StandardCharsets.UTF_8));
                sha.update((byte) 0);
            }
            StringBuilder result = new StringBuilder(64);
            for (byte value : sha.digest()) {
                result.append(Character.forDigit((value >>> 4) & 15, 16)).append(Character.forDigit(value & 15, 16));
            }
            return result.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("JDK SHA-256 unavailable", e);
        }
    }

    private static String encode(PublicKey key) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key.getEncoded());
    }

    public Map<String, PublicKey> getKeys(Purpose purpose) {
        return keys.get(purpose);
    }

    public LicenseVerifier newLicenseVerifier() {
        return new LicenseVerifier(getKeys(Purpose.LICENSE));
    }

    /**
     * Check before installing a replacement. The caller supplies all retained image/journal key
     * dependencies, including expired base capacity and repair receipts, not just live queries.
     * An empty dependency set is only correct after archives have been retired or re-signed.
     */
    public void requireSafeReplacement(LicenseTrustStore replacement, Collection<LicenseDocument> retained,
            Set<String> archivedLicenseKeys, Set<String> archivedRepairKeys) throws LicenseException {
        if (replacement == null || retained == null || archivedLicenseKeys == null || archivedRepairKeys == null) {
            throw invalid();
        }
        // A key identifier never silently changes meaning during an overlap upgrade.
        for (Purpose purpose : Purpose.values()) {
            for (Map.Entry<String, PublicKey> old : getKeys(purpose).entrySet()) {
                PublicKey next = replacement.getKeys(purpose).get(old.getKey());
                Purpose other = purpose == Purpose.LICENSE ? Purpose.TIME_REPAIR : Purpose.LICENSE;
                if (replacement.getKeys(other).containsKey(old.getKey())
                        || (next != null && !Arrays.equals(old.getValue().getEncoded(), next.getEncoded()))) {
                    throw new LicenseException(LicenseErrorCode.KEY_STILL_REQUIRED);
                }
                for (PublicKey otherKey : replacement.getKeys(other).values()) {
                    if (Arrays.equals(old.getValue().getEncoded(), otherKey.getEncoded())) {
                        throw new LicenseException(LicenseErrorCode.KEY_STILL_REQUIRED);
                    }
                }
            }
        }
        Set<String> required = new HashSet<>(archivedLicenseKeys);
        for (LicenseDocument document : retained) {
            if (document != null) {
                required.add(document.getKeyId());
            }
        }
        requireKeys(replacement, Purpose.LICENSE, required);
        requireKeys(replacement, Purpose.TIME_REPAIR, archivedRepairKeys);
    }

    private void requireKeys(LicenseTrustStore replacement, Purpose purpose, Set<String> required)
            throws LicenseException {
        for (String id : required) {
            PublicKey old = getKeys(purpose).get(id);
            PublicKey next = replacement.getKeys(purpose).get(id);
            if (old == null || next == null || !Arrays.equals(old.getEncoded(), next.getEncoded())) {
                throw new LicenseException(LicenseErrorCode.KEY_STILL_REQUIRED);
            }
        }
    }

    private static Purpose purpose(String name) throws LicenseException {
        for (Purpose purpose : Purpose.values()) {
            if (purpose.wireName.equals(name)) {
                return purpose;
            }
        }
        throw invalid();
    }

    private static void fields(JsonNode object, String... names) throws LicenseException {
        if (object == null || !object.isObject() || object.size() != names.length) {
            throw invalid();
        }
        for (String name : names) {
            if (!object.has(name)) {
                throw invalid();
            }
        }
    }

    private static LicenseException invalid() {
        return new LicenseException(LicenseErrorCode.INVALID_TRUST_STORE);
    }
}
