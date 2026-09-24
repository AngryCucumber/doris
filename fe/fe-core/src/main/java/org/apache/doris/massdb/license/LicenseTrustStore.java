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
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Explicit operator-installed public keys only; never fetches a certificate-supplied trust root. */
public final class LicenseTrustStore {
    public enum Purpose {
        LICENSE("license"),
        TIME_REPAIR("time_repair");

        private final String wireName;

        Purpose(String wireName) {
            this.wireName = wireName;
        }
    }

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
