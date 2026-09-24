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

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

class LicenseTrustStoreTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private KeyPair licenseKey;
    private KeyPair repairKey;

    @BeforeEach
    void setUp() throws Exception {
        licenseKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        repairKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    @Test
    void loadsPurposeScopedImmutablePublicKeys() throws Exception {
        ObjectNode manifest = manifest();
        byte[] bytes = bytes(manifest);
        LicenseTrustStore store = LicenseTrustStore.parse(bytes);
        Arrays.fill(bytes, (byte) 0);
        Assertions.assertArrayEquals(licenseKey.getPublic().getEncoded(),
                store.getKeys(LicenseTrustStore.Purpose.LICENSE).get("issuer").getEncoded());
        Assertions.assertFalse(store.getKeys(LicenseTrustStore.Purpose.LICENSE).containsKey("repair"));
        Assertions.assertFalse(store.getKeys(LicenseTrustStore.Purpose.TIME_REPAIR).containsKey("issuer"));
        Assertions.assertThrows(UnsupportedOperationException.class,
                () -> store.getKeys(LicenseTrustStore.Purpose.LICENSE).clear());
        Assertions.assertNotNull(store.newLicenseVerifier());
    }

    @Test
    void rejectsDuplicateIdsCrossPurposeMaterialAndPrivateKeys() throws Exception {
        ObjectNode manifest = manifest();
        ((ArrayNode) manifest.get("keys")).add(entry("issuer", "license", repairKey));
        reject(bytes(manifest));
        manifest = manifest();
        ((ArrayNode) manifest.get("keys")).set(1, entry("repair", "time_repair", licenseKey));
        reject(bytes(manifest));
        manifest = manifest();
        ((ObjectNode) manifest.get("keys").get(0)).put("public_key_spki",
                Base64.getUrlEncoder().withoutPadding().encodeToString(licenseKey.getPrivate().getEncoded()));
        reject(bytes(manifest));
    }

    @Test
    void rejectsNoncanonicalDerPaddingWrongAlgorithmAndUnknownPurpose() throws Exception {
        ObjectNode manifest = manifest();
        ObjectNode key = (ObjectNode) manifest.get("keys").get(0);
        key.put("public_key_spki", key.get("public_key_spki").textValue() + "=");
        reject(bytes(manifest));
        manifest = manifest();
        byte[] der = licenseKey.getPublic().getEncoded();
        der[8] = 0x71;
        ((ObjectNode) manifest.get("keys").get(0)).put("public_key_spki",
                Base64.getUrlEncoder().withoutPadding().encodeToString(der));
        reject(bytes(manifest));
        manifest = manifest();
        ((ObjectNode) manifest.get("keys").get(0)).put("purpose", "anything");
        reject(bytes(manifest));
    }

    @Test
    void rejectsMalformedConfigurationWithoutLeakingItsContents() throws Exception {
        String valid = manifest().toString();
        for (String value : new String[] {"null", "[]", "{}", valid + " {}",
                valid.replace("\"schema_version\":1", "\"schema_version\":true"),
                valid.replace("\"schema_version\":1", "\"schema_version\":2"),
                valid.replace("\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1"),
                valid.replace("\"schema_version\":1", "\"schema_version\":1,\"private_key\":\"SECRET\"")}) {
            reject(value.getBytes(StandardCharsets.UTF_8));
        }
        reject(new byte[] {(byte) 0xc3, (byte) 0x28});
        reject(new byte[65537]);
        reject(null);
        ObjectNode manifest = manifest();
        manifest.putArray("keys");
        reject(bytes(manifest));
        ArrayNode keys = manifest.putArray("keys");
        for (int i = 0; i < 33; i++) {
            keys.add(entry("key-" + i, "license", licenseKey));
        }
        reject(bytes(manifest));
    }

    @Test
    void retainsExpiredCapacityAndHistoricalArchiveKeysDuringRotation() throws Exception {
        LicenseTrustStore old = LicenseTrustStore.parse(bytes(manifest()));
        ObjectNode replacement = manifest();
        ArrayNode entries = replacement.putArray("keys");
        entries.add(entry("new-issuer", "license", KeyPairGenerator.getInstance("Ed25519").generateKeyPair()));
        entries.add(entry("repair", "time_repair", repairKey));
        LicenseTrustStore retired = LicenseTrustStore.parse(bytes(replacement));
        LicenseDocument expiredBase = new LicenseDocument(UUID.randomUUID(), "old", "issuer", "customer",
                "edition", "issuer", "fingerprint", 0, 0, 1, 1, 3, 10,
                Collections.singleton("DATA_QUERY"));
        Assertions.assertEquals(LicenseErrorCode.KEY_STILL_REQUIRED, Assertions.assertThrows(LicenseException.class,
                () -> old.requireSafeReplacement(retired, Collections.singleton(expiredBase),
                        Collections.emptySet(), Collections.emptySet())).getErrorCode());
        Assertions.assertThrows(LicenseException.class, () -> old.requireSafeReplacement(retired,
                Collections.emptyList(), Collections.singleton("issuer"), Collections.emptySet()));
        old.requireSafeReplacement(retired, Collections.emptyList(), Collections.emptySet(),
                Collections.singleton("repair"));
        entries.add(entry("issuer", "license", licenseKey));
        old.requireSafeReplacement(LicenseTrustStore.parse(bytes(replacement)),
                Collections.singleton(expiredBase), Collections.singleton("issuer"),
                Collections.singleton("repair"));
    }

    @Test
    void rejectsChangingTheMeaningOfAnExistingKeyId() throws Exception {
        LicenseTrustStore old = LicenseTrustStore.parse(bytes(manifest()));
        ObjectNode replacement = manifest();
        ((ArrayNode) replacement.get("keys")).set(0,
                entry("issuer", "license", KeyPairGenerator.getInstance("Ed25519").generateKeyPair()));
        LicenseTrustStore changed = LicenseTrustStore.parse(bytes(replacement));
        Assertions.assertThrows(LicenseException.class, () -> old.requireSafeReplacement(changed,
                Collections.emptyList(), Collections.emptySet(), Collections.emptySet()));
        replacement.putArray("keys").add(entry("issuer", "time_repair", licenseKey));
        LicenseTrustStore repurposed = LicenseTrustStore.parse(bytes(replacement));
        Assertions.assertThrows(LicenseException.class, () -> old.requireSafeReplacement(repurposed,
                Collections.emptyList(), Collections.emptySet(), Collections.emptySet()));
        replacement.putArray("keys").add(entry("renamed-repair", "time_repair", licenseKey));
        LicenseTrustStore renamed = LicenseTrustStore.parse(bytes(replacement));
        Assertions.assertThrows(LicenseException.class, () -> old.requireSafeReplacement(renamed,
                Collections.emptyList(), Collections.emptySet(), Collections.emptySet()));
    }

    private ObjectNode manifest() {
        ObjectNode result = JSON.createObjectNode().put("schema_version", 1);
        result.putArray("keys").add(entry("issuer", "license", licenseKey))
                .add(entry("repair", "time_repair", repairKey));
        return result;
    }

    private ObjectNode entry(String id, String purpose, KeyPair key) {
        return JSON.createObjectNode().put("kid", id).put("purpose", purpose).put("public_key_spki",
                Base64.getUrlEncoder().withoutPadding().encodeToString(key.getPublic().getEncoded()));
    }

    private byte[] bytes(ObjectNode object) {
        return object.toString().getBytes(StandardCharsets.UTF_8);
    }

    private void reject(byte[] bytes) {
        LicenseException error = Assertions.assertThrows(LicenseException.class, () -> LicenseTrustStore.parse(bytes));
        Assertions.assertEquals(LicenseErrorCode.INVALID_TRUST_STORE, error.getErrorCode());
        Assertions.assertNull(error.getCause());
        Assertions.assertFalse(error.toString().contains("SECRET"));
    }
}
