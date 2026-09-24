// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Public RFC seeds are test data, never production trust configuration. */
class LicenseFixedVectorTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static JsonNode vectors;
    private static LicenseTrustStore trust;

    @BeforeAll
    static void loadSharedFixture() throws Exception {
        try (InputStream stream = LicenseFixedVectorTest.class.getResourceAsStream(
                "/license/ed25519-fixed-vectors.json")) {
            Assertions.assertNotNull(stream, "Shared fixed-vector test resource is missing");
            vectors = JSON.readTree(stream);
        }
        ObjectNode manifest = JSON.createObjectNode().put("schema_version", 1);
        ArrayNode keys = manifest.putArray("keys");
        for (JsonNode vector : vectors.path("massdb_jws")) {
            keys.addObject().put("kid", vector.path("kid").asText())
                    .put("purpose", vector.path("purpose").asText())
                    .put("public_key_spki", encode(publicKey(vector).getEncoded()));
        }
        trust = LicenseTrustStore.parse(JSON.writeValueAsBytes(manifest));
    }

    @Test
    void matchesPublishedRfc8032KnownAnswers() throws Exception {
        for (JsonNode vector : vectors.path("rfc8032")) {
            byte[] message = hex(vector.path("message_hex").asText());
            byte[] expected = hex(vector.path("signature_hex").asText());
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKeyFromRfc(vector));
            signer.update(message);
            Assertions.assertArrayEquals(expected, signer.sign(), vector.path("name").asText());
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKeyFromRfc(vector));
            verifier.update(message);
            Assertions.assertTrue(verifier.verify(expected));
            expected[32] ^= 1;
            verifier.initVerify(publicKeyFromRfc(vector));
            verifier.update(message);
            Assertions.assertFalse(verifier.verify(expected));
        }
    }

    @Test
    void matchesFrozenLicenseJwsAndVerifiedClaims() throws Exception {
        JsonNode vector = vectors.path("massdb_jws").get(0);
        assertFrozenSignature(vector);
        LicenseDocument document = trust.newLicenseVerifier().verify(vector.path("compact").asText());
        JsonNode claims = JSON.readTree(vector.path("payload_utf8").asText());
        Assertions.assertEquals(claims.path("customer_id").asText(), document.getCustomerId());
        Assertions.assertEquals(claims.path("deployment_id").asText(), document.getDeploymentId().toString());
        Assertions.assertEquals(7, document.getSequence());
        Assertions.assertEquals(3, document.getMaxFeNodes());
        Assertions.assertEquals(8, document.getMaxBeNodes());
        Assertions.assertEquals(1900000000L, document.getExpiresAt());
        Assertions.assertEquals(vector.path("sha256").asText(), document.getFingerprint());
    }

    @Test
    void matchesFrozenRepairJwsAndVerifiedBinding() throws Exception {
        JsonNode vector = vectors.path("massdb_jws").get(1);
        assertFrozenSignature(vector);
        LicenseClockRepairVerifier.Ticket ticket = repairVerifier().verify(vector.path("compact").asText());
        JsonNode challenge = vectors.path("repair_challenge");
        Assertions.assertEquals(challenge.path("deployment_id").asText(), ticket.getDeploymentId().toString());
        Assertions.assertEquals(challenge.path("leader_term").asText(), ticket.getLeaderTerm().toString());
        Assertions.assertEquals(challenge.path("nonce").asText(), ticket.getNonce());
        Assertions.assertEquals(4, ticket.getClockEpoch());
        Assertions.assertEquals(12, ticket.getRepairAuthorizationVersion());
        Assertions.assertEquals(1800086400L, ticket.getExpiresAt());
        Assertions.assertEquals(vector.path("sha256").asText(), ticket.getFingerprint());
    }

    @Test
    void rejectsFrozenVectorsWithChangedPayloadSignatureOrPurpose() throws Exception {
        JsonNode license = vectors.path("massdb_jws").get(0);
        JsonNode repair = vectors.path("massdb_jws").get(1);
        for (JsonNode vector : vectors.path("massdb_jws")) {
            String[] segments = vector.path("compact").asText().split("\\.");
            ObjectNode altered = (ObjectNode) JSON.readTree(vector.path("payload_utf8").asText());
            altered.put("expires_at", altered.path("expires_at").asLong() + 1);
            String modifiedPayload = segments[0] + "." + encode(JSON.writeValueAsBytes(altered)) + "." + segments[2];
            byte[] signature = Base64.getUrlDecoder().decode(segments[2]);
            signature[32] ^= 1;
            String modifiedSignature = segments[0] + "." + segments[1] + "." + encode(signature);
            if ("license".equals(vector.path("purpose").asText())) {
                Assertions.assertThrows(LicenseException.class,
                        () -> trust.newLicenseVerifier().verify(modifiedPayload));
                Assertions.assertThrows(LicenseException.class,
                        () -> trust.newLicenseVerifier().verify(modifiedSignature));
            } else {
                Assertions.assertThrows(LicenseRepairException.class, () -> repairVerifier().verify(modifiedPayload));
                Assertions.assertThrows(LicenseRepairException.class, () -> repairVerifier().verify(modifiedSignature));
            }
        }
        Assertions.assertThrows(LicenseException.class,
                () -> trust.newLicenseVerifier().verify(repair.path("compact").asText()));
        Assertions.assertThrows(LicenseRepairException.class,
                () -> repairVerifier().verify(license.path("compact").asText()));
        LicenseVerifier wrongTrust = new LicenseVerifier(trust.getKeys(LicenseTrustStore.Purpose.TIME_REPAIR));
        Assertions.assertThrows(LicenseException.class, () -> wrongTrust.verify(license.path("compact").asText()));
    }

    private static void assertFrozenSignature(JsonNode vector) throws Exception {
        String input = encode(vector.path("header_utf8").asText().getBytes(StandardCharsets.UTF_8)) + "."
                + encode(vector.path("payload_utf8").asText().getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKeyFromRfc(rfc(vector)));
        signer.update(input.getBytes(StandardCharsets.US_ASCII));
        Assertions.assertEquals(vector.path("compact").asText(), input + "." + encode(signer.sign()));
    }

    private static LicenseClockRepairVerifier repairVerifier() {
        return new LicenseClockRepairVerifier(trust.getKeys(LicenseTrustStore.Purpose.TIME_REPAIR));
    }

    private static JsonNode rfc(JsonNode vector) {
        for (JsonNode candidate : vectors.path("rfc8032")) {
            if (candidate.path("name").asText().equals(vector.path("key_vector").asText())) {
                return candidate;
            }
        }
        throw new AssertionError("Fixed JWS references a missing RFC key");
    }

    private static PrivateKey privateKeyFromRfc(JsonNode vector) throws Exception {
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(
                hex("302e020100300506032b657004220420" + vector.path("seed_hex").asText())));
    }

    private static PublicKey publicKey(JsonNode vector) throws Exception {
        return publicKeyFromRfc(rfc(vector));
    }

    private static PublicKey publicKeyFromRfc(JsonNode vector) throws Exception {
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(
                hex("302a300506032b6570032100" + vector.path("public_key_hex").asText())));
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
