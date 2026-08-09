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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Leader-local short-lived authorization for one exact existing-cluster OBSERVE plan. */
final class MassDbLicenseUpgradeToken {
    static final long MAX_TTL_SECONDS = 900;
    private static final int FIELD_COUNT = 13;
    private static final int MAX_TOKEN_BYTES = 4096;
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private MassDbLicenseUpgradeToken() {
    }

    static final class Claims {
        final String upgradeSessionId;
        final String deploymentUuid;
        final String planSha256;
        final String membershipSha256;
        final String keysetSha256;
        final String inventorySha256;
        final String attestationSha256;
        final long issuedAt;
        final long expiresAt;
        final String nonce;

        Claims(String upgradeSessionId, String deploymentUuid,
                String planSha256, String membershipSha256,
                String keysetSha256, String inventorySha256, String attestationSha256,
                long issuedAt, long expiresAt, String nonce) {
            requireUuidV4(upgradeSessionId, "upgradeSessionId");
            requireUuidV4(deploymentUuid, "deploymentUuid");
            requireSha256(planSha256);
            requireSha256(membershipSha256);
            requireSha256(keysetSha256);
            requireSha256(inventorySha256);
            requireSha256(attestationSha256);
            requireAtom(nonce);
            if (issuedAt <= 0 || expiresAt <= issuedAt
                    || expiresAt - issuedAt > MAX_TTL_SECONDS) {
                fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED",
                        "upgrade token时间范围非法");
            }
            this.upgradeSessionId = upgradeSessionId;
            this.deploymentUuid = deploymentUuid;
            this.planSha256 = planSha256;
            this.membershipSha256 = membershipSha256;
            this.keysetSha256 = keysetSha256;
            this.inventorySha256 = inventorySha256;
            this.attestationSha256 = attestationSha256;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.nonce = nonce;
        }
    }

    static String issue(byte[] key, Claims claims) {
        requireKey(key);
        byte[] payload = serialize(claims).getBytes(StandardCharsets.US_ASCII);
        return ENCODER.encodeToString(payload) + "."
                + ENCODER.encodeToString(hmac(key, payload));
    }

    static Claims verify(byte[] key, String token, long now) {
        requireKey(key);
        if (token == null || token.isEmpty() || token.length() > MAX_TOKEN_BYTES) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED", "upgrade token为空或过长");
        }
        int separator = token.indexOf('.');
        if (separator <= 0 || separator != token.lastIndexOf('.')
                || separator == token.length() - 1) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED", "upgrade token封装错误");
        }
        try {
            String payloadPart = token.substring(0, separator);
            String signaturePart = token.substring(separator + 1);
            byte[] payload = DECODER.decode(payloadPart);
            byte[] signature = DECODER.decode(signaturePart);
            if (!payloadPart.equals(ENCODER.encodeToString(payload))
                    || !signaturePart.equals(ENCODER.encodeToString(signature))
                    || signature.length != 32
                    || !MessageDigest.isEqual(signature, hmac(key, payload))) {
                fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED",
                        "upgrade token认证失败");
            }
            String encoded = new String(payload, StandardCharsets.US_ASCII);
            String[] fields = encoded.split("\\n", -1);
            if (fields.length != FIELD_COUNT || !"1".equals(fields[0])
                    || !"INITIALIZE_OBSERVE".equals(fields[1])) {
                fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED",
                        "upgrade token字段错误");
            }
            Claims claims = new Claims(fields[2], fields[3], fields[4], fields[5],
                    fields[6], fields[7], fields[8], parseLong(fields[9]),
                    parseLong(fields[10]), fields[11]);
            if (!fields[12].isEmpty() || !encoded.equals(serialize(claims))
                    || now < claims.issuedAt || now > claims.expiresAt) {
                fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED",
                        "upgrade token已过期或不是canonical编码");
            }
            return claims;
        } catch (IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED", "upgrade token编码错误");
            return null;
        }
    }

    private static String serialize(Claims value) {
        return "1\nINITIALIZE_OBSERVE\n" + value.upgradeSessionId + "\n"
                + value.deploymentUuid + "\n" + value.planSha256 + "\n"
                + value.membershipSha256 + "\n" + value.keysetSha256 + "\n"
                + value.inventorySha256 + "\n" + value.attestationSha256 + "\n"
                + value.issuedAt + "\n" + value.expiresAt + "\n" + value.nonce + "\n";
    }

    private static byte[] hmac(byte[] key, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("HmacSHA256 unavailable", failure);
        }
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != 32) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED",
                    "upgrade HMAC key长度错误");
        }
    }

    private static void requireUuidV4(String value, String field) {
        try {
            UUID parsed = UUID.fromString(value);
            if (parsed.version() != 4 || parsed.variant() != 2
                    || !parsed.toString().equals(value)) {
                fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED",
                        field + "必须是canonical UUIDv4");
            }
        } catch (NullPointerException | IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED",
                    field + "必须是canonical UUIDv4");
        }
    }

    private static void requireSha256(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED", "upgrade摘要格式错误");
        }
    }

    private static void requireAtom(String value) {
        if (value == null || value.isEmpty() || value.length() > 128) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED", "upgrade nonce非法");
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (item < 0x21 || item > 0x7e || item == '.') {
                fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED", "upgrade nonce非法");
            }
        }
    }

    private static long parseLong(String value) {
        try {
            if (value.isEmpty() || value.length() > 1 && value.charAt(0) == '0') {
                throw new NumberFormatException();
            }
            return Long.parseLong(value);
        } catch (NumberFormatException failure) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED", "upgrade整数编码错误");
            return 0;
        }
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }
}
