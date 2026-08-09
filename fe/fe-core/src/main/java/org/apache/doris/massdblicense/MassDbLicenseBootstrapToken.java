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

/** HMAC-authenticated, short-lived authorization for exactly one bootstrap plan snapshot. */
public final class MassDbLicenseBootstrapToken {
    public static final long MAX_TTL_SECONDS = 900;
    private static final int FIELD_COUNT = 13;
    private static final int MAX_TOKEN_BYTES = 4096;
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private MassDbLicenseBootstrapToken() {
    }

    public static final class Claims {
        public final String bootstrapMarkerId;
        public final String deploymentUuid;
        public final String planSha256;
        public final String keysetSha256;
        public final String inventorySha256;
        public final long topologyRevision;
        public final long bootstrapSealGeneration;
        public final long issuedAt;
        public final long expiresAt;
        public final String nonce;

        public Claims(String bootstrapMarkerId, String deploymentUuid,
                String planSha256, String keysetSha256, String inventorySha256,
                long topologyRevision, long bootstrapSealGeneration,
                long issuedAt, long expiresAt, String nonce) {
            requireUuidV4(bootstrapMarkerId, "bootstrapMarkerId");
            requireUuidV4(deploymentUuid, "deploymentUuid");
            requireSha256(planSha256);
            requireSha256(keysetSha256);
            requireSha256(inventorySha256);
            requireAtom(nonce, "nonce");
            if (topologyRevision < 0 || bootstrapSealGeneration != 0 || issuedAt < 0
                    || expiresAt <= issuedAt || expiresAt - issuedAt > MAX_TTL_SECONDS) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED",
                        "bootstrap token revision、generation或时间非法");
            }
            this.bootstrapMarkerId = bootstrapMarkerId;
            this.deploymentUuid = deploymentUuid;
            this.planSha256 = planSha256.toLowerCase();
            this.keysetSha256 = keysetSha256.toLowerCase();
            this.inventorySha256 = inventorySha256.toLowerCase();
            this.topologyRevision = topologyRevision;
            this.bootstrapSealGeneration = bootstrapSealGeneration;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.nonce = nonce;
        }
    }

    public static String issue(byte[] key, Claims claims) {
        requireKey(key);
        if (claims == null) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", "bootstrap claims不能为空");
        }
        byte[] payload = serialize(claims).getBytes(StandardCharsets.US_ASCII);
        return ENCODER.encodeToString(payload) + "." + ENCODER.encodeToString(hmac(key, payload));
    }

    public static Claims verify(byte[] key, String token, long now) {
        requireKey(key);
        if (token == null || token.isEmpty() || token.length() > MAX_TOKEN_BYTES) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", "bootstrap token为空或过长");
        }
        int separator = token.indexOf('.');
        if (separator <= 0 || separator != token.lastIndexOf('.')
                || separator == token.length() - 1) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", "bootstrap token封装错误");
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
                fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", "bootstrap token认证失败");
            }
            String encoded = new String(payload, StandardCharsets.US_ASCII);
            String[] fields = encoded.split("\\n", -1);
            if (fields.length != FIELD_COUNT || !"1".equals(fields[0])
                    || !"BOOTSTRAP_CONTROL".equals(fields[1]) || !"SEAL".equals(fields[2])) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", "bootstrap token字段错误");
            }
            Claims claims = new Claims(fields[3], fields[4], fields[5], fields[6], fields[7],
                    parseLong(fields[8]), parseLong(fields[9]), parseLong(fields[10]),
                    parseLong(fields[11]), fields[12]);
            if (!encoded.equals(serialize(claims)) || now < claims.issuedAt
                    || now > claims.expiresAt) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED",
                        "bootstrap token已过期或不是canonical编码");
            }
            return claims;
        } catch (IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", "bootstrap token编码错误");
            return null;
        }
    }

    private static String serialize(Claims value) {
        return "1\nBOOTSTRAP_CONTROL\nSEAL\n" + value.bootstrapMarkerId + "\n"
                + value.deploymentUuid + "\n" + value.planSha256 + "\n"
                + value.keysetSha256 + "\n" + value.inventorySha256 + "\n"
                + value.topologyRevision + "\n" + value.bootstrapSealGeneration + "\n"
                + value.issuedAt + "\n" + value.expiresAt + "\n" + value.nonce;
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
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", "bootstrap HMAC key长度错误");
        }
    }

    private static void requireUuidV4(String value, String field) {
        try {
            UUID uuid = UUID.fromString(value);
            if (uuid.version() != 4 || !uuid.toString().equals(value)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED",
                        field + "必须是canonical UUIDv4");
            }
        } catch (NullPointerException | IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED",
                    field + "必须是canonical UUIDv4");
        }
    }

    private static void requireSha256(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", "bootstrap SHA-256格式错误");
        }
    }

    private static void requireAtom(String value, String field) {
        if (value == null || value.isEmpty() || value.length() > 128) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", field + "为空或过长");
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (item < 0x21 || item > 0x7e || item == '.') {
                fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", field + "不是安全ASCII atom");
            }
        }
    }

    private static long parseLong(String value) {
        try {
            if (value.isEmpty() || (value.length() > 1 && value.charAt(0) == '0')) {
                throw new NumberFormatException();
            }
            return Long.parseLong(value);
        } catch (NumberFormatException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED", "bootstrap整数编码错误");
            return 0;
        }
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }
}
