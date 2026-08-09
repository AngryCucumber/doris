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
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Component-local HMAC authenticated opaque token returned by validate and consumed by import. */
public final class MassDbLicensePreconditionToken {
    public static final long MAX_TTL_SECONDS = 900;
    private static final int FIELD_COUNT = 15;
    private static final int MAX_TOKEN_BYTES = 4096;
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private MassDbLicensePreconditionToken() {
    }

    public static final class Claims {
        private final String audience;
        private final String action;
        private final String activeSha256;
        private final Long activeExpiresAt;
        private final long enforcementEpoch;
        private final long topologyRevision;
        private final String inventorySnapshotSha256;
        private final String routingEvidenceSnapshotSha256;
        private final String candidateSha256;
        private final long candidateIssuedAt;
        private final long candidateExpiresAt;
        private final long tokenIssuedAt;
        private final long tokenExpiresAt;
        private final String nonce;

        public Claims(String audience, String action, String activeSha256, Long activeExpiresAt,
                long enforcementEpoch, long topologyRevision, String inventorySnapshotSha256,
                String routingEvidenceSnapshotSha256, String candidateSha256,
                long candidateIssuedAt, long candidateExpiresAt, long tokenIssuedAt,
                long tokenExpiresAt, String nonce) {
            requireAtom(audience, "audience");
            requireAtom(action, "action");
            requireNullableSha256(activeSha256);
            requireSha256(inventorySnapshotSha256);
            requireSha256(routingEvidenceSnapshotSha256);
            requireSha256(candidateSha256);
            requireAtom(nonce, "nonce");
            if (enforcementEpoch < 0 || topologyRevision < 0 || candidateIssuedAt < 0
                    || candidateExpiresAt <= candidateIssuedAt || tokenIssuedAt < 0
                    || tokenExpiresAt <= tokenIssuedAt
                    || tokenExpiresAt - tokenIssuedAt > MAX_TTL_SECONDS
                    || (activeExpiresAt != null && activeExpiresAt < 0)) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition claims时间或epoch错误");
            }
            this.audience = audience;
            this.action = action;
            this.activeSha256 = activeSha256 == null ? null : activeSha256.toLowerCase();
            this.activeExpiresAt = activeExpiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.topologyRevision = topologyRevision;
            this.inventorySnapshotSha256 = inventorySnapshotSha256.toLowerCase();
            this.routingEvidenceSnapshotSha256 = routingEvidenceSnapshotSha256.toLowerCase();
            this.candidateSha256 = candidateSha256.toLowerCase();
            this.candidateIssuedAt = candidateIssuedAt;
            this.candidateExpiresAt = candidateExpiresAt;
            this.tokenIssuedAt = tokenIssuedAt;
            this.tokenExpiresAt = tokenExpiresAt;
            this.nonce = nonce;
        }

        public String getAudience() {
            return audience;
        }

        public String getAction() {
            return action;
        }

        public String getActiveSha256() {
            return activeSha256;
        }

        public Long getActiveExpiresAt() {
            return activeExpiresAt;
        }

        public long getEnforcementEpoch() {
            return enforcementEpoch;
        }

        public long getTopologyRevision() {
            return topologyRevision;
        }

        public String getInventorySnapshotSha256() {
            return inventorySnapshotSha256;
        }

        public String getRoutingEvidenceSnapshotSha256() {
            return routingEvidenceSnapshotSha256;
        }

        public String getCandidateSha256() {
            return candidateSha256;
        }

        public long getCandidateIssuedAt() {
            return candidateIssuedAt;
        }

        public long getCandidateExpiresAt() {
            return candidateExpiresAt;
        }

        public long getTokenExpiresAt() {
            return tokenExpiresAt;
        }
    }

    public static String issue(byte[] key, Claims claims) {
        requireKey(key);
        if (claims == null) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition claims不能为空");
        }
        byte[] payload = serialize(claims).getBytes(StandardCharsets.US_ASCII);
        return ENCODER.encodeToString(payload) + "." + ENCODER.encodeToString(hmac(key, payload));
    }

    public static Claims verify(byte[] key, String token, long now) {
        requireKey(key);
        if (token == null || token.length() == 0 || token.length() > MAX_TOKEN_BYTES) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition token为空或过长");
        }
        int separator = token.indexOf('.');
        if (separator <= 0 || separator != token.lastIndexOf('.') || separator == token.length() - 1) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition token封装错误");
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
                fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition token认证失败");
            }
            String encoded = new String(payload, StandardCharsets.US_ASCII);
            String[] fields = encoded.split("\\n", -1);
            if (fields.length != FIELD_COUNT || !"1".equals(fields[0])) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition token版本或字段错误");
            }
            Claims claims = new Claims(fields[1], fields[2], nullable(fields[3]),
                    nullableLong(fields[4]), parseLong(fields[5]), parseLong(fields[6]),
                    fields[7], fields[8], fields[9], parseLong(fields[10]), parseLong(fields[11]),
                    parseLong(fields[12]), parseLong(fields[13]), fields[14]);
            if (!encoded.equals(serialize(claims)) || now < claims.tokenIssuedAt
                    || now > claims.tokenExpiresAt) {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition token已过期或不是canonical编码");
            }
            return claims;
        } catch (IllegalArgumentException e) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition token编码错误");
            return null;
        }
    }

    private static String serialize(Claims claims) {
        return "1\n" + claims.audience + "\n" + claims.action + "\n"
                + value(claims.activeSha256) + "\n" + value(claims.activeExpiresAt) + "\n"
                + claims.enforcementEpoch + "\n" + claims.topologyRevision + "\n"
                + claims.inventorySnapshotSha256 + "\n"
                + claims.routingEvidenceSnapshotSha256 + "\n"
                + claims.candidateSha256 + "\n" + claims.candidateIssuedAt + "\n"
                + claims.candidateExpiresAt + "\n" + claims.tokenIssuedAt + "\n"
                + claims.tokenExpiresAt + "\n" + claims.nonce;
    }

    private static byte[] hmac(byte[] key, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != 32) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition HMAC key长度错误");
        }
    }

    private static void requireAtom(String value, String field) {
        if (value == null || value.length() == 0 || value.length() > 128) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", field + "为空或过长");
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (item < 0x21 || item > 0x7e || item == '.') {
                fail("MASSDB_LICENSE_PRECONDITION_FAILED", field + "不是安全ASCII atom");
            }
        }
    }

    private static void requireNullableSha256(String value) {
        if (value != null) {
            requireSha256(value);
        }
    }

    private static void requireSha256(String value) {
        if (value == null || !value.matches("[0-9a-fA-F]{64}")) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition SHA-256格式错误");
        }
    }

    private static long parseLong(String value) {
        try {
            if (value.length() == 0 || (value.length() > 1 && value.charAt(0) == '0')) {
                throw new NumberFormatException();
            }
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            fail("MASSDB_LICENSE_PRECONDITION_FAILED", "precondition整数编码错误");
            return 0;
        }
    }

    private static String nullable(String value) {
        return "-".equals(value) ? null : value;
    }

    private static Long nullableLong(String value) {
        return "-".equals(value) ? null : parseLong(value);
    }

    private static String value(Object value) {
        return value == null ? "-" : value.toString();
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }
}
