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

/** HMAC-authenticated CAS token shared by non-NORMAL License control actions. */
public final class MassDbLicenseControlPreconditionToken {
    public static final long MAX_TTL_SECONDS = 900;
    private static final int FIELD_COUNT = 20;
    private static final int MAX_TOKEN_BYTES = 4096;
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private MassDbLicenseControlPreconditionToken() {
    }

    public static final class Claims {
        public final String audience;
        public final String action;
        public final String subjectId;
        public final String activeSha256;
        public final Long activeExpiresAt;
        public final long enforcementEpoch;
        public final long topologyRevision;
        public final String inventorySnapshotSha256;
        public final String routingEvidenceSnapshotSha256;
        public final String candidateSha256;
        public final long targetValue1;
        public final long targetValue2;
        public final long targetValue3;
        public final long snapshotValue1;
        public final long snapshotValue2;
        public final long tokenIssuedAt;
        public final long tokenExpiresAt;
        public final String nonce;

        public Claims(String audience, String action, String subjectId,
                String activeSha256, Long activeExpiresAt, long enforcementEpoch,
                long topologyRevision, String inventorySnapshotSha256,
                String routingEvidenceSnapshotSha256, String candidateSha256,
                long targetValue1, long targetValue2, long targetValue3,
                long snapshotValue1, long snapshotValue2, long tokenIssuedAt,
                long tokenExpiresAt, String nonce) {
            requireAtom(audience, "audience", false);
            requireAtom(action, "action", false);
            requireAtom(subjectId, "subjectId", true);
            requireNullableSha256(activeSha256);
            requireSha256(inventorySnapshotSha256);
            requireSha256(routingEvidenceSnapshotSha256);
            requireSha256(candidateSha256);
            requireAtom(nonce, "nonce", false);
            if (enforcementEpoch < 0 || topologyRevision < 0 || targetValue1 < 0
                    || targetValue2 < 0 || targetValue3 < 0 || snapshotValue1 < 0
                    || snapshotValue2 < 0 || tokenIssuedAt < 0
                    || tokenExpiresAt <= tokenIssuedAt
                    || tokenExpiresAt - tokenIssuedAt > MAX_TTL_SECONDS
                    || activeExpiresAt != null && activeExpiresAt < 0) {
                fail("control precondition整数、时间或epoch错误");
            }
            this.audience = audience;
            this.action = action;
            this.subjectId = subjectId;
            this.activeSha256 = activeSha256 == null ? null : activeSha256.toLowerCase();
            this.activeExpiresAt = activeExpiresAt;
            this.enforcementEpoch = enforcementEpoch;
            this.topologyRevision = topologyRevision;
            this.inventorySnapshotSha256 = inventorySnapshotSha256.toLowerCase();
            this.routingEvidenceSnapshotSha256 =
                    routingEvidenceSnapshotSha256.toLowerCase();
            this.candidateSha256 = candidateSha256.toLowerCase();
            this.targetValue1 = targetValue1;
            this.targetValue2 = targetValue2;
            this.targetValue3 = targetValue3;
            this.snapshotValue1 = snapshotValue1;
            this.snapshotValue2 = snapshotValue2;
            this.tokenIssuedAt = tokenIssuedAt;
            this.tokenExpiresAt = tokenExpiresAt;
            this.nonce = nonce;
        }
    }

    public static String issue(byte[] key, Claims claims) {
        requireKey(key);
        if (claims == null) {
            fail("control precondition claims不能为空");
        }
        byte[] payload = serialize(claims).getBytes(StandardCharsets.US_ASCII);
        return ENCODER.encodeToString(payload) + "."
                + ENCODER.encodeToString(hmac(key, payload));
    }

    public static Claims verify(byte[] key, String token, long now) {
        requireKey(key);
        if (token == null || token.isEmpty() || token.length() > MAX_TOKEN_BYTES) {
            fail("control precondition token为空或过长");
        }
        int separator = token.indexOf('.');
        if (separator <= 0 || separator != token.lastIndexOf('.')
                || separator == token.length() - 1) {
            fail("control precondition token封装错误");
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
                fail("control precondition token认证失败");
            }
            String encoded = new String(payload, StandardCharsets.US_ASCII);
            String[] fields = encoded.split("\\n", -1);
            if (fields.length != FIELD_COUNT || !"1".equals(fields[0])) {
                fail("control precondition token版本或字段错误");
            }
            Claims claims = new Claims(fields[1], fields[2], empty(fields[3]),
                    nullable(fields[4]), nullableLong(fields[5]), parseLong(fields[6]),
                    parseLong(fields[7]), fields[8], fields[9], fields[10],
                    parseLong(fields[11]), parseLong(fields[12]), parseLong(fields[13]),
                    parseLong(fields[14]), parseLong(fields[15]), parseLong(fields[16]),
                    parseLong(fields[17]), fields[18]);
            if (!encoded.equals(serialize(claims)) || now < claims.tokenIssuedAt
                    || now > claims.tokenExpiresAt || !fields[19].isEmpty()) {
                fail("control precondition token已过期或不是canonical编码");
            }
            return claims;
        } catch (IllegalArgumentException error) {
            fail("control precondition token编码错误");
            return null;
        }
    }

    private static String serialize(Claims value) {
        return "1\n" + value.audience + "\n" + value.action + "\n"
                + emptyValue(value.subjectId) + "\n" + nullableValue(value.activeSha256)
                + "\n" + nullableValue(value.activeExpiresAt) + "\n"
                + value.enforcementEpoch + "\n" + value.topologyRevision + "\n"
                + value.inventorySnapshotSha256 + "\n"
                + value.routingEvidenceSnapshotSha256 + "\n" + value.candidateSha256
                + "\n" + value.targetValue1 + "\n" + value.targetValue2 + "\n"
                + value.targetValue3 + "\n" + value.snapshotValue1 + "\n"
                + value.snapshotValue2 + "\n" + value.tokenIssuedAt + "\n"
                + value.tokenExpiresAt + "\n" + value.nonce + "\n";
    }

    private static byte[] hmac(byte[] key, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("HmacSHA256 unavailable", error);
        }
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != 32) {
            fail("control precondition HMAC key长度错误");
        }
    }

    private static void requireAtom(String value, String field, boolean emptyAllowed) {
        if (value == null || (!emptyAllowed && value.isEmpty()) || value.length() > 191) {
            fail(field + "为空或过长");
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (item < 0x21 || item > 0x7e || item == '.') {
                fail(field + "不是安全ASCII atom");
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
            fail("control precondition SHA-256格式错误");
        }
    }

    private static long parseLong(String value) {
        try {
            if (value.isEmpty() || value.length() > 1 && value.charAt(0) == '0') {
                throw new NumberFormatException();
            }
            return Long.parseLong(value);
        } catch (NumberFormatException error) {
            fail("control precondition整数编码错误");
            return 0;
        }
    }

    private static String nullable(String value) {
        return "-".equals(value) ? null : value;
    }

    private static Long nullableLong(String value) {
        return "-".equals(value) ? null : parseLong(value);
    }

    private static String empty(String value) {
        return "-".equals(value) ? "" : value;
    }

    private static String emptyValue(String value) {
        return value.isEmpty() ? "-" : value;
    }

    private static String nullableValue(Object value) {
        return value == null ? "-" : value.toString();
    }

    private static void fail(String message) {
        throw new MassDbLicenseException(
                "MASSDB_LICENSE_PRECONDITION_FAILED", message);
    }
}
