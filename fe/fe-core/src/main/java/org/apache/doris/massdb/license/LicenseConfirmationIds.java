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
import java.util.Base64;
import java.util.UUID;

/** Bounded confirmation hints. A hint establishes neither signature validity nor a committed fact. */
public final class LicenseConfirmationIds {
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(4)
                    .maxDocumentLength(LicenseClockRepairVerifier.MAX_COMPACT_LENGTH)
                    .maxStringLength(1024).maxNameLength(128).maxNumberLength(20).build()).build());

    private LicenseConfirmationIds() {
    }

    /**
     * Extract only the candidate's canonical receipt locator after an unknown transport outcome.
     * Never use this value to accept a repair, publish state, or report success. Malformed input
     * provides no hint; parser/provider diagnostics containing certificate bytes are discarded.
     */
    public static String repairIdHint(String compact) {
        if (compact == null || compact.isEmpty() || compact.length() > LicenseClockRepairVerifier.MAX_COMPACT_LENGTH) {
            return null;
        }
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 3) {
            return null;
        }
        for (String part : parts) {
            if (!part.matches("[A-Za-z0-9_-]+")) {
                return null;
            }
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(parts[1])) {
                return null;
            }
            String payload = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(decoded)).toString();
            try (JsonParser parser = JSON.createParser(payload)) {
                JsonNode claims = JSON.readTree(parser);
                if (claims == null || !claims.isObject() || parser.nextToken() != null) {
                    return null;
                }
                JsonNode id = claims.get("repair_id");
                if (id == null || !id.isTextual()) {
                    return null;
                }
                String value = id.textValue();
                return UUID.fromString(value).toString().equals(value) ? value : null;
            }
        } catch (IOException | IllegalArgumentException ignored) {
            return null;
        }
    }
}
