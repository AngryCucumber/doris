// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

class LicenseConfirmationIdsTest {
    private static final String ID = "12345678-1234-1234-1234-123456789abc";

    @Test
    void candidateIdentifierIsOnlyAnUnverifiedLocator() {
        // Header and signature are intentionally not authentic; the helper cannot authorize them.
        Assertions.assertEquals(ID, LicenseConfirmationIds.repairIdHint(compact("{\"repair_id\":\"" + ID + "\"}")));
    }

    @Test
    void absentWrongTypeOrNonCanonicalIdentifiersProvideNoHint() {
        Assertions.assertNull(LicenseConfirmationIds.repairIdHint(null));
        for (String body : new String[] {"null", "{}", "[]", "{\"repair_id\":null}", "{\"repair_id\":1}",
                "{\"repair_id\":\"1-1-1-1-1\"}", "{\"repair_id\":\"" + ID.toUpperCase() + "\"}",
                "{\"repair_id\":\"private.payload.signature\"}"}) {
            Assertions.assertNull(LicenseConfirmationIds.repairIdHint(compact(body)));
        }
    }

    @Test
    void duplicateFieldsTrailingJsonAndExcessiveDepthAreRejected() {
        for (String body : new String[] {
                "{\"repair_id\":\"" + ID + "\",\"repair_id\":\"" + ID + "\"}",
                "{\"repair_id\":\"" + ID + "\"} {}",
                "{\"repair_id\":\"" + ID + "\",\"nested\":[[[[[]]]]]}",
                "{\"repair_id\":\"" + ID + "\",\"x\":1,\"x\":2}"}) {
            Assertions.assertNull(LicenseConfirmationIds.repairIdHint(compact(body)));
        }
    }

    @Test
    void compactSizeAlphabetCanonicalEncodingAndUtf8AreBounded() {
        Assertions.assertNull(LicenseConfirmationIds.repairIdHint(String.join("", Collections.nCopies(16385, "a"))));
        Assertions.assertNull(LicenseConfirmationIds.repairIdHint("a.b.c.d"));
        Assertions.assertNull(LicenseConfirmationIds.repairIdHint("a.e30=.c"));
        Assertions.assertNull(LicenseConfirmationIds.repairIdHint("a.e31.c"));
        Assertions.assertNull(LicenseConfirmationIds.repairIdHint("a..c"));
        String invalidUtf8 = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] {(byte) 0xc3, 0x28});
        Assertions.assertNull(LicenseConfirmationIds.repairIdHint("a." + invalidUtf8 + ".c"));
        Assertions.assertNull(LicenseConfirmationIds.repairIdHint("a.e30.c\n"));
    }

    private static String compact(String payload) {
        return "a." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".c";
    }
}
