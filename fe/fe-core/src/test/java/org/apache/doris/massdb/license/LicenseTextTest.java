// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class LicenseTextTest {
    @Test
    void acceptsChineseSupplementaryAndFutureScalarValuesAcrossRuntimeUnicodeVersions() {
        Assertions.assertTrue(LicenseText.matches("客户 A", 256, false));
        String supplementary = new String(Character.toChars(0x1fae0));
        Assertions.assertTrue(LicenseText.matches(supplementary, 2, true));
        Assertions.assertTrue(LicenseText.matches(String.valueOf((char) 0x0378), 1, true));
        Assertions.assertFalse(LicenseText.matches(supplementary, 1, true));
    }

    @Test
    void rejectsControlFormatPrivateSurrogateAndNoncharacters() {
        for (int point : new int[] {0, 31, 127, 159, 0xad, 0x061c, 0x0890, 0x200b, 0x202e,
                0x206f, 0xd800, 0xdfff, 0xe000, 0xf8ff, 0xfdd0, 0xfdef, 0xfeff, 0xffff,
                0x110bd, 0x13430, 0x1fffe, 0xe0001, 0xe007f, 0xf0000, 0x10ffff}) {
            String value = "a" + new String(Character.toChars(point)) + "b";
            Assertions.assertFalse(LicenseText.matches(value, 256, false), "point " + point);
        }
    }

    @Test
    void distinguishesDisplayTextFromIdentifiersWithoutHostWhitespaceTables() {
        for (int point : new int[] {0x20, 0xa0, 0x1680, 0x2000, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000}) {
            String space = new String(Character.toChars(point));
            Assertions.assertTrue(LicenseText.matches("a" + space + "b", 256, false));
            Assertions.assertFalse(LicenseText.matches("a" + space + "b", 256, true));
            Assertions.assertFalse(LicenseText.matches(space + "ab", 256, false));
            Assertions.assertFalse(LicenseText.matches("ab" + space, 256, false));
        }
        Assertions.assertFalse(LicenseText.matches(null, 256, false));
        Assertions.assertFalse(LicenseText.matches("", 256, false));
    }
}
