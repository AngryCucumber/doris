// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

/** Protocol v1 code-point rules, independent of a JVM or issuer's Unicode database version. */
public final class LicenseText {
    private static final int[][] FORBIDDEN = {
            {0x0000, 0x001f}, {0x007f, 0x009f}, {0x00ad, 0x00ad}, {0x0600, 0x0605},
            {0x061c, 0x061c}, {0x06dd, 0x06dd}, {0x070f, 0x070f}, {0x0890, 0x0891},
            {0x08e2, 0x08e2}, {0x180e, 0x180e}, {0x200b, 0x200f}, {0x202a, 0x202e},
            {0x2060, 0x2064}, {0x2066, 0x206f}, {0xd800, 0xf8ff}, {0xfdd0, 0xfdef},
            {0xfeff, 0xfeff}, {0xfff9, 0xfffb}, {0x110bd, 0x110bd}, {0x110cd, 0x110cd},
            {0x13430, 0x1343f}, {0x1bca0, 0x1bca3}, {0x1d173, 0x1d17a},
            {0xe0001, 0xe0001}, {0xe0020, 0xe007f}, {0xf0000, 0xffffd}, {0x100000, 0x10fffd}
    };

    private LicenseText() {
    }

    /** Length is in UTF-16 code units; unassigned scalar values are intentionally permitted. */
    public static boolean matches(String value, int maximum, boolean identifier) {
        if (value == null || value.isEmpty() || value.length() > maximum) {
            return false;
        }
        for (int offset = 0; offset < value.length();) {
            int point = value.codePointAt(offset);
            int end = offset + Character.charCount(point);
            if ((point & 0xffff) >= 0xfffe || forbidden(point)
                    || (whitespace(point) && (identifier || offset == 0 || end == value.length()))) {
                return false;
            }
            offset = end;
        }
        return true;
    }

    private static boolean forbidden(int point) {
        for (int[] interval : FORBIDDEN) {
            if (point >= interval[0] && point <= interval[1]) {
                return true;
            }
        }
        return false;
    }

    private static boolean whitespace(int point) {
        return (point >= 0x09 && point <= 0x0d) || point == 0x20 || point == 0x85 || point == 0xa0
                || point == 0x1680 || (point >= 0x2000 && point <= 0x200a) || point == 0x2028
                || point == 0x2029 || point == 0x202f || point == 0x205f || point == 0x3000;
    }
}
