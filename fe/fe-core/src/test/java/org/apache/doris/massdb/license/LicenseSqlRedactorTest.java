// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.common.profile.SummaryProfile;
import org.apache.doris.qe.OriginStatement;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class LicenseSqlRedactorTest {
    @Test
    void ordinarySqlIsUnchanged() {
        for (String sql : new String[] {"SELECT 1", "SELECT license FROM t", "SELECT admin_license FROM t",
                "SHOW TABLES", "SELECT 'licensee admin'", "INSERT INTO t VALUES ('licensed')"}) {
            Assertions.assertSame(sql, LicenseSqlRedactor.redact(sql));
        }
        Assertions.assertNull(LicenseSqlRedactor.redact(null));
    }

    @Test
    void malformedNestedAndMultiStatementPacketsAreRedactedWithoutParsing() {
        for (String sql : new String[] {
                "ADMIN IMPORT LICENSE 'private.payload.signature'",
                "aDmIn /*comment*/ VaLiDaTe \n LiCeNsE 'private.payload.signature'",
                "ADMIN REPAIR LICENSE CLOCK 'private.payload.signature'",
                "SELECT 1; ADMIN IMPORT LICENSE 'private.payload.signature'; SELECT 2",
                "PREPARE x FROM 'ADMIN IMPORT LICENSE \\'private.payload.signature\\''",
                "ADMIN IMPORT LICENSE private.payload.signature",
                "ADMIN IMPORT LICENSE 'private.payload.signature",
                "ADMIN /*+ wrong private.payload.signature */ IMPORT LICENSE 'private.payload.signature'"}) {
            Assertions.assertEquals(LicenseSqlRedactor.REDACTED, LicenseSqlRedactor.redact(sql));
        }
    }

    @Test
    void nativeManagementRoutingDoesNotChangeUnrelatedDialectQueries() {
        for (String sql : new String[] {"SELECT license, admin FROM t",
                "SELECT transform(ARRAY[1, 2], x -> x + 1), 'license admin'",
                "SELECT 'ADMIN IMPORT LICENSE secret'; SELECT 1",
                "SELECT 1 /* ADMIN IMPORT LICENSE secret */",
                "PREPARE s FROM 'SELECT license, admin FROM t'"}) {
            Assertions.assertFalse(LicenseSqlRedactor.requiresNativeParser(sql), sql);
        }
        for (String sql : new String[] {"ADMIN IMPORT LICENSE 'a.b.c'",
                "/* before */ ADMIN /* inside */ VALIDATE LICENSE 'a.b.c'",
                "SELECT 'semi;colon'; -- comment\n ADMIN REPAIR LICENSE CLOCK 'a.b.c'",
                "SHOW LICENSE", "ADMIN LICENSE CLOCK CHALLENGE",
                "PREPARE s FROM 'ADMIN IMPORT LICENSE \\'a.b.c\\''"}) {
            Assertions.assertTrue(LicenseSqlRedactor.requiresNativeParser(sql), sql);
        }
        String modeSensitive = "SELECT 'value\\'; ADMIN IMPORT LICENSE 'a.b.c'";
        Assertions.assertTrue(LicenseSqlRedactor.requiresNativeParser(modeSensitive, true));
        Assertions.assertFalse(LicenseSqlRedactor.requiresNativeParser(modeSensitive, false));
    }

    @Test
    void originAndProfileKeepOnlySafeDisplayWhileExecutionRetainsExactBytes() {
        String sql = "ADMIN IMPORT LICENSE 'private.payload.signature'";
        OriginStatement origin = new OriginStatement(sql, 0);
        Assertions.assertEquals(sql, origin.originStmt);
        Assertions.assertEquals(LicenseSqlRedactor.REDACTED, origin.getSafeSql());
        Assertions.assertFalse(origin.toString().contains("private.payload.signature"));
        Assertions.assertEquals(LicenseSqlRedactor.REDACTED,
                new SummaryProfile.SummaryBuilder().sqlStatement(sql).build().get(SummaryProfile.SQL_STATEMENT));
    }
}
