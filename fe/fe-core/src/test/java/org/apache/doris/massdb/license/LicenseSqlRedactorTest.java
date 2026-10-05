// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.common.profile.SummaryProfile;
import org.apache.doris.persist.gson.GsonUtils;
import org.apache.doris.qe.OriginStatement;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class LicenseSqlRedactorTest {
    @Test
    void ordinarySqlIsUnchanged() {
        for (String sql : new String[] {"SELECT 1", "SELECT license FROM t", "SELECT admin_license FROM t",
                "SHOW TABLES", "SELECT 'licensee admin'", "INSERT INTO t VALUES ('licensed')",
                "SHOW CREATE TABLE license", "SHOW FULL COLUMNS FROM license",
                "SELECT * FROM license WHERE creator='admin'", "SELECT license, admin FROM t",
                "SELECT 1 /* admin show prepare license */", "PREPARE s FROM 'SELECT * FROM license'",
                "SELECT show AS license", "SELECT `admin` AS `license`", "SELECT 'admin import licensee'",
                "SELECT 'admin import licensé'", "SELECT 'admin import license\u00a0suffix'"}) {
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
                "PREPARE s FROM 'SELECT 1; ADMIN IMPORT LICENSE ''a.b.c'''",
                "PREPARE s FROM 'ADMIN IMPORT LICENSE \\'a.b.c\\''"}) {
            Assertions.assertTrue(LicenseSqlRedactor.requiresNativeParser(sql), sql);
        }
        String modeSensitive = "SELECT 'value\\'; ADMIN IMPORT LICENSE 'a.b.c'";
        Assertions.assertTrue(LicenseSqlRedactor.requiresNativeParser(modeSensitive, true));
        Assertions.assertFalse(LicenseSqlRedactor.requiresNativeParser(modeSensitive, false));
    }

    @Test
    void diagnosticPrefixesProtectMalformedAndNestedContentsWithoutWordCooccurrence() {
        for (String sql : new String[] {
                "SELECT 'unterminated; ADMIN IMPORT LICENSE 'private.payload.signature'",
                "SELECT 'ADMIN IMPORT LICENSE private.payload.signature'",
                "SELECT 1 /* ADMIN /* nested */ IMPORT LICENSE 'private.payload.signature' */",
                "ADMIN /* outer /* nested */ tail */ IMPORT LICENSE 'private.payload.signature'",
                "ADMIN -- comment\\\n still comment\n IMPORT LICENSE 'private.payload.signature'",
                "/* ADMIN /* ADMIN /* ADMIN IMPORT LICENSE 'private.payload.signature'",
                "SELECT `x\\`; ADMIN IMPORT LICENSE 'private.payload.signature'",
                "SELECT 'value\\'; ADMIN REPAIR LICENSE CLOCK 'private.payload.signature'"}) {
            Assertions.assertEquals(LicenseSqlRedactor.REDACTED, LicenseSqlRedactor.redact(sql), sql);
        }
    }

    @Test
    void nativeRoutingMatchesNestedCommentsLineContinuationsAndQuotedIdentifiers() {
        for (boolean noBackslashEscapes : new boolean[] {false, true}) {
            for (String sql : new String[] {
                    "/* outer /* inner */ tail */ ADMIN IMPORT LICENSE 'a.b.c'",
                    "ADMIN /* outer /* inner */ tail */ IMPORT LICENSE 'a.b.c'",
                    "-- continued\\\n SELECT 1;\n ADMIN IMPORT LICENSE 'a.b.c'",
                    "SELECT `value\\`; ADMIN IMPORT LICENSE 'a.b.c'",
                    "SELECT `semi;``colon`; ADMIN IMPORT LICENSE 'a.b.c'"}) {
                Assertions.assertTrue(LicenseSqlRedactor.requiresNativeParser(sql, noBackslashEscapes), sql);
            }
            for (String sql : new String[] {
                    "SELECT 1 -- continued\\\n ; ADMIN IMPORT LICENSE 'a.b.c'",
                    "SELECT 1 /* outer /* inner */ ; ADMIN IMPORT LICENSE 'a.b.c' */",
                    "SELECT `a; ADMIN IMPORT LICENSE secret`", "SHOW license_suffix", "SHOW license\u00a0suffix"}) {
                Assertions.assertFalse(LicenseSqlRedactor.requiresNativeParser(sql, noBackslashEscapes), sql);
            }
        }
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

    @Test
    void originDisplayIsLazyAndReusesSafeTextWithoutCopyingOrdinarySql() {
        for (String sql : new String[] {"SELECT 1", "ADMIN IMPORT LICENSE 'private.payload.signature'"}) {
            try (MockedStatic<LicenseSqlRedactor> redactor = Mockito.mockStatic(
                    LicenseSqlRedactor.class, Mockito.CALLS_REAL_METHODS)) {
                OriginStatement origin = new OriginStatement(sql, 0);
                redactor.verifyNoInteractions();
                String safe = origin.getSafeSql();
                Assertions.assertSame(safe, origin.getSafeSql());
                Assertions.assertSame(safe, origin.getSafeSql());
                Assertions.assertSame(sql, origin.originStmt);
                Assertions.assertSame(sql.startsWith("SELECT") ? sql : LicenseSqlRedactor.REDACTED, safe);
                redactor.verify(() -> LicenseSqlRedactor.redact(sql), Mockito.times(1));
                redactor.verify(() -> LicenseSqlRedactor.isSensitive(sql), Mockito.times(1));
            }
        }
        OriginStatement empty = new OriginStatement(null, 0);
        Assertions.assertNull(empty.getSafeSql());
        Assertions.assertNull(empty.getSafeSql());
    }

    @Test
    void restoredOriginsRecomputeDisplayAndIgnoreInjectedDiagnosticCache() {
        for (Gson gson : new Gson[] {GsonUtils.GSON, new Gson()}) {
            for (String sql : new String[] {null, "SELECT 1", "ADMIN IMPORT LICENSE 'private.payload.signature'"}) {
                OriginStatement original = new OriginStatement(sql, 3);
                String expected = original.getSafeSql();
                JsonObject stored = gson.toJsonTree(original).getAsJsonObject();
                Assertions.assertFalse(stored.has("safeSql"));
                stored.addProperty("safeSql", "private.payload.signature");
                OriginStatement restored = gson.fromJson(stored, OriginStatement.class);
                Assertions.assertEquals(sql, restored.originStmt);
                Assertions.assertEquals(3, restored.idx);
                Assertions.assertEquals(expected, restored.getSafeSql());
                Assertions.assertEquals(expected, restored.getSafeSql());
                Assertions.assertFalse(restored.toString().contains("private.payload.signature"));
                if ("SELECT 1".equals(sql)) {
                    Assertions.assertSame(restored.originStmt, restored.getSafeSql());
                }
            }
        }
    }
}
