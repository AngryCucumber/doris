// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

/** Safe representation established without parsing possibly malformed management SQL. */
public final class LicenseSqlRedactor {
    public static final String REDACTED = "[license management SQL redacted]";

    private LicenseSqlRedactor() {
    }

    /**
     * Conservatively redact the complete packet, including comments and nested PREPARE literals.
     * Keeping other statements from a failed multi-statement packet can otherwise leak an adjacent
     * certificate. This scan allocates nothing on ordinary SQL and deliberately needs no valid AST.
     */
    public static boolean isSensitive(String sql) {
        return containsWord(sql, "license") && (containsWord(sql, "admin")
                || containsWord(sql, "prepare") || containsWord(sql, "show"));
    }

    public static String redact(String sql) {
        return isSensitive(sql) ? REDACTED : sql;
    }

    /** Native management routing is narrower than conservative diagnostic redaction. */
    public static boolean requiresNativeParser(String sql) {
        return requiresNativeParser(sql, false);
    }

    public static boolean requiresNativeParser(String sql, boolean noBackslashEscapes) {
        if (!isSensitive(sql)) {
            return false;
        }
        boolean statementStart = true;
        boolean preparing = false;
        for (int i = 0; i < sql.length();) {
            i = skipTrivia(sql, i);
            if (i == sql.length()) {
                return false;
            }
            if (statementStart) {
                if (managementPrefix(sql, i)) {
                    return true;
                }
                preparing = wordAt(sql, i, "prepare");
                statementStart = false;
            }
            char current = sql.charAt(i++);
            if (current == ';') {
                statementStart = true;
                preparing = false;
            } else if (current == '\'' || current == '"' || current == '`') {
                // Text PREPARE is rejected by the native parser; its nested certificate must not
                // be passed to a configured external dialect converter before that rejection.
                if (preparing && current != '`' && managementPrefix(sql, skipTrivia(sql, i))) {
                    return true;
                }
                while (i < sql.length()) {
                    char quoted = sql.charAt(i++);
                    if (quoted == '\\' && !noBackslashEscapes && i < sql.length()) {
                        i++;
                    } else if (quoted == current) {
                        if (i < sql.length() && sql.charAt(i) == current) {
                            i++;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        return false;
    }

    private static boolean managementPrefix(String sql, int position) {
        if (wordAt(sql, position, "show")) {
            return wordAt(sql, skipTrivia(sql, position + 4), "license");
        }
        if (!wordAt(sql, position, "admin")) {
            return false;
        }
        int next = skipTrivia(sql, position + 5);
        if (wordAt(sql, next, "license")) {
            return true;
        }
        for (String operation : new String[] {"import", "validate", "repair"}) {
            if (wordAt(sql, next, operation)) {
                return wordAt(sql, skipTrivia(sql, next + operation.length()), "license");
            }
        }
        return false;
    }

    private static int skipTrivia(String sql, int position) {
        while (position < sql.length()) {
            if (Character.isWhitespace(sql.charAt(position))) {
                position++;
            } else if (sql.startsWith("/*", position)) {
                int end = sql.indexOf("*/", position + 2);
                position = end < 0 ? sql.length() : end + 2;
            } else if (sql.startsWith("--", position) || sql.charAt(position) == '#') {
                while (position < sql.length() && sql.charAt(position) != '\n' && sql.charAt(position) != '\r') {
                    position++;
                }
            } else {
                break;
            }
        }
        return position;
    }

    private static boolean wordAt(String sql, int position, String word) {
        return position + word.length() <= sql.length()
                && sql.regionMatches(true, position, word, 0, word.length())
                && (position + word.length() == sql.length()
                    || !Character.isJavaIdentifierPart(sql.charAt(position + word.length())));
    }

    private static boolean containsWord(String sql, String word) {
        if (sql == null) {
            return false;
        }
        char lower = word.charAt(0);
        char upper = Character.toUpperCase(lower);
        for (int i = 0; i <= sql.length() - word.length(); i++) {
            char initial = sql.charAt(i);
            if (initial != lower && initial != upper) {
                continue;
            }
            if ((i == 0 || !Character.isJavaIdentifierPart(sql.charAt(i - 1)))
                    && sql.regionMatches(true, i, word, 0, word.length())
                    && (i + word.length() == sql.length()
                        || !Character.isJavaIdentifierPart(sql.charAt(i + word.length())))) {
                return true;
            }
        }
        return false;
    }
}
