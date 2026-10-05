// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.util.ArrayDeque;
import java.util.Deque;

/** Safe representation established without parsing possibly malformed management SQL. */
public final class LicenseSqlRedactor {
    public static final String REDACTED = "[license management SQL redacted]";

    private LicenseSqlRedactor() {
    }

    /**
     * Recognize management command prefixes without requiring a valid AST. Certificate-bearing
     * prefixes also remain sensitive inside comments, quoted text or malformed packets: diagnostics
     * must not expose a certificate just because a preceding token could not be parsed. Ordinary
     * identifiers such as SHOW CREATE TABLE license or creator='admin' are not management commands.
     * The common path without a license token does not allocate or tokenize the SQL.
     */
    public static boolean isSensitive(String sql) {
        if (!containsWord(sql, "license")) {
            return false;
        }
        // Diagnostics can outlive the session, so protect commands under either SQL escape mode.
        return containsCertificatePrefix(sql) || scanManagement(sql, false) || scanManagement(sql, true);
    }

    public static String redact(String sql) {
        return isSensitive(sql) ? REDACTED : sql;
    }

    /** Native management routing is narrower than conservative diagnostic redaction. */
    public static boolean requiresNativeParser(String sql) {
        return requiresNativeParser(sql, false);
    }

    public static boolean requiresNativeParser(String sql, boolean noBackslashEscapes) {
        return containsWord(sql, "license") && scanManagement(sql, noBackslashEscapes);
    }

    private static boolean containsCertificatePrefix(String sql) {
        // Inspect comment/literal contents too, while preserving a prefix across a comment.
        // The stack makes nested or unterminated comments linear-time, even for malformed input.
        Deque<Integer> comments = null;
        int commentKind = 0; // 0: SQL, 1: line comment, 2: bracketed comment
        int prefix = 0; // 0: none, 1: ADMIN, 2: ADMIN IMPORT / VALIDATE / REPAIR
        for (int i = 0; i < sql.length();) {
            char current = sql.charAt(i);
            if (commentKind == 1 && current == '\\' && i + 1 < sql.length() && sql.charAt(i + 1) == '\n') {
                i += 2;
            } else if (commentKind == 1 && (current == '\n' || current == '\r')
                    || commentKind == 2 && sql.startsWith("*/", i)) {
                int saved = comments.pop();
                i += commentKind == 2 ? 2 : 1;
                prefix = saved & 3;
                commentKind = saved >> 2;
            } else if (commentKind != 1 && sql.startsWith("/*", i)
                    || commentKind == 0 && sql.startsWith("--", i)) {
                if (comments == null) {
                    comments = new ArrayDeque<>();
                }
                comments.push((commentKind << 2) | prefix);
                commentKind = current == '/' ? 2 : 1;
                prefix = 0;
                i += 2;
            } else if (current == ' ' || current == '\t' || current == '\n' || current == '\r') {
                i++;
            } else if (identifierPart(current)) {
                int start = i++;
                while (i < sql.length() && identifierPart(sql.charAt(i))) {
                    i++;
                }
                if (wordAt(sql, start, "admin")) {
                    prefix = 1;
                } else if (prefix == 1 && (wordAt(sql, start, "import") || wordAt(sql, start, "validate")
                        || wordAt(sql, start, "repair"))) {
                    prefix = 2;
                } else if (prefix == 2 && wordAt(sql, start, "license")) {
                    return true;
                } else {
                    prefix = 0;
                }
            } else {
                prefix = 0;
                i++;
            }
        }
        return false;
    }

    private static boolean scanManagement(String sql, boolean noBackslashEscapes) {
        boolean statementStart = true;
        boolean preparing = false;
        boolean certificatePrefixChecked = false;
        boolean certificatePrefixPresent = false;
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
                // Reject a text PREPARE containing a later/nested certificate command locally too.
                if (preparing) {
                    if (!certificatePrefixChecked) {
                        certificatePrefixPresent = containsCertificatePrefix(sql);
                        certificatePrefixChecked = true;
                    }
                    if (certificatePrefixPresent) {
                        return true;
                    }
                }
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
                    if (quoted == '\\' && current != '`' && !noBackslashEscapes && i < sql.length()) {
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
        return certificatePrefix(sql, next);
    }

    private static boolean certificatePrefix(String sql, int position) {
        int length;
        if (wordAt(sql, position, "import") || wordAt(sql, position, "repair")) {
            length = 6;
        } else if (wordAt(sql, position, "validate")) {
            length = 8;
        } else {
            return false;
        }
        return wordAt(sql, skipTrivia(sql, position + length), "license");
    }

    private static int skipTrivia(String sql, int position) {
        while (position < sql.length()) {
            char current = sql.charAt(position);
            if (current == ' ' || current == '\t' || current == '\n' || current == '\r') {
                position++;
            } else if (sql.startsWith("/*", position)) {
                // Match DorisLexer.BRACKETED_COMMENT, including nested comments.
                position += 2;
                int depth = 1;
                while (position < sql.length() && depth > 0) {
                    if (sql.startsWith("/*", position)) {
                        depth++;
                        position += 2;
                    } else if (sql.startsWith("*/", position)) {
                        depth--;
                        position += 2;
                    } else {
                        position++;
                    }
                }
            } else if (sql.startsWith("--", position)) {
                // A backslash-newline is part of SIMPLE_COMMENT even in NO_BACKSLASH_ESCAPES mode.
                while (position < sql.length() && sql.charAt(position) != '\n' && sql.charAt(position) != '\r') {
                    if (sql.charAt(position) == '\\' && position + 1 < sql.length()
                            && sql.charAt(position + 1) == '\n') {
                        position += 2;
                    } else {
                        position++;
                    }
                }
            } else {
                break;
            }
        }
        return position;
    }

    private static boolean wordAt(String sql, int position, String word) {
        return position + word.length() <= sql.length()
                && (position == 0 || !identifierPart(sql.charAt(position - 1)))
                && sql.regionMatches(true, position, word, 0, word.length())
                && (position + word.length() == sql.length()
                    || !identifierPart(sql.charAt(position + word.length())));
    }

    private static boolean identifierPart(char current) {
        // DorisLexer.LETTER accepts all non-ASCII code points, not only Java identifier letters.
        return current >= 128 || current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z'
                || current >= '0' && current <= '9' || current == '_' || current == '$';
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
            if (wordAt(sql, i, word)) {
                return true;
            }
        }
        return false;
    }
}
