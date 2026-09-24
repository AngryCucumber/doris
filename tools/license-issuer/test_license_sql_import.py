# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

import unittest

import license_sql_import


class LicenseSqlImportTest(unittest.TestCase):
    def test_exact_compact_and_operations(self):
        for operation, prefix in license_sql_import.PREFIXES.items():
            self.assertEqual(prefix + " 'e30.e30.AA_-';\n",
                             license_sql_import.make_sql(b"e30.e30.AA_-", operation))

    def test_quote_escape_and_statement_injection_are_rejected(self):
        for raw in (b"a.b.c'; SELECT 1; --", b'a.b.c\\', b'a.b.c"', b'a.b.c\n',
                    b'a.b.c\x00', b'\xff.b.c', b'a.b', b'..'):
            with self.assertRaisesRegex(ValueError, "Expected exact compact"):
                license_sql_import.make_sql(raw)

    def test_limit(self):
        self.assertTrue(license_sql_import.make_sql(b'a.b.' + b'c' * (65536 - 4)))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            license_sql_import.make_sql(b'a.b.' + b'c' * (65537 - 4))

    def test_unknown_operation(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            license_sql_import.make_sql(b'a.b.c', 'select')


if __name__ == "__main__":
    unittest.main()
