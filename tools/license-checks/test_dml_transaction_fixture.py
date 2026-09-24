#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Independent LP015 manifest/transition checks; no SQL execution or network calls."""

import unittest

import dml_transaction_fixture as fixture


class DmlTransactionFixtureTest(unittest.TestCase):
    def test_committed_and_rolled_back_models_are_distinct(self):
        manifest = fixture.build_manifest()
        seed, committed = manifest["models"]["seed200"], manifest["models"]["committed200"]
        self.assertEqual((200, 0, 199, 19900, 19900),
                         (seed["rows"], seed["min_id"], seed["max_id"], seed["sum_id"], seed["sum_v"]))
        self.assertEqual((200, 100, 299, 39900, 100039900),
                         (committed["rows"], committed["min_id"], committed["max_id"], committed["sum_id"], committed["sum_v"]))
        self.assertNotEqual(seed["canonical_csv_sha256"], committed["canonical_csv_sha256"])
        self.assertEqual("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                         manifest["models"]["empty"]["canonical_csv_sha256"])

    def test_each_supported_transaction_has_three_100_row_operations(self):
        phases = [phase for phase in fixture.build_manifest()["phases"] if phase["kind"] == "supported_transaction"]
        self.assertEqual(["ROLLBACK", "COMMIT"], [phase["end"] for phase in phases])
        for phase in phases:
            self.assertEqual("BEGIN", phase["begin"])
            self.assertEqual([100, 100, 100], [operation["affected_rows"] for operation in phase["operations"]])
            self.assertEqual(["DELETE", "UPDATE", "INSERT"], [operation["sql"].split()[0] for operation in phase["operations"]])
            self.assertEqual(["seed200"] * 3, [operation["visible_model"] for operation in phase["operations"]])

    def test_unsupported_paths_are_explicit_and_source_is_read_only(self):
        manifest = fixture.build_manifest()
        rejected = [phase for phase in manifest["phases"] if phase["kind"] == "unsupported_rejected"]
        self.assertEqual(3, len(rejected))
        self.assertTrue(all(any("expected_error" in operation for operation in phase["operations"]) for phase in rejected))
        noop = manifest["phases"][-1]
        self.assertEqual(("unsupported_ack_only", "START TRANSACTION", "ROLLBACK", "start_noop300"),
                         (noop["kind"], noop["begin"], noop["end"], noop["after"]))
        self.assertEqual(300, manifest["models"][noop["after"]]["rows"])
        for phase in manifest["phases"]:
            for operation in phase["operations"]:
                sql = operation["sql"]
                if sql.startswith(("INSERT", "UPDATE", "DELETE")):
                    self.assertIn("{{table}}", sql.split(" SELECT ")[0])
                    self.assertNotIn("license_perf.point_rows", sql.split(" SELECT ")[0])
        self.assertFalse(manifest["source_write_permitted"])
        self.assertFalse(manifest["full_1000_transactions_per_client_executed"])


if __name__ == "__main__":
    unittest.main()
