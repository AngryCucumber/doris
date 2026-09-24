#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Independent LP014 input/model checks; no database or network calls."""

import hashlib
from pathlib import Path
import tempfile
import unittest

import group_commit_fixture as fixture


class GroupCommitFixtureTest(unittest.TestCase):
    def test_interval_model_across_modulo_boundaries(self):
        for start, count in ((0, 1), (1020, 100), (99500, 1000), (99990, 10000)):
            with self.subTest(start=start, count=count):
                values = list(range(start, start + count))
                self.assertEqual({"n": count, "distinct_ids": count, "min_id": start, "max_id": start + count - 1,
                                  "sum_id": sum(values), "sum_grp": sum(value % 1024 for value in values),
                                  "sum_v": sum(value % 100000 for value in values), "bad_rows": 0},
                                 fixture.interval_model(start, count))

    def test_all_batch_sizes_both_full_prepare_modes_and_repeated_statement(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = fixture.generate_inputs(Path(directory))
            self.assertEqual([1, 100, 1000, 10000], manifest["batch_rows"])
            self.assertEqual(44404, manifest["rows"])
            self.assertEqual(16, len(manifest["cases"]))
            self.assertFalse(manifest["full_target_ingested"])
            self.assertEqual([(full, count, repeat) for full in (True, False)
                              for count in (1, 100, 1000, 10000) for repeat in (0, 1)],
                             [(case["full_prepare"], case["batch_rows"], case["repeat"])
                              for case in manifest["cases"]])
            data = (Path(directory) / "input.csv").read_bytes()
            self.assertEqual(manifest["input_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(44404 * 128, len(data))
            for case in manifest["cases"]:
                start, count = case["id_start"], case["batch_rows"]
                selected = data[start * 128:(start + count) * 128]
                self.assertEqual(case["input_sha256"], hashlib.sha256(selected).hexdigest())
                rows = [line.decode("ascii").split(",") for line in selected.splitlines()]
                self.assertEqual(list(range(start, start + count)), [int(row[0]) for row in rows])
                self.assertEqual(case["model"]["sum_grp"], sum(int(row[1]) for row in rows))
                self.assertEqual(case["model"]["sum_v"], sum(int(row[2]) for row in rows))
                padding = hashlib.sha256(b"20260922").hexdigest() * 2
                for row in rows:
                    prefix = ",".join(row[:3]) + ","
                    expected = hashlib.md5(row[0].encode("ascii"), usedforsecurity=False).hexdigest()
                    expected += padding[:127 - len(prefix) - len(expected)]
                    self.assertEqual(expected, row[3])

    def test_existing_input_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "input.csv"
            target.write_bytes(b"existing evidence")
            with self.assertRaises(FileExistsError):
                fixture.generate_inputs(Path(directory))
            self.assertEqual(b"existing evidence", target.read_bytes())


if __name__ == "__main__":
    unittest.main()
