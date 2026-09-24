#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline model and execution-profile evidence tests; never starts nodes or queries a database."""

import json
import signal
from pathlib import Path
import unittest
from unittest.mock import patch

import fanout_fixture as fixture


ID = "123456789abcdef-8123456789abcdef"
TABLE = "lp009_0123456789abcdef_64"
HOSTS = ["10.254.23." + str(index) for index in range(14, 18)]
TABLETS = list(range(1000, 1064))


def profile():
    # Synthetic format fixture only; it can never serve as actual four-BE evidence.
    lines = ["Summary:", f"   - Profile ID: {ID}", "   - Task State: OK",
             f"   - Sql Statement: {fixture.query_sql(TABLE)}", "   - Is Cached: No",
             "   - Total Instances Num: 8",
             "   - Instances Num Per BE: " + ",".join(host + ":28060:2" for host in HOSTS),
             f"DetailProfile({ID}):", "  Fragments:", "    Fragment 1:"]
    for index, host in enumerate(HOSTS):
        tablets = ", ".join(str(value) for value in TABLETS[index * 16:(index + 1) * 16])
        lines += [f"      FragmentLevelProfile:(host=TNetworkAddress(hostname:{host}, port:29050)):",
                  f"      Pipeline 0(host=TNetworkAddress(hostname:{host}, port:29050)):",
                  "        PipelineTask(index=0):", "           - TaskState: FINALIZED",
                  f"          OLAP_SCAN_OPERATOR(nereids_id=84. table_name={TABLE}({TABLE}))(id=0):",
                  "            CustomCounters:", f"               - TabletIds: [{tablets}]",
                  "               - ScanRows: 2.5M (2500000)"]
    return "\n".join(lines) + "\n"


class FanoutFixtureTest(unittest.TestCase):
    def test_cancellation_preserves_bounded_cleanup_and_restores_handlers(self):
        previous = {value: signal.getsignal(value) for value in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        cleaned = False
        with fixture.Cancellation() as cancellation:
            with self.assertRaises(fixture.Cancelled):
                try:
                    cancellation.cancel(signal.SIGTERM, None)
                finally:
                    cancellation.cancel(signal.SIGTERM, None)
                    cleaned = True
        self.assertTrue(cleaned)
        self.assertEqual(previous, {value: signal.getsignal(value) for value in previous})

    def parse(self, text):
        return fixture.parse_profile(text, ID, TABLE, HOSTS, TABLETS)

    def test_integer_floor_sum_against_brute_force(self):
        for count in (0, 1, 2, 97):
            for modulus, coefficient, constant in ((7, 3, 2), (7, 20, 24), (100000, 1024, 1000), (9, 0, 15)):
                with self.subTest(count=count, m=modulus, a=coefficient, b=constant):
                    expected = sum((coefficient * index + constant) // modulus for index in range(count))
                    self.assertEqual(expected, fixture.floor_sum(count, modulus, coefficient, constant))

    def test_group_model_handles_wrapping_and_non_multiple_group_counts(self):
        for rows in (1, 1023, 1024, 1025, 100003, 201231):
            expected = {}
            for identifier in range(rows):
                item = expected.setdefault(identifier % 1024, {"grp": identifier % 1024, "sum_v": 0, "n": 0})
                item["sum_v"] += identifier % 100000
                item["n"] += 1
            self.assertEqual(list(expected.values()), fixture.expected_groups(rows))

    def test_ten_million_row_model_is_not_reduced(self):
        groups = fixture.expected_groups()
        self.assertEqual(1024, len(groups))
        self.assertEqual(10000000, sum(row["n"] for row in groups))
        self.assertEqual(499995000000, sum(row["sum_v"] for row in groups))
        self.assertEqual(49999995000000, fixture.expected_integrity()["sum_id"])
        self.assertEqual(0, fixture.expected_integrity()["bad_rows"])

    def test_full_group_oracle_accepts_unordered_rows(self):
        expected = fixture.expected_groups()
        actual = [{key: str(value) for key, value in item.items()} for item in reversed(expected)]
        self.assertEqual(1024, len(fixture.check_groups(actual, expected)))
        for alteration in ("missing", "duplicate", "wrong_sum", "null"):
            changed = [dict(item) for item in actual]
            if alteration == "missing":
                changed.pop()
            elif alteration == "duplicate":
                changed[1] = changed[0]
            elif alteration == "wrong_sum":
                changed[0]["sum_v"] = str(int(changed[0]["sum_v"]) + 1)
            else:
                changed[0]["sum_v"] = None
            with self.subTest(alteration=alteration), self.assertRaises(ValueError):
                fixture.check_groups(changed, expected)

    def test_canonical_variant_ddl_preserves_all_properties(self):
        canonical = json.loads(fixture.CANONICAL.read_text())
        variants = fixture.variant_definitions("0123456789abcdef", canonical)
        self.assertEqual([64, 256, 1024], [item["buckets"] for item in variants])
        for item in variants:
            self.assertIn('UNIQUE KEY(id)', item["create_sql"])
            self.assertIn('"replication_num"="1"', item["create_sql"])
            self.assertIn('"store_row_column"="true"', item["create_sql"])
            self.assertIn('"number"="10000000"', item["insert_sql"])
            intervals = item["integrity_ranges"]
            self.assertEqual(20, len(intervals))
            self.assertEqual(0, intervals[0]["lower"])
            self.assertEqual(fixture.ROWS, intervals[-1]["upper"])
            self.assertTrue(all(left["upper"] == right["lower"] for left, right in zip(intervals, intervals[1:])))
            self.assertTrue(all("COUNT(DISTINCT id)" in interval["sql"] for interval in intervals))
            self.assertIn("payload<>MD5(CAST(id AS STRING))", item["integrity_sql"])
        canonical["datasets"]["bench_fanout"]["rows"] = 1000000
        with self.assertRaises(ValueError):
            fixture.variant_definitions("0123456789abcdef", canonical)

    def test_range_integrity_matches_independent_enumeration_and_covers_full_input(self):
        for lower, upper in ((0, 1), (1000, 1040), (99980, 100030), (9999900, 10000000)):
            ids = range(lower, upper)
            self.assertEqual({"n": len(ids), "distinct_ids": len(ids), "min_id": lower, "max_id": upper - 1,
                              "sum_id": sum(ids), "sum_grp": sum(value % 1024 for value in ids),
                              "sum_v": sum(value % 100000 for value in ids), "bad_rows": 0},
                             fixture.expected_integrity_range(lower, upper))
        ranges = [fixture.expected_integrity_range(lower, lower + fixture.INTEGRITY_RANGE_ROWS)
                  for lower in range(0, fixture.ROWS, fixture.INTEGRITY_RANGE_ROWS)]
        expected = fixture.expected_integrity()
        for key in ("n", "distinct_ids", "sum_id", "sum_grp", "sum_v", "bad_rows"):
            self.assertEqual(expected[key], sum(interval[key] for interval in ranges))

    def test_table_token_rejects_sql_or_path_injection(self):
        canonical = json.loads(fixture.CANONICAL.read_text())
        for token in ("../table", "x;DROP TABLE user", "", "0" * 15):
            with self.subTest(token=token), self.assertRaises(ValueError):
                fixture.variant_definitions(token, canonical)

    def test_runtime_profile_proves_four_active_scan_hosts_and_exact_ranges(self):
        actual = self.parse(profile())
        self.assertEqual(64, actual["actual_tablet_count"])
        self.assertEqual(8, actual["total_instances"])
        self.assertEqual(4, len(actual["actual_scans"]))
        for host in HOSTS:
            self.assertEqual(16, len(actual["per_be"][host]["tablet_ids"]))
            self.assertEqual(2500000, actual["per_be"][host]["scan_rows"])

    def test_scheduled_instances_or_explain_without_runtime_cannot_pass(self):
        text = profile().split(f"DetailProfile({ID}):")[0] + "EXPLAIN four BE nodes and tablets\n"
        with self.assertRaises(ValueError):
            self.parse(text)

    def test_registered_be_without_actual_scan_rows_is_rejected(self):
        text = profile().replace("- ScanRows: 2.5M (2500000)", "- ScanRows: 0", 1)
        with self.assertRaises(ValueError):
            self.parse(text)

    def test_unfinished_task_is_not_execution_proof(self):
        with self.assertRaises(ValueError):
            self.parse(profile().replace("TaskState: FINALIZED", "TaskState: BLOCKED", 1))

    def test_cached_or_wrong_query_profile_is_rejected(self):
        for old, new in (("Is Cached: No", "Is Cached: Yes"), ("Task State: OK", "Task State: ERROR"),
                         ("Profile ID: " + ID, "Profile ID: dead-beef")):
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.parse(profile().replace(old, new, 1))

    def test_missing_or_duplicate_runtime_tablets_are_rejected(self):
        for old, new in (("1000, 1001", "1001"), ("1000, 1001", "1000, 1000"), ("1016, 1017", "1000, 1017")):
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.parse(profile().replace(old, new, 1))

    def test_external_be_or_wrong_port_is_rejected(self):
        for old, new in (("hostname:10.254.23.14", "hostname:192.0.2.1"), ("port:29050", "port:1"),
                         ("10.254.23.14:28060:2", "10.254.23.14:28061:2")):
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.parse(profile().replace(old, new, 1))

    def test_extra_unowned_summary_entry_cannot_be_ignored(self):
        text = profile().replace("10.254.23.17:28060:2", "10.254.23.17:28060:2,192.0.2.1:28060:1")
        with self.assertRaises(ValueError):
            self.parse(text)

    def test_wrong_total_instance_count_is_rejected(self):
        with self.assertRaises(ValueError):
            self.parse(profile().replace("Total Instances Num: 8", "Total Instances Num: 4"))

    def test_truncated_tablet_or_approximate_row_counter_is_rejected(self):
        for old, new in (("1000, 1001", "1000, ..."), ("2.5M (2500000)", "2.5M")):
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.parse(profile().replace(old, new, 1))

    def test_scan_for_another_table_is_rejected(self):
        with self.assertRaises(ValueError):
            self.parse(profile().replace("table_name=" + TABLE, "table_name=someone_else", 1))

    def test_duplicate_runtime_task_is_rejected(self):
        text = profile()
        last = text.index("      Pipeline 0(host=TNetworkAddress(hostname:10.254.23.17")
        with self.assertRaises(ValueError):
            self.parse(text + text[last:])

    def test_changed_pid_guard_prevents_work_in_the_wrong_namespace(self):
        guard = fixture.ClusterGuard.__new__(fixture.ClusterGuard)
        guard.supervisor = {"pid": 999}
        guard.nodes = {"fe1": {"namespace": "net:[private]", "keeper": {}, "service": {}}}
        with patch.object(fixture.os, "readlink", return_value="net:[host]"), \
                patch.object(fixture.multinode, "same_process") as same, self.assertRaises(ValueError):
            guard.check()
        same.assert_not_called()
        with patch.object(fixture.os, "readlink", return_value="net:[private]"), \
                patch.object(fixture.multinode, "same_process", return_value=False), self.assertRaises(ValueError):
            guard.check()


if __name__ == "__main__":
    unittest.main()
