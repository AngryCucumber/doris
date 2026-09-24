#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Reject partial, stale, mixed and incorrectly correlated LP006/007 evidence offline."""

import copy
import hashlib
import json
import unittest

import complex_planning_oracle as oracle


QUERY_ID = "123456789abcdef-8123456789abcdef"


class ComplexPlanningOracleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(oracle.CONTRACT.read_text())
        cls.definition = oracle.verified_definition(cls.contract)

    def record(self, model="initial", started=1, finished=2):
        return {"clock_domain": "synthetic-test-jvm", "started_ns": started, "finished_ns": finished,
                "columns": [{"name": name, "type": "BIGINT"} for name in oracle.COLUMNS],
                "rows": [[str(self.definition[model][name]) for name in oracle.COLUMNS]]}

    def event(self, begin=10, ack=20):
        return {"clock_domain": "synthetic-test-jvm", "ddl_success": True,
                "started_ns": begin, "commit_ack_ns": ack}

    def test_frozen_fixture_recomputed_without_saved_expected_values(self):
        self.assertEqual(1024, self.definition["initial"]["matched_rows"])
        self.assertEqual(249965568, self.definition["initial"]["sum_expr_01"])
        self.assertEqual(7976693248, self.definition["initial"]["sum_expr_32"])
        self.assertEqual("df4655191fb71a17d4a7c19baa84f7cf4cd350ea9ab44418baef885a9c545a37",
                         self.definition["query_sha256_utf8"])
        for number, name in enumerate(oracle.COLUMNS[1:], 1):
            self.assertEqual(5120 * number, self.definition["changed"][name] - self.definition["initial"][name])

    def test_saved_oracle_tampering_is_detected(self):
        for field in ("expected_result_initial", "query_sql", "query_sha256_utf8", "event"):
            changed = copy.deepcopy(self.contract)
            fixture = changed["complex_planning_fixture"]
            if field == "expected_result_initial":
                fixture[field]["sum_expr_32"] += 1
            elif field == "event":
                fixture[field]["offset_seconds_from_measurement_start"] = 179
            else:
                fixture[field] += " "
            with self.subTest(field=field), self.assertRaises(ValueError):
                oracle.verified_definition(changed)

    def test_invalid_source_blocks(self):
        valid = self.contract["complex_planning_fixture"]["selected_64_id_blocks"]
        invalid = [valid[:-1], [valid[0]] * 16, [True] + valid[1:], [[]] + valid[1:],
                   [-1] + valid[1:], [15625] + valid[1:], ["1"] + valid[1:]]
        for blocks in invalid:
            with self.subTest(blocks=blocks), self.assertRaises(ValueError):
                oracle.values_for_blocks(blocks, 0)
        with self.assertRaises(ValueError):
            oracle.values_for_blocks(valid, True)

    def test_coordinated_replacement_is_not_the_frozen_workload(self):
        changed = copy.deepcopy(self.contract)
        fixture = changed["complex_planning_fixture"]
        blocks = list(range(16))
        fixture["selected_64_id_blocks"] = blocks
        fixture["query_sql"] = oracle.query_for_blocks(blocks)
        fixture["query_sha256_utf8"] = hashlib.sha256(fixture["query_sql"].encode()).hexdigest()
        fixture["expected_result_initial"] = oracle.values_for_blocks(blocks, 0)
        fixture["event"]["expected_result_after_commit"] = oracle.values_for_blocks(blocks, 1)
        with self.assertRaises(ValueError):
            oracle.verified_definition(changed)

    def test_all_columns_required_not_just_count(self):
        for index in range(len(oracle.COLUMNS)):
            record = self.record()
            record["rows"][0][index] = str(int(record["rows"][0][index]) + 1)
            with self.subTest(index=index), self.assertRaises(ValueError):
                oracle.verify_request(record, self.definition)

    def test_partial_duplicate_and_wrong_type_columns_are_rejected(self):
        for change in ("missing", "duplicate", "order", "nonnumeric", "malformed"):
            record = self.record()
            columns = record["columns"]
            if change == "missing":
                columns.pop()
            elif change == "duplicate":
                columns[1] = columns[0]
            elif change == "order":
                columns[1], columns[2] = columns[2], columns[1]
            elif change == "nonnumeric":
                columns[1]["type"] = "VARCHAR"
            else:
                columns[1]["type"] = None
            with self.subTest(change=change), self.assertRaises(ValueError):
                oracle.verify_request(record, self.definition)

    def test_noninteger_null_and_partial_rows_are_rejected(self):
        for value in (None, 1.0, 1, True, "1.0", "1e3", "01", "-0", "", "+1024"):
            record = self.record()
            record["rows"][0][0] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                oracle.verify_request(record, self.definition)
        for rows in ([], [[]], self.record()["rows"] * 2):
            record = self.record()
            record["rows"] = rows
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                oracle.verify_request(record, self.definition)

    def test_before_ddl_requires_old_model(self):
        self.assertEqual("completed_before_ddl", oracle.verify_request(
            self.record(), self.definition, self.event())["phase"])
        with self.assertRaises(ValueError):
            oracle.verify_request(self.record("changed"), self.definition, self.event())

    def test_after_commit_requires_new_model(self):
        self.assertEqual("started_after_commit_ack", oracle.verify_request(
            self.record("changed", 21, 22), self.definition, self.event())["phase"])
        with self.assertRaises(ValueError):
            oracle.verify_request(self.record("initial", 21, 22), self.definition, self.event())

    def test_overlap_and_equal_boundaries_allow_either_complete_model(self):
        for started, finished in ((1, 10), (9, 11), (1, 30), (11, 19), (20, 22)):
            for model in ("initial", "changed"):
                with self.subTest(started=started, finished=finished, model=model):
                    result = oracle.verify_request(self.record(model, started, finished),
                                                   self.definition, self.event())
                    self.assertEqual("overlaps_ddl_or_boundary", result["phase"])
                    self.assertEqual(model, result["matched_model"])
                    self.assertFalse(result["snapshot_time_inferred"])

    def test_overlap_does_not_allow_a_mixture_of_snapshots(self):
        record = self.record("initial", 1, 30)
        record["rows"][0][1] = str(self.definition["changed"]["sum_expr_01"])
        with self.assertRaises(ValueError):
            oracle.verify_request(record, self.definition, self.event())

    def test_monotonic_clock_origin_may_be_negative(self):
        result = oracle.verify_request(self.record("changed", -9, -8), self.definition, self.event(-20, -10))
        self.assertEqual("started_after_commit_ack", result["phase"])

    def test_unordered_or_unrelated_timestamps_and_failed_ddl_are_rejected(self):
        for event in (self.event(20, 10), dict(self.event(), clock_domain="another-jvm"),
                      dict(self.event(), ddl_success=False), dict(self.event(), commit_ack_ns=True)):
            with self.subTest(event=event), self.assertRaises(ValueError):
                oracle.verify_request(self.record(), self.definition, event)
        with self.assertRaises(ValueError):
            oracle.verify_request(self.record(started=3, finished=2), self.definition)

    def profile(self, cached=False):
        # Synthetic format only. No offline test result is real FE execution evidence.
        return (f"Summary:\n   - Profile ID: {QUERY_ID}\n   - Task State: OK\n"
                f"   - Sql Statement: {self.definition['query_sql']}\n   - Distributed Plan: plan\n"
                "Execution Summary:\n   - Parse SQL Time: 1ms\n   - Plan Time: 9ms\n"
                "     - Nereids Analysis Time: 2ms\n     - Nereids Rewrite Time: 3ms\n"
                "     - Nereids Optimize Time: N/A\n     - Nereids Translate Time: 4ms\n"
                f"   - Is Nereids: Yes\n   - Is Cached: {'Yes' if cached else 'No'}\n")

    def test_cold_profile_preserves_unavailable_optimize_timing(self):
        result = oracle.verify_profile(self.profile(), QUERY_ID, self.definition["query_sql"], cached=False)
        self.assertEqual(["Nereids Optimize Time"], result["unavailable_stage_timings"])
        self.assertFalse(result["all_stage_timings_available"])
        self.assertEqual("N/A", result["raw_stage_timings"]["Nereids Optimize Time"])

    def test_profile_must_match_request_identity_sql_and_cache_state(self):
        for source in (self.profile().replace(QUERY_ID, "123-456"),
                       self.profile().replace("AS sum_expr_32", "AS wrong_alias"),
                       self.profile().replace("Task State: OK", "Task State: ERROR"),
                       self.profile().replace("Is Nereids: Yes", "Is Nereids: No"),
                       self.profile(cached=True), self.profile().replace("Plan Time: 9ms", "Plan Time: N/A"),
                       self.profile().replace("   - Plan Time: 9ms\n", "")):
            with self.subTest(source=source), self.assertRaises(ValueError):
                oracle.verify_profile(source, QUERY_ID, self.definition["query_sql"], cached=False)

    def test_warm_profile_may_have_no_planning_timings(self):
        source = self.profile(cached=True)
        for duration in ("1ms", "9ms", "2ms", "3ms", "4ms"):
            source = source.replace(duration, "N/A")
        result = oracle.verify_profile(source, QUERY_ID, self.definition["query_sql"], cached=True)
        self.assertEqual(6, len(result["unavailable_stage_timings"]))

    def test_original_terminal_success_states_are_preserved_for_cold_and_cached_queries(self):
        for cached in (False, True):
            for state in ("OK", "EOF"):
                with self.subTest(cached=cached, state=state):
                    source = self.profile(cached=cached).replace("Task State: OK", "Task State: " + state)
                    result = oracle.verify_profile(source, QUERY_ID, self.definition["query_sql"], cached=cached)
                    self.assertEqual(state, result["task_state"])
                    self.assertEqual(cached, result["cached"])

    def test_error_running_and_nonterminal_states_never_pass_even_for_cached_queries(self):
        for cached in (False, True):
            for state in ("ERR", "ERROR", "RUNNING", "NOOP", "UNKNOWN", "CANCELLED", "eof", "ok", "EOF ERROR", ""):
                with self.subTest(cached=cached, state=state), self.assertRaisesRegex(ValueError, "Task State"):
                    oracle.verify_profile(self.profile(cached=cached).replace("Task State: OK", "Task State: " + state),
                                          QUERY_ID, self.definition["query_sql"], cached=cached)

    def test_eof_cannot_hide_duplicate_conflicting_or_misplaced_task_state(self):
        source = self.profile(cached=True).replace("Task State: OK", "Task State: EOF")
        invalid = [source.replace("Task State: EOF", "Task State: EOF\n   - Task State: EOF"),
                   source.replace("Task State: EOF", "Task State: EOF\n   - Task State: ERROR"),
                   source + "   - Task State: EOF\n",
                   source.replace("   - Task State: EOF\n", "") + "   - Task State: EOF\n"]
        for text in invalid:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "profile field: Task State"):
                oracle.verify_profile(text, QUERY_ID, self.definition["query_sql"], cached=True)

    def test_eof_still_requires_exact_query_sql_cache_flag_and_planning_field_schema(self):
        source = self.profile(cached=True).replace("Task State: OK", "Task State: EOF")
        invalid = [source.replace(QUERY_ID, "123-456"), source.replace("AS sum_expr_32", "AS other_sum"),
                   source.replace("Is Cached: Yes", "Is Cached: No"), source.replace("Is Nereids: Yes", "Is Nereids: No"),
                   source.replace("   - Plan Time: 9ms\n", ""), source.replace("Plan Time: 9ms", "Plan Time: invalid")]
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ValueError):
                oracle.verify_profile(text, QUERY_ID, self.definition["query_sql"], cached=True)
        cold = self.profile().replace("Task State: OK", "Task State: EOF").replace("Plan Time: 9ms", "Plan Time: N/A")
        with self.assertRaisesRegex(ValueError, "Cold query lacks"):
            oracle.verify_profile(cold, QUERY_ID, self.definition["query_sql"], cached=False)

    def test_concatenated_profiles_and_duplicate_fields_cannot_supply_identity(self):
        for text in (self.profile() * 2,
                     self.profile().replace(QUERY_ID, "123-456") + f"   - Profile ID: {QUERY_ID}\n",
                     self.profile() + "   - Is Cached: Yes\n",
                     self.profile() + "   - Task State: ERROR\n",
                     self.profile() + "   - Plan Time: 0ms\n",
                     self.profile().replace(f"   - Profile ID: {QUERY_ID}\n", "")
                     + f"   - Profile ID: {QUERY_ID}\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                oracle.verify_profile(text, QUERY_ID, self.definition["query_sql"], cached=False)

    def test_original_time_ms_format_is_validated_without_inventing_missing_values(self):
        for value in ("0ms", "999ms", "1sec0ms", "59sec999ms", "1min", "59min59sec", "1hour", "24hour59min"):
            with self.subTest(value=value):
                result = oracle.verify_profile(self.profile().replace("Plan Time: 9ms", "Plan Time: " + value),
                                               QUERY_ID, self.definition["query_sql"], cached=False)
                self.assertEqual(value, result["raw_stage_timings"]["Plan Time"])
        for value in ("", "  ", "garbage", "-1ms", "1.0ms", "60sec0ms", "1ms2sec", "0hour"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                oracle.verify_profile(self.profile().replace("Plan Time: 9ms", "Plan Time: " + value),
                                      QUERY_ID, self.definition["query_sql"], cached=False)


if __name__ == "__main__":
    unittest.main()
