#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline negative evidence tests; synthetic receipts never prove an actual concurrent FE event."""

import contextlib
import copy
import io
import json
import math
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import complex_planning_fixture as fixture


class ComplexPlanningFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.definition = fixture.oracle.verified_definition(json.loads(fixture.oracle.CONTRACT.read_text()))

    def test_default_cli_does_not_dispatch_probe(self):
        with patch.object(fixture, "make_plan", return_value={"status": "PLANNED_NOT_RUN"}) as plan, \
                patch.object(fixture, "probe", side_effect=AssertionError("unexpected network")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, fixture.main(["--output", "unused", "--cluster-record", "unused", "--rate", "1"]))
            plan.assert_called_once()

    def test_probe_requires_explicit_mode_and_input(self):
        with patch.object(fixture, "probe", return_value={"status": "FUNCTIONAL_WINDOW_PASS"}) as probe, \
                patch.object(fixture, "make_plan", side_effect=AssertionError("unexpected plan")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, fixture.main(["--mode", "probe", "--plan", "unused"]))
            probe.assert_called_once()

    def test_arrivals_are_complete_deterministic_and_independent_of_workers(self):
        first = fixture.arrivals(1.0, 180, 600, 20000)
        self.assertEqual(first, fixture.arrivals(1.0, 180, 600, 20000))
        self.assertEqual(20260922, first["seed"])
        for phase, seconds in (("warmup", 180), ("measurement", 600)):
            values = first[phase + "_offsets_ns"]
            self.assertTrue(values and all(type(value) is int and 0 < value < seconds * 1000000000 for value in values))
            self.assertEqual(sorted(set(values)), values)
        self.assertTrue(any(value < 180000000000 for value in first["measurement_offsets_ns"]))
        self.assertTrue(any(value > 180000000000 for value in first["measurement_offsets_ns"]))

    def test_arrival_limit_or_invalid_rate_never_silently_truncates_work(self):
        for rate in (0, -1, True, math.nan, math.inf, 101, "1"):
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                fixture.arrivals(rate, 180, 600, 20000)
        with self.assertRaises(ValueError):
            fixture.arrivals(1.0, 180, 600, 1)
        for warmup, window in ((-1, 600), (181, 600), (0, 180), (180, 601)):
            with self.subTest(warmup=warmup, window=window), self.assertRaises(ValueError):
                fixture.arrivals(1.0, warmup, window, 20000)

    def test_jsonl_partial_line_is_not_a_completed_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "requests.jsonl"
            path.write_bytes(b'{"a":1}\n{"a":')
            reader = fixture.JsonLines(path, 1024)
            self.assertEqual([{"a": 1}], reader.read())
            with self.assertRaises(ValueError):
                reader.read(final=True)
            with path.open("ab") as output:
                output.write(b'2}\n')
            self.assertEqual([{"a": 2}], reader.read(final=True))

    def test_jsonl_truncation_oversize_and_missing_final_file_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "requests.jsonl"
            reader = fixture.JsonLines(path, 1024)
            self.assertEqual([], reader.read())
            with self.assertRaises(ValueError):
                reader.read(final=True)
            path.write_text('{"a":1}\n')
            reader.read()
            path.write_text("")
            with self.assertRaises(ValueError):
                reader.read()
            path.write_text(" " * 1025)
            with self.assertRaises(ValueError):
                fixture.JsonLines(path, 1024).read()

    def case(self):
        # Only an offline oracle format fixture. No server, DDL or clock has run.
        start = {"clock_domain": "synthetic-test-jvm", "warmup_start_ns": 0, "measurement_start_ns": 1000000000}
        schedule = {"warmup_seconds": 1, "window_seconds": 240, "warmup_offsets_ns": [100, 200],
                    "measurement_offsets_ns": [181000000000, 182000000000]}
        event = {"clock_domain": start["clock_domain"], "scheduled_ns": 181000000000,
                 "started_ns": 181000000010, "commit_ack_ns": 181000000050,
                 "ddl_success": True, "ddl_attempted": True, "commit_outcome": "ACKNOWLEDGED",
                 "post_ddl_inspection_success": True, "sql": "ALTER VIEW " + fixture.oracle.VIEW
                 + " AS SELECT id, grp, v + 1 AS v, payload FROM license_perf.point_rows"}
        rows, profiles, explains = [], {}, {}
        for number in range(4):
            phase = "warmup" if number < 2 else "measurement"
            model = "initial" if number < 2 else "changed"
            index = number % 2
            when = start[phase + "_start_ns"] + schedule[phase + "_offsets_ns"][index]
            identifier, query_id = number + 1, f"abc-{number + 1:x}"
            record = {"request_id": identifier, "phase": phase, "clock_domain": start["clock_domain"],
                      "success": True, "arrival_index": index, "scheduled_ns": when, "request_started_ns": when,
                      "profile_overlap_cap_violation": False, "event_overlap": False,
                      "started_ns": when + 1, "finished_ns": when + 2, "request_finished_ns": when + 4,
                      "query_id": query_id, "query_id_same_connection": True, "query_id_sql": "SELECT last_query_id()",
                      "query_sha256_utf8": self.definition["query_sha256_utf8"], "sample_profile": True,
                      "columns": [{"name": name, "type": "BIGINT"} for name in fixture.oracle.COLUMNS],
                      "rows": [[str(self.definition[model][name]) for name in fixture.oracle.COLUMNS]]}
            if index == 1:
                name = f"explain-request-{identifier}.json"
                record["explain_file"] = name
                explains[name] = {"success": True, "target_request_id": identifier, "target_query_id": query_id,
                                  "phase": phase, "clock_domain": start["clock_domain"],
                                  "after_target_query_id_capture": True,
                                  "sql": "EXPLAIN PHYSICAL PLAN " + self.definition["query_sql"],
                                  "started_ns": when + 2, "finished_ns": when + 3,
                                  "rows": ["PhysicalSqlCache[0] output expressions"]}
            rows.append(record)
            profiles[query_id] = {"request_id": identifier, "proof": {"cached": index == 1}}
        intents = [{key: record[key] for key in ("request_id", "phase", "arrival_index", "scheduled_ns",
                                                "request_started_ns", "clock_domain")} for record in rows]
        return {"start": start, "schedule": schedule, "event": event, "rows": rows,
                "profiles": profiles, "explains": explains, "intents": intents}

    def check(self, case):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, value in (("measurement-start.json", case["start"]), ("arrivals.json", case["schedule"]),
                                ("event.json", case["event"]), *case["explains"].items()):
                fixture.SAVE(directory / name, value)
            for name, records in (("requests.jsonl", case["rows"]), ("request-starts.jsonl", case["intents"])):
                (directory / name).write_text("".join(json.dumps(record) + "\n" for record in records))
            return fixture.result_audit(directory, self.definition, {"case_id": "LP-007", "profile_every_n": 10},
                                        case["profiles"])

    def test_full_receipt_fixture_verifies_all_columns_and_phases_without_claiming_performance(self):
        result = self.check(self.case())
        self.assertEqual(4, result["requests_verified"])
        self.assertTrue(result["all_33_columns_per_request"])
        self.assertFalse(result["performance_pass"])
        self.assertEqual({"initial", "changed"}, set(result["cache_explain_models"]))

    def test_event_overlap_sample_cannot_be_skipped_duplicated_or_over_limit(self):
        case = self.case()
        case["rows"][2].update(event_overlap=True, event_overlap_ordinal=1, sample_reason="event_overlap")
        self.assertEqual(1, self.check(case)["event_overlap_samples_verified"])
        for changes in ({"event_overlap_ordinal": 65}, {"sample_profile": False},
                        {"profile_overlap_cap_violation": True}, {"sample_reason": "periodic"}):
            case = self.case()
            case["rows"][2].update(event_overlap=True, event_overlap_ordinal=1, sample_reason="event_overlap")
            case["rows"][2].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.check(case)

    def test_required_sampling_cannot_be_disabled_even_with_remaining_profile_phases(self):
        for index in range(4):
            case = self.case()
            case["rows"][index]["sample_profile"] = False
            case["profiles"].pop(case["rows"][index]["query_id"])
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "mandatory"):
                self.check(case)

    def test_worker_setup_cannot_omit_connection_cost_or_cross_the_window_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            value = {"worker": 0, "success": True, "clock_domain": "test", "connection_mode": "reuse",
                     "started_ns": -10, "finished_ns": 0, "connection_ns": 3, "session_init_ns": 2, "prepare_ns": 1}
            fixture.SAVE(output / "worker-setup-0.json", value)
            identity, start = {"clock_domain": "test"}, {"warmup_start_ns": 1}
            plan = {"concurrency": 1, "connection_mode": "reuse"}
            self.assertEqual([value], fixture.setup_audit(output, identity, start, plan))
            for changes in ({"connection_ns": -1}, {"prepare_ns": 100}, {"finished_ns": 2},
                            {"clock_domain": "foreign"}, {"success": False}):
                fixture.SAVE(output / "worker-setup-0.json", {**value, **changes})
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    fixture.setup_audit(output, identity, start, plan)

    def test_missing_scheduled_request_or_uncompleted_intent_is_not_a_successful_subset(self):
        for field in ("rows", "intents"):
            case = self.case()
            case[field].pop()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(case)

    def test_duplicate_ids_arrivals_or_query_ids_are_rejected(self):
        for field in ("request_id", "arrival_index", "query_id"):
            case = self.case()
            case["rows"][1][field] = case["rows"][0][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(case)

    def test_scheduled_time_total_boundaries_and_intent_must_match(self):
        for field in ("scheduled_ns", "request_started_ns", "request_finished_ns", "started_ns"):
            case = self.case()
            case["rows"][0][field] = 0
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(case)
        case = self.case()
        case["intents"][0]["clock_domain"] = "unrelated-jvm"
        with self.assertRaises(ValueError):
            self.check(case)

    def test_each_aggregate_column_must_be_correct_after_commit(self):
        for index in (0, 1, 16, 32):
            case = self.case()
            row = case["rows"][2]["rows"][0]
            row[index] = str(int(row[index]) + 1)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.check(case)

    def test_unknown_early_changed_or_foreign_clock_event_fails(self):
        for field, value in (("commit_outcome", "UNKNOWN"), ("scheduled_ns", 180000000000),
                             ("started_ns", 0), ("clock_domain", "other-jvm"), ("sql", "SELECT 1")):
            case = self.case()
            case["event"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(case)

    def test_profile_cache_phase_or_query_association_cannot_be_omitted(self):
        case = self.case()
        case["profiles"]["abc-3"]["proof"]["cached"] = True
        with self.assertRaises(ValueError):
            self.check(case)
        for field, value in (("query_id_same_connection", False), ("query_id_sql", "SELECT query_id()"),
                             ("query_sha256_utf8", "0" * 64)):
            case = self.case()
            case["rows"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(case)

    def test_explain_claim_requires_raw_cache_plan_from_same_request_and_clock(self):
        for field, value in (("rows", ["PhysicalOlapScan[0]"]), ("target_query_id", "another-query"),
                             ("clock_domain", "other-jvm"), ("finished_ns", 999999999999999),
                             ("sql", "EXPLAIN SELECT 1")):
            case = self.case()
            case["explains"]["explain-request-4.json"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(case)
        case = self.case()
        case["rows"][3]["explain_file"] = "../other.json"
        with self.assertRaises(ValueError):
            self.check(case)

    def test_profile_cookie_is_logged_out_even_when_body_read_fails(self):
        calls = []
        def exchange(state, method, path, headers, maximum, seconds, on_headers=None):
            calls.append(path)
            if on_headers:
                on_headers([("Set-Cookie", "PALO_SESSION_ID=synthetic; Path=/")])
                raise TimeoutError()
            self.assertEqual({"Cookie": "PALO_SESSION_ID=synthetic"}, headers)
            return 200, [], b'{"code":0}'
        with patch.object(fixture, "http_exchange", side_effect=exchange), \
                patch.object(fixture.support, "validate_live_identity"), \
                patch.dict(fixture.os.environ, {"TEST_COMPLEX_PASSWORD": "synthetic-password"}), \
                self.assertRaises(TimeoutError):
            fixture.profile_http({}, "root", "TEST_COMPLEX_PASSWORD", "abc-1")
        self.assertEqual(["/api/profile/text?query_id=abc-1", "/rest/v1/logout"], calls)

    def test_no_completion_claim_is_available_from_functional_fixture(self):
        value = fixture.incomplete()
        self.assertFalse(value["full_goal_complete"])
        self.assertFalse(value["LP006_complete"])
        self.assertFalse(value["LP007_complete"])
        self.assertFalse(value["release_performance_pass"])


class ComplexResourceLifecycleTest(unittest.TestCase):
    def receipts(self):
        output = {"name": "adapter", "thread_stopped": True, "errors": [],
                  "eof": ["stderr", "stdout"], "bytes": {"stdout": 0, "stderr": 0}}
        processes = [{"name": "adapter", "stopped": True, "output": output}]
        resources = {"complete": True, "failure_count": 0, "observer_thread_stopped": True,
                     "logs": [copy.deepcopy(output)]}
        return SimpleNamespace(resource_failure=None), processes, resources

    def test_plan_resource_budget_must_equal_actual_guard_limits(self):
        plan = {"rss_limit_mib": 2048, "resource_limits": dict(fixture.support.resources_module.LIMITS)}
        fixture.validate_resource_limits(plan)
        for changed in ({"rss_limit_mib": 1024}, {"rss_limit_mib": True}, {"resource_limits": {}},
                        {"resource_limits": {**plan["resource_limits"], "controller_rss_bytes": 1}}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                fixture.validate_resource_limits({**plan, **changed})

    def test_success_requires_final_eof_threads_and_no_late_resource_failure(self):
        budget, processes, resources = self.receipts()
        self.assertTrue(fixture.audit_auxiliary_cleanup(budget, processes, resources)["complete"])
        for changed in ({"thread_stopped": False}, {"errors": ["OSError"]}, {"eof": ["stdout"]},
                        {"bytes": {"stdout": 2 * 1024 * 1024 + 1, "stderr": 0}}):
            altered = copy.deepcopy(processes)
            altered[0]["output"].update(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                fixture.audit_auxiliary_cleanup(budget, altered, resources)
        budget.resource_failure = ("adapter_output", "OSError")
        with self.assertRaisesRegex(ValueError, "output failure"):
            fixture.audit_auxiliary_cleanup(budget, processes, resources)

    def test_stopped_flag_cannot_hide_process_cleanup_error_or_sampler_failure(self):
        budget, processes, resources = self.receipts()
        processes[0]["cleanup_error"] = {"class": "OSError"}
        with self.assertRaisesRegex(ValueError, "Helper cleanup failed"):
            fixture.audit_auxiliary_cleanup(budget, processes, resources)
        del processes[0]["cleanup_error"]
        for changed in ({"complete": False}, {"failure_count": 1}, {"observer_thread_stopped": False}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "Resource lifecycle"):
                fixture.audit_auxiliary_cleanup(budget, processes, {**resources, **changed})

    def test_resource_shutdown_runs_even_after_process_cleanup_raises(self):
        budget, _, receipt = self.receipts()
        processes, resources = Mock(), Mock()
        processes.stop_all.side_effect = OSError("process cleanup failed")
        resources.stop.return_value = receipt
        result = fixture.finish_auxiliary_resources(resources, processes, budget)
        resources.stop.assert_called_once()
        self.assertFalse(result["complete"])
        self.assertEqual("final_helper_shutdown", result["errors"][0]["step"])

    def test_processes_are_reaped_before_resource_evidence_failure_is_reported(self):
        budget, receipts, _ = self.receipts()
        order = []
        processes, resources = Mock(), Mock()
        processes.stop_all.side_effect = lambda: order.append("processes") or receipts
        def fail_evidence():
            order.append("resources")
            raise OSError("resource summary unavailable")
        resources.stop.side_effect = fail_evidence
        result = fixture.finish_auxiliary_resources(resources, processes, budget)
        self.assertEqual(["processes", "resources"], order)
        self.assertFalse(result["complete"])
        self.assertTrue(result["process_cleanup"][0]["stopped"])


if __name__ == "__main__":
    unittest.main()
