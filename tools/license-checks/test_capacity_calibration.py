#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

import csv
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import calibrate_read_capacity as capacity


def evidence_window(count=10000, p99=10):
    return {"scheduled_requests": count, "observed_requests": count, "successful_requests": count,
            "missing_requests": 0, "errors": {}, "cpu_boundary_verified": True,
            "p99_ms": p99, "drain_seconds": 0}


def assess_windows(windows, expected=None, formal=False):
    report = {"windows": windows}
    evidence = {"valid": True, "windows": windows}
    return capacity.assess(report, 100, 1, expected or len(windows), formal, evidence)


class CapacityDecisionsTest(unittest.TestCase):
    def test_fractional_capacity_sweep_preserves_a_sub_one_percent_bracket(self):
        rates = capacity.parse_rates("0.25,0.252")
        trials = [{"rate": rates[0], "assessment": "within_slo"},
                  {"rate": rates[1], "assessment": "outside_slo"}]
        result = capacity.capacity_bracket(trials, "confirm", True, rates)
        self.assertTrue(result["capacity_bracket_established"])
        self.assertAlmostEqual(result["bracket_width_percent_of_lower_bound"], .8)
        self.assertEqual(result["candidate_rates_30_60_85_percent"], [.075, .15, .2125])
        # A fractional offered rate does not waive the independent per-window sample floor.
        self.assertEqual(assess_windows([evidence_window(count=150)], formal=True), "invalid_trial")

    def test_capacity_cli_rejects_invalid_rates_and_keeps_integer_trial_names(self):
        rates = capacity.parse_rates("750,1000,1250")
        self.assertEqual(rates, [750, 1000, 1250])
        self.assertTrue(all(type(item) is int for item in rates))
        for value in ("", "1,", "NaN", "Infinity", "-1", "0", "100001", "2,1", "0.1,1e-1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                capacity.parse_rates(value)

    def test_current_baseline_identity_is_bound_to_actual_artifacts(self):
        identity = {"source_commit": "a" * 40, "fe_sha256": "b" * 64, "be_sha256": "c" * 64,
                    "environment_sha256": "d" * 64, "configuration_sha256": "e" * 64,
                    "fixture_sha256": "f" * 64, "client_sha256": "1" * 64}
        workload = {"p4_baseline_identity": identity, "build_identity": {"baseline_source_commit": "a" * 40}}
        bindings = {"fe_artifact": {"sha256": "b" * 64}, "be_artifact": {"sha256": "c" * 64}}
        self.assertEqual(capacity.baseline_identity(workload, bindings, required=True), identity)
        with self.assertRaisesRegex(ValueError, "executable artifacts"):
            capacity.baseline_identity(workload, dict(bindings, fe_artifact={"sha256": "0" * 64}), required=True)
        self.assertIsNone(capacity.baseline_identity({}, bindings))
        with self.assertRaisesRegex(ValueError, "complete p4_baseline_identity"):
            capacity.baseline_identity({}, bindings, required=True)

    def test_capacity_percentages_preserve_fractional_offered_rates(self):
        trials = [{"rate": 4250, "assessment": "within_slo"}, {"rate": 4290, "assessment": "outside_slo"}]
        result = capacity.capacity_bracket(trials, "confirm", True, [4250, 4290])
        self.assertTrue(result["capacity_bracket_established"])
        self.assertEqual(result["candidate_rates_30_60_85_percent"], [1275.0, 2550.0, 3612.5])

    def test_fixed_rate_success_is_not_an_unbounded_capacity_claim(self):
        result = capacity.capacity_bracket([{"rate": 1000, "assessment": "within_slo"}], "confirm", True, [1000])
        self.assertFalse(result["capacity_bracket_established"])
        self.assertIsNone(result["candidate_rates_30_60_85_percent"])

    def test_pilot_and_wide_brackets_never_freeze_capacity_percentages(self):
        tight = [{"rate": 1000, "assessment": "within_slo"}, {"rate": 1010, "assessment": "outside_slo"}]
        self.assertFalse(capacity.capacity_bracket(tight, "pilot", True, [1000, 1010])["capacity_bracket_established"])
        wide = [tight[0], {"rate": 2000, "assessment": "outside_slo"}]
        self.assertFalse(capacity.capacity_bracket(wide, "confirm", True, [1000, 2000])["capacity_bracket_established"])
        self.assertFalse(capacity.capacity_bracket(tight, "confirm", False, [1000, 1010])["capacity_bracket_established"])
        self.assertEqual([300, 600, 850], capacity.capacity_bracket(tight, "confirm", True, [1000, 1010])[
            "candidate_rates_30_60_85_percent"])

    def test_nonmonotonic_and_invalid_trials_require_investigation(self):
        trials = [{"rate": 1000, "assessment": "within_slo"}, {"rate": 1005, "assessment": "outside_slo"},
                  {"rate": 1010, "assessment": "within_slo"}, {"rate": 1015, "assessment": "outside_slo"}]
        result = capacity.capacity_bracket(trials, "confirm", True, [t["rate"] for t in trials])
        self.assertTrue(result["nonmonotonic_response"])
        self.assertFalse(result["capacity_bracket_established"])
        trials = [trials[0], {"rate": 1005, "assessment": "invalid_trial"}, trials[1]]
        self.assertFalse(capacity.capacity_bracket(trials, "confirm", True,
                         [t["rate"] for t in trials])["capacity_bracket_established"])

    def test_errors_and_count_disagreement_are_not_capacity_bounds(self):
        window = evidence_window()
        self.assertEqual("within_slo", assess_windows([window]))
        window["p99_ms"] = 101
        self.assertEqual("outside_slo", assess_windows([window]))
        window["errors"] = {"SQL_SYNTAX": 1}
        self.assertEqual("invalid_trial", assess_windows([window]))
        window["errors"] = {}
        window["observed_requests"] -= 1
        self.assertEqual("invalid_trial", assess_windows([window]))

    def test_early_bracket_cannot_skip_the_rest_of_the_frozen_sweep(self):
        trials = [{"rate": 1000, "assessment": "within_slo"}, {"rate": 1010, "assessment": "outside_slo"}]
        result = capacity.capacity_bracket(trials, "confirm", True, [1000, 1010, 1020])
        self.assertFalse(result["all_planned_trials_completed"])
        self.assertFalse(result["capacity_bracket_established"])

    def test_confirmation_requires_every_window_and_the_sample_floor(self):
        windows = [evidence_window(9999) for _ in range(10)]
        self.assertEqual("invalid_trial", assess_windows(windows, formal=True))
        self.assertEqual("within_slo", assess_windows(windows))
        windows = [evidence_window(10000) for _ in range(10)]
        self.assertEqual("within_slo", assess_windows(windows, formal=True))
        windows.pop()
        self.assertEqual("invalid_trial", assess_windows(windows, expected=10, formal=True))

    def test_nonfinite_or_negative_measurements_are_invalid(self):
        for invalid in (float("nan"), float("inf"), -1, None, True):
            self.assertEqual("invalid_trial", assess_windows([evidence_window(p99=invalid)]))

    def test_green_helper_flags_without_raw_artifact_evidence_are_not_a_measurement(self):
        report = {"windows": [evidence_window()], "identical_arrival_schedules_across_windows": True,
                  "identical_point_key_sequences_across_windows": True}
        self.assertEqual("invalid_trial", capacity.assess(report, 100, 1, 1))
        self.assertEqual("invalid_trial", capacity.assess(report, 100, 1, 1,
                         evidence={"valid": False, "windows": report["windows"]}))
        report["windows"][0]["cpu_boundary_verified"] = False
        self.assertEqual("invalid_trial", assess_windows(report["windows"]))


class RawEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="license-capacity-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workload = {"duration_seconds": 1, "warmup_seconds": 0, "concurrency": 2, "pairs": 1, "seed": 5,
                         "connection_mode": "reuse", "point_key_workload": {"table": "license_perf.point_rows",
                         "mode": "prepared", "seed": 8}, "build_identity": {"source": "test"}}
        self.ticks = {"fe": 123, "be": 456}

    def vector(self, directory, name, values, width):
        data = b"".join(struct.pack(">q" if width == 8 else ">i", value) for value in values)
        (directory / name).write_bytes(data)
        hashed = hashlib.sha256(data).hexdigest()
        (directory / (name + ".sha256")).write_text(hashed + "\n")
        return hashed

    def window(self, name="window-00", point=True):
        directory = self.root / name
        directory.mkdir()
        workload = dict(self.workload)
        if not point:
            workload.pop("point_key_workload")
            workload["queries"] = [{"sql": "SELECT 1", "expected_rows": 1}]
        arrivals = [1000000, 2000000, 3000000, 4000000]
        keys = [991111, 552222, 333, 654321]
        arrival_hash = self.vector(directory, "arrivals.bin", arrivals, 8)
        warmup_hash = self.vector(directory, "warmup-arrivals.bin", [], 8)
        key_hash = self.vector(directory, "point-keys.bin", keys, 4) if point else None
        warmup_key_hash = self.vector(directory, "warmup-point-keys.bin", [], 4) if point else None
        (directory / "arrival-count").write_text("4\n")
        for worker in range(2):
            header = "index,query_index,scheduled_ns,start_ns,end_ns,rows,error_code,sql_state"
            rows = []
            for index in range(worker, len(arrivals), 2):
                row = [index, 0, arrivals[index], arrivals[index] + 1000, arrivals[index] + 3000, 1, 0, "00000"]
                if point:
                    row.append(keys[index])
                rows.append(",".join(str(value) for value in row))
            (directory / ("worker-%d.csv" % worker)).write_text(header + (",point_key" if point else "")
                                                              + "\n" + "\n".join(rows) + "\n")
        epoch = 1000000000
        def cpu(start):
            return {name: {"cpu_seconds": 1.0 if start else 2.0, "rss_bytes": 1000,
                    "start_ticks": ticks, "sample_started_ns": epoch - 1000 if start else epoch + 10**9 + 1000,
                    "sample_ended_ns": epoch - 500 if start else epoch + 10**9 + 2000}
                    for name, ticks in self.ticks.items()}
        start = {"epoch_ns": epoch, "cpu": cpu(True)}
        end = {"epoch_ns": epoch, "last_request_end_ns": epoch + arrivals[-1] + 3000,
               "request_interval_end_ns": epoch + 10**9, "measurement_end_ns": epoch + 10**9 + 3000, "cpu": cpu(False)}
        lifecycle = {"completed": True, "cleanup_start_ns": end["measurement_end_ns"] + 1000,
                     "cleanup_end_ns": end["measurement_end_ns"] + 10000}
        for filename, data in (("measurement-start.json", start), ("measurement-end.json", end), ("lifecycle.json", lifecycle)):
            capacity.write_json(directory / filename, data)
        resources = {"cpu": {"start": start["cpu"], "end": end["cpu"]},
                     "boundary": capacity.baseline.boundary_evidence(start, end, lifecycle), "samples": []}
        capacity.write_json(directory / "resources.json", resources)
        report = capacity.baseline.summarize(directory, 4, 1, resources["cpu"])
        report.update(process_exit_code=0, cpu_boundary_verified=True, arrival_seed=5,
                      schedule_hash_matches_helper=True, arrival_schedule_sha256=arrival_hash,
                      warmup_arrival_schedule_sha256=warmup_hash, connection_mode="reuse",
                      query_workload_kind="uniform_point_keys" if point else "static_query_vector")
        if point:
            report["point_keys"] = {"seed": 8, "range_inclusive": [0, 999999], "mode": "prepared", "count": 4,
                                    "sha256": key_hash, "warmup_sha256": warmup_key_hash, "hashes_verified": True}
            oracle = {"algorithm": "lowercase_md5_ascii_decimal_id", "unique_precomputed_keys": 4,
                      "comparison_inside_request_timing": True, "precomputation_before_connections": True}
            capacity.write_json(directory / "point-result-oracle.json", oracle)
            report["point_result_oracle"] = oracle
        capacity.write_json(directory / "summary.json", report)
        return directory, workload, report

    def test_complete_binary_csv_and_cpu_evidence_is_recomputed(self):
        for point in (True, False):
            directory, workload, report = self.window("point" if point else "static", point)
            result = capacity.verify_window(directory, report, workload, self.ticks)
            self.assertEqual(result["successful_requests"], 4)
            self.assertEqual(result["p99_ms"], .003)
            self.assertTrue(result["cpu_boundary_verified"])

    def test_duplicate_request_is_invalid_even_when_helper_counts_still_claim_complete(self):
        directory, workload, report = self.window()
        path = directory / "worker-0.csv"
        rows = path.read_text().splitlines()
        rows[2] = rows[1]
        path.write_text("\n".join(rows) + "\n")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            capacity.verify_window(directory, report, workload, self.ticks)

    def test_csv_point_key_must_match_the_actual_binary_sequence(self):
        directory, workload, report = self.window()
        path = directory / "worker-0.csv"
        path.write_text(path.read_text().replace(",991111\n", ",991112\n"))
        with self.assertRaisesRegex(ValueError, "Executed point key"):
            capacity.verify_window(directory, report, workload, self.ticks)

    def test_missing_or_false_boundary_and_schedule_flags_are_rejected(self):
        for key in ("cpu_boundary_verified", "schedule_hash_matches_helper"):
            directory, workload, report = self.window(key)
            report[key] = False
            capacity.write_json(directory / "summary.json", report)
            with self.assertRaises(ValueError):
                capacity.verify_window(directory, report, workload, self.ticks)

    def test_fake_green_point_hash_does_not_replace_recomputed_hash(self):
        directory, workload, report = self.window()
        (directory / "point-keys.bin.sha256").write_text("0" * 64)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            capacity.verify_window(directory, report, workload, self.ticks)

    def test_missing_point_oracle_cannot_be_replaced_by_summary_claim(self):
        directory, workload, report = self.window()
        (directory / "point-result-oracle.json").unlink()
        with self.assertRaises(FileNotFoundError):
            capacity.verify_window(directory, report, workload, self.ticks)

    def test_point_oracle_requires_all_warmup_and_measurement_keys(self):
        directory, workload, report = self.window()
        report["point_result_oracle"]["unique_precomputed_keys"] = 3
        capacity.write_json(directory / "point-result-oracle.json", report["point_result_oracle"])
        capacity.write_json(directory / "summary.json", report)
        with self.assertRaisesRegex(ValueError, "does not cover"):
            capacity.verify_window(directory, report, workload, self.ticks)

    def test_untimed_oracle_comparison_is_not_the_declared_workload(self):
        directory, workload, report = self.window()
        report["point_result_oracle"]["comparison_inside_request_timing"] = False
        capacity.write_json(directory / "point-result-oracle.json", report["point_result_oracle"])
        capacity.write_json(directory / "summary.json", report)
        with self.assertRaisesRegex(ValueError, "oracle is missing or differs"):
            capacity.verify_window(directory, report, workload, self.ticks)

    def test_reported_latency_cannot_override_slow_raw_requests(self):
        directory, workload, report = self.window()
        report["p99_ms"] = 0
        capacity.write_json(directory / "summary.json", report)
        with self.assertRaisesRegex(ValueError, "p99_ms differs"):
            capacity.verify_window(directory, report, workload, self.ticks)

    def test_reported_cpu_cost_cannot_override_actual_boundary_counters(self):
        directory, workload, report = self.window()
        report["fe_cpu_seconds_per_success"] = 0
        capacity.write_json(directory / "summary.json", report)
        with self.assertRaisesRegex(ValueError, "CPU per success"):
            capacity.verify_window(directory, report, workload, self.ticks)

    def test_frozen_static_full_result_oracle_must_match_actual_summary(self):
        directory, workload, report = self.window(point=False)
        workload["queries"][0]["expected_result"] = {
            "columns": [{"label": "1", "jdbc_type": 4}], "rows": [["1"]]}
        with self.assertRaisesRegex(ValueError, "Static full-result oracle"):
            capacity.verify_window(directory, report, workload, self.ticks)
        query = workload["queries"][0]
        report["static_result_oracles"] = [{"query_index": 0,
            "sha256": hashlib.sha256(capacity.baseline.encode_result_oracle(query)).hexdigest(),
            "columns": 1, "rows": 1, "ordered": True, "comparison_inside_request_timing": True}]
        capacity.write_json(directory / "summary.json", report)
        self.assertEqual(capacity.verify_window(directory, report, workload, self.ticks)["successful_requests"], 4)

    def driver_evidence(self):
        workload = {"concurrency": 2, "connection_mode": "reuse",
                    "point_key_workload": {"mode": "prepared"}}
        records = [{"worker": worker, "connection_mode": "reuse", "driver_class": "org.mariadb.jdbc.Driver",
                    "connection_classes": {"org.mariadb.jdbc.Connection": 1}, "queries": [{"query_index": 0,
                    "prepared": True, "statement_count": 1, "warmup_execute_attempts": 1,
                    "measured_execute_attempts": 2, "same_reused_statement": True,
                    "statement_classes": {"org.mariadb.jdbc.ServerPreparedStatement": 1}}]} for worker in range(2)]
        return workload, records

    def save_driver_evidence(self, records):
        for worker, record in enumerate(records):
            capacity.write_json(self.root / ("driver-worker-%d.json" % worker), record)
        return {"driver_evidence": records}

    def test_actual_server_statement_and_repeated_execute_evidence_is_accepted(self):
        workload, records = self.driver_evidence()
        capacity.verify_driver_evidence(self.root, self.save_driver_evidence(records), workload, 4, 2)

    def test_client_prepared_fallback_is_not_server_prepared_evidence(self):
        workload, records = self.driver_evidence()
        records[0]["queries"][0]["statement_classes"] = {"org.mariadb.jdbc.ClientPreparedStatement": 1}
        with self.assertRaisesRegex(ValueError, "server-prepared"):
            capacity.verify_driver_evidence(self.root, self.save_driver_evidence(records), workload, 4, 2)

    def test_reprepare_or_stale_execute_counts_cannot_claim_reuse(self):
        for field, value in (("statement_count", 3), ("measured_execute_attempts", 1),
                             ("same_reused_statement", False)):
            workload, records = self.driver_evidence()
            records[0]["queries"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "reuse evidence"):
                capacity.verify_driver_evidence(self.root, self.save_driver_evidence(records), workload, 4, 2)

    def test_short_connections_cannot_hide_extra_connections(self):
        workload, records = self.driver_evidence()
        records[0]["connection_classes"]["org.mariadb.jdbc.Connection"] = 2
        with self.assertRaisesRegex(ValueError, "connection count"):
            capacity.verify_driver_evidence(self.root, self.save_driver_evidence(records), workload, 4, 2)

    def test_cpu_last_request_boundary_is_checked_against_actual_csv(self):
        directory, workload, report = self.window()
        end = capacity.read_json(directory / "measurement-end.json")
        end["last_request_end_ns"] += 1
        capacity.write_json(directory / "measurement-end.json", end)
        resources = capacity.read_json(directory / "resources.json")
        resources["boundary"] = capacity.baseline.boundary_evidence(
            capacity.read_json(directory / "measurement-start.json"), end,
            capacity.read_json(directory / "lifecycle.json"))
        capacity.write_json(directory / "resources.json", resources)
        with self.assertRaisesRegex(ValueError, "actual final request"):
            capacity.verify_window(directory, report, workload, self.ticks)

    def test_trial_requires_every_actual_window_and_frozen_build_identity(self):
        windows = [self.window("window-%02d" % index)[2] for index in range(2)]
        report = {"windows": windows, "identical_arrival_schedules_across_windows": True,
                  "identical_point_key_sequences_across_windows": True}
        path = self.root / "input.json"
        capacity.write_json(path, self.workload)
        capacity.write_json(self.root / "workload.json", self.workload)
        bindings = {name: {"sha256": name + "-hash"}
                    for name in ("runner", "jdbc_helper", "jdbc_jar", "contract", "fe_artifact", "be_artifact")}
        identity = {"runner_sha256": "runner-hash", "java_helper_sha256": "jdbc_helper-hash",
                    "jdbc_sha256": "jdbc_jar-hash", "performance_contract_sha256": "contract-hash",
                    "workload_sha256": capacity.digest(path), "build_identity": self.workload["build_identity"],
                    "artifact_sha256": {name: name + "-hash" for name in ("fe_artifact", "be_artifact")}}
        capacity.write_json(self.root / "identity.json", identity)
        frozen = {"bindings": bindings, "service_start_ticks": self.ticks}
        audit = capacity.verify_trial(self.root, report, self.workload, frozen, path)
        self.assertTrue(audit["valid"], audit)
        raw = {item["path"]: item["sha256"] for item in audit["raw_artifact_bindings"]}
        sample = self.root / "window-00/worker-0.csv"
        self.assertEqual(raw[str(sample.resolve())], capacity.digest(sample))
        self.assertIn(str((self.root / "window-00/arrivals.bin").resolve()), raw)
        self.assertIn(str((self.root / "identity.json").resolve()), raw)
        with patch.object(capacity, "raw_artifact_bindings", side_effect=[audit["raw_artifact_bindings"], []]):
            changed = capacity.verify_trial(self.root, report, self.workload, frozen, path)
        self.assertFalse(changed["valid"])
        self.assertIn("changed during", changed["errors"][0])
        identity["artifact_sha256"]["be_artifact"] = "different"
        capacity.write_json(self.root / "identity.json", identity)
        self.assertFalse(capacity.verify_trial(self.root, report, self.workload, frozen, path)["valid"])

    def test_raw_bindings_reject_symlinks(self):
        actual = self.root / "raw.csv"
        actual.write_text("original bytes\n")
        (self.root / "alias.csv").symlink_to(actual)
        with self.assertRaisesRegex(ValueError, "symlink"):
            capacity.raw_artifact_bindings(self.root)


class ControllerLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="license-capacity-lifecycle-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def wait_file(self, path, process):
        deadline = time.monotonic() + 8
        while not path.exists():
            self.assertIsNone(process.poll(), "Controller exited before publishing test process identity")
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.02)

    def test_cli_sweep_keeps_fractional_artifacts_distinct_and_integer_names_unchanged(self):
        workload = {"case_id": "LP-001", "pairs": 1, "warmup_seconds": 0, "duration_seconds": 1,
                    "timeout_seconds": 1, "services": {name: {"pid": os.getpid()} for name in ("fe", "be")}}
        capacity.write_json(self.root / "input.json", workload)
        capacity.write_json(self.root / "contract.json", {"cases": [{"id": "LP-001", "load_shape": {
            "warmup_seconds": 0, "duration_seconds_per_window": 1}}]})
        fake = self.root / "fake_runner.py"
        fake.write_text("import json,pathlib,sys\n"
                        "args=sys.argv[1:]\n"
                        "source=pathlib.Path(args[args.index('--workload')+1])\n"
                        "output=pathlib.Path(args[args.index('--output')+1])\n"
                        "output.mkdir(exist_ok=False)\n"
                        "workload=json.loads(source.read_text())\n"
                        "(output/'workload.json').write_text(source.read_text())\n"
                        "window=" + repr(evidence_window(count=2)) + "\n"
                        "(output/'report.json').write_text(json.dumps({'windows':[window,window]}))\n"
                        "print(json.dumps({'rate':workload['rate']}),flush=True)\n")
        # Includes adjacent representable floats, scientific notation, and historical integer names.
        text = "1e-7,1.01e-7,0.5,0.5000000000000001,0.505,1.0,1000"
        labels = ["1e-07", "1.01e-07", "0.5", "0.5000000000000001", "0.505", "1", "1000"]
        expected_rates = [1e-7, 1.01e-7, .5, .5000000000000001, .505, 1, 1000]
        output = self.root / "result"
        argv = ["capacity", "--workload", str(self.root / "input.json"), "--rates", text,
                "--p99-slo-ms", "100", "--mode", "pilot", "--output", str(output),
                "--java-home", str(self.root), "--jdbc-jar", str(self.root / "fake.jar")]
        audited = []
        def audit(directory, report, candidate, frozen, path):
            actual = capacity.read_json(directory / "workload.json")
            self.assertEqual(actual, capacity.read_json(path))
            self.assertEqual(actual, candidate)
            audited.append(actual["rate"])
            return {"valid": True, "windows": report["windows"], "errors": [], "input_rate": actual["rate"]}
        with patch.object(sys, "argv", argv), patch.object(capacity, "RUNNER", fake), \
                patch.object(capacity, "CONTRACT", self.root / "contract.json"), \
                patch.object(capacity.baseline, "check_workload"), \
                patch.object(capacity, "freeze_bindings", return_value={}), \
                patch.object(capacity, "verify_trial", side_effect=audit):
            self.assertEqual(capacity.main(), 0)
        self.assertEqual(audited, expected_rates)
        result = capacity.read_json(output / "report.json")
        self.assertEqual(result["frozen_inputs"]["rates"], expected_rates)
        self.assertFalse(result["bracket"]["capacity_bracket_established"])
        self.assertEqual(len(result["trials"]), len(expected_rates))
        for label, rate, trial in zip(labels, expected_rates, result["trials"]):
            with self.subTest(label=label):
                stem = "rate-" + label
                self.assertEqual(capacity.read_json(output / (stem + ".json"))["rate"], rate)
                self.assertEqual(capacity.read_json(output / (stem + ".log"))["rate"], rate)
                self.assertEqual(capacity.read_json(output / stem / "workload.json")["rate"], rate)
                self.assertEqual(trial["report"], str(output / stem / "report.json"))
                self.assertEqual(trial["artifact_audit"], str(output / (stem + "-artifact-audit.json")))
                self.assertEqual(capacity.read_json(Path(trial["artifact_audit"]))["input_rate"], rate)
                self.assertEqual(trial["exit_code"], 0)
                self.assertEqual(trial["assessment"], "within_slo")
                self.assertEqual(trial["cleanup"]["remaining_live_pids"], [])
        self.assertEqual({path.name for path in output.iterdir()},
                         {"frozen-inputs.json", "report.json"} | {
                             "rate-" + label + suffix for label in labels
                             for suffix in ("", ".json", ".log", "-artifact-audit.json")})

    def test_cancellation_during_cleanup_is_deferred_not_discarded(self):
        with capacity.interrupt_handlers() as checkpoint:
            with capacity.shield_cleanup_signals():
                os.kill(os.getpid(), signal.SIGTERM)
                checkpoint()
            with self.assertRaises(capacity.CalibrationInterrupted):
                checkpoint()

    def test_parent_exit_does_not_leave_a_term_ignoring_descendant_running(self):
        child_file = self.root / "child.pid"
        ready = self.root / "ready"
        child_code = ("import signal,time,pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                      + "pathlib.Path(" + repr(str(ready)) + ").write_text('ready'); time.sleep(60)")
        parent_code = ("import subprocess,sys,pathlib,time; p=subprocess.Popen([sys.executable,'-c',"
                       + repr(child_code) + "], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                       + "pathlib.Path(" + repr(str(child_file)) + ").write_text(str(p.pid)); "
                       + "\nwhile not pathlib.Path(" + repr(str(ready)) + ").exists(): time.sleep(.01)")
        process = subprocess.Popen([sys.executable, "-c", parent_code], start_new_session=True)
        try:
            self.assertEqual(process.wait(timeout=8), 0)
            child = int(child_file.read_text())
            self.assertIn(child, capacity.live_group_members(process.pid))
            started = time.monotonic()
            result = capacity.terminate_client(process, grace_seconds=.2, kill_grace_seconds=.5)
            self.assertTrue(result["kill_sent"])
            self.assertEqual(result["remaining_live_pids"], [])
            self.assertLess(time.monotonic() - started, 2)
        finally:
            capacity.terminate_client(process, grace_seconds=.1, kill_grace_seconds=.2)

    def test_sigterm_sighup_and_keyboard_interrupt_clean_the_new_session(self):
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(signal=number):
                root = self.root / str(number)
                root.mkdir()
                workload = {"case_id": "LP-001", "pairs": 1, "warmup_seconds": 0, "duration_seconds": 1,
                            "timeout_seconds": 1, "services": {name: {"pid": os.getpid()} for name in ("fe", "be")}}
                capacity.write_json(root / "input.json", workload)
                capacity.write_json(root / "contract.json", {"cases": [{"id": "LP-001", "load_shape": {
                    "warmup_seconds": 0, "duration_seconds_per_window": 1}}]})
                fake = root / "fake_runner.py"
                fake.write_text("import subprocess,sys,os,pathlib,time\n"
                                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
                                "pathlib.Path(" + repr(str(root / "child.pid")) + ").write_text(str(child.pid))\n"
                                "pathlib.Path(" + repr(str(root / "runner.pid")) + ").write_text(str(os.getpid()))\n"
                                "time.sleep(60)\n")
                harness = ("import sys,pathlib; sys.path.insert(0," + repr(str(capacity.HERE)) + "); "
                           "import calibrate_read_capacity as m; "
                           "m.RUNNER=pathlib.Path(" + repr(str(fake)) + "); "
                           "m.CONTRACT=pathlib.Path(" + repr(str(root / "contract.json")) + "); "
                           "m.baseline.check_workload=lambda w: None; m.freeze_bindings=lambda a,w: {}; "
                           "sys.argv=['capacity','--workload'," + repr(str(root / "input.json"))
                           + ",'--rates','100,200','--p99-slo-ms','100','--mode','pilot','--output',"
                           + repr(str(root / "result")) + ",'--java-home'," + repr(str(root))
                           + ",'--jdbc-jar'," + repr(str(root / "fake.jar")) + "]; sys.exit(m.main())")
                process = subprocess.Popen([sys.executable, "-c", harness], start_new_session=True,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                runner = None
                try:
                    self.wait_file(root / "runner.pid", process)
                    runner = int((root / "runner.pid").read_text())
                    self.assertTrue(capacity.live_group_members(runner))
                    process.send_signal(number)
                    self.assertEqual(process.wait(timeout=10), 128 + number)
                    report = capacity.read_json(root / "result/report.json")
                    self.assertEqual(report["interrupted"]["signal"], number)
                    self.assertFalse(report["bracket"]["capacity_bracket_established"])
                    self.assertEqual(capacity.live_group_members(runner), [])
                finally:
                    capacity.terminate_client(process, grace_seconds=.1, kill_grace_seconds=.2)
                    if runner and capacity.live_group_members(runner):
                        os.killpg(runner, signal.SIGKILL)

    def test_last_trial_rechecks_frozen_inputs_before_qualifying(self):
        workload = {"case_id": "LP-001", "pairs": 1, "warmup_seconds": 0, "duration_seconds": 1,
                    "timeout_seconds": 1, "services": {name: {"pid": os.getpid()} for name in ("fe", "be")}}
        capacity.write_json(self.root / "input.json", workload)
        capacity.write_json(self.root / "contract.json", {"cases": [{"id": "LP-001", "load_shape": {
            "warmup_seconds": 0, "duration_seconds_per_window": 1}}]})
        argv = ["capacity", "--workload", str(self.root / "input.json"), "--rates", "1000", "--p99-slo-ms", "100",
                "--mode", "pilot", "--output", str(self.root / "result"), "--java-home", str(self.root),
                "--jdbc-jar", str(self.root / "fake.jar")]
        process = SimpleNamespace(pid=12345, returncode=0, poll=lambda: 0)
        with patch.object(sys, "argv", argv), patch.object(capacity, "CONTRACT", self.root / "contract.json"), \
                patch.object(capacity.baseline, "check_workload"), patch.object(capacity, "freeze_bindings", return_value={}), \
                patch.object(capacity, "check_bindings", side_effect=[[], ["jdbc_helper: digest changed"]]) as checks, \
                patch.object(capacity.subprocess, "Popen", return_value=process), \
                patch.object(capacity, "terminate_client", return_value={"remaining_live_pids": []}), \
                patch.object(capacity, "verify_trial", return_value={"valid": True, "windows": [], "errors": []}):
            self.assertEqual(capacity.main(), 2)
            self.assertEqual(checks.call_count, 2)
        report = capacity.read_json(self.root / "result/report.json")
        self.assertEqual(report["trials"][0]["assessment"], "invalid_trial")
        self.assertEqual(report["trials"][0]["frozen_input_errors"], ["jdbc_helper: digest changed"])
        self.assertFalse(report["bracket"]["capacity_bracket_established"])

    def test_signal_during_client_launch_still_runs_owned_group_cleanup(self):
        workload = {"case_id": "LP-001", "pairs": 1, "warmup_seconds": 0, "duration_seconds": 1,
                    "timeout_seconds": 1, "services": {name: {"pid": os.getpid()} for name in ("fe", "be")}}
        capacity.write_json(self.root / "input.json", workload)
        capacity.write_json(self.root / "contract.json", {"cases": [{"id": "LP-001", "load_shape": {
            "warmup_seconds": 0, "duration_seconds_per_window": 1}}]})
        argv = ["capacity", "--workload", str(self.root / "input.json"), "--rates", "1000", "--p99-slo-ms", "100",
                "--mode", "pilot", "--output", str(self.root / "result"), "--java-home", str(self.root),
                "--jdbc-jar", str(self.root / "fake.jar")]
        process = SimpleNamespace(pid=12345, returncode=0, poll=lambda: 0)
        def spawn(*args, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            return process
        with patch.object(sys, "argv", argv), patch.object(capacity, "CONTRACT", self.root / "contract.json"), \
                patch.object(capacity.baseline, "check_workload"), patch.object(capacity, "freeze_bindings", return_value={}), \
                patch.object(capacity, "check_bindings", return_value=[]), \
                patch.object(capacity.subprocess, "Popen", side_effect=spawn), \
                patch.object(capacity, "terminate_client", return_value={"remaining_live_pids": []}) as cleanup:
            self.assertEqual(capacity.main(), 128 + signal.SIGTERM)
            cleanup.assert_called_once_with(process)
        report = capacity.read_json(self.root / "result/report.json")
        self.assertEqual(report["interrupted"]["signal"], signal.SIGTERM)
        self.assertFalse(report["bracket"]["capacity_bracket_established"])


if __name__ == "__main__":
    unittest.main()
