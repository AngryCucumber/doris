#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Independent arithmetic and adversarial evidence tests; no FE/BE requests."""

import copy
import importlib.util
import itertools
import json
import math
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("p4_statistics", Path(__file__).with_name("p4_statistics.py"))
P4 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P4)


class ArithmeticTest(unittest.TestCase):
    def test_constant_five_pair_distribution_is_exact(self):
        result = P4.bootstrap([.5] * 5, 71)
        self.assertEqual(result["ci95_percent"], [.5, .5])
        self.assertEqual(result["confidence_radius_percent"], 0)

    def test_bootstrap_tracks_independently_enumerated_five_pair_distribution(self):
        values = [-2, -1, 0, 1, 2]
        exact = sorted(sum(draw) / 5 for draw in itertools.product(values, repeat=5))
        def percentile(q):
            index = (len(exact) - 1) * q
            lower = math.floor(index)
            return exact[lower] * (1 - (index - lower)) + exact[math.ceil(index)] * (index - lower)
        observed = P4.bootstrap(values, 20260922)
        self.assertAlmostEqual(observed["mean_percent"], 0)
        for actual, expected in zip(observed["ci95_percent"], [percentile(.025), percentile(.975)]):
            self.assertLessEqual(abs(actual - expected), .2)

    def test_four_pairs_never_become_a_qualified_result(self):
        with self.assertRaises(P4.EvidenceError):
            P4.bootstrap([0] * 4, 1)

    def test_fewer_resamples_or_nonfinite_values_are_rejected(self):
        for values, draws in (([0] * 5, 9999), ([0, 0, 0, 0, float("nan")], 10000)):
            with self.subTest(values=values, draws=draws), self.assertRaises(P4.EvidenceError):
                P4.bootstrap(values, 1, draws)

    def pair(self, metric, a, b):
        left = {name: 10.0 for name in P4.METRICS}
        right = dict(left)
        left[metric], right[metric] = a, b
        return {"metrics": left}, {"metrics": right}

    def test_throughput_decrease_and_cpu_increase_both_mean_harm(self):
        for metric, a, b in (("success_qps", 100, 99.5), ("fe_cpu_seconds_per_success", 100, 100.5)):
            result = P4.metric_analysis([self.pair(metric, a, b)] * 5, 1, "AB")[metric]
            self.assertEqual(result["status"], "REGRESSION")
            self.assertGreater(result["ci95_percent"][0], 0)
            self.assertLess(result["ci95_percent"][1], 1)  # Small measurable harm is still harm.

    def test_improvement_is_not_an_adverse_directional_failure(self):
        for metric, a, b in (("success_qps", 100, 101), ("p99_ms", 100, 99)):
            result = P4.metric_analysis([self.pair(metric, a, b)] * 5, 1, "AB")[metric]
            self.assertEqual(result["status"], "PASS")

    def test_nonsignificant_but_wide_interval_is_not_equivalence(self):
        pairs = [self.pair("p99_ms", 100, value) for value in (90, 95, 100, 105, 110)]
        result = P4.metric_analysis(pairs, 1, "AB")["p99_ms"]
        self.assertLess(result["ci95_percent"][0], 0)
        self.assertGreater(result["ci95_percent"][1], 2)
        self.assertEqual(result["status"], "INCONCLUSIVE")

    def test_aa_noise_is_recorded_without_an_extra_single_pair_gate(self):
        pairs = [self.pair("fe_cpu_seconds_per_success", 100, value) for value in (99, 101, 99, 101, 100)]
        result = P4.metric_analysis(pairs, 1, "AA")["fe_cpu_seconds_per_success"]
        self.assertEqual(result["resolution_band_percent"], 1)
        self.assertGreater(result["absolute_pair_p95_percent"], 1)
        self.assertLess(result["confidence_radius_percent"], 1)
        self.assertEqual(result["status"], "AA_ELIGIBLE")

    def test_zero_cpu_is_not_silently_omitted(self):
        with self.assertRaisesRegex(P4.EvidenceError, "Zero metric"):
            P4.metric_analysis([self.pair("be_cpu_seconds_per_success", 0, 0)] * 5, 1, "AB")


class FrozenEvidenceTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p4-statistics-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.a_binary = self.write("a.jar", b"baseline binary")
        self.b_binary = self.write("b.jar", b"candidate binary")
        self.be_binary = self.write("be", b"same unmodified backend")
        self.auditor = self.write("protocol-auditor.py", b"# Test stand-in, not real protocol evidence\n")
        identity = {name: "a" * (40 if name == "source_commit" else 64) for name in P4.IDENTITY_FIELDS}
        identity.update(fe_sha256=P4.digest(self.a_binary), be_sha256=P4.digest(self.be_binary))
        candidate = dict(identity, source_commit="b" * 40, fe_sha256=P4.digest(self.b_binary))
        self.identities = {"A": identity, "B": candidate}
        self.cell = {"id": "G1-text-reuse-low", "group": "G1", "warmup_seconds": 120, "duration_seconds": 300,
                     "concurrency": 1, "connection_mode": "reuse", "rate_fraction": .30, "rate": 300,
                     "workload_sha256": "c" * 64, "arrival_schedule_sha256": "d" * 64,
                     "request_count": 90000, "seed": 20260922,
                     "slo": {"p99_ms": 100, "max_drain_seconds": 1, "max_error_rate": 0, "max_timeout_rate": 0}}
        self.order = ["AB", "BA", "AB", "BA", "AB"]
        self.freeze_time = 10**16
        self.compare_time = 3 * 10**16
        capacity_windows = [{"successful_requests": 300000, "scheduled_requests": 300000,
                             "observed_requests": 300000, "missing_requests": 0, "errors": {},
                             "cpu_boundary_verified": True, "p99_ms": 10, "drain_seconds": 0} for _ in range(10)]
        trials = []
        for rate, assessment, p99 in ((1000, "within_slo", 10), (1010, "outside_slo", 101)):
            windows = [dict(window, p99_ms=p99) for window in capacity_windows]
            raw = self.write(f"capacity-{rate}-raw.csv", b"Synthetic capacity receipt\n")
            audit = self.write_json(f"capacity-{rate}-audit.json", {"valid": True, "errors": [], "windows": windows,
                                    "raw_artifact_bindings": [P4.reference(raw)]})
            trials.append({"rate": rate, "assessment": assessment, "exit_code": 0,
                           "watchdog_terminated": False, "frozen_input_errors": [], "artifact_audit": str(audit)})
        self.capacity = {"frozen_inputs": {"phase": "A_ONLY", "mode": "confirm", "current_group": "G1",
                         "business_workload_sha256": self.cell["workload_sha256"],
                         "baseline_identity": copy.deepcopy(self.identities["A"]),
                         "cell_id": self.cell["id"], "p99_slo_ms": 100, "max_drain_seconds": 1,
                         "rates": [1000, 1010], "template": {"pairs": 5, "warmup_seconds": 120,
                         "duration_seconds": 300, "concurrency": 1, "connection_mode": "reuse"},
                         "bindings": {"fe_artifact": P4.reference(self.a_binary), "be_artifact": P4.reference(self.be_binary)}},
                         "bracket": {"capacity_bracket_established": True,
                         "largest_tested_rate_within_slo": 1000, "smallest_tested_rate_outside_slo_above_it": 1010},
                         "trials": trials}
        self.capacity_path = self.write_json("capacity.json", self.capacity)
        self.inputs = {"schema_version": 1, "cell": self.cell, "identities": self.identities,
                       "capacity_report": P4.reference(self.capacity_path), "ab_order": self.order,
                       "aa_windows": self.windows(["AA"] * 5, "aa", 10**12)}

    def write(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return path

    def write_json(self, name, content):
        return self.write(name, (json.dumps(content) + "\n").encode())

    def bind_window(self, window):
        raw = self.write(f"{window['window_id']}-raw.csv", b"Synthetic test receipt; never a real performance pass\n")
        audit = self.write_json(f"{window['window_id']}-audit.json", {"status": "VERIFIED",
                                "window": {key: value for key, value in window.items() if key != "evidence"},
                                "auditor": P4.reference(self.auditor), "raw_artifacts": [P4.reference(raw)]})
        window["evidence"] = P4.reference(audit)

    def windows(self, order, prefix, start):
        result = []
        for pair, variants in enumerate(order):
            for variant in variants:
                index = len(result)
                window = {"window_id": f"{prefix}-{index}", "pair_id": pair, "variant": variant,
                          "boot_id": P4.boot_id(),
                          "monotonic_clock_domain": "controller_monotonic_exact",
                          "identity": copy.deepcopy(self.identities[variant]),
                          "workload_sha256": self.cell["workload_sha256"], "rate": 300,
                          "arrival_schedule_sha256": self.cell["arrival_schedule_sha256"],
                          "warmup_seconds": 120, "duration_seconds": 300, "effective_duration_seconds": 300,
                          "start_monotonic_ns": start + index * 500 * 10**9,
                          "end_monotonic_ns": start + (index * 500 + 300) * 10**9,
                          "warmup_start_monotonic_ns": start + (index * 500 - 120) * 10**9,
                          "warmup_end_monotonic_ns": start + index * 500 * 10**9,
                          "scheduled_requests": 90000, "observed_requests": 90000, "successful_requests": 90000,
                          "error_count": 0, "timeout_count": 0, "retry_count": 0,
                          "oracle_verified": True, "cleanup_verified": True, "cpu_boundary_verified": True,
                          "metrics": {"success_qps": 300, "p95_ms": 5, "p99_ms": 10,
                                      "fe_cpu_seconds_per_success": .001, "be_cpu_seconds_per_success": .002}}
                self.bind_window(window)
                result.append(window)
        return result

    def frozen(self):
        with patch.object(P4.time, "monotonic_ns", return_value=self.freeze_time):
            frozen = P4.freeze(self.inputs)
        self.frozen_path = self.write_json("frozen.json", frozen)
        self.publication_path = self.write_json("frozen.json.published.json", {
            "freeze": P4.reference(self.frozen_path), "published_monotonic_ns": self.freeze_time + 100,
            "boot_id": P4.boot_id()})
        return frozen

    def comparison(self):
        inputs = {"schema_version": 1, "freeze_sha256": P4.digest(self.frozen_path),
                  "actual_freeze_sha256": P4.digest(self.frozen_path),
                  "publication": P4.reference(self.publication_path),
                  "windows": self.windows(self.order, "ab", 2 * 10**16)}
        for window in inputs["windows"]:
            window["freeze_sha256"] = inputs["freeze_sha256"]
            window["freeze_publication_sha256"] = inputs["publication"]["sha256"]
            self.bind_window(window)
        return inputs

    def compare(self, frozen, inputs):
        with patch.object(P4.time, "monotonic_ns", return_value=self.compare_time):
            return P4.compare(frozen, inputs)

    def test_complete_bound_equal_windows_pass_one_cell_only(self):
        frozen = self.frozen()
        self.assertEqual(frozen["status"], "FROZEN_ELIGIBLE")
        result = self.compare(frozen, self.comparison())
        self.assertEqual(result["status"], "PASS")
        self.assertIn("One frozen business comparison", result["scope"])

    def test_ab_order_is_normalized_by_identity_not_execution_position(self):
        frozen, inputs = self.frozen(), self.comparison()
        for window in inputs["windows"]:
            if window["variant"] == "B":
                window["metrics"]["p99_ms"] = 10.01
                self.bind_window(window)
        result = self.compare(frozen, inputs)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["analysis"]["p99_ms"]["pair_count"], 5)

    def test_short_samples_errors_retries_and_missing_oracle_are_not_dropped(self):
        frozen = self.frozen()
        for field, value in (("successful_requests", 9999), ("error_count", 1), ("timeout_count", 1),
                             ("retry_count", 1), ("oracle_verified", False), ("cleanup_verified", False),
                             ("cpu_boundary_verified", False)):
            with self.subTest(field=field):
                inputs = self.comparison()
                inputs["windows"][0][field] = value
                self.bind_window(inputs["windows"][0])
                with self.assertRaises(P4.EvidenceError):
                    self.compare(frozen, inputs)

    def test_duplicate_or_overlapping_windows_cannot_manufacture_independent_pairs(self):
        frozen = self.frozen()
        for mutation in ("duplicate_id", "overlap", "shorten"):
            inputs = self.comparison()
            second = inputs["windows"][1]
            if mutation == "duplicate_id":
                second["window_id"] = inputs["windows"][0]["window_id"]
            elif mutation == "overlap":
                second["start_monotonic_ns"] = inputs["windows"][0]["start_monotonic_ns"]
            else:
                second["end_monotonic_ns"] = second["start_monotonic_ns"] + 1
            with self.subTest(mutation=mutation), self.assertRaises(P4.EvidenceError):
                self.compare(frozen, inputs)

    def test_raw_artifact_mutation_invalidates_unchanged_summary(self):
        frozen, inputs = self.frozen(), self.comparison()
        self.write("ab-0-raw.csv", b"changed after audit")
        with self.assertRaisesRegex(P4.EvidenceError, "digest changed"):
            self.compare(frozen, inputs)

    def test_raw_receipt_reuse_cannot_become_a_new_independent_window(self):
        frozen, inputs = self.frozen(), self.comparison()
        first = P4.read_json(inputs["windows"][0]["evidence"]["path"])
        second_path = Path(inputs["windows"][1]["evidence"]["path"])
        second = P4.read_json(second_path)
        second["raw_artifacts"] = first["raw_artifacts"]
        second_path.write_text(json.dumps(second))
        inputs["windows"][1]["evidence"] = P4.reference(second_path)
        with self.assertRaisesRegex(P4.EvidenceError, "receipts were reused"):
            self.compare(frozen, inputs)

    def test_wrong_clock_domain_is_not_an_independent_window(self):
        frozen, inputs = self.frozen(), self.comparison()
        inputs["windows"][0]["boot_id"] = "another-boot"
        with self.assertRaisesRegex(P4.EvidenceError, "clock domain"):
            self.compare(frozen, inputs)

    def test_unknown_clock_cannot_silently_default_to_zero_uncertainty(self):
        frozen, inputs = self.frozen(), self.comparison()
        del inputs["windows"][0]["monotonic_clock_domain"]
        with self.assertRaisesRegex(P4.EvidenceError, "proven exact or bounded"):
            self.compare(frozen, inputs)

    def test_bounded_mapping_uses_worst_case_for_interwindow_overlap(self):
        frozen, inputs = self.frozen(), self.comparison()
        first, second = inputs["windows"][:2]
        second["warmup_start_monotonic_ns"] = first["end_monotonic_ns"] + 10
        for window in (first, second):
            window["monotonic_clock_domain"] = "bounded_jvm_mapping"
            window["monotonic_mapping_uncertainty_ns"] = 100
            window["monotonic_mapping"] = {"offset_lower_ns": -100, "estimated_offset_ns": 0, "offset_upper_ns": 100}
            self.bind_window(window)
        with self.assertRaisesRegex(P4.EvidenceError, "overlap"):
            self.compare(frozen, inputs)

    def test_missing_bounded_uncertainty_is_rejected(self):
        frozen, inputs = self.frozen(), self.comparison()
        inputs["windows"][0]["monotonic_clock_domain"] = "bounded_jvm_mapping"
        with self.assertRaises((P4.EvidenceError, KeyError)):
            self.compare(frozen, inputs)

    def test_normalized_metrics_must_equal_protocol_audit(self):
        frozen, inputs = self.frozen(), self.comparison()
        inputs["windows"][0]["metrics"]["p95_ms"] = 4
        with self.assertRaisesRegex(P4.EvidenceError, "differs from its protocol audit"):
            self.compare(frozen, inputs)

    def test_candidate_window_before_freeze_is_rejected(self):
        frozen, inputs = self.frozen(), self.comparison()
        for window in inputs["windows"]:
            window["start_monotonic_ns"] -= 2 * 10**16 - 10**12
            window["end_monotonic_ns"] -= 2 * 10**16 - 10**12
            window["warmup_start_monotonic_ns"] -= 2 * 10**16 - 10**12
            window["warmup_end_monotonic_ns"] -= 2 * 10**16 - 10**12
            self.bind_window(window)
        with self.assertRaisesRegex(P4.EvidenceError, "A-only/A-B phase"):
            self.compare(frozen, inputs)

    def test_window_duration_cannot_understate_actual_denominator(self):
        frozen, inputs = self.frozen(), self.comparison()
        window = inputs["windows"][0]
        window["end_monotonic_ns"] = window["start_monotonic_ns"] + 450 * 10**9
        self.bind_window(window)
        with self.assertRaisesRegex(P4.EvidenceError, "actual request interval"):
            self.compare(frozen, inputs)

    def test_modified_capacity_raw_input_is_not_covered_by_cached_valid_flag(self):
        self.write("capacity-1000-raw.csv", b"changed after the controller audit")
        with self.assertRaisesRegex(P4.EvidenceError, "digest changed"):
            self.frozen()

    def test_capacity_from_another_environment_cannot_freeze(self):
        self.capacity["frozen_inputs"]["baseline_identity"]["environment_sha256"] = "f" * 64
        self.write_json("capacity.json", self.capacity)
        self.inputs["capacity_report"] = P4.reference(self.capacity_path)
        with self.assertRaisesRegex(P4.EvidenceError, "different A environment"):
            self.frozen()

    def test_next_warmup_cannot_overlap_the_previous_measurement(self):
        frozen, inputs = self.frozen(), self.comparison()
        inputs["windows"][1]["warmup_start_monotonic_ns"] = inputs["windows"][0]["end_monotonic_ns"] - 1
        self.bind_window(inputs["windows"][1])
        with self.assertRaisesRegex(P4.EvidenceError, "overlap"):
            self.compare(frozen, inputs)

    def test_aa_raw_receipts_cannot_be_relabelled_as_ab(self):
        frozen, inputs = self.frozen(), self.comparison()
        aa = P4.read_json(frozen["aa_windows"][0]["evidence"]["path"])
        path = Path(inputs["windows"][0]["evidence"]["path"])
        audit = P4.read_json(path)
        audit["raw_artifacts"] = aa["raw_artifacts"]
        path.write_text(json.dumps(audit))
        inputs["windows"][0]["evidence"] = P4.reference(path)
        with self.assertRaisesRegex(P4.EvidenceError, "A/A raw requests"):
            self.compare(frozen, inputs)

    def test_symlink_alias_cannot_prove_a_second_raw_window(self):
        frozen, inputs = self.frozen(), self.comparison()
        alias = self.root / "alias.csv"
        alias.symlink_to(self.root / "ab-0-raw.csv")
        path = Path(inputs["windows"][1]["evidence"]["path"])
        audit = P4.read_json(path)
        audit["raw_artifacts"] = [{"path": str(alias), "sha256": P4.digest(alias)}]
        path.write_text(json.dumps(audit))
        inputs["windows"][1]["evidence"] = P4.reference(path)
        with self.assertRaisesRegex(P4.EvidenceError, "receipts were reused"):
            self.compare(frozen, inputs)

    def test_hardlink_alias_cannot_prove_a_second_raw_window(self):
        frozen, inputs = self.frozen(), self.comparison()
        alias = self.root / "hardlink.csv"
        os.link(self.root / "ab-0-raw.csv", alias)
        path = Path(inputs["windows"][1]["evidence"]["path"])
        audit = P4.read_json(path)
        audit["raw_artifacts"] = [P4.reference(alias)]
        path.write_text(json.dumps(audit))
        inputs["windows"][1]["evidence"] = P4.reference(path)
        with self.assertRaisesRegex(P4.EvidenceError, "receipts were reused"):
            self.compare(frozen, inputs)

    def test_each_ab_window_must_bind_published_freeze_before_execution(self):
        frozen, inputs = self.frozen(), self.comparison()
        inputs["windows"][0]["freeze_sha256"] = "e" * 64
        self.bind_window(inputs["windows"][0])
        with self.assertRaisesRegex(P4.EvidenceError, "before execution"):
            self.compare(frozen, inputs)

    def test_window_started_during_unpublished_freeze_is_not_eligible(self):
        frozen, inputs = self.frozen(), self.comparison()
        first = inputs["windows"][0]
        first["start_monotonic_ns"] = self.freeze_time + 50
        first["end_monotonic_ns"] = first["start_monotonic_ns"] + 300 * 10**9
        first["warmup_end_monotonic_ns"] = first["start_monotonic_ns"]
        first["warmup_start_monotonic_ns"] = first["start_monotonic_ns"] - 120 * 10**9
        self.bind_window(first)
        with self.assertRaisesRegex(P4.EvidenceError, "A-only/A-B phase"):
            self.compare(frozen, inputs)

    def test_aa_candidate_or_changed_be_never_freezes(self):
        self.inputs["aa_windows"][1]["variant"] = "B"
        with self.assertRaises(P4.EvidenceError):
            self.frozen()
        self.inputs["aa_windows"][1]["variant"] = "A"
        self.identities["B"]["be_sha256"] = "b" * 64
        with self.assertRaisesRegex(P4.EvidenceError, "share be_sha256"):
            self.frozen()

    def test_capacity_lower_only_pilot_or_wrong_slo_cannot_freeze_rate(self):
        for mutation in ("no_upper", "pilot", "wrong_slo", "wrong_fraction", "wide_bracket"):
            with self.subTest(mutation=mutation):
                capacity = copy.deepcopy(self.capacity)
                cell = copy.deepcopy(self.cell)
                if mutation == "no_upper":
                    capacity["trials"] = capacity["trials"][:1]
                elif mutation == "pilot":
                    capacity["frozen_inputs"]["mode"] = "pilot"
                elif mutation == "wrong_slo":
                    cell["slo"]["p99_ms"] = 200
                elif mutation == "wrong_fraction":
                    cell["rate"] = 301
                else:
                    capacity["frozen_inputs"]["rates"][-1] = 1020
                    capacity["trials"][-1]["rate"] = 1020
                path = self.write_json("changed-capacity.json", capacity)
                with self.assertRaises(P4.EvidenceError):
                    P4.capacity_evidence(P4.reference(path), cell, self.identities["A"])

    def test_capacity_claim_is_recomputed_from_audited_latency(self):
        audit_path = self.capacity["trials"][1]["artifact_audit"]
        audit = P4.read_json(audit_path)
        for window in audit["windows"]:
            window["p99_ms"] = 10
        Path(audit_path).write_text(json.dumps(audit))
        with self.assertRaisesRegex(P4.EvidenceError, "assessment disagrees"):
            self.frozen()

    def test_bands_order_and_schedule_cannot_change_after_freeze(self):
        for mutation in ("band", "order", "schedule", "freeze_hash"):
            frozen, inputs = self.frozen(), self.comparison()
            if mutation == "band":
                frozen["method"]["resolution_percent"]["p99_ms"] = 100
            elif mutation == "order":
                inputs["windows"][0]["variant"] = "B"
            elif mutation == "schedule":
                inputs["windows"][0]["arrival_schedule_sha256"] = "f" * 64
            else:
                inputs["freeze_sha256"] = "f" * 64
            with self.subTest(mutation=mutation), self.assertRaises(P4.EvidenceError):
                self.compare(frozen, inputs)

    def test_noisy_aa_remains_inconclusive_without_b_inspection(self):
        for index, window in enumerate(self.inputs["aa_windows"]):
            if index % 2:
                window["metrics"]["p99_ms"] = [9, 10.5, 9, 10.5, 10][index // 2]
                self.bind_window(window)
        frozen = self.frozen()
        self.assertEqual(frozen["status"], "FROZEN_INCONCLUSIVE")
        self.assertEqual(self.compare(frozen, self.comparison())["status"], "INCONCLUSIVE")

    def test_cli_failures_are_retained_as_inconclusive_and_never_overwritten(self):
        inputs = self.write_json("inputs.json", {"schema_version": 1})
        output = self.root / "result.json"
        argv = ["p4_statistics", "freeze", "--input", str(inputs), "--output", str(output)]
        with patch("sys.argv", argv):
            self.assertEqual(P4.main(), 2)
        self.assertEqual(P4.read_json(output)["status"], "INCONCLUSIVE")
        original = output.read_bytes()
        with patch("sys.argv", argv), self.assertRaises(P4.EvidenceError):
            P4.main()
        self.assertEqual(output.read_bytes(), original)

    def test_cli_publishes_separate_digest_after_freeze_body(self):
        inputs = self.write_json("complete-inputs.json", self.inputs)
        output = self.root / "cli-freeze.json"
        argv = ["p4_statistics", "freeze", "--input", str(inputs), "--output", str(output)]
        with patch("sys.argv", argv), patch.object(P4.time, "monotonic_ns", return_value=self.freeze_time):
            self.assertEqual(P4.main(), 0)
        publication = P4.read_json(output.with_suffix(".json.published.json"))
        self.assertEqual(publication["freeze"], P4.reference(output))
        self.assertGreaterEqual(publication["published_monotonic_ns"], P4.read_json(output)["created_monotonic_ns"])

    def test_duplicate_json_keys_or_nan_cannot_be_audited(self):
        for content in (b'{"status":"FAIL","status":"PASS"}', b'{"metric":NaN}'):
            path = self.write("invalid.json", content)
            with self.assertRaises(P4.EvidenceError):
                P4.read_json(path)


if __name__ == "__main__":
    unittest.main()
