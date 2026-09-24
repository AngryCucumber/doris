#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Distribution, lifecycle and statistical error-path checks; no cluster or performance load."""

import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import measure_license_primitives as probe


def sample(operation=probe.VALIDATION):
    config = {"operation": operation, "threads": 1, "expected_java_runtime": "17.0.4+8",
              "expected_cpu_affinity": "0-4",
              "minimum_operations": 10, "duration_nanos": 100, "warmup_operations": 10, "warmup_nanos": 100}
    phase = {"completed": True, "error_class": None, "operations": 10, "epoch_ns": 1000,
             "last_request_end_ns": 1100, "cpu_start_sample_begin_ns": 990, "cpu_start_sample_end_ns": 995,
             "cpu_end_sample_begin_ns": 1105, "cpu_end_sample_end_ns": 1110, "cleanup_end_ns": 1120,
             "process_cpu_start_ns": 100, "process_cpu_end_ns": 200, "worker_allocated_bytes": 20,
             "gc_collections": 0, "gc_millis": 0, "memory_after": {"VmHWM": 1024},
             "workers": [{"operations": 10, "first_start_ns": 1001, "last_end_ns": 1100,
                          "cpus_allowed_list_before": "0-4", "cpus_allowed_list_after": "0-4"}],
             "latency_histogram": [[10, 10, 10, 10]]}
    raw = {"operation": operation, "threads": 1, "java_runtime": "17.0.4+8", "clock_suspect_at_end": False,
           "actual_cpu_affinity_before": "0-4", "actual_cpu_affinity_after": "0-4",
           "measurement": copy.deepcopy(phase), "warmup": copy.deepcopy(phase)}
    return raw, config


class LicensePrimitiveTest(unittest.TestCase):
    def test_complete_p1_matrix_keeps_thread_and_payload_dimensions(self):
        matrix = probe.matrix()
        self.assertEqual(42, len(matrix))
        self.assertEqual(42, len({tuple(cell.items()) for cell in matrix}))
        case = next(case for case in json.loads(probe.CONTRACT.read_text())["cases"] if case["id"] == "LP-023")
        self.assertEqual(list(probe.THREADS), case["load_shape"]["threads"])
        self.assertEqual(list(probe.fixtures.SIZES), case["load_shape"]["payload_sizes_bytes"])
        for operation, size_count in ((probe.VALIDATION, 3), (probe.REJECTION, 1)):
            self.assertEqual(size_count * 3, len([cell for cell in matrix if cell["operation"] == operation]))
        for operation in probe.HOT[1:]:
            self.assertEqual(9, len([cell for cell in matrix if cell["operation"] == operation]))

    def test_every_call_is_represented_and_quantiles_use_full_distribution(self):
        raw, config = sample()
        result = probe.verify_window(raw, config)
        self.assertEqual(10, result["histogram_operations"])
        self.assertEqual([10, 10], result["p99_ns_bounds"])
        self.assertEqual(10, result["successful_operations"])
        self.assertFalse(result["client_end_to_end_including_queue_measured"])
        self.assertIsNone(result["management_queue_wait_ms"])

    def test_negative_operations_never_count_as_successes(self):
        raw, config = sample(probe.REJECTION)
        result = probe.verify_window(raw, config)
        self.assertEqual(0, result["successful_operations"])
        self.assertEqual(10, result["expected_rejections"])
        self.assertEqual(0, result["successful_operations_per_second"])
        self.assertEqual(result["operation_rate"], result["expected_rejections_per_second"])

    def test_corrupt_histogram_count_bounds_and_order_fail(self):
        for buckets in ([[10, 10, 10, 9]], [[10, 10, 11, 10]], [[10, 10, 10, -1]],
                        [[10, 10, 10, 5], [10, 10, 10, 5]], []):
            raw, config = sample()
            raw["measurement"]["latency_histogram"] = buckets
            with self.subTest(buckets=buckets), self.assertRaises(ValueError):
                probe.verify_window(raw, config)

    def test_request_and_cpu_lifecycle_reject_early_finish_or_wrong_boundary(self):
        changes = [("last_request_end_ns", 1099), ("cpu_start_sample_end_ns", 1001),
                   ("cpu_end_sample_begin_ns", 1099), ("cleanup_end_ns", 1109),
                   ("operations", 9), ("worker_allocated_bytes", -1), ("completed", False)]
        for field, value in changes:
            raw, config = sample()
            raw["measurement"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe.verify_window(raw, config)
        raw, config = sample()
        raw["measurement"]["workers"][0]["last_end_ns"] = 1099
        raw["measurement"]["last_request_end_ns"] = 1099
        with self.assertRaises(ValueError):
            probe.verify_window(raw, config)

    def test_wrong_runtime_and_suspect_clock_fail(self):
        for key, value in (("java_runtime", "17.0.2+8"), ("clock_suspect_at_end", True), ("threads", 8)):
            raw, config = sample()
            raw[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.verify_window(raw, config)

    def test_requested_affinity_does_not_substitute_for_actual_process_or_worker_cpus(self):
        for field in ("actual_cpu_affinity_before", "actual_cpu_affinity_after"):
            for actual in ("0-3", "0-5", "1-4", None):
                raw, config = sample()
                raw[field] = actual
                with self.subTest(field=field, actual=actual), self.assertRaises(ValueError):
                    probe.verify_window(raw, config)
        for phase in ("warmup", "measurement"):
            for field in ("cpus_allowed_list_before", "cpus_allowed_list_after"):
                raw, config = sample()
                raw[phase]["workers"][0][field] = "0-3"
                with self.subTest(phase=phase, field=field), self.assertRaises(ValueError):
                    probe.verify_window(raw, config)
        raw, config = sample()
        config["expected_cpu_affinity"] = "0-3"
        with self.assertRaisesRegex(ValueError, "predeclared"):
            probe.verify_window(raw, config)

    def test_actual_cpu_list_parser_handles_kernel_ranges_and_rejects_malformed_values(self):
        self.assertEqual({0, 1, 2, 3, 4}, probe.cpu_set("0-2,3,4"))
        for actual in ("", "-1", "4-0", "0-4,", "0-4-8", "all", "0-999999999", None):
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                probe.cpu_set(actual)

    def test_compiled_inventory_rejects_changed_deleted_and_added_shadow_classes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root / "LicensePrimitiveCostProbe.class"
            worker = root / "LicensePrimitiveCostProbe$Worker.class"
            main.write_bytes(b"main-bytecode")
            worker.write_bytes(b"worker-bytecode")
            report = {"frozen_inputs": {}, "compiled_classpath": {
                "directory": str(root), "classes_sha256": probe.compiled_class_inventory(root)}}
            self.assertEqual([], probe.check_frozen_inputs(report))
            worker.write_bytes(b"changed-worker-bytecode")
            self.assertTrue(probe.check_frozen_inputs(report))
            worker.write_bytes(b"worker-bytecode")
            worker.unlink()
            self.assertTrue(probe.check_frozen_inputs(report))
            worker.write_bytes(b"worker-bytecode")
            shadow = root / "org/apache/doris/massdb/license/LicenseVerifier.class"
            shadow.parent.mkdir(parents=True)
            shadow.write_bytes(b"first-classpath-shadow")
            self.assertTrue(probe.check_frozen_inputs(report))
            shadow.unlink()
            self.assertEqual([], probe.check_frozen_inputs(report))
            (root / "untracked-package").symlink_to(root / "org", target_is_directory=True)
            self.assertTrue(probe.check_frozen_inputs(report))
            (root / "untracked-package").unlink()
            main.unlink()
            self.assertTrue(probe.check_frozen_inputs(report))

    def test_missing_compile_freeze_is_not_accepted(self):
        self.assertTrue(probe.check_frozen_inputs({"frozen_inputs": {}}))

    def test_histogram_bounds_cover_submicrosecond_and_long_tail_values(self):
        for value in [0, 1, 4095, 4096, 8191, 8192, 1000000000, (1 << 63) - 1]:
            shift = max(0, value.bit_length() - 12)
            index = (value >> shift) + shift * 2048
            lower, upper = probe.bucket_bounds(index)
            self.assertLessEqual(lower, value)
            self.assertGreaterEqual(upper, value)
            if value < 4096:
                self.assertEqual(lower, upper)
            else:
                self.assertLessEqual((upper - lower) / value, 1 / 2048)

    def test_precision_preserves_histogram_uncertainty_and_original_targets(self):
        raw, config = sample()
        window = probe.verify_window(raw, config)
        window["p95_ns_bounds"] = [100, 110]
        window["p99_ns_bounds"] = [100, 110]
        result = probe.precision([copy.deepcopy(window) for _ in range(10)], 20260922)
        self.assertEqual("precision_insufficient", result["p99_ns"]["status"])
        self.assertGreater(result["p99_ns"]["confidence_radius_percent"], 2)
        self.assertEqual(2, result["p99_ns"]["precision_target_percent"])
        self.assertEqual(1, result["operation_rate"]["precision_target_percent"])

    def test_fewer_than_five_pairs_cannot_pass(self):
        raw, config = sample()
        window = probe.verify_window(raw, config)
        result = probe.precision([window] * 8, 20260922)
        self.assertTrue(all(metric["status"] == "insufficient_pairs" for metric in result.values()))

    def test_identical_integer_latencies_do_not_certify_an_unknown_clock(self):
        raw, config = sample()
        result = probe.precision([probe.verify_window(raw, config)] * 10, 20260922)
        for metric in ("p95_ns", "p99_ns"):
            self.assertEqual("clock_resolution_unverified", result[metric]["status"])
            self.assertFalse(result[metric]["clock_quantization_included"])
        self.assertEqual("precision_met", result["operation_rate"]["status"])

    def test_counter_tick_uncertainty_cannot_be_averaged_away_by_more_pairs(self):
        raw, config = sample()
        window = probe.verify_window(raw, config)
        for metric in ("p95_ns", "p99_ns"):
            window[metric] = 42
            window[metric + "_bounds"] = [42, 42]
        for count in (10, 20):
            result = probe.precision([window] * count, 20260922, 1e9 / 24000000 + 1)
            self.assertEqual("precision_insufficient", result["p99_ns"]["status"])
            self.assertEqual(count // 2, result["p99_ns"]["pairs"])
            self.assertGreater(result["p99_ns"]["confidence_radius_percent"], 2)

    def test_counter_uncertainty_preserves_qualified_longer_latencies(self):
        raw, config = sample()
        window = probe.verify_window(raw, config)
        for metric in ("p95_ns", "p99_ns"):
            window[metric] = 100000
            window[metric + "_bounds"] = [100000, 100020]
        result = probe.precision([window] * 10, 20260922, 1e9 / 24000000 + 1)
        self.assertEqual("precision_met", result["p99_ns"]["status"])
        self.assertGreater(result["p99_ns"]["confidence_radius_percent"], .08)
        self.assertEqual(2, result["p99_ns"]["precision_target_percent"])

    def test_invalid_clock_uncertainty_is_rejected(self):
        for uncertainty in (0, -1, True, float("nan"), float("inf"), "1"):
            with self.subTest(uncertainty=uncertainty), self.assertRaises(ValueError):
                probe.precision([], 20260922, uncertainty)

    def test_clock_capability_binds_raw_wait_and_local_clock_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            observed = {"status": "CLOCK_CAPABILITY_OBSERVED", "architecture": "aarch64",
                        "architected_counter_frequency_hz": 24000000,
                        "architected_counter_period_ns_numerator": 1000000000,
                        "architected_counter_period_ns_denominator": 24000000}
            raw = path.parent / "probe.stdout"
            raw.write_text(json.dumps(observed))
            environment = {"boot_id": "same-boot", "time_namespace": "time:[1]",
                           "clocksource": "arch_sys_counter"}
            receipt = {"status": "CAPABILITY_OBSERVED_NOT_PERFORMANCE_PASS", **environment,
                       "observed": observed, "commands": [{"name": "probe", "returncode": 0,
                       "real_parent_wait": True, "stdout_sha256": probe.lifecycle.digest(raw)}]}
            with patch.object(probe, "clock_environment", return_value=environment):
                path.write_text(json.dumps(receipt))
                self.assertAlmostEqual(42.6666666667, probe.clock_capability(path)[
                    "duration_quantization_uncertainty_ns"])
                for field, value in (("boot_id", "old-boot"), ("time_namespace", "time:[2]"),
                                     ("clocksource", "other")):
                    changed = copy.deepcopy(receipt)
                    changed[field] = value
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        probe.clock_capability(path)
                changed = copy.deepcopy(receipt)
                changed["commands"][0]["real_parent_wait"] = False
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    probe.clock_capability(path)
                path.write_text(json.dumps(receipt))
                raw.write_text("{}")
                with self.assertRaises(ValueError):
                    probe.clock_capability(path)

    def test_repeatable_signed_drift_is_not_precision_success(self):
        raw, config = sample()
        a = probe.verify_window(raw, config)
        b = copy.deepcopy(a)
        b["operation_rate"] *= 1.1
        result = probe.precision([a, b] * 5, 20260922)
        self.assertEqual("AA_directional_drift", result["operation_rate"]["status"])

    def test_owned_child_is_cleaned_when_checkpoint_interrupts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pidfile = root / "pid"
            def interrupted():
                try:
                    if pidfile.read_text().isdigit():
                        raise InterruptedError("test cancellation")
                except FileNotFoundError:
                    pass
            command = [sys.executable, "-c", "import os,pathlib,time;pathlib.Path(" + repr(str(pidfile))
                       + ").write_text(str(os.getpid()));time.sleep(60)"]
            with self.assertRaises(InterruptedError):
                probe.run_owned(command, root / "child.log", 5, interrupted)
            pid = int(pidfile.read_text())
            self.assertFalse(Path("/proc/%d" % pid).exists())
            receipt = json.loads((root / "child.log.cleanup.json").read_text())
            self.assertEqual("InterruptedError", receipt["original_error"]["class"])
            self.assertEqual([], receipt["cleanup"]["remaining_live_pids"])
            self.assertTrue(receipt["cleanup"]["term_sent"])

    def test_timeout_and_success_both_persist_cleanup_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(TimeoutError):
                probe.run_owned([sys.executable, "-c", "import time;time.sleep(60)"],
                                root / "timeout.log", .1, lambda: None)
            receipt = json.loads((root / "timeout.log.cleanup.json").read_text())
            self.assertTrue(receipt["watchdog_expired"])
            self.assertEqual("TimeoutError", receipt["original_error"]["class"])
            self.assertEqual([], receipt["cleanup"]["remaining_live_pids"])
            probe.run_owned([sys.executable, "-c", "pass"], root / "success.log", 5, lambda: None)
            receipt = json.loads((root / "success.log.cleanup.json").read_text())
            self.assertEqual(0, receipt["exit_code_after_cleanup"])
            self.assertIsNone(receipt["original_error"])
            self.assertFalse(receipt["cleanup"]["term_sent"])

    def test_cleanup_failure_does_not_replace_original_interruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual_cleanup = probe.lifecycle.terminate_client
            def cleanup_then_fail(process):
                actual_cleanup(process)
                raise RuntimeError("secondary cleanup failure")
            def interrupted():
                raise InterruptedError("primary cancellation")
            with patch.object(probe.lifecycle, "terminate_client", side_effect=cleanup_then_fail):
                with self.assertRaisesRegex(InterruptedError, "primary cancellation") as caught:
                    probe.run_owned([sys.executable, "-c", "import time;time.sleep(60)"],
                                    root / "child.log", 5, interrupted)
            receipt = json.loads((root / "child.log.cleanup.json").read_text())
            self.assertIn("secondary cleanup failure", receipt["cleanup_error"])
            self.assertEqual("InterruptedError", receipt["original_error"]["class"])
            self.assertEqual([], caught.exception.cleanup_receipt["cleanup"]["remaining_live_pids"])

    def test_receipt_write_failure_retains_primary_error_and_in_memory_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def interrupted():
                raise InterruptedError("primary cancellation")
            with patch.object(probe.lifecycle, "write_json", side_effect=OSError("receipt disk failure")):
                with self.assertRaisesRegex(InterruptedError, "primary cancellation") as caught:
                    probe.run_owned([sys.executable, "-c", "import time;time.sleep(60)"],
                                    root / "child.log", 5, interrupted)
            receipt = caught.exception.cleanup_receipt
            self.assertIn("receipt disk failure", receipt["receipt_write_error"])
            self.assertEqual([], receipt["cleanup"]["remaining_live_pids"])

    def test_signal_deferred_until_cleanup_finishes_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending = [False]
            actual_cleanup = probe.lifecycle.terminate_client
            def cleanup_then_interrupt(process):
                result = actual_cleanup(process)
                pending[0] = True
                return result
            def checkpoint():
                if pending[0]:
                    raise probe.lifecycle.CalibrationInterrupted(signal.SIGTERM)
            with patch.object(probe.lifecycle, "terminate_client", side_effect=cleanup_then_interrupt):
                with self.assertRaises(probe.lifecycle.CalibrationInterrupted):
                    probe.run_owned([sys.executable, "-c", "pass"], root / "child.log", 5, checkpoint)
            receipt = json.loads((root / "child.log.cleanup.json").read_text())
            self.assertEqual("CalibrationInterrupted", receipt["original_error"]["class"])
            self.assertEqual([], receipt["cleanup"]["remaining_live_pids"])

    def test_real_sigterm_persists_receipt_and_cleans_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pidfile = root / "child.pid"
            child = "import os,pathlib,time;pathlib.Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid()));time.sleep(60)"
            source = ("import sys\nfrom pathlib import Path\nsys.path.insert(0," + repr(str(probe.HERE)) + ")\n"
                      "import measure_license_primitives as p\n"
                      "try:\n with p.lifecycle.interrupt_handlers() as checkpoint:\n"
                      "  p.run_owned(" + repr([sys.executable, "-c", child]) + ",Path("
                      + repr(str(root / "child.log")) + "),30,checkpoint)\n"
                      "except p.lifecycle.CalibrationInterrupted:\n pass\n")
            controller = subprocess.Popen([sys.executable, "-B", "-c", source], start_new_session=True,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child_group = None
            try:
                deadline = time.monotonic() + 5
                while controller.poll() is None and time.monotonic() < deadline:
                    try:
                        value = pidfile.read_text()
                        if value.isdigit():
                            child_group = int(value)
                            break
                    except FileNotFoundError:
                        pass
                    time.sleep(.01)
                self.assertIsNotNone(child_group)
                controller.send_signal(signal.SIGTERM)
                self.assertEqual(0, controller.wait(timeout=10))
                receipt = json.loads((root / "child.log.cleanup.json").read_text())
                self.assertEqual("CalibrationInterrupted", receipt["original_error"]["class"])
                self.assertEqual([], receipt["cleanup"]["remaining_live_pids"])
                self.assertFalse(Path("/proc/%d" % child_group).exists())
            finally:
                probe.lifecycle.terminate_client(controller)
                if child_group is not None:
                    if probe.lifecycle.live_group_members(child_group):
                        try:
                            os.killpg(child_group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == "__main__":
    unittest.main()
