#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline LP026 resource-boundary tests; no FE/BE, Java or live proc sampling is required."""

import io
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import background_http_resources as resources


def observation(rss=1, threads=1, at=1):
    return {"rss_bytes": rss, "VmRSS_bytes": rss, "VmHWM_bytes": rss, "VmSwap_bytes": 0,
            "threads": threads, "sample_monotonic_ns": at, "user_cpu_ticks": at, "system_cpu_ticks": at,
            "io": {key: at for key in resources.IO_KEYS}}


class BackgroundHttpResourcesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.output = root / ".build-records" / "owned"
        self.output.mkdir(parents=True)
        self.root_patch = patch.object(resources, "ROOT", root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.guard = resources.ResourceGuard(self.output, {"namespace": "net:[123]"})
        self.guard.stream = io.BytesIO()

    def test_memory_budget_uses_actual_rss_and_kernel_highwater_not_heap(self):
        limit = resources.LIMITS["helper_rss_bytes"]
        self.assertEqual([], resources.exceeded("helper", observation(limit)))
        self.assertIn("helper_rss_budget", resources.exceeded("helper", observation(limit + 1)))
        row = observation(1)
        row["VmHWM_bytes"] = limit + 1
        self.assertIn("helper_rss_budget", resources.exceeded("helper", row))
        self.assertEqual([], resources.exceeded("service", observation(limit * 100)))

    def test_controller_threads_have_a_distinct_bound(self):
        self.assertIn("controller_thread_budget", resources.exceeded(
            "controller", observation(threads=resources.LIMITS["controller_threads"] + 1)))
        self.assertEqual([], resources.exceeded("supervisor", observation(threads=1000)))

    def test_network_is_namespace_scoped_without_double_counting_loopback(self):
        row = resources.network_values(b"header\n lo: 10 2 0 0 0 0 0 0 10 2 0 0 0 0 0 0\n")
        self.assertFalse(row["process_attribution"])
        self.assertFalse(row["rx_plus_tx_summed"])
        self.assertEqual(10, row["interfaces"]["lo"]["rx_bytes"])
        self.assertEqual(10, row["interfaces"]["lo"]["tx_bytes"])
        for raw in (b"lo: 1 2\n", b"lo: -1 " + b"0 " * 15 + b"\n"):
            with self.assertRaises(ValueError):
                resources.network_values(raw)

    def test_io_counter_schema_is_complete_and_duplicates_are_rejected(self):
        raw = "\n".join(key + ": 7" for key in resources.IO_KEYS).encode()
        self.assertEqual(set(resources.IO_KEYS), set(resources.io_values(raw)))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            resources.io_values(raw + b"\nrchar: 8")
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            resources.io_values(b"rchar: 1\n")

    def test_stat_parser_handles_parentheses_in_comm_and_records_cpu_rss_start(self):
        fields = ["0"] * 22
        fields[0], fields[11], fields[12], fields[17], fields[19], fields[21] = "S", "7", "9", "3", "123", "2"
        with patch.object(resources.os, "sysconf", return_value=4096):
            row = resources.stat_values(("100 (name ) inside) " + " ".join(fields)).encode())
        self.assertEqual(123, row["start_ticks"])
        self.assertEqual(8192, row["rss_bytes"])
        self.assertEqual((7, 9, 3), (row["user_cpu_ticks"], row["system_cpu_ticks"], row["threads"]))

    def test_changed_pid_command_executable_or_namespace_invalidates_sample(self):
        pin = {"pid": 42, "start_ticks": 12, "namespace": "net:[123]", "executable": "/original/java",
               "command_sha256": "a" * 64}
        for changed in ({"start_ticks": 13}, {"namespace": "net:[456]"},
                        {"executable": "/foreign/java"}, {"command_sha256": "b" * 64}):
            with self.subTest(changed=changed), patch.object(resources, "process_identity", return_value={**pin, **changed}), \
                    self.assertRaisesRegex(ValueError, "Pinned process identity changed"):
                resources.sample_process(pin)

    def test_process_identity_records_command_digest_without_archiving_properties(self):
        fields = ["0"] * 22
        fields[0], fields[19] = "S", "123"
        raw_stat = ("42 (java) " + " ".join(fields)).encode()
        command = b"/original/java\x00-Dexample=private-value\x00"
        with patch.object(resources, "bounded_read", side_effect=[raw_stat, command, raw_stat]), \
                patch.object(resources.os, "readlink", side_effect=["/original/java", "net:[123]"]):
            pin = resources.process_identity(42)
        self.assertEqual(resources.hashlib.sha256(command).hexdigest(), pin["command_sha256"])
        self.assertEqual(len(command), pin["command_bytes"])
        self.assertNotIn("private-value", str(pin))
        self.assertFalse(pin["raw_command_archived"])

    def test_combined_rss_budget_excludes_product_services_and_supervisor(self):
        actors = {name: {"name": name, "role": role, "active": True}
                  for name, role in (("controller", "controller"), ("java", "helper"), ("fe", "service"))}
        self.guard.actors = actors
        with patch.object(self.guard, "sample_actor", side_effect=lambda actor: observation(1000 if actor["role"] == "service" else 3)), \
                patch.object(resources.os, "readlink", return_value="net:[123]"), \
                patch.object(resources, "bounded_read", return_value=b"lo: " + b"0 " * 16), \
                patch.dict(resources.LIMITS, combined_fixture_rss_bytes=5):
            self.guard.sample()
        self.assertEqual(["combined_sampled_rss_budget"], [item["kind"] for item in self.guard.failures])

    def test_registration_error_is_partial_failure_and_cleanup_is_still_allowed(self):
        with patch.object(resources, "process_identity", side_effect=FileNotFoundError()):
            actor = self.guard.register("short_helper", 42, "helper")
        self.assertEqual(0, actor["samples"])
        self.assertEqual(1, actor["capture_errors"])
        with self.assertRaisesRegex(ValueError, "resource budget/identity/evidence"):
            self.guard.check()
        self.guard.begin_cleanup()
        self.guard.check()
        self.assertTrue(self.guard.failed.is_set())

    def test_sample_failure_preserves_previous_rows_and_resource_budget_event(self):
        pin = {"pid": 42, "start_ticks": 12, "namespace": "net:[123]"}
        with patch.object(resources, "process_identity", return_value=pin), \
                patch.object(resources, "sample_process", return_value=observation()) as sample:
            actor = self.guard.register("helper", 42, "helper")
            sample.return_value = observation(resources.LIMITS["helper_rss_bytes"] + 1, at=2)
            self.guard.sample_actor(actor)
        self.assertEqual(2, actor["samples"])
        self.assertEqual(1, actor["first"]["sample_monotonic_ns"])
        self.assertEqual(2, actor["last"]["sample_monotonic_ns"])
        self.assertTrue(self.guard.failed.is_set())
        self.assertIn(b"process_sample", self.guard.stream.getvalue())

    def test_exit_transition_requires_real_owned_wait_and_marks_missing_final_sample(self):
        actor = {"name": "short", "role": "helper", "pin": {"pid": 42, "start_ticks": 12}, "samples": 1}
        child = Mock()
        child.wait.return_value = 0
        self.guard.helper_processes["short"] = child
        with patch.object(resources, "sample_process", side_effect=resources.ProcessObservationUnavailable(
                "incomplete_memory_counters")):
            self.assertIsNone(self.guard.sample_actor(actor))
        child.wait.assert_called_once_with(timeout=0.05)
        self.assertEqual(1, actor["samples"])
        self.assertTrue(actor["last_unavailable_exit_sample"]["final_RSS_not_observed"])
        self.assertEqual(0, actor["last_unavailable_exit_sample"]["exit_code"])
        self.assertFalse(self.guard.failed.is_set())

    def test_missing_proc_or_memory_of_live_helper_is_not_treated_as_exit(self):
        actor = {"name": "live", "role": "helper", "pin": {"pid": 42, "start_ticks": 12}}
        child = Mock()
        child.wait.side_effect = subprocess.TimeoutExpired("owned", 0.05)
        self.guard.helper_processes["live"] = child
        for error in (FileNotFoundError(), resources.ProcessObservationUnavailable("empty_command_or_zombie")):
            with self.subTest(error=type(error).__name__), patch.object(resources, "sample_process", side_effect=error), \
                    self.assertRaises(type(error)):
                self.guard.sample_actor(actor)
        self.assertNotIn("last_unavailable_exit_sample", actor)

    def test_identity_mismatch_is_not_forgiven_even_if_helper_exits(self):
        actor = {"name": "changed", "role": "helper", "pin": {"pid": 42, "start_ticks": 12}}
        child = Mock()
        child.wait.return_value = 0
        self.guard.helper_processes["changed"] = child
        with patch.object(resources, "sample_process", side_effect=ValueError("Pinned process identity changed")), \
                self.assertRaisesRegex(ValueError, "identity changed"):
            self.guard.sample_actor(actor)
        child.wait.assert_not_called()

    def test_evidence_write_failure_is_bounded_and_does_not_hide_stop_cleanup(self):
        broken = Mock()
        broken.write.side_effect = OSError("disk unavailable")
        self.guard.stream = broken
        self.guard.write({"type": "sample"})
        self.assertTrue(self.guard.failed.is_set())
        first, second = Mock(), Mock()
        first.stop.side_effect = OSError("output stop failed")
        first.summary.return_value = {"name": "first"}
        second.summary.return_value = {"name": "second"}
        self.guard.logs = [first, second]
        with patch.object(self.guard, "sample"):
            result = self.guard.stop()
        second.stop.assert_called_once()
        broken.close.assert_called_once()
        self.assertFalse(result["complete"])
        self.assertEqual(2, len(result["logs"]))

    def test_resource_evidence_file_has_a_hard_byte_bound(self):
        with patch.dict(resources.LIMITS, resource_evidence_bytes=4):
            self.guard.write({"too_long": True})
        self.assertEqual(0, self.guard.evidence_bytes)
        self.assertEqual(b"", self.guard.stream.getvalue())
        self.assertTrue(self.guard.failed.is_set())

    def test_background_stream_rejects_growth_before_writing_the_excess(self):
        capture = resources.BoundedOutput(Mock(), self.output, "broker", Mock())
        capture.streams["stdout"] = io.BytesIO()
        with patch.dict(resources.LIMITS, output_bytes_per_stream=4):
            capture.accept("stdout", b"1234")
            with self.assertRaisesRegex(ValueError, "Background output byte bound"):
                capture.accept("stdout", b"5")
        self.assertEqual(b"1234", capture.streams["stdout"].getvalue())
        self.assertEqual(4, capture.bytes["stdout"])

    def test_background_reader_failure_closes_all_owned_pipe_and_file_handles(self):
        child, failure, selected = Mock(), Mock(), Mock()
        capture = resources.BoundedOutput(child, self.output, "broker", failure)
        capture.streams = {"stdout": Mock(), "stderr": Mock()}
        key = SimpleNamespace(fileobj=child.stdout, data="stdout")
        selected.__enter__ = Mock(return_value=selected)
        selected.__exit__ = Mock(return_value=False)
        selected.get_map.return_value = {1: key}
        selected.select.return_value = [(key, resources.selectors.EVENT_READ)]
        with patch.object(resources.selectors, "DefaultSelector", return_value=selected), \
                patch.object(resources.os, "set_blocking"), patch.object(resources.os, "read", return_value=b"12345"), \
                patch.dict(resources.LIMITS, output_bytes_per_stream=4):
            capture.run()
        failure.assert_called_once_with("broker_output", "ValueError")
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()
        for stream in capture.streams.values():
            stream.close.assert_called_once()
            stream.write.assert_not_called()

    def test_stuck_observer_marks_incomplete_but_still_stops_output_capture(self):
        self.guard.thread = Mock()
        self.guard.thread.is_alive.return_value = True
        capture = Mock()
        capture.summary.return_value = {"name": "broker"}
        self.guard.logs = [capture]
        result = self.guard.stop()
        self.guard.thread.join.assert_called_once_with(timeout=3)
        capture.stop.assert_called_once()
        self.assertFalse(result["observer_thread_stopped"])
        self.assertFalse(result["complete"])
        self.assertTrue(result["may_miss_transient_peaks"])
        self.assertFalse(result["performance_pass"])


if __name__ == "__main__":
    unittest.main()
