#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Owned fake JDBC JVMs only: real process/clock/cleanup receipts, no DB requests.

Before the candidate patch is applied, select its directory with
MASSDB_P4_LIFECYCLE_CANDIDATE. An optional MASSDB_P4_LIFECYCLE_TEST_OUTPUT keeps
every synthetic raw receipt for review; these are never performance evidence.
"""

import copy
import importlib.util
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

import p4_jdbc_lifecycle as lifecycle
from test_baseline_statistics import FAKE_DRIVER_SOURCE


class JdbcLifecycleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidate = Path(os.environ.get("MASSDB_P4_LIFECYCLE_CANDIDATE", Path(__file__).parent)).resolve()
        spec = importlib.util.spec_from_file_location("lifecycle_candidate_runner", candidate / "run_performance_baseline.py")
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)
        cls.runner.SOURCE = candidate / "LicenseJdbcBaseline.java"
        if "lifecycle_context" not in inspect.signature(cls.runner.run_window).parameters:
            raise RuntimeError("Select the reviewed lifecycle candidate or apply its patch; old helper is not upgraded")
        output = os.environ.get("MASSDB_P4_LIFECYCLE_TEST_OUTPUT")
        cls.temporary = None if output else tempfile.TemporaryDirectory(prefix="p4-jdbc-lifecycle-")
        cls.root = Path(output or cls.temporary.name).resolve()
        if output:
            cls.root.mkdir(parents=True, exist_ok=False)
        cls.classes = cls.root / "classes"
        cls.classes.mkdir()
        java_home = os.environ.get("JAVA_HOME")
        javac = Path(java_home, "bin/javac") if java_home else Path(shutil.which("javac")).resolve()
        cls.java = javac.with_name("java")
        driver = cls.root / "FakeBaselineDriver.java"
        driver.write_text(FAKE_DRIVER_SOURCE)
        result = subprocess.run([str(javac), "--release", "17", "-d", str(cls.classes),
                                 str(cls.runner.SOURCE), str(driver)], capture_output=True, text=True)
        (cls.root / "compile.log").write_text(result.stdout + result.stderr)
        result.check_returncode()
        cls.jar = cls.root / "fake-jdbc.jar"
        with zipfile.ZipFile(cls.jar, "w") as jar:
            jar.writestr("META-INF/services/java.sql.Driver", "FakeBaselineDriver\n")
            for file in cls.classes.glob("FakeBaselineDriver*.class"):
                jar.write(file, file.name)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def setUp(self):
        self.directory = self.root / self._testMethodName
        self.directory.mkdir()
        self.window = self.directory / "window"
        self.workload = {"host": "127.0.0.1", "port": 1, "database": "fake_no_socket", "user": "fake",
                         "concurrency": 1, "rate": 5, "duration_seconds": 1, "warmup_seconds": 1,
                         "timeout_seconds": 2, "seed": 20260922, "connection_mode": "reuse",
                         "coordination_timeout_seconds": 3, "drain_timeout_seconds": 2,
                         "session_sql": ["SET fake_session=1"],
                         "services": {name: {"pid": os.getpid()} for name in ("fe", "be")},
                         "queries": [{"sql": "SELECT ?", "mode": "prepared", "parameters": [42], "expected_rows": 1,
                                      "expected_result": {"columns": [{"label": "payload", "jdbc_type": 12}],
                                                          "rows": [["a1d0c6e83f027327d8461063f4ac58a6"]]}}]}
        bindings = {"runner": lifecycle.reference(self.runner.__file__),
                    "calibrator": lifecycle.reference(lifecycle.evidence.capacity.__file__),
                    "jdbc_helper": lifecycle.reference(self.runner.SOURCE), "jdbc_driver": lifecycle.reference(self.jar)}
        for key in ("fe_artifact", "be_artifact", "environment", "configuration", "fixture", "client"):
            path = self.directory / (key + ".synthetic")
            path.write_text("OFFLINE FAKE JDBC ONLY: " + key + "\n")
            bindings[key] = lifecycle.reference(path)
        identity = {"source_commit": "a" * 40}
        for key, field in (("fe_artifact", "fe_sha256"), ("be_artifact", "be_sha256"),
                           ("environment", "environment_sha256"), ("configuration", "configuration_sha256"),
                           ("fixture", "fixture_sha256"), ("client", "client_sha256")):
            identity[field] = bindings[key]["sha256"]
        self.workload["build_identity"] = {"baseline_source_commit": identity["source_commit"],
            "fe_artifact": bindings["fe_artifact"]["path"], "be_artifact": bindings["be_artifact"]["path"]}
        workload_path = self.write_json(self.directory / "workload.json", self.workload)
        self.context = {"window_id": self._testMethodName, "pair_id": 0, "phase": "AA", "variant": "A",
                        "identity": identity, "workload": lifecycle.reference(workload_path), "bindings": bindings,
                        "max_clock_uncertainty_ns": 500_000_000,
                        "context_deadline_monotonic_ns": time.monotonic_ns() + 30_000_000_000}
        env = patch.dict(os.environ, {"MASSDB_BASELINE_FAKE_LOG": str(self.directory / "fake-driver-events.csv")})
        env.start()
        self.addCleanup(env.stop)

    def write_json(self, path, value):
        path.write_text(json.dumps(value, indent=2) + "\n")
        return path

    def run_window(self, context=True):
        return self.runner.run_window(self.workload, self.window, self.java, self.jar, self.classes,
                                      lifecycle_context=self.context if context else None)

    def completion(self):
        value = lifecycle.read_json(self.window / "p4-completion.json")
        self.assertEqual(value["remaining_live_pids"], [])
        self.assertFalse(Path("/proc", str(value["helper_pid"])).exists())
        return value

    def assert_rejected_and_waited(self):
        with self.assertRaises((ValueError, KeyError)):
            self.run_window()
        value = self.completion()
        self.assertTrue(value["exit_code"] != 0 or value["controller_errors"])
        return value

    def test_default_profile_preserves_old_receipts(self):
        result = self.run_window(context=False)
        self.assertEqual(result["process_exit_code"], 0)
        self.assertEqual(result["errors"], {})
        self.assertTrue(result["cpu_boundary_verified"])
        self.assertEqual(set(lifecycle.read_json(self.window / "measurement-ready.json")), {"ready_ns"})
        self.assertFalse(list(self.window.glob("p4-*")))

    def test_real_owned_jvm_handshake_and_same_jvm_boundaries(self):
        result = self.run_window()
        self.assertEqual(result["errors"], {})
        self.assertGreater(result["successful_requests"], 0)
        self.assertTrue(result["cpu_boundary_verified"])
        launch = lifecycle.read_json(self.window / "p4-launch.json")
        completion = self.completion()
        self.assertEqual(completion["exit_code"], 0)
        self.assertEqual(completion["controller_errors"], [])
        bridge = lifecycle.read_json(lifecycle.verify_reference(completion["bridge"]))
        helper = lifecycle.read_json(lifecycle.verify_reference(bridge["helper_clock"]))
        ready = lifecycle.read_json(self.window / "measurement-ready.json")
        start = lifecycle.read_json(self.window / "measurement-start.json")
        end = lifecycle.read_json(self.window / "measurement-end.json")
        cleanup = lifecycle.read_json(self.window / "lifecycle.json")
        mapping = lifecycle.evidence.clock_bridge(launch, lifecycle.reference(self.window / "p4-launch.json"), bridge, helper)
        self.assertLessEqual(helper["jvm_sample_ns"], ready["warmup_start_ns"])
        self.assertGreaterEqual(ready["warmup_end_ns"] - ready["warmup_start_ns"], 10**9)
        self.assertLessEqual(ready["warmup_end_ns"], ready["ready_ns"])
        self.assertLessEqual(ready["ready_ns"], start["epoch_ns"])
        self.assertEqual(end["request_interval_end_ns"] - start["epoch_ns"], 10**9)
        self.assertLessEqual(cleanup["cleanup_end_ns"] + mapping["offset_upper_ns"], completion["completed_monotonic_ns"])
        self.assertGreater(mapping["uncertainty_ns"], 0)
        self.assertEqual(helper["helper_pid"], completion["helper_pid"])
        self.assertEqual(helper["helper_start_ticks"], completion["helper_start_ticks"])
        events = (self.directory / "fake-driver-events.csv").read_text().splitlines()
        executions = [int(line.split(",")[2]) for line in events if line.startswith("execute,")]
        self.assertGreaterEqual(min(executions), ready["warmup_start_ns"])

    def make_ab_context(self, published=None):
        self.context.update(phase="AB", variant="B")
        frozen = self.write_json(self.directory / "synthetic-freeze.json",
                                 {"status": "FROZEN_ELIGIBLE", "identities": {"B": self.context["identity"]}})
        self.context["freeze"] = lifecycle.reference(frozen)
        publication = self.write_json(self.directory / "synthetic-publication.json",
            {"freeze": self.context["freeze"], "boot_id": lifecycle.statistics.boot_id(),
             "published_monotonic_ns": published if published is not None else time.monotonic_ns()})
        self.context["publication"] = lifecycle.reference(publication)

    def test_ab_context_binds_explicit_publication_before_real_fake_jvm(self):
        self.make_ab_context()
        self.run_window()
        launch = lifecycle.read_json(self.window / "p4-launch.json")
        self.assertEqual((launch["phase"], launch["variant"]), ("AB", "B"))
        self.assertEqual(launch["freeze"], self.context["freeze"])
        self.assertEqual(self.completion()["controller_errors"], [])

    def test_future_publication_rejected_before_launch(self):
        self.make_ab_context(time.monotonic_ns() + 10**12)
        with patch.object(self.runner.subprocess, "Popen") as popen, self.assertRaisesRegex(ValueError, "published"):
            self.run_window()
        popen.assert_not_called()

    def test_expired_context_rejected_before_launch(self):
        self.context["context_deadline_monotonic_ns"] = time.monotonic_ns() - 1
        with patch.object(self.runner.subprocess, "Popen") as popen, self.assertRaisesRegex(ValueError, "Expired"):
            self.run_window()
        popen.assert_not_called()

    def test_a_only_context_cannot_name_candidate_b(self):
        self.context["variant"] = "B"
        with patch.object(self.runner.subprocess, "Popen") as popen, self.assertRaisesRegex(ValueError, "A/A"):
            self.run_window()
        popen.assert_not_called()

    def test_uncertainty_above_frozen_limit_aborts_and_waits(self):
        self.context["max_clock_uncertainty_ns"] = 1
        self.assert_rejected_and_waited()
        self.assertFalse((self.window / "measurement-ready.json").exists())

    def test_wrong_reply_nonce_aborts_and_waits(self):
        original = lifecycle.read_json
        def altered(path):
            value = original(path)
            if Path(path).name == "p4-helper-clock.json":
                value["nonce"] = "0" * 64
            return value
        with patch.object(lifecycle, "read_json", side_effect=altered):
            self.assert_rejected_and_waited()
        self.assertFalse((self.window / "measurement-ready.json").exists())

    def test_wrong_helper_lifetime_aborts_and_waits(self):
        original = lifecycle.read_json
        def altered(path):
            value = original(path)
            if Path(path).name == "p4-clock-ready.json":
                value["helper_start_ticks"] += 1
            return value
        with patch.object(lifecycle, "read_json", side_effect=altered):
            self.assert_rejected_and_waited()

    def alter_publish(self, name, change):
        original = lifecycle.publish
        def altered(path, value):
            if Path(path).name == name:
                value = change(value)
                if value is None:
                    return
            return original(path, value)
        return patch.object(lifecycle, "publish", side_effect=altered)

    def test_helper_rejects_stale_readiness_nonce(self):
        with self.alter_publish("p4-clock-request.properties", lambda value: value.replace("ready_nonce=", "wrong_nonce=")):
            self.assert_rejected_and_waited()
        self.assertFalse((self.window / "p4-helper-clock.json").exists())

    def test_helper_rejects_wrong_ack_nonce(self):
        with self.alter_publish("p4-clock-ack.properties", lambda value: value.replace("nonce=", "wrong_nonce=")):
            self.assert_rejected_and_waited()
        self.assertFalse((self.window / "measurement-ready.json").exists())

    def test_helper_rejects_expired_ack(self):
        with self.alter_publish("p4-clock-ack.properties", lambda value: None):
            self.assert_rejected_and_waited()
        failure = lifecycle.read_json(self.window / "client-failure.json")
        self.assertEqual(failure["phase"], "clock_handshake")
        self.assertFalse((self.window / "measurement-ready.json").exists())

    def test_binding_drift_after_ack_still_waits_and_writes_failure(self):
        original = lifecycle.LifecycleController.poll
        changed = False
        def drifting(controller):
            nonlocal changed
            original(controller)
            if controller.bridge is not None and not changed:
                Path(self.context["bindings"]["client"]["path"]).write_text("changed input\n")
                changed = True
        with patch.object(lifecycle.LifecycleController, "poll", drifting):
            completion = self.assert_rejected_and_waited()
        self.assertEqual(completion["exit_code"], 0)
        self.assertTrue(completion["controller_errors"])
        self.assertTrue((self.window / "lifecycle.json").is_file())

    def test_binding_drift_before_ack_aborts_without_skipping_wait(self):
        original = lifecycle.LifecycleController.attach
        def drifting(controller, process):
            original(controller, process)
            Path(self.context["bindings"]["client"]["path"]).write_text("changed input\n")
        with patch.object(lifecycle.LifecycleController, "attach", drifting):
            self.assert_rejected_and_waited()
        self.assertFalse((self.window / "measurement-ready.json").exists())

    def test_context_expiry_after_spawn_aborts_and_waits(self):
        original = lifecycle.LifecycleController.attach
        def expiring(controller, process):
            original(controller, process)
            controller.launch["context_deadline_monotonic_ns"] = time.monotonic_ns() - 1
        with patch.object(lifecycle.LifecycleController, "attach", expiring):
            self.assert_rejected_and_waited()

    def test_completion_requires_actual_wait(self):
        self.window.mkdir()
        controller = lifecycle.LifecycleController(self.workload, self.window, self.context,
                    self.runner.__file__, self.runner.SOURCE, self.jar, self.classes)
        with self.assertRaisesRegex(ValueError, "waited"):
            controller.finish()
        self.assertFalse((self.window / "p4-completion.json").exists())

    def test_malformed_cleanup_still_leaves_waited_failure_receipt(self):
        original = lifecycle.LifecycleController.finish
        def corrupting(controller, failure=None):
            (self.window / "lifecycle.json").write_text("{}\n")
            return original(controller, failure)
        with patch.object(lifecycle.LifecycleController, "finish", corrupting):
            completion = self.assert_rejected_and_waited()
        self.assertEqual(completion["exit_code"], 0)
        self.assertIn("InvalidWarmupOrCleanupEvidence", completion["controller_errors"])

    def test_actual_warmup_after_expiry_is_rejected_conservatively(self):
        original = lifecycle.LifecycleController.check_warmup
        def expiring(controller):
            ready = lifecycle.read_json(self.window / "measurement-ready.json")
            controller.launch["context_deadline_monotonic_ns"] = (
                ready["warmup_start_ns"] + controller.mapping["offset_upper_ns"] - 1)
            return original(controller)
        with patch.object(lifecycle.LifecycleController, "check_warmup", expiring):
            self.assert_rejected_and_waited()
        self.assertFalse((self.window / "measurement-start.json").exists())


if __name__ == "__main__":
    unittest.main()
