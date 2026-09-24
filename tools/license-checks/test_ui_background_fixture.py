#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline contract/corruption cases; no SQL, Java, browser or child process execution."""

import copy
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import ui_background_fixture as background


def helper_pin():
    return {"pid": 42, "start_ticks": 99, "state": "S", "namespace": "net:[1]",
            "exe": "/test/javac", "command_sha256": "a" * 64}


def helper_observation(pin=None):
    pin = pin or helper_pin()
    stat = {key: pin[key] for key in ("start_ticks", "state")}
    return {"before": stat, "identity": pin, "after": dict(stat)}


class FakeChild:
    pid = 42

    def __init__(self, exit_code=0, timeout=False):
        self.returncode = None
        self.exit_code, self.timeout, self.waits = exit_code, timeout, []

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.waits.append(timeout)
        if self.timeout:
            raise subprocess.TimeoutExpired("private-command-not-archived", timeout)
        self.returncode = self.exit_code
        return self.returncode


class UiBackgroundExitHandshakeTest(unittest.TestCase):
    def test_matching_live_identity_is_not_waited_or_signalled(self):
        child, api = FakeChild(), Mock()
        with patch.object(background, "process_observation", return_value=helper_observation()):
            self.assertTrue(background.owned_live(api, child, helper_pin(), "test"))
        self.assertEqual([], child.waits)
        api.stop_owned.assert_not_called()

    def test_incomplete_exit_waits_and_records_actual_nonzero_status(self):
        child, events = FakeChild(exit_code=7), []
        with patch.object(background, "process_observation", return_value={"before": {"start_ticks": 99, "state": "Z"}}):
            self.assertFalse(background.owned_live(Mock(), child, helper_pin(), "test", emit=events.append))
        self.assertEqual([background.EXIT_SETTLE_SECONDS], child.waits)
        self.assertEqual(7, events[0]["exit_code"])
        self.assertTrue(events[0]["parent_wait_complete"])

    def test_missing_resource_requires_bounded_exit_even_if_remaining_identity_is_complete(self):
        for timeout in (False, True):
            child = FakeChild(timeout=timeout)
            with self.subTest(timeout=timeout), \
                    patch.object(background, "process_observation", return_value=helper_observation()):
                if timeout:
                    with self.assertRaises(background.BackgroundProcessError) as caught:
                        background.owned_live(Mock(), child, helper_pin(), "resource_read", force_exit_wait=True)
                    self.assertEqual('IDENTITY_UNAVAILABLE_CHILD_STILL_LIVE', caught.exception.reason)
                else:
                    self.assertFalse(background.owned_live(Mock(), child, helper_pin(), 'resource_read',
                                                           force_exit_wait=True))
            self.assertEqual([background.EXIT_SETTLE_SECONDS], child.waits)

    def test_incomplete_but_live_process_is_rejected_without_signal(self):
        child, api, events = FakeChild(timeout=True), Mock(), []
        with patch.object(background, "process_observation", return_value={}):
            with self.assertRaises(background.BackgroundProcessError) as caught:
                background.reap_owned(api, child, helper_pin(), emit=events.append)
        self.assertEqual("IDENTITY_UNAVAILABLE_CHILD_STILL_LIVE", caught.exception.reason)
        self.assertEqual(1, len(child.waits))
        api.stop_owned.assert_not_called()
        self.assertNotIn("private-command", json.dumps(events))

    def test_reuse_and_live_exec_namespace_command_changes_never_use_exit_exception(self):
        changes = [("start_ticks", 100), ("exe", "/other/java"),
                   ("namespace", "net:[2]"), ("command_sha256", "b" * 64)]
        for key, value in changes:
            child, api = FakeChild(), Mock()
            observed = helper_observation(dict(helper_pin(), **{key: value}))
            with self.subTest(key=key), patch.object(background, "process_observation", return_value=observed):
                with self.assertRaises(background.BackgroundProcessError):
                    background.reap_owned(api, child, helper_pin())
            self.assertEqual([], child.waits)
            api.stop_owned.assert_not_called()

    def test_empty_command_requires_wait_instead_of_a_new_live_pin(self):
        observed = helper_observation(dict(helper_pin(), command_sha256=hashlib.sha256(b"").hexdigest()))
        child = FakeChild(timeout=True)
        with patch.object(background, "process_observation", return_value=observed):
            with self.assertRaises(background.BackgroundProcessError) as caught:
                background.owned_live(Mock(), child, helper_pin(), "test")
        self.assertEqual("IDENTITY_UNAVAILABLE_CHILD_STILL_LIVE", caught.exception.reason)

    def test_original_deadline_caps_handshake_and_expired_deadline_cannot_wait(self):
        for deadline, expected in ((10.1, 0.1), (10, None)):
            child = FakeChild()
            with self.subTest(deadline=deadline), patch.object(background.time, "monotonic", return_value=10), \
                    patch.object(background, "process_observation", return_value={}):
                if expected is None:
                    with self.assertRaises(background.BackgroundProcessError) as caught:
                        background.owned_live(Mock(), child, helper_pin(), "test", deadline)
                    self.assertEqual("EXIT_HANDSHAKE_DEADLINE", caught.exception.reason)
                    self.assertEqual([], child.waits)
                else:
                    self.assertFalse(background.owned_live(Mock(), child, helper_pin(), "test", deadline))
                    self.assertAlmostEqual(expected, child.waits[0])

    def test_phase_deadline_is_passed_to_check_and_late_completion_still_fails(self):
        fixture = background.Background.__new__(background.Background)
        fixture.check = Mock()
        fixture.whole_deadline = 1000
        condition = Mock(return_value=True)
        with patch.object(background.time, 'monotonic', return_value=10.1):
            with self.assertRaisesRegex(ValueError, 'phase deadline expired'):
                fixture._await(condition, 10)
        fixture.check.assert_called_once_with(phase_deadline=10)
        condition.assert_not_called()

    def test_check_passes_phase_deadline_to_owned_exit_handshake(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            with patch.object(background.time, 'monotonic', return_value=10), \
                    patch.object(background, 'owned_live', return_value=False) as live:
                self.assertEqual([], fixture.check(phase_deadline=10.1))
            self.assertEqual(10.1, live.call_args.args[4])

    def test_wait_without_actual_popen_exit_cannot_pass(self):
        child = Mock(pid=42)
        child.poll.return_value = None
        child.wait.return_value = 0
        with patch.object(background, "process_observation", return_value={}):
            with self.assertRaises(background.BackgroundProcessError) as caught:
                background.owned_live(Mock(), child, helper_pin(), "test")
        self.assertEqual("WAIT_WITHOUT_EXIT_RECEIPT", caught.exception.reason)

    def test_pin_missing_does_not_acquire_a_live_process(self):
        child = FakeChild()
        with patch.object(background, "process_observation", return_value=helper_observation()):
            with self.assertRaises(background.BackgroundProcessError) as caught:
                background.owned_live(Mock(), child, None, "test")
        self.assertEqual("MISSING_OWNED_PIN", caught.exception.reason)
        self.assertEqual([], child.waits)

    def test_lifetime_change_during_bracket_is_rejected_even_when_identity_matches(self):
        observed = helper_observation()
        observed["after"]["start_ticks"] = 100
        child = FakeChild()
        with patch.object(background, "process_observation", return_value=observed):
            with self.assertRaises(background.BackgroundProcessError) as caught:
                background.owned_live(Mock(), child, helper_pin(), "test")
        self.assertEqual("PROCESS_LIFETIME_CHANGED", caught.exception.reason)
        self.assertEqual([], child.waits)

    def test_already_exited_child_has_real_wait_receipt_without_a_live_pin(self):
        child, events, api = FakeChild(exit_code=-15), [], Mock()
        child.returncode = -15
        self.assertTrue(background.reap_owned(api, child, None, emit=events.append))
        self.assertEqual(-15, events[0]["exit_code"])
        self.assertTrue(events[0]["parent_wait_complete"])
        api.stop_owned.assert_not_called()

    def fixture(self, directory):
        fixture = background.Background.__new__(background.Background)
        fixture.output, fixture.guard = directory, Mock()
        fixture.whole_deadline = float("inf")
        fixture.process, fixture.pin = FakeChild(), helper_pin()
        fixture.peak, fixture.samples, fixture.last_sample = 0, 0, 0
        fixture.plan = {"resources": {"cpus": [0], "rss_limit_mib": 1024}}
        fixture.api = Mock()
        fixture.api.rss_mib.return_value = 20
        return fixture

    def test_exit_during_resource_read_discards_sample_instead_of_inventing_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            with patch.object(background, "owned_live", side_effect=[True, False]), \
                    patch.object(background.os, "sched_getaffinity", return_value={0}), \
                    patch.object(Path, "read_text", side_effect=FileNotFoundError):
                self.assertEqual([], fixture.check())
            self.assertFalse((fixture.output / "resources.jsonl").exists())
            self.assertIsNone(fixture.process_events[0]["rss_bytes"])
            self.assertEqual("EXITED_PARTIAL_SAMPLE_DISCARDED", fixture.process_events[0]["reason"])

    def test_missing_resource_while_still_live_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            with patch.object(background, "owned_live", return_value=True), \
                    patch.object(background.os, "sched_getaffinity", return_value={0}), \
                    patch.object(Path, "read_text", side_effect=FileNotFoundError):
                with self.assertRaises(background.BackgroundProcessError) as caught:
                    fixture.check()
            self.assertEqual("LIVE_RESOURCE_EVIDENCE_MISSING", caught.exception.reason)
            self.assertEqual(0, fixture.samples)

    def test_diagnostic_save_failure_does_not_replace_primary_identity_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            fixture.api.save.side_effect = OSError("private filesystem message")
            with patch.object(background, "process_observation", return_value=helper_observation(dict(helper_pin(), start_ticks=100))):
                with self.assertRaises(background.BackgroundProcessError) as caught:
                    background.owned_live(fixture.api, fixture.process, fixture.pin, "test", emit=fixture._process_event)
            self.assertEqual("PROCESS_LIFETIME_CHANGED", caught.exception.reason)
            self.assertEqual("OSError", fixture.process_evidence_errors[0]["error_class"])

    def test_compile_primary_failure_survives_reap_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            jar = fixture.output / 'helper.jar'
            jar.write_bytes(b'fixture')
            fixture.guard.jar = jar
            fixture.api.sha.return_value = 'digest'
            fixture.frozen = {"java_home": "/test/jdk", "dependencies_sha256": {str(jar): 'digest'}}
            fixture._launch = Mock()
            fixture._await = Mock(side_effect=background.BackgroundProcessError('FIRST_FAILURE', 'compile'))
            with patch.object(background, 'verify_frozen'), \
                    patch.object(background, 'reap_owned', side_effect=background.BackgroundProcessError('REAP_FAILURE', 'reap')):
                with self.assertRaises(background.BackgroundProcessError) as caught:
                    fixture.start()
            self.assertEqual('FIRST_FAILURE', caught.exception.reason)
            self.assertEqual(['FIRST_FAILURE', 'REAP_FAILURE'], [event['reason'] for event in fixture.process_events])


def profile():
    value = {key: bounds[0] for key, bounds in background.BOUNDS.items()}
    value.update(schema_version=1, seed=20260922,
                 rate_basis="explicit_functional_input_not_capacity_qualification",
                 read_account={"username": "ui_reader", "host": "%", "password_env": "MASSDB_UI_READ_PASSWORD"},
                 write_account={"username": "ui_writer", "host": "%", "password_env": "MASSDB_UI_WRITE_PASSWORD"})
    return value


def receipt(outcome="OK"):
    return {"sequence": "0", "scheduled_ns": "1000100", "started_ns": "1100100", "finished_ns": "1200100",
            "outcome": outcome, "affected_rows": "-1", "sql_state": "NONE", "error_code": "0", "e2e_ns": "200000"}


class UiBackgroundBoundaryTest(unittest.TestCase):
    def test_every_rate_and_bound_is_explicit(self):
        value = profile()
        self.assertEqual(value, background.validate_config(value))
        for key in background.BOUNDS:
            broken = copy.deepcopy(value)
            del broken[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                background.validate_config(broken)

    def test_boolean_zero_or_excessive_rates_cannot_disable_bounds(self):
        for key, value in (("read_rate_per_second", True), ("write_batches_per_second", 0),
                           ("read_workers", 33), ("duration_seconds", 30), ("cleanup_timeout_seconds", 0)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                background.validate_config(dict(profile(), **{key: value}))

    def test_batched_write_size_is_bounded_before_any_process(self):
        value = profile()
        value.update(write_batches_per_second=20, write_batch_rows=1000)
        with self.assertRaisesRegex(ValueError, "Expected write rows"):
            background.validate_config(value)

    def test_read_and_write_cannot_share_account_or_secret_reference(self):
        for key in ("username", "password_env"):
            value = profile()
            value["write_account"][key] = value["read_account"][key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                background.validate_config(value)

    def test_literal_credentials_and_capacity_claims_are_rejected(self):
        value = profile()
        value["write_account"]["password"] = "must-not-archive"
        with self.assertRaises(ValueError):
            background.validate_config(value)
        with self.assertRaises(ValueError):
            background.validate_config(dict(profile(), rate_basis="qualified_capacity"))

    def test_old_browser_plan_cannot_silently_acquire_writes(self):
        self.assertIsNone(background.validate_probe(None, {}, None))
        with self.assertRaisesRegex(ValueError, "cannot acquire"):
            background.validate_probe(None, {}, Path("new-background.json"))
        with self.assertRaisesRegex(ValueError, "same explicit"):
            background.validate_probe(None, {"background": {}}, None)

    def test_background_password_must_be_explicit_and_is_not_in_argv(self):
        value = profile()
        admin = {"username": "admin", "password_env": "MASSDB_UI_ADMIN_PASSWORD"}
        with patch.dict(background.os.environ, {}, clear=True), self.assertRaises(ValueError):
            background.secret_environment(value, admin)
        environment = {item["password_env"]: "synthetic" for item in
                       (value["read_account"], value["write_account"], admin)}
        with patch.dict(background.os.environ, dict(environment, JAVA_TOOL_OPTIONS="injection"), clear=True):
            self.assertEqual(environment, background.secret_environment(value, admin))

    def test_ack_is_not_unknown_or_a_row_count_only_success(self):
        value = receipt("UNKNOWN")
        value.update(affected_rows="-1", sql_state="08006", error_code="2013")
        result = background.receipt_values(value, "write", 100, 1000000, 4, 1)
        self.assertFalse(result["successful"])
        self.assertFalse(result["slo_met"])
        value.update(outcome="ACK", affected_rows="4")
        with self.assertRaisesRegex(ValueError, "error or early"):
            background.receipt_values(value, "write", 100, 1000000, 4, 1)

    def test_latency_includes_client_queue_and_cannot_be_rewritten(self):
        value = receipt()
        value.update(started_ns="10000100", finished_ns="10100100", e2e_ns="9100000")
        result = background.receipt_values(value, "read", 100, 1000000, 1, 1)
        self.assertTrue(result["successful"])
        self.assertFalse(result["slo_met"])
        value["e2e_ns"] = "100000"
        with self.assertRaisesRegex(ValueError, "timing mismatch"):
            background.receipt_values(value, "read", 100, 1000000, 1, 1)

    def evidence(self, directory):
        value = profile()
        token = "a" * 32
        identity = {"pid": 42, "start_ticks": 99, "namespace": "net:[1]"}
        start = {"token": token, "epoch_java_monotonic_ns": 1000000, **identity}
        end = {"token": token, "scheduled_window_complete": True, "java_monotonic_ns": 300001000000, **identity}
        (directory / "window-start.json").write_text(json.dumps(start))
        (directory / "window-end.json").write_text(json.dumps(end))
        (directory / "read-arrivals.tsv").write_text("sequence\toffset_ns\tid\n0\t100\t7\n")
        (directory / "write-arrivals.tsv").write_text("sequence\toffset_ns\tfirst_id\trows\n0\t100\t1000000000\t1\n")
        (directory / "visibility.tsv").write_text("sequence\tobserved_ns\tack_or_error_ns\trows\tstate\n"
                                                  "0\t1300100\t1200100\t1\tFULL_MODEL_VISIBLE\n")
        for stream, outcome, affected in (("read", "OK", "-1"), ("write", "ACK", "1")):
            row = dict(receipt(outcome), affected_rows=affected)
            with (directory / (stream + "-0.tsv")).open("w", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=list(row), delimiter="\t")
                writer.writeheader()
                writer.writerow(row)
        api = SimpleNamespace(read_json=lambda path: json.loads(path.read_text()),
                              sha=lambda path: hashlib.sha256(path.read_bytes()).hexdigest())
        summary = {"token": token, "status": "PASS", "planned_reads": 1, "planned_write_batches": 1, **identity,
                   **{stream + "_schedule_sha256": api.sha(directory / (stream + "-arrivals.tsv"))
                      for stream in ("read", "write")}}
        return api, value, summary

    def test_missing_or_duplicate_receipts_cannot_become_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            api, value, summary = self.evidence(directory)
            self.assertEqual(1, background.audit_receipts(api, directory, value, summary)["read"]["successful"])
            path = directory / "read-0.tsv"
            original = path.read_text()
            path.write_text(original + original.splitlines(keepends=True)[1])
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                background.audit_receipts(api, directory, value, summary)
            path.write_text(original.splitlines(keepends=True)[0])
            with self.assertRaisesRegex(ValueError, "Missing"):
                background.audit_receipts(api, directory, value, summary)

    def test_coordinated_write_schedule_change_still_rejects_wrong_id_domain(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            api, value, summary = self.evidence(directory)
            path = directory / "write-arrivals.tsv"
            path.write_text(path.read_text().replace("1000000000", "1000000001"))
            summary["write_schedule_sha256"] = api.sha(path)
            with self.assertRaisesRegex(ValueError, "ID domains"):
                background.audit_receipts(api, directory, value, summary)

    def test_missing_pin_does_not_mean_popen_exited(self):
        process = FakeChild(timeout=True)
        api = Mock()
        with patch.object(background, "process_observation", return_value={}), \
                self.assertRaisesRegex(ValueError, "identity changed"):
            background.reap_owned(api, process, helper_pin())
        api.stop_owned.assert_not_called()

    def test_ack_without_independent_visibility_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            api, value, summary = self.evidence(directory)
            path = directory / "visibility.tsv"
            original = path.read_text()
            path.write_text(original.splitlines(keepends=True)[0])
            with self.assertRaisesRegex(ValueError, "Missing independent"):
                background.audit_receipts(api, directory, value, summary)
            path.write_text(original.replace("1300100", "9999999999"))
            with self.assertRaisesRegex(ValueError, "visibility failure/SLO"):
                background.audit_receipts(api, directory, value, summary)

    def test_full_target_count_cannot_replace_exact_python_model_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            api = SimpleNamespace(read_json=lambda path: json.loads(path.read_text()))
            value = profile()
            source = {"rows": 1000000, "full_values_verified": True, "canonical_sha256": "source-model"}
            summary = {"status": "PASS", "source_before": source, "source_after": source,
                       "planned_write_batches": 1, "target_after": {"rows": 1, "full_values_verified": True,
                           "exact_id_domains_verified": True,
                           "canonical_sha256": background.expected_rows_digest([1000000000])}}
            batch = {"sequence": 0, "rows": 1, "request_state": "ACK", "observed_committed": True,
                     "unknown_absence_is_rollback_proof": False}
            (directory / "write-batch-resolution.json").write_text(json.dumps([batch]))
            with patch.object(background, "expected_source_digest", return_value="source-model"):
                self.assertEqual(1, background.audit_full_models(api, directory, value, summary)["target_rows"])
                summary["target_after"]["canonical_sha256"] = background.expected_rows_digest([1000000001])
                with self.assertRaisesRegex(ValueError, "Full target differs"):
                    background.audit_full_models(api, directory, value, summary)

    def test_signal_helper_success_cannot_replace_actual_popen_exit(self):
        process = Mock(pid=42)
        process.poll.return_value = None
        api = Mock()
        api.same.return_value = True
        api.stop_owned.return_value = True
        with patch.object(background, "process_observation", return_value=helper_observation()), \
                self.assertRaisesRegex(ValueError, "still reports"):
            background.reap_owned(api, process, helper_pin())

    def test_marker_failure_and_corrupt_summary_still_attempt_owned_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "summary.json").write_text("{")
            fixture = background.Background.__new__(background.Background)
            fixture.output, fixture.finished, fixture.profile = directory, False, profile()
            fixture.config_path = directory / "config.json"
            fixture.config_path.write_text("{}")
            fixture.process, fixture.pin = Mock(), {"pid": 42, "start_ticks": 99, "namespace": "net:[1]"}
            fixture.process.poll.return_value = 0
            fixture.work_pin, fixture.token = fixture.pin, "a" * 32
            fixture.frozen = {"java_home": "/synthetic/jdk"}
            fixture.classpath, fixture.guard, fixture.peak, fixture.samples = "classes", Mock(), 0, 0
            fixture.whole_deadline = float("inf")
            fixture.config = {"cell": "cell-001", "table": "license_perf.ui_bg_" + fixture.token}
            fixture.plan = {"output": str(directory)}

            def save(path, value):
                if path.name == "stop.json":
                    raise OSError("synthetic private marker error")
                path.write_text(json.dumps(value))

            fixture.api = SimpleNamespace(save=save, read_json=lambda path: json.loads(path.read_text()),
                                          sha=lambda path: hashlib.sha256(path.read_bytes()).hexdigest())
            def launch(command, name, phase_deadline):
                self.assertIn("--cleanup-only", command)
                (directory / "cleanup.json").write_text(json.dumps({"token": fixture.token,
                    **fixture.pin, "cleanup_confirmed": True}))
            fixture._launch, fixture._await = Mock(side_effect=launch), Mock()
            with patch.object(background, "reap_owned", return_value=True) as reap, \
                    patch.object(background, "verify_frozen"):
                result = fixture.finish()
            self.assertEqual(2, reap.call_count)
            fixture._launch.assert_called_once()
            self.assertTrue(result["cleanup_confirmed"])
            self.assertEqual("FAIL", result["status"])
            self.assertTrue({"stop_marker", "summary_read"} <= {item["stage"] for item in result["errors"]})


class Clock:
    def __init__(self): self.now = 10.0
    def monotonic(self): return self.now
    def sleep(self, seconds): self.now += seconds

class StartupPinTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        timer = patch.multiple(background.time, monotonic=self.clock.monotonic, sleep=self.clock.sleep)
        timer.start(); self.addCleanup(timer.stop)
        self.expected = {k: helper_pin()[k] for k in ('pid', 'namespace', 'exe', 'command_sha256')}

    def acquire(self, observations, child=None, deadline=100):
        child = child or FakeChild(timeout=True)
        with patch.object(background, 'process_observation', side_effect=observations):
            return background.acquire_launch_pin(Mock(), child, self.expected, deadline, lambda: None)

    def test_original_empty_pin_reproduces_actual_drift_failure(self):
        original = dict(helper_pin(), command_sha256=hashlib.sha256(b'').hexdigest())
        with patch.object(background, 'process_observation', return_value=helper_observation()):
            with self.assertRaises(background.BackgroundProcessError) as caught:
                background.owned_live(Mock(), FakeChild(timeout=True), original, 'actual-v3-reproduction')
        self.assertEqual('LIVE_IDENTITY_CHANGED', caught.exception.reason)

    def test_empty_pin_requires_two_later_exact_matches(self):
        empty = helper_observation(dict(helper_pin(), command_sha256=hashlib.sha256(b'').hexdigest()))
        result = self.acquire([empty, helper_observation(), helper_observation()])
        self.assertEqual(helper_pin(), result['pin'])
        self.assertEqual(3, result['event']['attempts'])
        self.assertEqual(2, result['event']['consecutive_complete_matches'])
        self.assertEqual(empty, result['event']['first_observation'])

    def test_matching_live_child_is_not_waited(self):
        child = FakeChild(timeout=True)
        self.acquire([helper_observation(), helper_observation()], child)
        self.assertEqual([], child.waits)

    def test_nonempty_command_executable_namespace_pid_changes_are_rejected(self):
        for field, value in [('command_sha256', 'b'*64), ('exe', '/wrapper'), ('namespace', 'net:[2]'), ('pid', 43)]:
            with self.subTest(field=field), self.assertRaises(background.BackgroundProcessError) as caught:
                self.acquire([helper_observation(dict(helper_pin(), **{field:value}))])
            self.assertEqual('STARTUP_IDENTITY_MISMATCH', caught.exception.reason)

    def test_second_read_exec_change_is_not_allowed(self):
        with self.assertRaises(background.BackgroundProcessError) as caught:
            self.acquire([helper_observation(), helper_observation(dict(helper_pin(), exe='/new/exe'))])
        self.assertEqual('STARTUP_IDENTITY_MISMATCH', caught.exception.reason)

    def test_lifetime_change_inside_or_between_reads_is_rejected(self):
        changed = helper_observation(); changed['after']['start_ticks'] = 100
        for observations in ([changed], [helper_observation(), helper_observation(dict(helper_pin(), start_ticks=100))]):
            with self.subTest(), self.assertRaises(background.BackgroundProcessError) as caught:
                self.acquire(observations)
            self.assertEqual('PROCESS_LIFETIME_CHANGED', caught.exception.reason)

    def test_missing_read_restarts_consecutive_count(self):
        result = self.acquire([helper_observation(), {}, helper_observation(), helper_observation()])
        self.assertEqual(4, result['event']['attempts'])

    def test_persistent_empty_obeys_phase_and_startup_deadlines(self):
        empty = helper_observation(dict(helper_pin(), command_sha256=hashlib.sha256(b'').hexdigest()))
        for budget in (0.002, 0.25):
            self.clock.now = 10
            with self.subTest(budget=budget), patch.object(background, 'process_observation', return_value=empty):
                with self.assertRaises(background.BackgroundProcessError) as caught:
                    background.acquire_launch_pin(Mock(), FakeChild(timeout=True), self.expected, 10+budget, lambda: None)
            self.assertEqual('STARTUP_IDENTITY_DEADLINE', caught.exception.reason)
            self.assertLessEqual(self.clock.now, 10+budget)

    def test_successful_read_after_deadline_still_fails(self):
        count = 0
        def read(*args):
            nonlocal count
            count += 1
            if count == 2: self.clock.now = 10.02
            return helper_observation()
        with patch.object(background, 'process_observation', side_effect=read), self.assertRaises(background.BackgroundProcessError) as caught:
            background.acquire_launch_pin(Mock(), FakeChild(timeout=True), self.expected, 10.01, lambda: None)
        self.assertEqual('STARTUP_IDENTITY_DEADLINE', caught.exception.reason)

    def test_early_exit_has_real_nonzero_parent_wait(self):
        child = FakeChild(exit_code=17); child.returncode = 17
        with self.assertRaises(background.BackgroundProcessError) as caught: self.acquire([], child)
        self.assertEqual('STARTUP_EXIT_BEFORE_IDENTITY', caught.exception.reason)
        self.assertEqual(17, caught.exception.observation['last_observation']['exit_code'])
        self.assertTrue(caught.exception.observation['last_observation']['parent_wait_complete'])
        self.assertEqual([5], child.waits)

    def fixture(self, directory):
        item = background.Background.__new__(background.Background)
        item.output, item.guard, item.api = directory, Mock(), Mock()
        item.whole_deadline, item.environment = 100, {}
        return item

    def test_popen_owned_before_failure_and_early_exit_waited(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(Path(directory)); child = FakeChild(exit_code=3)
            def fail(*args):
                self.assertIs(child, fixture.process); self.assertIsNone(fixture.pin)
                child.returncode = 3
                raise InterruptedError('cancel')
            with patch.object(background.subprocess, 'Popen', return_value=child), patch.object(background, 'acquire_launch_pin', side_effect=fail):
                with self.assertRaises(InterruptedError): fixture._launch([sys.executable, '-V'], 'test', 20)
            self.assertEqual([5], child.waits)
            self.assertEqual(3, fixture.process_events[-1]['exit_code'])

    def test_pin_retained_before_evidence_write_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(Path(directory)); fixture.api.save.side_effect=OSError('disk')
            acquired = {'pin':helper_pin(), 'event':{'reason':'EXPECTED_LAUNCH_IDENTITY_CONFIRMED'}}
            with patch.object(background.subprocess, 'Popen', return_value=FakeChild(timeout=True)), patch.object(background, 'acquire_launch_pin', return_value=acquired):
                with self.assertRaises(OSError): fixture._launch([sys.executable, '-V'], 'test', 20)
            self.assertEqual(helper_pin(), fixture.pin)

    def test_expired_phase_does_not_launch_child(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(background.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(ValueError, 'phase deadline expired'):
                self.fixture(Path(directory))._launch([sys.executable, '-V'], 'test', 10)
            launch.assert_not_called()

    def test_cancellation_not_swallowed(self):
        guard = Mock(side_effect=[None, InterruptedError('cancel')])
        with patch.object(background, 'process_observation', return_value={}):
            with self.assertRaises(InterruptedError):
                background.acquire_launch_pin(Mock(), FakeChild(timeout=True), self.expected, 20, guard)

    def test_frozen_nonempty_command_drift_still_rejected(self):
        result=self.acquire([helper_observation(), helper_observation()])
        with patch.object(background, 'process_observation', return_value=helper_observation(dict(helper_pin(), command_sha256='c'*64))):
            with self.assertRaises(background.BackgroundProcessError) as caught:
                background.owned_live(Mock(), FakeChild(timeout=True), result['pin'], 'after')
        self.assertEqual('LIVE_IDENTITY_CHANGED', caught.exception.reason)



if __name__ == "__main__":
    unittest.main()
