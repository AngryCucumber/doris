#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import ui_concurrent_fixture as fixture


def evidence(count=1, role="admin", auth=False):
    cell = {"id": "cell-001", "target": "fe1", "prefix": "", "language": "en", "role": role, "contexts": count}
    preparation = {"concurrency_limit": 4, "local_cap_millis": 90000,
                   "created_contexts": count, "ready_count": count, "maximum_inflight": min(count, 4),
                   "records": [{"context": index, "status": "fulfilled", "ready_ms": 10} for index in range(count)]}
    result = {"cell": cell, "status": "PASS", "preparation": preparation, "contexts_alive_at_release": count,
              "contexts_alive_after_window": count, "contexts": [],
              "window": {"contexts": count, "status": "PASS", "epoch_ms": 1000, "ready": [], "receipts": []}}
    for index in range(count):
        record = {"context": index, "network": [], "context_closed": True, "server_session_logout_confirmed": True,
                  "blocked_requests": 0, "page_error_events": 0}
        receipt = {"context": index, "ready_ms": 10, "epoch_ms": 1000, "finished_ms": 301000,
                   "status": "PASS", "events": []}
        result["contexts"].append(record)
        result["window"]["receipts"].append(receipt)
        result["window"]["ready"].append({"context": index, "status": "fulfilled", "ready_ms": 10})
        for planned in fixture.base.refresh_cadence_plan(True, True)["events"]:
            start = 1000 + planned["offset_ms"]
            endpoint = {"Home": "hardware", "Playground": "databases", "Configuration": "configuration"}[planned["target"]]
            denied = role != "admin" and (planned["target"] != "Playground" or auth)
            identifier = planned["sequence"] + 1
            receipt["events"].append({**planned, "context": index, "status": "PASS", "scheduled_ms": start,
                "deadline_ms": min(301000, start + 20000), "started_ms": start, "finished_ms": start + 10,
                "queue_ms": 0, "e2e_ms": 10, "matched_network_ids": [identifier],
                "expected_endpoint": endpoint, "expected_original_denial": denied, "oracle_verified": True})
            record["network"].append({"id": identifier, "action": f"cadence-{planned['sequence']}", "endpoint": endpoint,
                "method": "GET", "http_status": 200, "content_type": "json", "business_code": 401 if denied else 0,
                "business_success": not denied, "original_permission_denial": denied, "failed": False,
                "start_ms": start + 1, "finished_ms": start + 9})
    return result, cell, {"auth_all": auth}


class PreparationAndRssEvidenceTest(unittest.TestCase):
    def pin(self, pid):
        return {"pid": pid, "start_ticks": pid * 100, "namespace": "net:[1]",
                "exe": "/test/owned", "command_sha256": "a" * 64}

    def test_preparation_requires_all_fifty_with_fixed_four_maximum(self):
        browser, _, _ = evidence(50)
        self.assertTrue(fixture.audit_preparation(browser["preparation"], 50))
        for change in ({"created_contexts": 49}, {"ready_count": 49}, {"maximum_inflight": 5},
                       {"local_cap_millis": 90001}, {"concurrency_limit": 5}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                fixture.audit_preparation(dict(browser["preparation"], **change), 50)
        missing = copy.deepcopy(browser["preparation"])
        missing["records"][49] = {"context": 49, "status": "NOT_STARTED"}
        with self.assertRaisesRegex(ValueError, "readiness"):
            fixture.audit_preparation(missing, 50)
        late = copy.deepcopy(browser["preparation"])
        late["records"][49]["ready_ms"] = 90000
        with self.assertRaisesRegex(ValueError, "readiness"):
            fixture.audit_preparation(late, 50)

    def test_preparation_receipt_has_its_own_small_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preparation.json"
            path.write_text('{"created_contexts":50}')
            self.assertEqual(50, fixture.read_preparation_report(path)["created_contexts"])
            path.write_bytes(b' ' * (fixture.MAX_PREPARATION_REPORT + 1))
            with self.assertRaisesRegex(ValueError, "exceeds bound"):
                fixture.read_preparation_report(path)

    def test_crossing_is_exactly_the_sampled_sum_without_a_second_observation(self):
        pins = [self.pin(1), self.pin(2)]
        def observed(pin, role):
            return {"pid": pin["pid"], "start_ticks": pin["start_ticks"], "role": role,
                    "status": "OBSERVED", "rss_bytes": 4 * 1024 ** 3}
        with mock.patch.object(fixture, "observe_rss", side_effect=observed) as sampler:
            snapshot = fixture.rss_snapshot([('node_chromium', pins)])
            with self.assertRaises(fixture.ResourceGuardError) as caught:
                fixture.enforce_rss_snapshot(snapshot, 6144)
            self.assertEqual(2, sampler.call_count)
        self.assertIs(caught.exception.snapshot, snapshot)
        self.assertEqual('CLIENT_RSS_LIMIT_EXCEEDED', caught.exception.reason)
        self.assertEqual(8 * 1024 ** 3, snapshot['observed_rss_sum_bytes'])
        self.assertEqual(snapshot['observed_rss_sum_bytes'], sum(item['rss_bytes'] for item in snapshot['processes']))
        self.assertIn('not_PSS', snapshot['measurement'])
        self.assertFalse(snapshot['simultaneous_atomic_snapshot'])

    def test_same_process_in_two_roles_is_not_counted_twice(self):
        pin = self.pin(1)
        observed = {"pid": 1, "start_ticks": 100, "role": 'node_chromium',
                    "status": 'OBSERVED', "rss_bytes": 1234}
        with mock.patch.object(fixture, 'observe_rss', return_value=observed) as sampler:
            snapshot = fixture.rss_snapshot([('node_chromium', [dict(pin, state='R')]),
                                             ('background_jvm', [dict(pin, state='S')])])
        self.assertEqual(sampler.call_count, 1)
        self.assertEqual(snapshot['observed_rss_sum_bytes'], 1234)
        self.assertEqual(snapshot['processes'][0]['additional_roles'], ['background_jvm'])

    def test_pid_lifetime_ambiguity_is_rejected_without_mixing_processes(self):
        pin = self.pin(1)
        with mock.patch.object(fixture, 'observe_rss', return_value={"pid": 1, "start_ticks": 100,
                "status": 'OBSERVED', "rss_bytes": 10}):
            with self.assertRaisesRegex(ValueError, 'Ambiguous process identity'):
                fixture.rss_snapshot([('node', [pin]), ('other', [dict(pin, start_ticks=101)])])

    def test_missing_rss_stays_null_and_all_missing_cannot_be_zero_pass(self):
        with mock.patch.object(fixture, 'observe_rss', return_value={"pid": 1, "start_ticks": 100,
                "status": 'UNAVAILABLE_OR_IDENTITY_CHANGED', "rss_bytes": None}):
            snapshot = fixture.rss_snapshot([('node', [self.pin(1)])])
        self.assertIsNone(snapshot['processes'][0]['rss_bytes'])
        self.assertIsNone(snapshot['observed_rss_sum_bytes'])
        self.assertEqual(1, snapshot['unavailable_processes'])
        with self.assertRaises(fixture.ResourceGuardError) as caught:
            fixture.enforce_rss_snapshot(snapshot, 6144)
        self.assertEqual('RSS_OBSERVATION_UNAVAILABLE', caught.exception.reason)

    def test_rss_guard_keeps_exact_original_limit_without_rounding(self):
        snapshot = {'observed_rss_sum_bytes': 6144 * 1024 ** 2}
        self.assertEqual(6144, fixture.enforce_rss_snapshot(snapshot, 6144))
        snapshot['observed_rss_sum_bytes'] += 1
        with self.assertRaises(fixture.ResourceGuardError):
            fixture.enforce_rss_snapshot(snapshot, 6144)

    def test_crossing_archive_write_error_preserves_reason_and_exact_frame(self):
        snapshot = {'observed_rss_sum_bytes': 7000 * 1024 ** 2, 'processes': []}
        error = fixture.ResourceGuardError('CLIENT_RSS_LIMIT_EXCEEDED', snapshot)
        with mock.patch.object(fixture.base, 'save', side_effect=OSError('private filesystem detail')) as save, \
                mock.patch.object(fixture, 'observe_rss') as sampler:
            result = fixture.persist_resource_crossing(Path('/owned'), error, 6144)
        self.assertEqual(result, 'OSError')
        sampler.assert_not_called()
        self.assertEqual(error.reason, 'CLIENT_RSS_LIMIT_EXCEEDED')
        self.assertIs(save.call_args.args[1]['snapshot'], snapshot)


class ConcurrentUiTest(unittest.TestCase):
    def test_background_start_keeps_structured_first_failure_after_finish(self):
        with tempfile.TemporaryDirectory(dir=fixture.base.ROOT / '.build-records') as directory:
            value = {"cells": fixture.cells('single'), "source_sha256": {}, "output": directory,
                     "stop_on_failed_window": True}
            background = mock.Mock()
            background.start.side_effect = fixture.background_module.BackgroundProcessError(
                'LIVE_IDENTITY_CHANGED', 'compile_check', {'mismatched_fields': ['exe']})
            background.finish.return_value = {'status': 'FAIL', 'cleanup_confirmed': False}
            report = {'windows': []}
            with mock.patch.object(fixture.background_module, 'Background', return_value=background), \
                    mock.patch.object(fixture, 'run_window') as run:
                with self.assertRaisesRegex(ValueError, 'cleanup unconfirmed'):
                    fixture.execute_windows(value, SimpleNamespace(targets=[{'name': 'fe1'}]),
                        [{'role': role} for role in fixture.base.ROLES], {'fe1': {}},
                        time.monotonic() + 10, True, report, Path(directory))
            run.assert_not_called()
            background.finish.assert_called_once()
            record = report['windows'][0]
            self.assertEqual('LIVE_IDENTITY_CHANGED', record['background_failure']['reason'])
            self.assertEqual('compile_check', record['background_failure']['process_stage'])
            self.assertEqual(54, len(value['cells']))
            self.assertFalse(record['physical_cleanup_confirmed'])

    def test_no_background_cancelled_attempt_is_recorded_without_inventing_cleanup(self):
        with tempfile.TemporaryDirectory(dir=fixture.base.ROOT / ".build-records") as directory:
            value = {"cells": fixture.cells("single"), "source_sha256": {}, "output": directory,
                     "stop_on_failed_window": True}
            report, output = {"windows": []}, Path(directory)
            with mock.patch.object(fixture, "run_window", side_effect=InterruptedError) as run:
                with self.assertRaisesRegex(ValueError, "cleanup unconfirmed"):
                    fixture.execute_windows(value, SimpleNamespace(targets=[{"name": "fe1"}]),
                        [{"role": role} for role in fixture.base.ROLES], {"fe1": {}},
                        time.monotonic() + 10, None, report, output)
            run.assert_called_once()
            stored = fixture.base.read_json(output / 'report.json')["windows"]
            self.assertEqual(stored[0]['failure_class'], 'InterruptedError')
            self.assertFalse(stored[0]['physical_cleanup_confirmed'])
            attempted = {record['cell']['id'] for record in stored}
            remaining = [cell['id'] for cell in value['cells'] if cell['id'] not in attempted]
            self.assertEqual(len(remaining), 53)
            self.assertNotIn('cell-001', remaining)

    def test_finish_exception_is_persisted_and_refuses_next_window(self):
        with tempfile.TemporaryDirectory(dir=fixture.base.ROOT / ".build-records") as directory:
            value = {"cells": fixture.cells("single"), "source_sha256": {}, "output": directory,
                     "stop_on_failed_window": True}
            report, output = {"windows": []}, Path(directory)
            background = mock.Mock()
            background.finish.side_effect = RuntimeError('synthetic cleanup failure')
            with mock.patch.object(fixture.background_module, "Background", return_value=background), \
                    mock.patch.object(fixture, "run_window", return_value={"cell": value["cells"][0],
                        "status": "PASS", "physical_cleanup_confirmed": True}) as run:
                with self.assertRaisesRegex(ValueError, "cleanup unconfirmed"):
                    fixture.execute_windows(value, SimpleNamespace(targets=[{"name": "fe1"}]),
                        [{"role": role} for role in fixture.base.ROLES], {"fe1": {}},
                        time.monotonic() + 10, True, report, output)
            run.assert_called_once()
            stored = fixture.base.read_json(output / 'report.json')["windows"]
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0]['background']['failure_class'], 'RuntimeError')
            self.assertFalse(stored[0]['background']['cleanup_confirmed'])

    def test_matrix_stop_follows_background_finish_persistence_and_cleanup(self):
        for background_status, browser_status, cleanup, enabled, expected_count in (
                ("PASS", "PASS", True, True, 54), ("FAIL", "PASS", True, True, 1),
                ("PASS", "FAIL", True, True, 1), ("FAIL", "PASS", True, False, 54),
                ("FAIL", "PASS", False, True, 1)):
            with self.subTest(background=background_status, browser=browser_status, cleanup=cleanup, enabled=enabled), \
                    tempfile.TemporaryDirectory(dir=fixture.base.ROOT / ".build-records") as directory:
                output = Path(directory)
                value = {"cells": fixture.cells("single"), "source_sha256": {}, "output": directory,
                         "stop_on_failed_window": enabled}
                report = {"windows": []}
                events = []
                def run(_value, cell, *_args):
                    events.append((cell["id"], "run"))
                    return {"cell": cell, "status": browser_status, "physical_cleanup_confirmed": True}
                def make_background(_api, _value, _guard, _target, cell, *_args):
                    def finish():
                        events.append((cell["id"], "finish"))
                        return {"status": background_status, "cleanup_confirmed": cleanup}
                    return SimpleNamespace(start=lambda: events.append((cell["id"], "start")), finish=finish)
                accounts = [{"role": role} for role in fixture.base.ROLES]
                guard = SimpleNamespace(targets=[{"name": "fe1"}])
                with mock.patch.object(fixture, "run_window", side_effect=run), \
                        mock.patch.object(fixture.background_module, "Background", side_effect=make_background):
                    call = lambda: fixture.execute_windows(value, guard, accounts, {"fe1": {}},
                        time.monotonic() + 10, True, report, output)
                    if cleanup:
                        call()
                    else:
                        with self.assertRaisesRegex(ValueError, "cleanup unconfirmed"):
                            call()
                self.assertEqual(len(value["cells"]), 54)
                self.assertEqual(len(report["windows"]), expected_count)
                self.assertEqual(len(fixture.base.read_json(output / "report.json")["windows"]), expected_count)
                self.assertEqual(events, [(f"cell-{index:03d}", phase) for index in range(1, expected_count + 1)
                                          for phase in ("start", "run", "finish")])
                if expected_count == 1:
                    self.assertEqual(report["stop_reason"]["code"],
                                     "FAILED_WINDOW_POLICY" if cleanup else "WINDOW_CLEANUP_UNCONFIRMED")

    def test_frozen_stop_policy_keeps_success_and_legacy_failure_behavior(self):
        for enabled in (False, True):
            self.assertIsNone(fixture.window_stop_reason({"cell": {"id": "cell-001"}, "status": "PASS",
                                                         "physical_cleanup_confirmed": True}, enabled))
        record = {"cell": {"id": "cell-002"}, "status": "FAIL", "physical_cleanup_confirmed": True}
        self.assertIsNone(fixture.window_stop_reason(record, False))
        self.assertEqual(fixture.window_stop_reason(record, True),
                         {"code": "FAILED_WINDOW_POLICY", "cell": "cell-002"})

    def test_background_functional_failure_stops_only_after_confirmed_cleanup(self):
        record = {"cell": {"id": "cell-003"}, "status": "FAIL", "physical_cleanup_confirmed": True,
                  "background": {"status": "FAIL", "cleanup_confirmed": True}}
        self.assertEqual(fixture.window_stop_reason(record, True)["code"], "FAILED_WINDOW_POLICY")
        for enabled in (False, True):
            record["background"]["cleanup_confirmed"] = False
            self.assertEqual(fixture.window_stop_reason(record, enabled)["code"], "WINDOW_CLEANUP_UNCONFIRMED")

    def test_cleanup_failure_overrides_success_or_disabled_policy(self):
        for enabled in (False, True):
            for record in (None, {}, {"cell": {"id": "cell-001"}, "status": "PASS",
                                      "physical_cleanup_confirmed": False}):
                self.assertEqual(fixture.window_stop_reason(record, enabled)["code"], "WINDOW_CLEANUP_UNCONFIRMED")

    def test_failed_physical_cleanup_stops_next_window_even_without_background(self):
        fixture.require_cleanup_before_next_window({"physical_cleanup_confirmed": True})
        for record in ({}, {"physical_cleanup_confirmed": False},
                       {"physical_cleanup_confirmed": False, "background": {"cleanup_confirmed": True}},
                       {"physical_cleanup_confirmed": True, "background": {"cleanup_confirmed": False}}):
            with self.assertRaisesRegex(ValueError, "next window refused"):
                fixture.require_cleanup_before_next_window(record)

    def test_browser_or_proxy_cleanup_failure_is_aggregated_and_blocks_matrix(self):
        real_cleanup = fixture.base.cleanup_browser
        for failed_key in ("owned_children_exited", "proxy_handlers_closed", "private_profile_removed"):
            with self.subTest(failed_key=failed_key), tempfile.TemporaryDirectory(
                    dir=fixture.base.ROOT / ".build-records") as directory:
                def cleanup(*args):
                    value = real_cleanup(*args)
                    value[failed_key] = False
                    return value
                plan = {"output": directory, "resources": {"cell_timeout_seconds": 420}}
                cell = {"id": "cell-001", "contexts": 1, "prefix": ""}
                with mock.patch.object(fixture, "open_proxy", side_effect=RuntimeError("synthetic failure")), \
                        mock.patch.object(fixture.base, "cleanup_browser", side_effect=cleanup):
                    result = fixture.run_window(plan, cell, {}, {}, {}, None, time.monotonic() + 420, None)
                self.assertFalse(result["physical_cleanup_confirmed"])
                with self.assertRaisesRegex(ValueError, "next window refused"):
                    fixture.require_cleanup_before_next_window(result)

    def test_real_cjs_background_receipt_satisfies_existing_python_consumer_and_missing_fields_fail(self):
        node = os.environ.get("MASSDB_UI_TEST_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Set MASSDB_UI_TEST_NODE for the offline JS/Python contract test")
        module = fixture.base.HERE / "LicenseUiConcurrentFixture.cjs"
        program = """const f = require(process.argv[1]);
const e = { token: 'a'.repeat(32), start_receipt: { unix_millis: 1000 } };
f.recordBackgroundAction(e, 11500);
f.recordBackgroundEnd(e, { token: e.token, unix_millis: 301500, scheduled_window_complete: true }, 301510);
process.stdout.write(JSON.stringify(e));"""
        run = subprocess.run([node, "-e", program, str(module)], capture_output=True, timeout=10, check=True)
        producer = json.loads(run.stdout)
        background = fixture.background_module
        for missing in (None, "token", "browser_actions_started_unix_millis", "browser_context_held_until_unix_millis"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory(
                    dir=fixture.base.ROOT / ".build-records") as directory:
                root = Path(directory)
                output = root / "cell-001-background"
                output.mkdir()
                (root / "cell-001").mkdir()
                receipt = dict(producer)
                if missing:
                    del receipt[missing]
                # 50 contexts can exceed the original single-context 2 MiB JSON cap.
                fixture.base.save(root / "cell-001/browser.json", {"background": receipt, "padding": "x" * 2097152})
                fixture.base.save(output / "window-end.json", {})
                fixture.base.save(output / "summary.json", {"status": "PASS", "cleanup_confirmed": True})
                consumer = background.Background.__new__(background.Background)
                consumer.output, consumer.finished = output, False
                consumer.profile = {"verify_timeout_seconds": 1, "drain_seconds": 1, "cleanup_timeout_seconds": 1}
                consumer.whole_deadline = time.monotonic() + 10
                consumer.process, consumer.pin = None, None
                consumer.api = fixture.BackgroundApi(root / "cell-001/browser.json")
                consumer.guard, consumer.frozen = mock.Mock(), {}
                consumer.classpath, consumer.token, consumer.peak, consumer.samples = None, 'a' * 32, 0, 0
                consumer.config = {"cell": "cell-001", "table": "synthetic"}
                consumer.plan = {"output": str(root)}
                consumer._identity_receipt = mock.Mock(return_value=True)
                with mock.patch.object(background, "reap_owned", return_value=True), \
                        mock.patch.object(background, "verify_frozen"), \
                        mock.patch.object(background, "audit_receipts", return_value={}), \
                        mock.patch.object(background, "audit_full_models", return_value={}):
                    result = consumer.finish()
                self.assertEqual(result["browser_interval_overlap"], missing is None)
                self.assertEqual(result["status"], "PASS" if missing is None else "FAIL")

    def test_concurrent_report_bound_is_enforced_and_does_not_expand_other_input_bounds(self):
        with tempfile.TemporaryDirectory(dir=fixture.base.ROOT / ".build-records") as directory:
            report = Path(directory) / "browser.json"
            other = Path(directory) / "config.json"
            report.write_text(json.dumps({"padding": "x" * 2097152}))
            other.write_bytes(report.read_bytes())
            api = fixture.BackgroundApi(report)
            self.assertEqual(len(api.read_json(report)["padding"]), 2097152)
            with self.assertRaisesRegex(ValueError, "JSON input exceeds"):
                api.read_json(other)
            with mock.patch.object(fixture, "MAX_BROWSER_REPORT", 64):
                with self.assertRaisesRegex(ValueError, "Browser report exceeds"):
                    api.read_json(report)


    def test_complete_single_and_multi_topologies_keep_original_context_counts(self):
        single, multi = fixture.cells("single"), fixture.cells("multi")
        self.assertEqual(len(single), 54)
        self.assertEqual(len(multi), 108)
        self.assertEqual({row["contexts"] for row in single}, {1, 10, 50})
        self.assertEqual({row["contexts"] for row in multi}, {1, 10})
        self.assertEqual({row["target"] for row in multi}, {"fe1", "fe2", "fe3"})
        self.assertEqual(len({row["id"] for row in multi}), 108)

    def test_all_contexts_require_independent_complete_api_evidence(self):
        for count in (1, 10, 50):
            result = fixture.audit_browser(*evidence(count))
            self.assertEqual(result["successful_page_operations"], 31 * count)
            self.assertFalse(result["AA_qualified"])
            self.assertIsNone(result["page_p99"])

    def test_nonadmin_denials_never_enter_successful_operation_samples(self):
        result = fixture.audit_browser(*evidence(10, "reader", False))
        self.assertEqual(result["original_permission_denials"], 200)
        self.assertEqual(result["successful_page_operations"], 110)
        self.assertEqual(result["page_samples"]["Home:refresh"]["successful"], [])

    def test_auth_all_denial_preserves_all_requests_without_success_throughput(self):
        result = fixture.audit_browser(*evidence(10, "unprivileged", True))
        self.assertEqual(result["successful_page_operations"], 0)
        self.assertEqual(result["original_permission_denials"], 310)

    def test_serial_windows_cannot_be_presented_as_concurrent(self):
        browser, cell, expected = evidence(10)
        browser["window"]["receipts"][1]["epoch_ms"] += 300000
        with self.assertRaises(ValueError):
            fixture.audit_browser(browser, cell, expected)

    def test_missing_context_or_early_closed_context_fails(self):
        for mutate in (lambda value: value["contexts"].pop(),
                       lambda value: value.update(contexts_alive_after_window=9)):
            browser, cell, expected = evidence(10)
            mutate(browser)
            with self.assertRaises(ValueError):
                fixture.audit_browser(browser, cell, expected)

    def test_late_ready_context_cannot_join_after_release(self):
        browser, cell, expected = evidence(10)
        browser["window"]["ready"][5]["ready_ms"] = 1001
        with self.assertRaises(ValueError):
            fixture.audit_browser(browser, cell, expected)

    def test_hidden_queue_and_deadline_overrun_are_rejected(self):
        for mutate in (lambda item: item.update(queue_ms=5), lambda item: item.update(finished_ms=item["deadline_ms"] + 1)):
            browser, cell, expected = evidence()
            mutate(browser["window"]["receipts"][0]["events"][0])
            with self.assertRaises(ValueError):
                fixture.audit_browser(browser, cell, expected)

    def test_request_failure_mime_or_success_body_cannot_be_substituted(self):
        for change in ({"http_status": 503}, {"failed": True}, {"content_type": "html"}, {"business_code": 401}):
            browser, cell, expected = evidence()
            browser["contexts"][0]["network"][0].update(change)
            with self.assertRaises(ValueError):
                fixture.audit_browser(browser, cell, expected)

    def test_reused_or_duplicate_network_request_is_rejected(self):
        browser, cell, expected = evidence()
        browser["contexts"][0]["network"].append(copy.deepcopy(browser["contexts"][0]["network"][0]))
        with self.assertRaises(ValueError):
            fixture.audit_browser(browser, cell, expected)

    def test_context_cleanup_and_logout_are_required(self):
        for key in ("context_closed", "server_session_logout_confirmed"):
            browser, cell, expected = evidence()
            browser["contexts"][0][key] = False
            with self.assertRaises(ValueError):
                fixture.audit_browser(browser, cell, expected)

    def test_config_pipe_handles_partial_nonblocking_writes_and_closes(self):
        read_fd, write_fd = os.pipe()
        process = SimpleNamespace(stdin=os.fdopen(write_fd, "wb"), poll=lambda: None)
        received = bytearray()
        def drain():
            try:
                while chunk := os.read(read_fd, 4096):
                    received.extend(chunk)
            finally:
                os.close(read_fd)
        thread = threading.Thread(target=drain)
        thread.start()
        payload = b"synthetic-no-credentials\n" * 10000
        fixture.write_config(process, payload, time.monotonic() + 2, lambda: None)
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(received, payload)
        self.assertTrue(process.stdin.closed)

    def test_unread_config_pipe_times_out_and_closes(self):
        read_fd, write_fd = os.pipe()
        process = SimpleNamespace(stdin=os.fdopen(write_fd, "wb"), poll=lambda: None)
        try:
            with self.assertRaises(ValueError):
                fixture.write_config(process, b"x" * 100000, time.monotonic() + 0.01, lambda: None)
            self.assertTrue(process.stdin.closed)
        finally:
            os.close(read_fd)

    def test_config_bound_rejects_before_writing(self):
        with self.assertRaises(ValueError):
            fixture.write_config(None, b"x" * 2097153, time.monotonic() + 2, lambda: None)

    def test_proxy_thread_start_failure_closes_socket_without_waiting_on_shutdown(self):
        proxy = mock.Mock()
        proxy.__enter__ = mock.Mock(side_effect=RuntimeError("start failed"))
        with mock.patch.object(fixture.base, "PrefixProxy", return_value=proxy):
            with self.assertRaises(RuntimeError):
                fixture.open_proxy({}, "", None, time.monotonic() + 1)
        proxy.server.server_close.assert_called_once()
        proxy.server.shutdown.assert_not_called()

    def test_first_proxy_failure_still_removes_new_private_profile(self):
        with tempfile.TemporaryDirectory(dir=fixture.base.ROOT / ".build-records") as directory:
            value = {"output": directory, "resources": {"cell_timeout_seconds": 420}}
            cell = {"id": "cell-001", "contexts": 1, "prefix": ""}
            with mock.patch.object(fixture, "open_proxy", side_effect=RuntimeError("synthetic failure")):
                result = fixture.run_window(value, cell, {}, {}, {}, None, time.monotonic() + 420, None)
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(result["cleanup"][0]["private_profile_removed"])
            self.assertFalse((Path(directory) / "cell-001/private-profile").exists())


if __name__ == "__main__":
    unittest.main()
