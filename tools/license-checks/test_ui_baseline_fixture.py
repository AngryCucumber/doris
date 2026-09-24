#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline boundary tests. No services, SQL, Node, browser or benchmark is started."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import ui_baseline_fixture as fixture


class UiBaselineBoundaryTest(unittest.TestCase):
    def test_child_diagnostics_retain_only_bounded_counts_hashes_and_fixed_categories(self):
        value = fixture.ChildDiagnostics()
        value.add("stderr", b"Timeout")
        value.add("stderr", b"Error: password=hunter2 Cookie=private; Authorization=token\n")
        value.add("stdout", b"arbitrary account secrets")
        receipt = value.receipt()
        self.assertEqual(["TimeoutError"], receipt["streams"]["stderr"]["recognized_error_categories"])
        self.assertFalse(receipt["raw_text_archived"])
        serialized = json.dumps(receipt)
        for secret in ("hunter2", "Cookie", "Authorization", "secrets"):
            self.assertNotIn(secret, serialized)
        value.add("stdout", b"x" * 1048576)
        self.assertFalse(value.within_bound())

    def cadence_evidence(self, role="admin", auth_all=True):
        schedule = fixture.refresh_cadence_plan(True, True)
        epoch, wall = 1000, 1700000000000
        browser = {"cell": {"role": role}, "network": [], "background": {
            "start_receipt": {"unix_millis": wall}, "end_receipt": {"unix_millis": wall + 301000}},
            "refresh_cadence": {"schedule": schedule, "epoch_ms": epoch, "status": "PASS", "events": [],
                                "background_window_verified": True}}
        for planned in schedule["events"]:
            due = epoch + planned["offset_ms"]
            denied = role != "admin" and (planned["target"] != "Playground" or auth_all)
            endpoint = {"Home": "hardware", "Playground": "databases", "Configuration": "configuration"}[planned["target"]]
            number = planned["sequence"] + 1
            action = f"cadence-{planned['sequence']}"
            browser["refresh_cadence"]["events"].append({**planned, "scheduled_ms": due,
                "deadline_ms": min(epoch + 300000, due + 20000), "status": "PASS", "started_ms": due,
                "finished_ms": due + 3, "queue_ms": 0, "e2e_ms": 3, "oracle_verified": True,
                "matched_network_ids": [number], "expected_endpoint": endpoint, "expected_original_denial": denied,
                "action_id": action, "started_unix_millis": wall + due, "finished_unix_millis": wall + due + 3})
            browser["network"].append({"id": number, "action": action, "endpoint": endpoint, "method": "GET",
                "http_status": 200, "content_type": "json", "failed": False, "business_success": not denied,
                "business_code": 401 if denied else 0, "original_permission_denial": denied,
                "start_ms": due + 1, "finished_ms": due + 2})
        return schedule, browser

    def test_refresh_cadence_requires_explicit_background_and_preserves_all_arrivals(self):
        self.assertIsNone(fixture.refresh_cadence_plan(False, False))
        with self.assertRaisesRegex(ValueError, "explicit constant"):
            fixture.refresh_cadence_plan(True, False)
        plan = fixture.refresh_cadence_plan(True, True)
        refreshes = [event for event in plan["events"] if event["kind"] == "refresh"]
        self.assertEqual(list(range(10000, 300000, 10000)), [event["offset_ms"] for event in refreshes])
        self.assertEqual([95000, 195000], [event["offset_ms"] for event in plan["events"] if event["kind"] == "navigate"])

    def test_refresh_audit_requires_matching_real_request_and_body_oracle(self):
        schedule, browser = self.cadence_evidence()
        result = fixture.audit_refresh_cadence(schedule, browser, True)
        self.assertEqual(31, result["verified_events"])
        self.assertEqual(29, result["successful_business_refreshes"])
        browser["network"][0].update(business_code=401, business_success=False, original_permission_denial=True)
        with self.assertRaisesRegex(ValueError, "contradicts"):
            fixture.audit_refresh_cadence(schedule, browser, True)

    def test_refresh_denial_oracle_is_not_successful_business_throughput(self):
        schedule, browser = self.cadence_evidence("reader", True)
        result = fixture.audit_refresh_cadence(schedule, browser, True)
        self.assertEqual("PASS", result["status"])
        self.assertEqual(31, result["original_permission_denials_verified"])
        self.assertEqual(0, result["successful_business_refreshes"])

    def test_refresh_missing_duplicate_or_unplanned_api_requests_cannot_pass(self):
        schedule, browser = self.cadence_evidence()
        browser["network"].append(dict(browser["network"][0], id=1000))
        with self.assertRaisesRegex(ValueError, "duplicate/background"):
            fixture.audit_refresh_cadence(schedule, browser, True)
        schedule, browser = self.cadence_evidence()
        browser["network"].pop(0)
        with self.assertRaisesRegex(ValueError, "missing or reused"):
            fixture.audit_refresh_cadence(schedule, browser, True)
        schedule, browser = self.cadence_evidence()
        browser["refresh_cadence"]["events"].pop()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            fixture.audit_refresh_cadence(schedule, browser, True)

    def test_refresh_arrivals_cannot_be_rebased_or_hide_queue_time(self):
        schedule, browser = self.cadence_evidence()
        browser["refresh_cadence"]["events"][1]["scheduled_ms"] += 10
        with self.assertRaisesRegex(ValueError, "rebased"):
            fixture.audit_refresh_cadence(schedule, browser, True)
        schedule, browser = self.cadence_evidence()
        browser["refresh_cadence"]["events"][1]["started_ms"] += 1
        with self.assertRaisesRegex(ValueError, "omitted queue"):
            fixture.audit_refresh_cadence(schedule, browser, True)

    def test_refresh_action_must_finish_inside_real_background_interval(self):
        schedule, browser = self.cadence_evidence()
        browser["background"]["end_receipt"]["unix_millis"] -= 15000
        with self.assertRaisesRegex(ValueError, "outside its action"):
            fixture.audit_refresh_cadence(schedule, browser, True)

    def test_refresh_audit_rejects_self_consistent_overlapping_actions(self):
        schedule, browser = self.cadence_evidence()
        event = next(item for item in browser["refresh_cadence"]["events"] if item["offset_ms"] == 90000)
        event["finished_ms"] = event["scheduled_ms"] + 15000
        event["finished_unix_millis"] = event["started_unix_millis"] + 15000
        event["e2e_ms"] = 15000
        # The 95-second navigation keeps its individually valid timestamps but now overlaps the 90-second refresh.
        with self.assertRaisesRegex(ValueError, "overlap"):
            fixture.audit_refresh_cadence(schedule, browser, True)

    def test_default_mode_cannot_dispatch_probe(self):
        with patch.object(fixture, "make_plan", return_value={"status": "PLANNED_NOT_RUN"}) as plan, \
                patch.object(fixture, "probe") as probe, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, fixture.main(["--output", "unused"]))
        plan.assert_called_once()
        probe.assert_not_called()

    def test_probe_requires_explicit_mode_and_plan(self):
        with patch.object(fixture, "probe", return_value={"status": "FUNCTIONAL_SUBSET_PASS"}) as probe, \
                patch.object(fixture, "make_plan") as plan, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, fixture.main(["--mode", "probe", "--plan", "unused"]))
        probe.assert_called_once()
        plan.assert_not_called()

    def test_failure_does_not_print_reflected_secret(self):
        output = io.StringIO()
        with patch.object(fixture, "make_plan", side_effect=RuntimeError("password=do-not-print")), \
                contextlib.redirect_stdout(output):
            self.assertEqual(2, fixture.main(["--output", "unused"]))
        self.assertNotIn("do-not-print", output.getvalue())
        self.assertEqual("UI_FIXTURE_INPUT_OR_RUNTIME_FAILURE", json.loads(output.getvalue())["error"])

    def test_relative_controller_command_is_a_live_benchmark(self):
        self.assertTrue(fixture.is_benchmark_command(fixture.ROOT,
            ["python3", "tools/license-checks/measure_license_primitives.py", "--mode", "run"]))
        self.assertTrue(fixture.is_benchmark_command(fixture.HERE,
            ["python3", "./run_performance_baseline.py"]))
        self.assertTrue(fixture.is_benchmark_command("/tmp", ["python3", str(fixture.HERE / "calibrate_read_capacity.py")]))
        self.assertTrue(fixture.is_benchmark_command(fixture.ROOT, ["java", "LicensePrimitiveCostProbe"]))

    def test_unrelated_same_basename_is_not_claimed_as_our_benchmark(self):
        self.assertFalse(fixture.is_benchmark_command("/another/project", ["python3", "measure_license_primitives.py"]))
        self.assertFalse(fixture.is_benchmark_command("/another/project", ["java", "LicensePrimitiveCostProbe"]))
        self.assertFalse(fixture.is_benchmark_command(fixture.ROOT, ["python3", "tools/license-checks/ui_baseline_fixture.py"]))

    def test_prefix_strips_once_and_preserves_query(self):
        for prefix in fixture.PREFIXES:
            self.assertEqual("/rest/v1/config/fe/?conf_item=http_port", fixture.upstream_path(
                prefix + "/rest/v1/config/fe/?conf_item=http_port", prefix))
        self.assertEqual("/proxy/fe/home", fixture.upstream_path("/proxy/fe/proxy/fe/home", "/proxy/fe"))

    def test_proxy_refuses_escape_and_ambiguous_paths(self):
        for path in ("/home", "/proxy/festival/home", "http://evil.invalid/home", "//evil.invalid/home",
                     "/proxy/fe/../home", "/proxy/fe/%2e%2e/home", "/proxy/fe/%2Fhome", "/proxy/fe/home#secret"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                fixture.upstream_path(path, "/proxy/fe")

    def test_redirect_is_fixed_to_actual_target_and_prefix(self):
        target = {"host": "127.0.0.1", "port": 28030}
        self.assertEqual("http://127.0.0.1:12345/proxy/fe/home", fixture.redirect_location(
            "http://127.0.0.1:28030/home", target, "/proxy/fe", "http://127.0.0.1:12345"))
        for value in ("http://127.0.0.1:8080/home", "http://evil.invalid:28030/home", "//evil.invalid/home",
                      "http://user:secret@127.0.0.1:28030/home", "relative-home"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                fixture.redirect_location(value, target, "", "http://127.0.0.1:12345")

    def account_file(self, directory):
        path = Path(directory) / "accounts.json"
        value = {"schema_version": 1, "accounts": [
            {"role": role, "username": "ui_" + role, "host": "%", "password_env": "MASSDB_UI_" + role.upper() + "_PASSWORD"}
            for role in fixture.ROLES]}
        path.write_text(json.dumps(value))
        return path, value

    def test_accounts_are_references_and_never_accept_literal_passwords(self):
        with tempfile.TemporaryDirectory() as directory:
            path, value = self.account_file(directory)
            self.assertEqual(3, len(fixture.account_config(path)))
            value["accounts"][0]["password"] = "secret"
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                fixture.account_config(path)

    def test_account_roles_cannot_be_emulated_with_same_account_or_admin_env(self):
        with tempfile.TemporaryDirectory() as directory:
            path, value = self.account_file(directory)
            value["accounts"][1]["username"] = value["accounts"][0]["username"]
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                fixture.account_config(path)
            path, value = self.account_file(directory)
            value["accounts"][1]["password_env"] = "HOME"
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                fixture.account_config(path)

    def test_grants_require_actual_admin_and_exclude_node_from_nonadmin(self):
        self.assertTrue(fixture.privilege_summary([{"GlobalPrivs": "Admin_priv"}], "admin")["global_admin"])
        for role, privileges in (("admin", "Select_priv"), ("reader", "Admin_priv"), ("reader", "Node_priv")):
            with self.subTest(role=role), self.assertRaises(ValueError):
                fixture.privilege_summary([{"GlobalPrivs": privileges}], role)
        result = fixture.privilege_summary([{"GlobalPrivs": "NULL", "Comment": "do-not-print", "Password": "Yes"}], "reader")
        self.assertNotIn("do-not-print", json.dumps(result))

    def test_invalid_resources_cannot_disable_deadlines_or_memory_bound(self):
        base = {"cpus": [0], "rss_limit_mib": 1024, "reserve_mib": 1024,
                "cell_timeout_seconds": 60, "whole_timeout_seconds": 300}
        fixture.validate_resources(base)
        for key, value in (("cpus", []), ("rss_limit_mib", 0), ("reserve_mib", 0),
                           ("cell_timeout_seconds", 0), ("whole_timeout_seconds", True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture.validate_resources(dict(base, **{key: value}))

    def test_owned_paths_cannot_escape_through_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            (root / ".build-records").mkdir(parents=True)
            outside = Path(directory) / "outside"
            outside.mkdir()
            (root / ".build-records" / "escape").symlink_to(outside)
            with patch.object(fixture, "ROOT", root):
                self.assertEqual(root / ".build-records/new", fixture.owned(root / ".build-records/new"))
                with self.assertRaises(ValueError):
                    fixture.owned(root / ".build-records/escape/new")

    def test_cleanup_never_signals_reused_or_unverified_pid(self):
        with patch.object(fixture, "same", return_value=False), patch.object(fixture.os, "kill") as kill:
            self.assertTrue(fixture.stop_owned([{"pid": 12345}]))
        kill.assert_not_called()

    def test_failed_process_wait_does_not_skip_proxy_or_profile_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "private-profile"
            profile.mkdir()
            (profile / "cookie-secret").write_text("secret")
            process = Mock()
            process.wait.side_effect = TimeoutError("private exception must not escape")
            proxy = Mock()
            proxy.close.return_value = True
            with patch.object(fixture, "stop_owned", return_value=False):
                result = fixture.cleanup_browser(process, [], profile, proxy)
            self.assertFalse(result["owned_children_exited"])
            self.assertTrue(result["private_profile_removed"])
            self.assertTrue(result["proxy_handlers_closed"])
            self.assertEqual([{"operation": "reap_node", "error_class": "TimeoutError"}], result["errors"])
            proxy.close.assert_called_once_with()

    def test_partial_fixture_never_claims_full_case_or_background(self):
        state = fixture.incomplete()
        for key in ("LP021_complete", "LP022_complete", "full_goal_complete"):
            self.assertIs(False, state[key])
        self.assertEqual("not_selected", state["background_query_write"])
        self.assertEqual("not_implemented", state["B_P2U_overlay"])


if __name__ == "__main__":
    unittest.main()
