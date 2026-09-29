#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline scheduling/rejection oracles. Synthetic windows never establish real capacity."""

import copy
import hashlib
import json
import os
import signal
import subprocess
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

import p4_protocol_capacity as capacity
import test_flight_performance
import test_external_scanner_performance
import test_external_read_performance


def save(path, value):
    path.write_text(json.dumps(value) + "\n")
    return capacity.ref(path)


def fixture(root, name="flight", mode="confirm", pairs=5):
    source = test_flight_performance if name == "flight" else test_external_scanner_performance
    source.fixture(root)
    old = capacity.read(root / "raw/p4-launch.json")
    base = {key: value for key, value in old.items() if key not in capacity.RESERVED}
    profile = capacity.read(root / "profile.json")
    profile.update(qualification="formal", rate=30, warmup_seconds=180, duration_seconds=600, max_requests=25000)
    return {"schema_version": 1, "run_id": "offline-synthetic", "protocol": name, "mode": mode,
            "cell_id": ("G2" if name == "flight" else "G3") + "-offline", "rates": [30, 30.29], "pairs": pairs,
            "slo": {"p99_ms": 1000, "max_drain_seconds": 1, "max_error_rate": 0, "max_timeout_rate": 0},
            "profile_template": save(root / "formal-profile.json", profile),
            "context_template": save(root / "context-template.json", base), "runtime": old["runtime"],
            "deadline_seconds": 100000,
            "observer": {"cluster_record": save(root / "cluster.json", {"synthetic": True}), "client_cpus": [4], "server_cpus": [6, 7],
                "interval_seconds": 1, "http_timeout_seconds": 1, "max_gap_seconds": 3, "start_timeout_seconds": 15,
                "finish_timeout_seconds": 15, "max_log_bytes": 64 * 1024**2, "client_sample_seconds": .5, "client_max_gap_seconds": 2,
                "max_samples": 102001, "min_free_disk_bytes": 1024**2,
                "rss_limits_bytes": {role: 1024**3 for role in ("fe", "be", "observer", "client")}}}


def audited_windows(root, frozen, rate_index=0, pairs=None, epoch=10**12):
    """Independent closed-form metrics; no protocol runner or capacity formula is called."""
    selected = frozen["profiles"][rate_index]; p = selected["profile"]
    result = []
    for slot in range(2 * (pairs or frozen["template"]["pairs"])):
        warm = epoch + slot * (p["warmup_seconds"] + p["duration_seconds"] + 1) * 10**9
        start = warm + p["warmup_seconds"] * 10**9
        count = selected["request_count"]
        raw = root / ("raw-%d-%d.txt" % (rate_index, slot)); raw.write_text("synthetic independent terminal receipt")
        window = {"window_id": "r%d-w%d" % (rate_index, slot), "pair_id": slot // 2, "variant": "A", "boot_id": frozen["boot_id"],
            "identity": frozen["baseline_identity"], "workload_sha256": frozen["business_workload_sha256"],
            "arrival_schedule_sha256": selected["arrival_schedule_sha256"], "rate": p["rate"], "warmup_seconds": p["warmup_seconds"],
            "duration_seconds": p["duration_seconds"], "warmup_start_monotonic_ns": warm, "warmup_end_monotonic_ns": start,
            "start_monotonic_ns": start, "end_monotonic_ns": start + p["duration_seconds"] * 10**9,
            "monotonic_clock_domain": "bounded_jvm_mapping", "monotonic_mapping_uncertainty_ns": 10,
            "monotonic_mapping": {"offset_lower_ns": 0, "estimated_offset_ns": 10, "offset_upper_ns": 20},
            "effective_duration_seconds": p["duration_seconds"], "scheduled_requests": count, "observed_requests": count,
            "successful_requests": count, "error_count": 0, "timeout_count": 0, "retry_count": 0,
            "oracle_verified": True, "cleanup_verified": True, "cpu_boundary_verified": True,
            "metrics": {"p95_ms": 10, "p99_ms": 20, "success_qps": count / p["duration_seconds"],
                        "fe_cpu_seconds_per_success": .001, "be_cpu_seconds_per_success": .002}}
        result.append({"status": "VERIFIED", "formal_shape_met": True, "window": window,
            "auditor": frozen["bindings"]["protocol_runner"], "dependency_bindings": [], "raw_artifacts": [capacity.ref(raw)]})
    return result


def external_fixture(root, mode="confirm", rates=None):
    """Synthetic full source/schema receipts; no file is a real DB/JVM executable."""
    module = capacity.protocol("external_read")
    test_external_read_performance.fixture(root)
    old = capacity.read(root / "raw/p4-launch.json")
    base = {key: value for key, value in old.items() if key not in capacity.RESERVED}
    source = capacity.read(base["external_source"]["path"])
    state = capacity.read(source["state"]["path"]); state["container_id"] = "e" * 64
    source["state"] = save(Path(source["state"]["path"]), state)
    base["external_source"] = save(Path(base["external_source"]["path"]), source)
    for name in ("environment", "fixture"):
        path = Path(base["bindings"][name]["path"]); value = capacity.read(path)
        value["external_source"] = base["external_source"]
        base["bindings"][name] = save(path, value); base["identity"][name + "_sha256"] = base["bindings"][name]["sha256"]
    profile = capacity.read(root / "profile.json")
    profile.update(qualification="formal" if mode == "confirm" else "diagnostic", rate=30,
                   warmup_seconds=180 if mode == "confirm" else 2, duration_seconds=600 if mode == "confirm" else 3, max_requests=25000)
    spec = {"schema_version": 1, "run_id": "synthetic-external", "protocol": "external_read", "mode": mode,
            "cell_id": "G2-external-synthetic", "rates": rates or [30, 30.29], "pairs": 5 if mode == "confirm" else 1,
            "slo": {"p99_ms": 1000, "max_drain_seconds": 1, "max_error_rate": 0, "max_timeout_rate": 0},
            "profile_template": save(root / "formal-profile.json", profile),
            "context_template": save(root / "context-template.json", base), "runtime": old["runtime"],
            "deadline_seconds": 100000, "arrival_schedules": [],
            "observer": {"cluster_record": save(root / "cluster.json", {"synthetic": True}), "client_cpus": [4], "server_cpus": [6, 7],
                "interval_seconds": 1, "http_timeout_seconds": 1, "max_gap_seconds": 3, "start_timeout_seconds": 15,
                "finish_timeout_seconds": 15, "max_log_bytes": 64 * 1024**2, "client_sample_seconds": .5, "client_max_gap_seconds": 2,
                "max_samples": 102001, "min_free_disk_bytes": 1024**2,
                "rss_limits_bytes": {role: 1024**3 for role in ("fe", "be", "observer", "client")}}}
    runtime = capacity.read(old["runtime"]["path"])
    for index, rate in enumerate(spec["rates"]):
        directory = root / ("declared-%d" % index); directory.mkdir(); (directory / "plan").mkdir()
        value = {**profile, "rate": rate}; profile_ref = save(directory / "profile.json", value)
        command = capacity.external_plan_command(runtime, profile_ref["path"], directory / "plan")
        receipt = {"schema_version": 1, "profile": profile_ref, "runtime": old["runtime"], "command": command,
            "pin": {"pid": 987, "start_ticks": 123, "exe": str((Path(runtime["java_home"]) / "bin/java").resolve()),
                    "command_sha256": hashlib.sha256(b"\0".join(os.fsencode(item) for item in command) + b"\0").hexdigest()},
            "boot_id": capacity.stats.boot_id(), "started_monotonic_ns": 1, "completed_monotonic_ns": 2,
            "exit_code": 0, "parent_wait_complete": True, "remaining_live_pids": [], "errors": [],
            "evidence_scope": "SYNTHETIC_TEST_NEVER_ACTUAL_PERFORMANCE"}
        for phase, planned in module.plan(value).items():
            path = directory / "plan" / (phase + "-arrivals.tsv"); path.write_text(planned["tsv"])
            receipt[phase] = capacity.ref(path)
        receipt["metadata"] = save(directory / "plan/plan.json", {"network_clients_created": 0, "formal_performance_pass": False})
        spec["arrival_schedules"].append(save(directory / "completion.json", receipt))
    return spec


class ExternalCapacityTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="external-capacity-offline-", dir=capacity.stats.ROOT / ".build-records")
        self.addCleanup(self.temporary.cleanup); self.root = Path(self.temporary.name)

    def test_registry_retains_catalog_and_s3_as_separate_full_read_business_models(self):
        module = capacity.protocol("external_read"); value = test_external_read_performance.profile()
        bindings = []
        for kind, case in (("catalog", "LP-005"), ("s3_tvf", "LP-008")):
            profile = {**value, "source_kind": kind}; module.plan(profile)
            binding = module.business_binding(profile); bindings.append(binding["sha256"])
            self.assertEqual(binding["fields"]["case_id"], case)
            self.assertEqual(binding["fields"]["connection_mode"], "reuse_jdbc_streaming")
            self.assertEqual(binding["fields"]["rows_per_operation"], 1000000)
        self.assertNotEqual(*bindings)

    def test_existing_external_schema_runtime_private_query_and_raw_source_are_frozen(self):
        spec = external_fixture(self.root)
        with patch.object(capacity.subprocess, "Popen", side_effect=AssertionError("planning launched a process")):
            frozen = capacity.prepare_plan(spec)
        self.assertEqual(frozen["current_group"], "G2")
        self.assertEqual(frozen["template"]["connection_mode"], "reuse_jdbc_streaming")
        base = capacity.read(spec["context_template"]["path"])
        self.assertEqual(frozen["bindings"]["private_query"], base["private_query"])
        self.assertEqual(frozen["bindings"]["external_source"], base["external_source"])
        self.assertTrue(all(item["request_count"] >= 10000 for item in frozen["profiles"]))
        self.assertTrue(any(key.startswith("runtime_dependency_") for key in frozen["bindings"]))
        self.assertTrue(any(key.startswith("external_source_") for key in frozen["bindings"]))
        self.assertFalse(frozen["formal_performance_pass"])

    def test_actual_java_one_ns_difference_is_accepted_but_actual_hash_is_frozen(self):
        spec = external_fixture(self.root); receipt = capacity.read(spec["arrival_schedules"][0]["path"])
        path = Path(receipt["measurement"]["path"]); lines = path.read_text().splitlines()
        index, offset = lines[1].split("\t"); lines[1] = index + "\t" + str(int(offset) + 1)
        path.write_text("\n".join(lines) + "\n"); receipt["measurement"] = capacity.ref(path)
        spec["arrival_schedules"][0] = save(Path(spec["arrival_schedules"][0]["path"]), receipt)
        frozen = capacity.prepare_plan(spec); first = frozen["profiles"][0]
        self.assertEqual(first["arrival_schedule_sha256"], receipt["measurement"]["sha256"])
        self.assertNotEqual(first["arrival_schedule_sha256"], first["reference_schedule_sha256"])
        # The frozen raw bytes cannot be exchanged for the near-equal Python reference afterward.
        path.write_text(capacity.protocol("external_read").plan(first["profile"])["measurement"]["tsv"])
        with self.assertRaises(ValueError): capacity.check_bindings(frozen)

    def test_missing_actual_plan_wrong_jvm_wait_or_profile_never_qualifies(self):
        spec = external_fixture(self.root)
        for change in ("missing", "wait", "runtime", "profile", "command", "network", "two_ns", "count"):
            with self.subTest(change=change):
                local = copy.deepcopy(spec); ref = local["arrival_schedules"][0]; original = Path(ref["path"]).read_bytes()
                receipt = json.loads(original); changed_path = None; old_bytes = None
                try:
                    if change == "missing": local["arrival_schedules"] = []
                    elif change == "wait": receipt["parent_wait_complete"] = False
                    elif change == "runtime": receipt["runtime"] = local["profile_template"]
                    elif change == "profile": receipt["profile"] = local["context_template"]
                    elif change == "command": receipt["command"][-3] = "--execute"
                    elif change == "network":
                        changed_path = Path(receipt["metadata"]["path"]); old_bytes = changed_path.read_bytes()
                        receipt["metadata"] = save(changed_path, {"network_clients_created": 1, "formal_performance_pass": False})
                    else:
                        changed_path = Path(receipt["measurement"]["path"]); old_bytes = changed_path.read_bytes()
                        lines = old_bytes.decode().splitlines()
                        if change == "count": lines.pop()
                        else:
                            index, offset = lines[1].split("\t"); lines[1] = index + "\t" + str(int(offset) + 2)
                        changed_path.write_text("\n".join(lines) + "\n"); receipt["measurement"] = capacity.ref(changed_path)
                    if change != "missing": local["arrival_schedules"][0] = save(Path(ref["path"]), receipt)
                    with self.assertRaises(ValueError): capacity.prepare_plan(local)
                finally:
                    Path(ref["path"]).write_bytes(original)
                    if changed_path is not None: changed_path.write_bytes(old_bytes)

    def test_private_source_drift_cpu_overlap_and_short_confirmation_are_rejected(self):
        spec = external_fixture(self.root); frozen = capacity.prepare_plan(spec)
        with self.assertRaisesRegex(ValueError, "CPUs overlap"):
            capacity.prepare_plan({**spec, "observer": {**spec["observer"], "client_cpus": [4, 5]}})
        with self.assertRaises(ValueError): capacity.prepare_plan({**spec, "pairs": 4})
        private = Path(frozen["bindings"]["private_query"]["path"]); private.write_text("changed private SQL")
        with self.assertRaises(ValueError): capacity.check_bindings(frozen)

    def test_external_read_reuses_real_capacity_loop_and_complete_pair_shape(self):
        spec = external_fixture(self.root)
        report, calls, closed = CapacityTest.synthetic_run(self, spec)
        self.assertEqual(len(calls), 20); self.assertEqual(closed, [True] * 20)
        self.assertEqual(report["status"], "CAPACITY_CONFIRMED")
        self.assertFalse(report["formal_performance_pass"])
        base = capacity.read(spec["context_template"]["path"])
        for call in calls:
            self.assertEqual(call["private_query"], base["private_query"])
            self.assertEqual(call["external_source"], base["external_source"])
            self.assertIn(report["freeze"]["sha256"], call["window_id"])
        self.assertEqual([call["pair_id"] for call in calls[:10]], [0, 0, 1, 1, 2, 2, 3, 3, 4, 4])
        self.assertTrue(all(trial["exit_code"] == 0 for trial in report["trials"]))
        frozen = report["frozen_inputs"]
        cell = {"id": spec["cell_id"], "group": "G2", "workload_sha256": frozen["business_workload_sha256"],
                "slo": spec["slo"], "concurrency": 1, "connection_mode": "reuse_jdbc_streaming", "rate_fraction": .3, "rate": 9}
        proof = capacity.stats.capacity_evidence(capacity.ref(self.root / "result/report.json"), cell, frozen["baseline_identity"])
        self.assertEqual(proof["confirmed_lower_rate"], 30)

    def test_external_diagnostic_pilot_and_changed_executed_schedule_cannot_confirm(self):
        spec = external_fixture(self.root, mode="pilot")
        report, calls, closed = CapacityTest.synthetic_run(self, spec, "schedule")
        self.assertEqual(len(calls), 2); self.assertEqual(closed, [True, True])
        self.assertEqual(report["status"], "INCONCLUSIVE")
        self.assertEqual(report["trials"][0]["assessment"], "invalid_trial")
        self.assertIn("predeclared actual bytes", report["trials"][0]["errors"][0]["reason"])

    def test_external_diagnostic_pilot_is_four_windows_and_not_capacity(self):
        spec = external_fixture(self.root, mode="pilot")
        report, calls, closed = CapacityTest.synthetic_run(self, spec)
        self.assertEqual(len(calls), 4); self.assertEqual(closed, [True] * 4)
        self.assertEqual(report["status"], "PILOT_COMPLETE_NOT_QUALIFIED")
        self.assertFalse(report["bracket"]["capacity_bracket_established"])

    def test_schedule_launch_failure_still_cleans_owned_child_and_keeps_receipt(self):
        spec = external_fixture(self.root, mode="pilot"); child = MagicMock(pid=54321, returncode=0)
        child.poll.return_value = 0; child.wait.return_value = 0
        request = {key: spec[key] for key in ("profile_template", "runtime", "rates")}; request["timeout_seconds"] = 20
        output = self.root / "failed-schedule"
        with patch.object(capacity.subprocess, "Popen", return_value=child), \
                patch.object(capacity.protocol("external_read"), "acquire_process", side_effect=ValueError("launch identity failed")), \
                patch.object(capacity.legacy, "terminate_client") as cleanup, \
                patch.object(capacity.legacy, "live_group_members", return_value=[]):
            with self.assertRaises(ValueError): capacity.generate_external_schedules(request, output)
        cleanup.assert_called_once_with(child); child.wait.assert_called_once_with(timeout=5)
        receipt = capacity.read(output / "rate-0/completion.json")
        self.assertTrue(receipt["parent_wait_complete"]); self.assertEqual(receipt["errors"], ["ValueError"])
        self.assertFalse((output / "report.json").exists())

    def test_explicit_schedule_action_uses_only_original_plan_branch_and_actual_wait_receipts(self):
        spec = external_fixture(self.root, mode="pilot"); module = capacity.protocol("external_read")
        request = {key: spec[key] for key in ("profile_template", "runtime", "rates")}; request["timeout_seconds"] = 20
        children = []
        def spawn(command, **kwargs):
            self.assertTrue(kwargs["start_new_session"]); self.assertEqual(command[-3], "--plan")
            profile = capacity.read(command[-2]); output = Path(command[-1]); output.mkdir()
            for phase, planned in module.plan(profile).items(): (output / (phase + "-arrivals.tsv")).write_text(planned["tsv"])
            save(output / "plan.json", {"network_clients_created": 0, "formal_performance_pass": False})
            child = MagicMock(pid=54321, returncode=0); child.poll.return_value = 0; children.append(child)
            return child
        def acquire(child, command, deadline):
            return {"pid": child.pid, "start_ticks": 123, "exe": str(Path(command[0]).resolve()),
                    "command_sha256": hashlib.sha256(b"\0".join(os.fsencode(item) for item in command) + b"\0").hexdigest()}
        with patch.object(capacity.subprocess, "Popen", side_effect=spawn), patch.object(module, "acquire_process", side_effect=acquire), \
                patch.object(capacity.legacy, "terminate_client") as cleanup, patch.object(capacity.legacy, "live_group_members", return_value=[]):
            result = capacity.generate_external_schedules(request, self.root / "mock-java-plan")
        self.assertEqual(cleanup.call_count, 2); self.assertEqual(len(result["arrival_schedules"]), 2)
        self.assertFalse(result["formal_performance_pass"])
        for child, receipt_ref in zip(children, result["arrival_schedules"]):
            self.assertEqual(child.wait.call_count, 2)
            receipt = capacity.read(receipt_ref["path"]); self.assertEqual(receipt["exit_code"], 0)
            self.assertTrue(receipt["parent_wait_complete"]); self.assertEqual(receipt["errors"], [])

    def test_signal_during_plan_launch_is_observed_after_owned_cleanup(self):
        spec = external_fixture(self.root, mode="pilot"); module = capacity.protocol("external_read")
        request = {key: spec[key] for key in ("profile_template", "runtime", "rates")}; request["timeout_seconds"] = 20
        child = MagicMock(pid=54321, returncode=0); child.poll.return_value = 0
        def spawn(*args, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM); return child
        with patch.object(capacity.subprocess, "Popen", side_effect=spawn), \
                patch.object(module, "acquire_process", return_value={"pid": 54321}), \
                patch.object(capacity.legacy, "terminate_client") as cleanup, patch.object(capacity.legacy, "live_group_members", return_value=[]):
            with self.assertRaises(capacity.legacy.CalibrationInterrupted):
                capacity.generate_external_schedules(request, self.root / "cancelled-plan")
        cleanup.assert_called_once_with(child)
        self.assertTrue(capacity.read(self.root / "cancelled-plan/rate-0/completion.json")["parent_wait_complete"])

    def test_source_sampler_reads_complete_container_cgroup_without_any_network(self):
        spec = external_fixture(self.root, mode="pilot"); base = capacity.read(spec["context_template"]["path"])
        source = capacity.read(base["external_source"]["path"]); module = capacity.protocol("external_read")
        group = "/sys/fs/cgroup/system.slice/docker-" + "e" * 64 + ".scope"
        files = {"/proc/103/cgroup": "0::" + group.removeprefix("/sys/fs/cgroup") + "\n"}
        files.update({group + "/" + name: value for name, value in {
            "memory.current": "20000", "memory.peak": "30000", "memory.max": "536870912",
            "memory.swap.max": "0", "memory.events": "oom_kill 0\n", "cpu.max": "100000 100000",
            "cpu.stat": "usage_usec 200\nuser_usec 100\nsystem_usec 100\n"}.items()})
        original = Path.read_text
        def read_text(path, *args, **kwargs):
            return files[str(path)] if str(path) in files else original(path, *args, **kwargs)
        with patch.object(Path, "read_text", read_text), patch.object(module, "pin", return_value=source["service"]), \
                patch.object(capacity.os, "sched_getaffinity", return_value={5}), patch.object(capacity, "rss", return_value=1000):
            sample = capacity.external_source_sample(module, base)
            self.assertEqual(sample["cgroup_memory_peak_bytes"], 30000)
            self.assertEqual(sample["cgroup_cpu_stat"]["usage_usec"], 200)
            self.assertLessEqual(sample["sample_started_monotonic_ns"], sample["sample_ended_monotonic_ns"])
            for key, bad in (("memory.max", "1073741824"), ("memory.swap.max", "max"), ("cpu.max", "max 100000")):
                path = group + "/" + key; old = files[path]; files[path] = bad
                with self.subTest(key=key), self.assertRaises(ValueError): capacity.external_source_sample(module, base)
                files[path] = old

    def source_rows(self):
        spec = external_fixture(self.root, mode="pilot"); base = capacity.read(spec["context_template"]["path"])
        source = capacity.read(base["external_source"]["path"]); group = "/sys/fs/cgroup/system.slice/docker-" + "e" * 64 + ".scope"
        def sample(index):
            return {"sample_started_monotonic_ns": (index + 2) * 10**9, "sample_ended_monotonic_ns": (index + 2) * 10**9 + 100,
                "pin": source["service"], "cpu_affinity": [5], "rss_bytes": 1000, "cgroup_path": group,
                "cgroup_memory_current_bytes": 10000, "cgroup_memory_peak_bytes": 20000 + index,
                "cgroup_memory_limit_bytes": 536870912, "cgroup_memory_swap_max": "0", "cgroup_oom_kill": 2,
                "cgroup_cpu_max": ["100000", "100000"], "cgroup_cpu_stat": {"usage_usec": 100 + index, "user_usec": 50 + index, "system_usec": 50}}
        rows = [{"monotonic_ns": (index + 2) * 10**9 + 101, "external_source": sample(index)} for index in range(4)]
        return spec, source, sample(-1), sample(4), rows

    def test_source_auditor_requires_complete_cgroup_and_process_interval(self):
        spec, source, before, after, rows = self.source_rows(); path = self.root / "source-samples.jsonl"
        def check(values):
            path.write_text("".join(json.dumps(item) + "\n" for item in values))
            return capacity.audit_external_samples(path, spec["observer"], source, before, after, 2500000000, 4500000000)
        accepted = check(rows); self.assertEqual(accepted["sample_count"], 4); self.assertEqual(accepted["cgroup_oom_kill_delta"], 0)
        for field, bad in (("cgroup_memory_limit_bytes", 1073741824), ("cgroup_cpu_max", ["max", "100000"]),
                           ("cgroup_cpu_stat", {"usage_usec": 1, "user_usec": 1, "system_usec": 1})):
            original = after[field]; after[field] = bad
            with self.subTest(snapshot_field=field), self.assertRaises(ValueError): check(rows)
            after[field] = original
        for mutation in ("missing", "single", "tail", "gap", "identity", "group", "oom", "memory", "rss", "swap", "quota", "cpu_reset", "order"):
            bad = copy.deepcopy(rows)
            if mutation == "missing": bad[1].pop("external_source")
            elif mutation == "single": bad = bad[:1]
            elif mutation == "tail": bad.pop()
            elif mutation == "gap": bad = bad[::3]
            elif mutation == "identity": bad[1]["external_source"]["pin"]["start_ticks"] += 1
            elif mutation == "group": bad[1]["external_source"]["cgroup_path"] += "changed"
            elif mutation == "oom": bad[1]["external_source"]["cgroup_oom_kill"] += 1
            elif mutation == "memory": bad[1]["external_source"]["cgroup_memory_current_bytes"] = 536870913
            elif mutation == "rss": bad[1]["external_source"]["rss_bytes"] = 536870913
            elif mutation == "swap": bad[1]["external_source"]["cgroup_memory_swap_max"] = "max"
            elif mutation == "quota": bad[1]["external_source"]["cgroup_cpu_max"][0] = "max"
            elif mutation == "cpu_reset": bad[1]["external_source"]["cgroup_cpu_stat"]["usage_usec"] = 1
            else: bad[1]["external_source"]["sample_ended_monotonic_ns"] = bad[1]["monotonic_ns"] + 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): check(bad)


class CapacityTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="capacity-offline-", dir=capacity.stats.ROOT / ".build-records")
        self.addCleanup(self.temporary.cleanup); self.root = Path(self.temporary.name)

    def frozen(self):
        value = capacity.prepare_plan(fixture(self.root)); value["boot_id"] = capacity.stats.boot_id(); return value

    def test_real_flight_and_scanner_planners_cover_10000_complete_queries_without_any_process(self):
        for name in ("flight", "scanner"):
            root = self.root / name; root.mkdir()
            with patch.object(capacity.subprocess, "Popen", side_effect=AssertionError("plan launched process")):
                frozen = capacity.prepare_plan(fixture(root, name))
            self.assertEqual(frozen["phase"], "A_ONLY")
            self.assertTrue(all(item["request_count"] >= 10000 for item in frozen["profiles"]))
            self.assertFalse(frozen["formal_performance_pass"])
            self.assertEqual(frozen["precision_policy"]["limits_percent"], {"success_qps":1.,"p95_ms":2.,"p99_ms":2.,"fe_cpu_seconds_per_success":1.,"be_cpu_seconds_per_success":1.})

    def test_pilot_uses_declared_single_pair_and_cannot_confirm_capacity(self):
        spec = fixture(self.root, mode="pilot", pairs=1)
        frozen = capacity.prepare_plan(spec)
        self.assertEqual(frozen["template"]["pairs"], 1)
        bracket = capacity.legacy.capacity_bracket([{"rate":30,"assessment":"within_slo"},{"rate":30.29,"assessment":"outside_slo"}], "pilot", False, [30,30.29])
        self.assertFalse(bracket["capacity_bracket_established"])

    def test_unsupported_protocols_and_candidate_context_are_explicitly_rejected(self):
        spec = fixture(self.root)
        for name in ("http", "dml", "complex"):
            with self.subTest(name=name), self.assertRaises(ValueError): capacity.prepare_plan({**spec, "protocol":name})
        context = capacity.read(spec["context_template"]["path"]); context["variant"]="B"
        spec["context_template"] = save(Path(spec["context_template"]["path"]),context)
        with self.assertRaises(ValueError): capacity.prepare_plan(spec)

    def test_confirmation_does_not_shorten_or_waive_samples_or_numeric_slos(self):
        spec=fixture(self.root)
        for change in ({"pairs":4},{"rates":[30,30]},{"rates":[30,float("nan")]},{"slo":{**spec["slo"],"max_error_rate":.1}}):
            with self.subTest(change=change),self.assertRaises(ValueError):capacity.prepare_plan({**spec,**change})
        profile=capacity.read(spec["profile_template"]["path"]);profile["qualification"]="diagnostic"
        spec["profile_template"]=save(Path(spec["profile_template"]["path"]),profile)
        with self.assertRaises(ValueError):capacity.prepare_plan(spec)
        profile["qualification"]="formal";profile["duration_seconds"]=600
        spec["profile_template"]=save(Path(spec["profile_template"]["path"]),profile)
        with self.assertRaises(ValueError):capacity.prepare_plan({**spec,"rates":[.5,.501]})

    def test_long_window_is_explicitly_budgeted_instead_of_cut_at_four_hours(self):
        spec=fixture(self.root);profile=capacity.read(spec["profile_template"]["path"])
        profile.update(rate=.2,duration_seconds=60000)
        spec["rates"]=[.2,.201];spec["profile_template"]=save(Path(spec["profile_template"]["path"]),profile)
        plan=capacity.prepare_plan(spec)
        self.assertGreater(plan["observer_seconds"],14400)
        self.assertLessEqual(plan["observer_seconds"],102000)
        self.assertGreaterEqual(plan["profiles"][0]["request_count"],10000)

    def test_complete_slo_miss_is_distinct_from_failed_or_incomplete_window(self):
        frozen=self.frozen();audits=audited_windows(self.root,frozen)
        audits[-1]["window"]["metrics"]["p99_ms"]=2000
        windows,_,_=capacity.capacity_windows(audits,frozen,0,1)
        self.assertEqual(capacity.assess(windows,frozen),"outside_slo")
        audits[-1]["window"]["error_count"]=1
        with self.assertRaises(ValueError):capacity.capacity_windows(audits,frozen,0,1)

    def test_complete_drain_miss_is_valid_upper_evidence_but_denominator_must_include_it(self):
        frozen=self.frozen();audits=audited_windows(self.root,frozen)
        last=audits[-1]["window"];last["end_monotonic_ns"]+=2*10**9;last["effective_duration_seconds"]+=2
        last["metrics"]["success_qps"]=last["successful_requests"]/602
        windows,_,_=capacity.capacity_windows(audits,frozen,0,1)
        self.assertEqual(capacity.assess(windows,frozen),"outside_slo")
        last["metrics"]["success_qps"]=last["successful_requests"]/600
        with self.assertRaises(ValueError):capacity.capacity_windows(audits,frozen,0,1)

    def test_missing_pair_wrong_variant_precision_shortcut_and_partial_samples_reject(self):
        frozen=self.frozen();audits=audited_windows(self.root,frozen)
        for mutation in ("short","B","count","cleanup","pair","boot","shape","clock"):
            value=copy.deepcopy(audits)
            if mutation=="short":value.pop()
            elif mutation=="B":value[0]["window"]["variant"]="B"
            elif mutation=="count":value[0]["window"]["successful_requests"]=9999
            elif mutation=="cleanup":value[0]["window"]["cleanup_verified"]=False
            elif mutation=="pair":value[0]["window"]["pair_id"]=1
            elif mutation=="boot":value[0]["window"]["boot_id"]="another"
            elif mutation=="shape":value[0]["formal_shape_met"]=False
            else:value[0]["window"]["monotonic_mapping_uncertainty_ns"]=0
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):capacity.capacity_windows(value,frozen,0,1)

    def test_prepublication_warmup_overlap_and_raw_hardlink_reuse_reject(self):
        frozen=self.frozen();audits=audited_windows(self.root,frozen)
        with self.assertRaises(ValueError):capacity.capacity_windows(audits,frozen,0,audits[0]["window"]["warmup_start_monotonic_ns"])
        value=copy.deepcopy(audits);value[1]["window"].update({key:value[0]["window"][key] for key in
            ("warmup_start_monotonic_ns","warmup_end_monotonic_ns","start_monotonic_ns","end_monotonic_ns")})
        with self.assertRaises(ValueError):capacity.capacity_windows(value,frozen,0,1)
        link=self.root/"reused";os.link(audits[0]["raw_artifacts"][0]["path"],link)
        audits[1]["raw_artifacts"]=[capacity.ref(link)]
        with self.assertRaises(ValueError):capacity.capacity_windows(audits,frozen,0,1)

    def test_raw_change_and_wrong_protocol_auditor_cannot_become_capacity_evidence(self):
        frozen=self.frozen();audits=audited_windows(self.root,frozen)
        value=copy.deepcopy(audits);value[0]["auditor"]=capacity.ref(capacity.SOURCE)
        with self.assertRaises(ValueError):capacity.capacity_windows(value,frozen,0,1)
        Path(audits[0]["raw_artifacts"][0]["path"]).write_text("changed")
        with self.assertRaises(ValueError):capacity.capacity_windows(audits,frozen,0,1)

    def test_last_sample_reads_complete_tail_and_rejects_truncated_final_audit(self):
        path=self.root/"samples";path.write_bytes(b'{"n":1}\n{"n":2}\n{"n":')
        self.assertEqual(capacity.last_sample(path,100),{"n":2})
        with self.assertRaises(ValueError):list(capacity.iter_samples(path,100))

    def test_cleanup_reaps_owned_observer_even_when_post_sample_binding_or_wait_fails(self):
        frozen=self.frozen();frozen["absolute_deadline_monotonic_ns"]=time.monotonic_ns()+10**9
        owner=capacity.ObserverWindow(frozen,capacity.protocol("flight"),self.root,self.root/"stop")
        process=MagicMock(pid=12345,returncode=143);process.poll.return_value=None
        process.wait.side_effect=RuntimeError("wait rejected")
        owner.process=process
        with patch.object(capacity,"last_sample",side_effect=ValueError("raw changed")),\
             patch.object(capacity.legacy,"terminate_client") as reap,\
             patch.object(capacity.legacy,"live_group_members",return_value=[]):owner.close(True)
        reap.assert_called_once_with(process)
        receipt=capacity.read(self.root/"observer-completion.json")
        self.assertEqual(receipt["pid"],12345);self.assertTrue(receipt["failures"])

    def test_decimal_one_percent_boundary_and_nonmonotonic_or_missing_trials(self):
        for upper, expected in ((1.01,True),(1.010000001,False)):
            trials=[{"rate":1,"assessment":"within_slo"},{"rate":upper,"assessment":"outside_slo"}]
            self.assertEqual(capacity.capacity_bracket(trials,"confirm",True,[1,upper])["capacity_bracket_established"],expected)
        trials=[{"rate":1,"assessment":"outside_slo"},{"rate":1.01,"assessment":"within_slo"}]
        self.assertFalse(capacity.capacity_bracket(trials,"confirm",True,[1,1.01])["capacity_bracket_established"])
        self.assertFalse(capacity.capacity_bracket(trials[:1],"confirm",True,[1,1.01])["capacity_bracket_established"])

    def synthetic_run(self, spec, failure=None):
        """Exercise real scheduler/reporting with invented driver/observer bytes only."""
        module=capacity.protocol(spec["protocol"]); dispatched=[]; closed=[]; normalized={}
        epoch=time.monotonic_ns()+10**9
        class Observer:
            def __init__(self,frozen,module,directory,stop,checkpoint):self.frozen=frozen;self.directory=directory
            def start(self):
                if failure=="observer_start":raise ValueError("synthetic start failure")
                if failure=="signal":os.kill(os.getpid(),signal.SIGTERM)
            def close(self,complete):closed.append(complete)
            def audit(self,raw):return save(self.directory/"observer-audit.json",{"synthetic_only":True})
        def run_window(profile_ref,context,runtime_ref,output,stop):
            self.assertEqual(context["phase"],"CAPACITY");self.assertEqual(context["variant"],"A")
            self.assertEqual(runtime_ref,spec["runtime"])
            dispatched.append(context)
            output.mkdir();launch=save(output/"launch.json",{**context,"created_monotonic_ns":time.monotonic_ns()})
            receipt=save(output/"raw.json",{"synthetic_only":True,"window_id":context["window_id"]})
            if failure=="client":return {"status":"INVALID_WINDOW"}
            profile=capacity.read(profile_ref["path"]);index=len(dispatched)-1
            start=epoch+index*1000*10**9;warm=profile["warmup_seconds"];seconds=profile["duration_seconds"]
            count=module.plan(profile)["measurement"]["requests"]
            if spec["protocol"] == "external_read":
                declaration = capacity.read(spec["arrival_schedules"][spec["rates"].index(profile["rate"])]["path"])
                for phase in ("warmup", "measurement"):
                    path = output / (phase + "-arrivals.tsv")
                    path.write_bytes(Path(declaration[phase]["path"]).read_bytes())
                    if failure == "schedule" and phase == "warmup":
                        lines = path.read_text().splitlines(); sequence, offset = lines[1].split("\t")
                        lines[1] = sequence + "\t" + str(int(offset) + 1); path.write_text("\n".join(lines) + "\n")
            lower_rate=profile["rate"]==spec["rates"][0]
            window={"window_id":context["window_id"],"pair_id":context["pair_id"],"variant":"A","boot_id":capacity.stats.boot_id(),
                "identity":context["identity"],"workload_sha256":module.business_binding(profile)["sha256"],
                "arrival_schedule_sha256":module.plan(profile)["measurement"]["sha256"],"rate":profile["rate"],
                "warmup_seconds":warm,"duration_seconds":seconds,"warmup_start_monotonic_ns":start,"warmup_end_monotonic_ns":start+warm*10**9,
                "start_monotonic_ns":start+warm*10**9,"end_monotonic_ns":start+(warm+seconds)*10**9,
                "monotonic_clock_domain":"bounded_jvm_mapping","monotonic_mapping_uncertainty_ns":10,
                "monotonic_mapping":{"offset_lower_ns":0,"estimated_offset_ns":10,"offset_upper_ns":20},
                "effective_duration_seconds":seconds,"scheduled_requests":count,"observed_requests":count,"successful_requests":count,
                "error_count":0,"timeout_count":0,"retry_count":0,"oracle_verified":True,"cleanup_verified":True,"cpu_boundary_verified":True,
                "metrics":{"p95_ms":10,"p99_ms":20 if lower_rate else 2000,"success_qps":count/seconds,
                           "fe_cpu_seconds_per_success":.001,"be_cpu_seconds_per_success":.002}}
            formal=profile["qualification"]=="formal"
            normalized[context["window_id"]]={"status":"VERIFIED" if formal else "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED",
                "formal_shape_met":formal and count>=10000,"window":window,
                "auditor":capacity.ref(module.SOURCE),"dependency_bindings":[],"raw_artifacts":[launch,receipt]}
            return {"status":"RAW_WINDOW_COMPLETE","launch":launch,"window_directory":str(output)}
        def normalize(manifest):
            if failure=="normalize":raise ValueError("synthetic raw failure")
            return normalized[capacity.read(manifest["launch"]["path"])["window_id"]]
        with patch.object(capacity,"ObserverWindow",Observer),patch.object(module,"run_window",run_window),patch.object(module,"normalize",normalize):
            result=capacity.run(spec,self.root/"result")
        return result,dispatched,closed

    def test_actual_scheduler_structure_keeps_five_independent_pairs_and_stats_capacity_schema(self):
        spec=fixture(self.root);report,dispatched,closed=self.synthetic_run(spec)
        self.assertEqual(len(dispatched),20);self.assertEqual(closed,[True]*20)
        self.assertEqual([row["pair_id"] for row in dispatched[:10]],[0,0,1,1,2,2,3,3,4,4])
        self.assertEqual(len({row["window_id"] for row in dispatched}),20)
        self.assertEqual(report["status"],"CAPACITY_CONFIRMED")
        self.assertFalse(report["formal_performance_pass"])
        frozen=report["frozen_inputs"]
        cell={"id":spec["cell_id"],"group":"G2","workload_sha256":frozen["business_workload_sha256"],"slo":spec["slo"],
              "concurrency":1,"connection_mode":"reuse_fe_and_be_channels","rate_fraction":.3,"rate":9}
        proof=capacity.stats.capacity_evidence(capacity.ref(self.root/"result/report.json"),cell,frozen["baseline_identity"])
        self.assertEqual(proof["confirmed_lower_rate"],30);self.assertEqual(proof["confirmed_upper_rate"],30.29)
        self.assertFalse(report["bracket"]["AA_precision_proven"])

    def test_pilot_executes_only_requested_pair_and_retains_no_capacity_claim(self):
        spec=fixture(self.root,mode="pilot",pairs=1);report,calls,closed=self.synthetic_run(spec)
        self.assertEqual(len(calls),4);self.assertEqual(len(closed),4)
        self.assertEqual(report["status"],"PILOT_COMPLETE_NOT_QUALIFIED");self.assertFalse(report["bracket"]["capacity_bracket_established"])

    def test_failed_client_never_becomes_slo_upper_bound_and_observer_is_closed(self):
        spec=fixture(self.root);report,calls,closed=self.synthetic_run(spec,"client")
        self.assertEqual(len(calls),1);self.assertEqual(closed,[False])
        self.assertEqual(report["trials"][0]["assessment"],"invalid_trial")
        self.assertFalse(report["bracket"]["capacity_bracket_established"])

    def test_partial_observer_start_is_closed_without_launching_protocol(self):
        spec=fixture(self.root);report,calls,closed=self.synthetic_run(spec,"observer_start")
        self.assertEqual(calls,[]);self.assertEqual(closed,[False])
        self.assertEqual(report["status"],"INCONCLUSIVE")

    def test_raw_normalization_failure_stops_sweep_and_preserves_invalid_receipt(self):
        spec=fixture(self.root);report,calls,closed=self.synthetic_run(spec,"normalize")
        self.assertEqual(len(calls),1);self.assertEqual(closed,[True])
        self.assertFalse(capacity.read(report["trials"][0]["artifact_audit"])["valid"])

    def test_real_signal_is_checked_before_protocol_and_cleanup_restores_handlers(self):
        spec=fixture(self.root);old=signal.getsignal(signal.SIGTERM)
        report,calls,closed=self.synthetic_run(spec,"signal")
        self.assertEqual(calls,[]);self.assertEqual(closed,[False]);self.assertEqual(signal.getsignal(signal.SIGTERM),old)
        self.assertEqual(report["trials"][0]["errors"][0]["class"],"CalibrationInterrupted")

    def test_window_identity_binds_both_actual_prepublished_capacity_hashes(self):
        spec=fixture(self.root);report,calls,_=self.synthetic_run(spec)
        for launch in calls:
            self.assertIn(report["freeze"]["sha256"],launch["window_id"])
            self.assertIn(report["publication"]["sha256"],launch["window_id"])

    def test_short_diagnostic_pilot_runs_but_cannot_feed_formal_capacity_or_confirm(self):
        spec=fixture(self.root,mode="pilot",pairs=1);profile=capacity.read(spec["profile_template"]["path"])
        profile.update(qualification="diagnostic",warmup_seconds=2,duration_seconds=3)
        spec["profile_template"]=save(Path(spec["profile_template"]["path"]),profile)
        report,calls,_=self.synthetic_run(spec)
        self.assertEqual(len(calls),4);self.assertEqual(report["status"],"PILOT_COMPLETE_NOT_QUALIFIED")
        self.assertLess(report["frozen_inputs"]["profiles"][0]["request_count"],10000)
        with self.assertRaises(ValueError):capacity.prepare_plan({**spec,"mode":"confirm","pairs":5})
        with self.assertRaises(ValueError):capacity.stats.capacity_evidence(capacity.ref(self.root/"result/report.json"),{},{})

    def test_coordinated_derived_slo_rewrite_cannot_detach_from_frozen_spec(self):
        report,_,_=self.synthetic_run(fixture(self.root))
        frozen=report["frozen_inputs"];frozen["p99_slo_ms"]=3000
        report["freeze"]=save(Path(report["freeze"]["path"]),frozen)
        publication=capacity.read(report["publication"]["path"]);publication["freeze"]=report["freeze"]
        report["publication"]=save(Path(report["publication"]["path"]),publication)
        save(self.root/"result/report.json",report)
        with self.assertRaisesRegex(ValueError,"derived policy differs"):
            capacity.verify_report(self.root/"result/report.json")

    def test_observed_natural_zombie_is_distinct_from_reused_pid_and_actual_wait_is_owned(self):
        module=capacity.protocol("flight")
        child=subprocess.Popen(["sleep","0.15"],start_new_session=True)
        try:
            pin=module.pin(child.pid)
            live,state=capacity.helper_memory(module,pin);self.assertEqual(state,"LIVE");self.assertEqual(live["pin"],pin)
            time.sleep(.2)  # Do not poll: deliberately preserve the own child's short Z state.
            ended,state=capacity.helper_memory(module,pin)
            self.assertIsNone(ended);self.assertEqual(state,"EXIT_OBSERVED_UNREAPED")
            with self.assertRaises(ValueError):capacity.helper_memory(module,{**pin,"start_ticks":pin["start_ticks"]+1})
        finally:
            child.wait(timeout=2)
        self.assertEqual(child.returncode,0)

    def test_client_rss_requires_complete_coverage_gaps_and_actual_active_helper(self):
        pin={"pid":42,"start_ticks":12};path=self.root/"client.jsonl"
        settings={"max_log_bytes":100000,"client_max_gap_seconds":1.5,"rss_limits_bytes":{"client":100}}
        rows=[{"monotonic_ns":index*10**9,"combined_rss_bytes":20,"helper":{"pin":pin,"rss_bytes":10} if index in (1,2) else None,
               "helper_state":"LIVE" if index in (1,2) else "NOT_YET_LAUNCHED" if index==0 else "EXIT_OBSERVED_UNREAPED"} for index in range(4)]
        def check(value):
            path.write_text("".join(json.dumps(row)+"\n" for row in value))
            capacity.audit_client_samples(path,settings,pin,500000000,2500000000,1000000000,2000000000)
        check(rows)
        for mutation in ("early_only","missing_tail","gap","active_absence","wrong_pid"):
            bad=copy.deepcopy(rows)
            if mutation=="early_only":bad=bad[1:2]
            elif mutation=="missing_tail":bad.pop()
            elif mutation=="gap":bad.pop(1)
            elif mutation=="active_absence":bad[1].update(helper=None,helper_state="EXIT_OBSERVED_UNREAPED")
            else:bad[1]["helper"]["pin"]["pid"]=43
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):check(bad)


if __name__ == "__main__":
    unittest.main()
