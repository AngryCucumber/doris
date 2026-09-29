#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline evidence counterexamples; synthetic receipts never count as actual Flight performance."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import flight_performance as flight


def profile(concurrency=1):
    return {"schema_version": 1, "profile": flight.PROFILE, "qualification": "diagnostic", "seed": 20260922,
            "batch_size": 1024, "concurrency": concurrency, "rate": 5.5, "warmup_seconds": 2,
            "duration_seconds": 3, "drain_seconds": 5, "max_requests": 1000}


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n"); return flight.reference(path)


def mutate(path, function):
    value = flight.read_json(path); function(value); save(path, value)


def mutate_row(path, function):
    values = [json.loads(line) for line in path.read_text().splitlines()]
    function(values); path.write_text("".join(json.dumps(value) + "\n" for value in values))


def raw_stat(pid, start, user, system):
    fields = ["S"] + ["0"] * 49
    fields[11], fields[12], fields[19] = str(user), str(system), str(start)
    return f"{pid} (synthetic worker) " + " ".join(fields) + "\n"


def fixture(root, concurrency=1):
    directory = root / "raw"; directory.mkdir()
    p = profile(concurrency); workload = save(root / "profile.json", p)
    # This synthetic identity exercises binding checks only. No file is an executable or real DB package.
    jdk = root / "jdk"
    for name in ("bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so", "release"):
        path = jdk / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('JAVA_VERSION="17.0.4"\n' if name == "release" else "synthetic " + name)
    jar = root / "synthetic.jar"; jar.write_text("synthetic, never executed")
    classes = root / "classes"; classes.mkdir()
    for name in ("LicenseFlightPerformance.class", "LicenseFlightPerformance$Session.class",
                 "LicenseFlightFixture.class", "LicenseFlightFixture$Session.class"):
        (classes / name).write_text("synthetic, never executed")
    runtime = {"schema_version": 1, "main_class": "LicenseFlightPerformance", "java_home": str(jdk),
        "classes_directory": str(classes), "sources": {key: flight.reference(value) for key, value in flight.SOURCES.items()},
        "jdk": {name: flight.reference(jdk / name) for name in ("bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so", "release")},
        "jars": [flight.reference(jar)], "classes": [flight.reference(path) for path in sorted(classes.iterdir())]}
    runtime_ref = save(root / "runtime.json", runtime)
    identity = {"source_commit": "a" * 40}; bindings = dict(runtime["sources"])
    for key, field in flight.IDENTITIES.items():
        path = root / (key + ".txt"); path.write_text("synthetic " + key)
        bindings[key] = flight.reference(path); identity[field] = bindings[key]["sha256"]
    services, configs = {}, {}
    for index, role in enumerate(("fe", "be")):
        services[role] = {"pid": 100 + index, "start_ticks": 1000 + index, "namespace": "net:[1234]",
                          "exe": "/synthetic/" + role, "command_sha256": "b" * 64}
        path = root / (role + ".conf"); path.write_text(f"arrow_flight_sql_port = {30000 + index}\n")
        configs[role] = flight.reference(path)
    launch = {"schema_version": 1, "phase": "AA", "variant": "A", "window_id": "synthetic-flight", "pair_id": 0,
        "identity": identity, "bindings": bindings, "workload": workload, "max_clock_uncertainty_ns": 100,
        "coordination_seconds": 10, "context_deadline_monotonic_ns": 20_000_000_000, "services": services,
        "service_configs": configs, "endpoints": {"fe_flight_port": 30000, "be_flight_port": 30001,
        "user": "root", "password_env": "MASSDB_TEST_PASSWORD"}, "runtime": runtime_ref, "launch_token": "c" * 64,
        "boot_id": "synthetic-boot", "created_monotonic_ns": 9_000_000_000, "namespace": "net:[1234]",
        "utc_anchor": {"before_monotonic_ns": 9_000_000_000, "utc_ns": 1, "after_monotonic_ns": 9_000_000_001}}
    launch_ref = save(directory / "p4-launch.json", launch)
    config = {**launch["endpoints"], "profile": p, "launch": launch_ref, "namespace": launch["namespace"],
              "services": services, "clock_ticks_per_second": 100, "coordination_seconds": 10}
    save(directory / "config.json", config)
    command = flight.command_for(runtime, directory / "config.json")
    helper_pin = {"pid": 42, "start_ticks": 999, "namespace": launch["namespace"], "exe": str(jdk / "bin/java"),
                  "command_sha256": hashlib.sha256(b"\0".join(os.fsencode(item) for item in command) + b"\0").hexdigest()}
    save(directory / "process.json", {"pin": helper_pin, "command": command})
    actual = {"launch_token": launch["launch_token"], "launch_sha256": launch_ref["sha256"], "boot_id": launch["boot_id"],
              "helper_pid": 42, "helper_start_ticks": 999, "namespace": launch["namespace"]}
    helper_ref = save(directory / "p4-helper-clock.json", {**actual, "schema_version": 1, "nonce": "d" * 32, "jvm_sample_ns": 9_500_000_000})
    bridge = {"schema_version": 1, **{key: actual[key] for key in ("launch_token", "launch_sha256", "boot_id")},
              "nonce": "d" * 32, "controller_before_ns": 9_500_000_000, "controller_after_ns": 9_500_000_020,
              "helper_clock": helper_ref}
    bridge_ref = save(directory / "p4-clock-bridge.json", bridge)
    save(directory / "p4-clock-ready.json", {**actual, "connections": concurrency, "ready_nonce": "ready"})
    planned = flight.plan(p); epoch = 10_000_000_000; calls = [0] * concurrency; last_phase_end = None
    for phase, seconds in (("warmup", 2), ("measurement", 3)):
        schedule = planned[phase]; (directory / (phase + "-arrivals.tsv")).write_text(schedule["tsv"])
        rows = [[] for _ in range(concurrency)]; previous = [epoch] * concurrency; last = epoch
        for index, offset in enumerate(schedule["offsets"]):
            worker = index % concurrency; calls[worker] += 1; scheduled = epoch + offset
            started = max(previous[worker], scheduled) + 1000; ended = started + 1_000_000
            previous[worker] = ended; last = max(last, ended)
            rows[worker].append({"sequence": index, "worker": worker, "scheduled_ns": scheduled,
                "started_ns": started, "finished_ns": ended, "e2e_ns": ended - scheduled,
                "service_ns": ended - started, "queue_ns": started - scheduled, "status": "READ_PASS",
                "session_id": worker, "session_call": calls[worker], "fe_execute_calls": 1,
                "frontend_channel_reused": True, "backend_channel_reused": True, "stream_close_completed": True,
                "backend_channels_created": 1 if calls[worker] == 1 else 0,
                "rows": 1000000, "rows_verified": 1000000, "complete_model_rows": 1000000, "sha256": flight.MODEL_SHA,
                "schema": flight.SCHEMA, "requested_session_batch_size": 1024, "actual_record_batch_rows": [65536] * 15 + [16960],
                "first_record_batch": {"batch_index": 0, "rows": 65536, "schema": flight.SCHEMA, "vectors": [
                    {"name": "id", "vector_class": "org.apache.arrow.vector.BigIntVector", "arrow_type": "Int(64, true)"},
                    {"name": "payload", "vector_class": "org.apache.arrow.vector.VarCharVector", "arrow_type": "Utf8"}]},
                "endpoint": "grpc+tcp://127.0.0.1:30001", "ticket_sha256": hashlib.sha256(f"{phase}:{index}".encode()).hexdigest(),
                "elapsed_nanos_with_complete_oracle": 900000, "elapsed_nanos_with_oracle_and_diagnostics": 950000})
        for worker, values in enumerate(rows):
            (directory / f"{phase}-{worker}.jsonl").write_text("".join(json.dumps(row) + "\n" for row in values))
        end = max(epoch + seconds * 10**9, last)
        def cpu(final):
            return {role: {"pid": pin["pid"], "start_ticks": pin["start_ticks"],
                    "raw_stat": raw_stat(pin["pid"], pin["start_ticks"], 150 if final else 100, 30 if final else 10),
                    "sample_started_java_ns": end + 10 if final else epoch - 1000,
                    "sample_ended_java_ns": end + 50 if final else epoch - 100} for role, pin in services.items()}
        save(directory / (phase + "-start.json"), {**actual, "epoch_ns": epoch, "cpu": cpu(False)})
        last_phase_end = {**actual, "epoch_ns": epoch, "last_request_end_ns": last, "request_interval_end_ns": end,
            "java_monotonic_ns": end + 100, "scheduled_requests": len(schedule["offsets"]), "successful_requests": len(schedule["offsets"]),
            "arrival_schedule_sha256": schedule["sha256"], "cpu": cpu(True)}
        save(directory / (phase + "-end.json"), last_phase_end)
        if phase == "warmup":
            save(directory / "measurement-ready.json", {**actual, "warmup_start_ns": epoch, "warmup_end_ns": end + 100, "ready_ns": end + 200})
        epoch = end + 1_000_000_000
    end = last_phase_end["java_monotonic_ns"]
    for worker in range(concurrency):
        save(directory / f"session-{worker}-open.json", {"worker": worker, "session_id": worker, "frontend_channels": 1, "opened_ns": 9_100_000_000})
        save(directory / f"session-{worker}-close.json", {"worker": worker, "close_started_ns": end + 10,
            "close_finished_ns": end + 100, "channels_and_allocator_closed": True, "frontend_channels_closed": 1,
            "backend_channels_closed": 1 if worker < max(planned["warmup"]["requests"], planned["measurement"]["requests"]) else 0})
    save(directory / "lifecycle.json", {**actual, "cleanup_end_ns": end + 200, "sessions_closed": True, "workers_stopped": True})
    save(directory / "summary.json", {**actual, "status": "RAW_WINDOW_COMPLETE", "errors": 0, "harness_retries": 0, "cleanup_confirmed": True})
    completion = {**actual, "schema_version": 1, "exit_code": 0, "parent_wait_complete": True, "remaining_live_pids": [],
        "controller_errors": [], "completed_monotonic_ns": end + 10000, "bridge": bridge_ref,
        "utc_anchor": {"before_monotonic_ns": end + 10000, "utc_ns": 10, "after_monotonic_ns": end + 10001}}
    completion_ref = save(directory / "p4-completion.json", completion)
    return {"window_directory": str(directory), "launch": launch_ref, "completion": completion_ref}, p, config


class InputTests(unittest.TestCase):
    def test_retained_matrix_only_and_no_65535(self):
        for batch in (1024, 8192):
            for count in (1, 8):
                p = profile(count); p["batch_size"] = batch; self.assertEqual(flight.validate_profile(p), p)
        for key, value in (("batch_size", 65535), ("concurrency", 16), ("seed", 1), ("rate", True), ("rate", float("nan"))):
            p = profile(); p[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): flight.validate_profile(p)

    def test_formal_minimum_does_not_count_rows_as_operations(self):
        p = profile(); p["qualification"] = "formal"
        with self.assertRaisesRegex(ValueError, "cannot be shortened"): flight.plan(p)
        p.update(warmup_seconds=180, duration_seconds=600, rate=1, max_requests=20000)
        with self.assertRaisesRegex(ValueError, "10000 complete"): flight.plan(p)
        p["duration_seconds"] = 11000
        self.assertGreaterEqual(flight.plan(p)["measurement"]["requests"], 10000)

    def test_business_binding_excludes_rate_duration_and_includes_batch_concurrency(self):
        first = flight.business_binding(profile()); p = profile(); p.update(rate=9.5, duration_seconds=4)
        self.assertEqual(flight.business_binding(p), first)
        p["batch_size"] = 8192; self.assertNotEqual(flight.business_binding(p), first)
        self.assertNotEqual(flight.business_binding(profile(8)), first)
        p = profile(); p["drain_seconds"] += 1; self.assertNotEqual(flight.business_binding(p), first)

    def test_fractional_rate_no_floor_and_schedule_prefix(self):
        p = profile(); original = flight.plan(p)
        p["rate"] = 5; self.assertNotEqual(flight.plan(p)["measurement"]["sha256"], original["measurement"]["sha256"])
        self.assertEqual(original["warmup"]["offsets"], original["measurement"]["offsets"][:original["warmup"]["requests"]])

    def test_full_independent_model_is_fixed_without_materializing_rows(self):
        self.assertEqual(flight.verify_model(), "d07f615ccea4c0f21cc4a7505c400a0b47d454eaa06521092e607aa646c21a68")

    def test_percentile_uses_operations_and_interpolation(self):
        self.assertAlmostEqual(flight.percentile([1, 2, 3, 101], .95), 86.3)
        self.assertIsNone(flight.percentile([], .99))

    def test_actual_exec_identity_is_acquired_and_wrong_command_is_rejected(self):
        command = [sys.executable, "-c", "import time; time.sleep(30)"]
        child = subprocess.Popen(command, start_new_session=True)
        try:
            actual = flight.acquire_process(child, command, time.monotonic() + 2)
            self.assertEqual(actual["pid"], child.pid)
            with self.assertRaisesRegex(ValueError, "never executed"):
                flight.acquire_process(child, [*command, "wrong"], time.monotonic() + .01)
        finally:
            flight.reap(child)

    def test_wait_reaps_only_owned_child_even_if_it_exits_before_signal(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        flight.reap(child); self.assertIsNotNone(child.returncode)
        with self.assertRaises(FileNotFoundError): flight.lifecycle.start_ticks(child.pid)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.manifest, self.profile, self.config = fixture(self.root)
        self.directory = Path(self.manifest["window_directory"])

    def tearDown(self): self.temp.cleanup()

    def audit(self): return flight.normalize(self.manifest)

    def test_valid_synthetic_receipts_are_diagnostic_never_performance_pass(self):
        result = self.audit(); measured = result["request_audit"]["measurement"]
        self.assertEqual(result["status"], "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED")
        self.assertFalse(result["formal_shape_met"]); self.assertFalse(result["formal_performance_pass"])
        self.assertAlmostEqual(measured["success_qps"], measured["successful_requests"] / 3)
        self.assertAlmostEqual(measured["p99_ms"], 1.001)
        self.assertAlmostEqual(measured["fe_cpu_seconds_per_success"], .7 / measured["successful_requests"])
        self.assertEqual(result["window"]["monotonic_mapping_uncertainty_ns"], 10)

    def test_eight_independent_sessions_reused_across_both_phases(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, _, _ = fixture(Path(temporary), 8)
            self.assertEqual(flight.normalize(manifest)["window"]["error_count"], 0)

    def test_every_raw_failure_remains_visible(self):
        def fail(rows): rows[0].update(status="ERROR", error_class="FlightRuntimeException", error_code="READ_ERROR", flight_error_code="TIMED_OUT")
        mutate_row(self.directory / "measurement-0.jsonl", fail)
        mutate(self.directory / "measurement-end.json", lambda value: value.update(successful_requests=value["successful_requests"] - 1))
        derived = flight.audit_requests(self.directory, self.profile, self.config)
        self.assertEqual(derived["measurement"]["error_count"], 1); self.assertEqual(derived["measurement"]["timeout_count"], 1)
        with self.assertRaisesRegex(ValueError, "failures preserved"): self.audit()

    def test_missing_completion_is_rejected(self):
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows.pop())
        with self.assertRaisesRegex(ValueError, "missing completion"): self.audit()

    def test_duplicate_completion_is_rejected(self):
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows.append(rows[0]))
        with self.assertRaisesRegex(ValueError, "duplicate/foreign"): self.audit()

    def test_old_ticket_reuse_is_rejected_across_warmup_and_measurement(self):
        ticket = json.loads((self.directory / "warmup-0.jsonl").read_text().splitlines()[0])["ticket_sha256"]
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows[0].update(ticket_sha256=ticket))
        with self.assertRaisesRegex(ValueError, "reused/invalid FE ticket"): self.audit()

    def test_incomplete_million_row_oracle_is_rejected(self):
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows[0].update(rows_verified=999999))
        with self.assertRaisesRegex(ValueError, "million-row"): self.audit()

    def test_wrong_values_digest_is_rejected(self):
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows[0].update(sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "million-row"): self.audit()

    def test_actual_batches_cannot_hide_missing_rows(self):
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows[0]["actual_record_batch_rows"].pop())
        with self.assertRaisesRegex(ValueError, "batches incomplete"): self.audit()

    def test_batch_size_hint_is_not_claimed_as_actual_record_batch_size(self):
        result = self.audit(); self.assertEqual(result["window"]["error_count"], 0)  # Actual synthetic batches are 65536, requested1024.

    def test_changed_exact_arrow_type_rejected(self):
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows[0]["first_record_batch"]["vectors"][0].update(arrow_type="Int(32, true)"))
        with self.assertRaisesRegex(ValueError, "exact vector schema"): self.audit()

    def test_queue_cannot_be_subtracted_from_e2e(self):
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows[0].update(e2e_ns=1000000))
        with self.assertRaisesRegex(ValueError, "queue/service/E2E"): self.audit()

    def test_shorter_denominator_rejected(self):
        mutate(self.directory / "measurement-end.json", lambda value: value.update(request_interval_end_ns=value["request_interval_end_ns"] - 1))
        with self.assertRaisesRegex(ValueError, "denominator"): self.audit()

    def test_cpu_must_enclose_last_completion(self):
        mutate(self.directory / "measurement-end.json", lambda value: value["cpu"]["fe"].update(sample_started_java_ns=value["request_interval_end_ns"] - 1))
        with self.assertRaisesRegex(ValueError, "CPU sample"): self.audit()

    def test_cpu_raw_lifetime_cannot_be_relabeled(self):
        mutate(self.directory / "measurement-start.json", lambda value: value["cpu"]["fe"].update(raw_stat=raw_stat(100, 9999, 100, 10)))
        with self.assertRaisesRegex(ValueError, "CPU raw lifetime"): self.audit()

    def test_recreated_backend_channel_is_rejected(self):
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows[0].update(backend_channels_created=1))
        with self.assertRaisesRegex(ValueError, "channel reuse"): self.audit()

    def test_missing_stream_close_rejected(self):
        mutate_row(self.directory / "measurement-0.jsonl", lambda rows: rows[0].update(stream_close_completed=False))
        with self.assertRaisesRegex(ValueError, "stream close"): self.audit()

    def test_channel_close_error_rejected(self):
        mutate(self.directory / "session-0-close.json", lambda value: value.update(channels_and_allocator_closed=False))
        with self.assertRaisesRegex(ValueError, "open/close"): self.audit()

    def test_warmup_must_cover_complete_warmup_window(self):
        mutate(self.directory / "measurement-ready.json", lambda value: value.update(warmup_end_ns=value["warmup_end_ns"] - 100))
        with self.assertRaisesRegex(ValueError, "actual warmup"): self.audit()

    def test_parent_wait_required(self):
        mutate(self.directory / "p4-completion.json", lambda value: value.update(parent_wait_complete=False))
        self.manifest["completion"] = flight.reference(self.directory / "p4-completion.json")
        with self.assertRaisesRegex(ValueError, "parent wait"): self.audit()

    def test_completion_binding_drift_does_not_pass(self):
        mutate(self.directory / "p4-completion.json", lambda value: value.update(exit_code=2))
        with self.assertRaisesRegex(ValueError, "digest changed"): self.audit()

    def test_runtime_module_changes_invalidate_returned_evidence(self):
        result = self.audit(); target = self.root / "jdk/lib/modules"; target.write_text("changed")
        binding = next(value for value in result["dependency_bindings"] if value["path"] == str(target))
        with self.assertRaisesRegex(ValueError, "digest changed"): flight.verify_reference(binding)

    def test_raw_alias_is_rejected(self):
        (self.directory / "alias").symlink_to(self.directory / "summary.json")
        with self.assertRaisesRegex(ValueError, "symlink"): self.audit()

    def test_clock_uncertainty_cannot_be_silently_zeroed(self):
        path = self.directory / "p4-clock-bridge.json"
        mutate(path, lambda value: value.update(controller_after_ns=value["controller_before_ns"] + 1000))
        mutate(self.directory / "p4-completion.json", lambda value: value.update(bridge=flight.reference(path)))
        self.manifest["completion"] = flight.reference(self.directory / "p4-completion.json")
        with self.assertRaisesRegex(ValueError, "uncertainty"): self.audit()

    def test_clock_nonce_from_another_execution_rejected(self):
        path = self.directory / "p4-clock-bridge.json"
        mutate(path, lambda value: value.update(nonce="another-clock-handshake"))
        mutate(self.directory / "p4-completion.json", lambda value: value.update(bridge=flight.reference(path)))
        self.manifest["completion"] = flight.reference(self.directory / "p4-completion.json")
        with self.assertRaisesRegex(ValueError, "nonce"): self.audit()

    def test_source_phase_cannot_relabel_candidate_as_capacity(self):
        launch = flight.read_json(self.directory / "p4-launch.json"); launch.update(phase="CAPACITY", variant="B")
        with self.assertRaisesRegex(ValueError, "A-only"): flight.validate_context(launch, self.profile)

    def test_ab_requires_matching_freeze_before_launch(self):
        launch = flight.read_json(self.directory / "p4-launch.json"); launch["phase"] = "AB"
        with self.assertRaises(KeyError): flight.validate_context(launch, self.profile)

    def test_expired_context_refused_before_network_client_creation(self):
        launch = flight.read_json(self.directory / "p4-launch.json"); launch["context_deadline_monotonic_ns"] = time.monotonic_ns() - 1
        with patch.object(flight.subprocess, "Popen") as spawned, self.assertRaisesRegex(ValueError, "expired/unbounded"):
            flight.validate_context(launch, self.profile, live=True)
        spawned.assert_not_called()


if __name__ == "__main__":
    unittest.main()
