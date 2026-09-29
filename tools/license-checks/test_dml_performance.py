#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Synthetic offline evidence tests; never launch Java, a database or a browser."""

import base64
import csv
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import dml_performance as dml


def profile(kind="insert_select", concurrency=1):
    return {"schema_version": 1, "profile": dml.PROFILE, "operation": kind, "concurrency": concurrency,
        "qualification": "diagnostic", "license_state": "EXPIRED", "seed": 20260922, "rows_per_operation": 100,
        "warmup_seconds": 2, "duration_seconds": 3, "rate_per_second": 10.0, "timeout_seconds": 5, "drain_seconds": 10,
        "prepare_timeout_seconds": 120, "verify_timeout_seconds": 120, "cleanup_timeout_seconds": 30,
        "coordination_timeout_seconds": 10, "max_requests": 1000, "max_rows": 100000, "min_disk_free_bytes": 2 * 1024**3,
        "read_account": {"username": "metadata", "host": "%", "password_env": "MASSDB_UI_READ_PASSWORD"},
        "write_account": {"username": "writer", "host": "%", "password_env": "MASSDB_UI_WRITE_PASSWORD"},
        "storage_paths": ["/independently-frozen/owned-test-storage"]}


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True)); return dml.reference(path)


def fixture(directory, value=None):
    value = value or profile(); planned = dml.plan(value)
    identity = {"token": "a" * 32, "pid": 42, "start_ticks": 99, "namespace": "net:[123]"}
    summary = {**identity, "table": "license_perf.dml_perf_" + identity["token"],
               "operation": value["operation"], "status": "RAW_WINDOW_COMPLETE", "errors": 0,
               "automatic_write_replays": 0, "cleanup_confirmed": True}
    cpu = {role: {"pid": pid, "start_ticks": 10 + pid} for role, pid in (("fe", 100), ("be", 101))}
    epoch = 10_000_000_000
    resolutions, before, storage = [], [], []
    for phase in ("warmup", "measurement"):
        part = planned[phase]; (directory / (phase + "-arrivals.tsv")).write_text(part["tsv"])
        summary[phase + "_schedule_sha256"] = dml.statistics.digest(directory / (phase + "-arrivals.tsv"))
        receipts = [[] for _ in range(value["concurrency"])]; last = epoch
        for index, offset in enumerate(part["arrivals"]):
            domain = part["first_domain"] + index; scheduled = epoch + offset; started = scheduled + 100; ended = scheduled + 1000
            info = "U{'label':'label_%d', 'status':'VISIBLE', 'txnId':'%d'}" % (domain, domain + 1)
            receipts[index % value["concurrency"]].append({"sequence": index, "domain": domain, "scheduled_ns": scheduled,
                "started_ns": started, "finished_ns": ended, "e2e_ns": ended - scheduled, "outcome": "ACK", "affected_rows": 100,
                "sql_state": "NONE", "error_code": 0, "ok_info_b64": base64.b64encode(info.encode()).decode()})
            last = max(last, ended)
            empty = value["operation"] == "delete"
            resolutions.append({"domain": domain, "rows": 0 if empty else 100, "version": -1 if empty else 1 if value["operation"] == "update" else 0,
                "request_outcome": "ACK", "observed_committed": True, "unknown_absence_is_rollback_proof": False})
            before.append({"domain": domain, "rows": 0 if value["operation"] == "insert_select" else 100,
                "version": -1 if value["operation"] == "insert_select" else 0, "request_outcome": "NOT_SENT",
                "observed_committed": False, "unknown_absence_is_rollback_proof": False})
        for worker, rows in enumerate(receipts):
            with (directory / f"{phase}-{worker}.tsv").open("w", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=["sequence", "domain", "scheduled_ns", "started_ns", "finished_ns", "e2e_ns",
                    "outcome", "affected_rows", "sql_state", "error_code", "ok_info_b64"], delimiter="\t")
                writer.writeheader(); writer.writerows(rows)
        duration = value["warmup_seconds"] if phase == "warmup" else value["duration_seconds"]
        end = max(epoch + duration * 10**9, last)
        first = {role: {**pin, "cpu_seconds": 1.0, "sample_started_java_ns": epoch - 100, "sample_ended_java_ns": epoch - 1} for role, pin in cpu.items()}
        final = {role: {**pin, "cpu_seconds": 1.1, "sample_started_java_ns": end, "sample_ended_java_ns": end + 100} for role, pin in cpu.items()}
        save(directory / (phase + "-start.json"), {**identity, "epoch_ns": epoch, "java_monotonic_ns": epoch - 1000, "cpu": first})
        save(directory / (phase + "-end.json"), {**identity, "epoch_ns": epoch, "request_interval_end_ns": end,
            "last_request_end_ns": last, "java_monotonic_ns": end + 1000, "cpu": final,
            "scheduled_requests": len(part["arrivals"]), "successful_requests": len(part["arrivals"])})
        for second in range(duration): storage.append({**identity, "phase": phase, "java_monotonic_ns": epoch + second * 10**9,
            "storage": [{"path": value["storage_paths"][0], "usable_bytes": value["min_disk_free_bytes"] + 1000000}]})
        epoch = end + 10**9
    (directory / "storage.jsonl").write_text("".join(json.dumps(item) + "\n" for item in storage))
    save(directory / "quota-before.json", {"raw_rows": [["Left", "10.000 GB", "1000", ""]],
        "remaining_bytes_lower_bound": int(Decimal("9.999") * 1024**3), "remaining_replica_count": 1000})
    summary["target_before"] = dml.expected_target(value["operation"], before)
    summary["target_after"] = dml.expected_target(value["operation"], resolutions)
    source = {"rows": 1000000, "full_values_verified": True, "canonical_sha256": dml.lifecycle.expected_source_digest(), "schema_sha256": "c" * 64}
    summary.update(source_before=source, source_after=source)
    save(directory / "batch-resolution.json", resolutions); save(directory / "summary.json", summary)
    return value, summary, identity, cpu


def mutate_row(path, change):
    rows = dml.csv_rows(path); change(rows[0]); fields = list(rows[0])
    with path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, delimiter="\t"); writer.writeheader(); writer.writerows(rows)


class DmlInputTest(unittest.TestCase):
    def test_fixed_shapes_and_formal_bounds(self):
        for kind in ("insert_select", "update", "delete"):
            for count in (1, 8): self.assertEqual(dml.validate_config(profile(kind, count))["concurrency"], count)
        for key, value in (("concurrency", 2), ("rows_per_operation", 99), ("seed", 1), ("rate_per_second", float("nan")),
                           ("rate_per_second", True), ("license_state", "PENDING"), ("max_requests", 500001)):
            candidate = profile(); candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): dml.validate_config(candidate)
        value = profile(); value["qualification"] = "formal"
        with self.assertRaisesRegex(ValueError, "too short"): dml.validate_config(value)

    def test_drain_budget_changes_the_frozen_business_identity(self):
        original = profile(); changed = {**original, "drain_seconds": original["drain_seconds"] + 1}
        self.assertNotEqual(dml.business_binding(original)["sha256"], dml.business_binding(changed)["sha256"])
        self.assertEqual(dml.business_binding(changed)["fields"]["drain_seconds"], changed["drain_seconds"])

    def test_resource_caps_refuse_before_any_target_or_request(self):
        for key, value in (("max_rows", 100), ("min_disk_free_bytes", 1024**3), ("rate_per_second", 1000),
                           ("storage_paths", ["relative"])):
            candidate = profile(); candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): dml.plan(candidate)

    def test_complete_schedules_have_disjoint_warmup_measured_domains(self):
        result = dml.plan(profile()); warm, measured = result["warmup"], result["measurement"]
        self.assertEqual(measured["first_domain"], warm["requests"])
        self.assertEqual(result["total_requests"], warm["requests"] + measured["requests"])
        self.assertEqual(result["target_rows_bound"], result["total_requests"] * 100)
        self.assertFalse(result["formal_performance_pass"])
        self.assertEqual(dml.plan(profile()), result)

    def test_business_binding_changes_with_operation_not_rate_or_license_condition(self):
        value = profile(); first = dml.business_binding(value)
        value.update(rate_per_second=12, license_state="VALID"); self.assertEqual(dml.business_binding(value), first)
        value["operation"] = "update"; self.assertNotEqual(dml.business_binding(value), first)

    def test_only_g4_facade_has_explicit_release(self):
        fixture = dml.DmlPerformance.__new__(dml.DmlPerformance); fixture.check = Mock()
        fixture.coordinate(); fixture.check.assert_called_once()


class DmlReceiptTest(unittest.TestCase):
    def test_three_real_semantic_models_keep_hundred_row_operations(self):
        for kind in ("insert_select", "update", "delete"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary); value, summary, _, _ = fixture(path, profile(kind, 8))
                audit = dml.audit_requests(path, value, summary); models = dml.audit_models(path, value, summary, audit)
                self.assertTrue(models["verified"]); self.assertFalse(models["online_visibility_latency_measured"])
                self.assertEqual(audit["phases"]["measurement"]["error_count"], 0)
                self.assertAlmostEqual(audit["phases"]["measurement"]["p99_ms"], .001)
                self.assertAlmostEqual(audit["phases"]["measurement"]["service_p99_ms"], .0009)
                self.assertAlmostEqual(audit["phases"]["measurement"]["queue_p99_ms"], .0001)
                self.assertTrue(dml.audit_resource_admission(path, value, audit)["verified"])

    def test_unknown_visible_result_never_becomes_ack(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); value, summary, _, _ = fixture(path)
            mutate_row(path / "measurement-0.tsv", lambda row: row.update(outcome="UNKNOWN", affected_rows="-1", ok_info_b64=""))
            end = dml.read_json(path / "measurement-end.json"); end["successful_requests"] -= 1; save(path / "measurement-end.json", end)
            audit = dml.audit_requests(path, value, summary)
            self.assertEqual(audit["phases"]["measurement"]["error_count"], 1)
            resolution = dml.read_json(path / "batch-resolution.json")
            domain = audit["planned"]["warmup"]["requests"]; resolution[domain]["request_outcome"] = "UNKNOWN"
            save(path / "batch-resolution.json", resolution)
            self.assertTrue(dml.audit_models(path, value, summary, audit)["verified"])
            resolution[domain]["request_outcome"] = "ACK"; save(path / "batch-resolution.json", resolution)
            with self.assertRaisesRegex(ValueError, "rewrote"): dml.audit_models(path, value, summary, audit)

    def test_empty_update_delete_and_partial_batches_fail(self):
        for kind in ("update", "delete"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary); value, summary, _, _ = fixture(path, profile(kind))
                mutate_row(path / "measurement-0.tsv", lambda row: row.update(affected_rows="0"))
                with self.assertRaisesRegex(ValueError, "row count"): dml.audit_requests(path, value, summary)
        with self.assertRaisesRegex(ValueError, "partial"):
            dml.expected_target("insert_select", [{"domain": 0, "rows": 99}])

    def test_duplicate_ack_transaction_or_malformed_commit_is_rejected(self):
        for mutation in ("duplicate", "aborted", "duplicate_field"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary); value, summary, _, _ = fixture(path)
                first = dml.csv_rows(path / "warmup-0.tsv")[0]["ok_info_b64"]
                def change(row):
                    if mutation == "duplicate": row["ok_info_b64"] = first
                    else:
                        text = base64.b64decode(row["ok_info_b64"]).decode()
                        text = text.replace("VISIBLE", "ABORTED") if mutation == "aborted" else text + "'txnId':'9'"
                        row["ok_info_b64"] = base64.b64encode(text.encode()).decode()
                mutate_row(path / "measurement-0.tsv", change)
                with self.assertRaises(ValueError): dml.audit_requests(path, value, summary)

    def test_corrupt_timing_cpu_schedule_and_domains_rejected(self):
        for mutation in ("domain", "early", "e2e", "duplicate", "cpu", "end", "schedule"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary); value, summary, _, _ = fixture(path)
                if mutation in ("domain", "early", "e2e"):
                    def change(row):
                        if mutation == "domain": row["domain"] = "0"
                        if mutation == "early": row["started_ns"] = str(int(row["scheduled_ns"]) - 1)
                        if mutation == "e2e": row["e2e_ns"] = "0"
                    mutate_row(path / "measurement-0.tsv", change)
                elif mutation == "duplicate":
                    file = path / "measurement-0.tsv"; file.write_text(file.read_text() + file.read_text().splitlines()[1] + "\n")
                elif mutation == "schedule":
                    file = path / "measurement-arrivals.tsv"; file.write_text(file.read_text().replace("\t100\n", "\t99\n", 1))
                else:
                    file = path / "measurement-end.json"; data = dml.read_json(file)
                    if mutation == "cpu": data["cpu"]["fe"]["sample_started_java_ns"] = 1
                    else: data["request_interval_end_ns"] += 1
                    save(file, data)
                with self.assertRaises(ValueError): dml.audit_requests(path, value, summary)

    def test_source_and_target_full_value_digests_are_independent(self):
        for model in ("target_before", "target_after", "source_before", "source_after"):
            with self.subTest(model=model), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary); value, summary, _, _ = fixture(path)
                audit = dml.audit_requests(path, value, summary)
                summary = json.loads(json.dumps(summary)); summary[model]["canonical_sha256"] = "0" * 64
                with self.assertRaises(ValueError): dml.audit_models(path, value, summary, audit)

    def test_disk_or_quota_failure_never_counts_as_valid_capacity(self):
        for mutation in ("quota", "replicas", "disk", "gap"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary); value, summary, _, _ = fixture(path); audit = dml.audit_requests(path, value, summary)
                if mutation in ("quota", "replicas"):
                    file = path / "quota-before.json"; item = dml.read_json(file)
                    if mutation == "quota": item["remaining_bytes_lower_bound"] = 1
                    else: item["remaining_replica_count"] = 0
                    save(file, item)
                else:
                    file = path / "storage.jsonl"; items = [json.loads(line) for line in file.read_text().splitlines()]
                    if mutation == "disk": items[-1]["storage"][0]["usable_bytes"] = 1
                    else: items = [item for item in items if item["phase"] != "measurement"]
                    file.write_text("".join(json.dumps(item) + "\n" for item in items))
                with self.assertRaises(ValueError): dml.audit_resource_admission(path, value, audit)


def normalization_fixture(root, phase="AA", formal=False, clock_limit=10000):
    directory = root / "window"; directory.mkdir(); candidate = profile()
    if formal: candidate.update(qualification="formal", warmup_seconds=180, duration_seconds=600, rate_per_second=.03)
    value, summary, identity, cpu = fixture(directory, candidate)
    input_ref = save(root / "workload.json", value)
    bindings = {key: dml.reference(path) for key, path in (("runner", dml.SOURCE), ("java_helper", dml.JAVA_SOURCE),
        ("process_lifecycle", dml.lifecycle.__file__), ("clock_adapter", dml.clocks.__file__), ("statistics", dml.statistics.__file__))}
    for key in ("jdbc_driver", "fe_artifact", "be_artifact", "environment", "configuration", "fixture", "client"):
        file = root / (dml.semantics.DRIVER_NAME if key == "jdbc_driver" else key)
        file.write_text("Synthetic offline protocol fixture: " + key); bindings[key] = dml.reference(file)
    runtime = root / "offline-jdk"
    for relative in ("bin/java", "bin/javac", "lib/modules", "release"):
        file = runtime / relative; file.parent.mkdir(parents=True, exist_ok=True); file.write_text("offline-only-runtime-" + relative)
    classes = directory / "classes"; classes.mkdir(); (classes / "LicenseDmlPerformance.class").write_text("offline bytecode stand-in; never executed")
    frozen = {"config": value, "input_path": input_ref["path"], "input_sha256": input_ref["sha256"], "java_home": str(runtime),
        "jdk_runtime": {relative: dml.statistics.digest(runtime / relative) for relative in ("bin/java", "bin/javac", "lib/modules", "release")},
        "source_sha256": {str(path): dml.statistics.digest(path) for path in (dml.SOURCE, dml.JAVA_SOURCE)},
        "dependencies_sha256": {bindings["jdbc_driver"]["path"]: bindings["jdbc_driver"]["sha256"]}}
    build = {"source_commit": "a" * 40}
    for key, field in (("fe_artifact", "fe_sha256"), ("be_artifact", "be_sha256"), ("environment", "environment_sha256"),
                       ("configuration", "configuration_sha256"), ("fixture", "fixture_sha256"), ("client", "client_sha256")):
        build[field] = bindings[key]["sha256"]
    launch = {"schema_version": 1, "phase": phase, "variant": "B" if phase == "AB" else "A", "launch_token": identity["token"],
        "window_id": "G4-offline-0", "pair_id": 0, "boot_id": dml.statistics.boot_id(), "created_monotonic_ns": 500000000,
        "utc_anchor": {"before_monotonic_ns": 500000000, "utc_ns": 1000000000, "after_monotonic_ns": 500000001},
        "max_clock_uncertainty_ns": clock_limit, "identity": build, "workload": input_ref, "bindings": bindings,
        "service_start_ticks": {role: pin["start_ticks"] for role, pin in cpu.items()}}
    if phase == "AB":
        freeze_ref = save(root / "freeze.json", {"status": "FROZEN_ELIGIBLE", "identities": {"A": build, "B": build},
            "cell": {"group": "G4", "workload_sha256": dml.business_binding(value)["sha256"], "rate": value["rate_per_second"],
                "concurrency": value["concurrency"], "warmup_seconds": value["warmup_seconds"], "duration_seconds": value["duration_seconds"],
                "connection_mode": "reuse", "seed": 20260922, "license_state": value["license_state"],
                "request_count": dml.plan(value)["measurement"]["requests"],
                "arrival_schedule_sha256": dml.plan(value)["measurement"]["schedule_sha256"]}})
        publication = save(root / "publication.json", {"freeze": freeze_ref, "boot_id": launch["boot_id"], "published_monotonic_ns": 400000000})
        launch.update(freeze=freeze_ref, publication=publication)
    launch_ref = save(directory / "p4-launch.json", launch)
    config = {**value, "token": identity["token"], "table": summary["table"], "namespace": identity["namespace"],
              "launch": launch_ref, "cpu_services": cpu}
    save(directory / "config.json", config)
    save(directory / "create-intent.json", {**identity, "table": config["table"], "absent_before_create": True})
    save(directory / "owner.json", {**identity, "table": config["table"], "create_acknowledged": True,
        "configuration_sha256": dml.statistics.digest(directory / "config.json"),
        "identity": {"tablet_ids": list(range(1, 17)), "schema_sha256": "d" * 64}})
    save(directory / "helper-identity.json", {"frozen": frozen,
        "classes": {str(classes / "LicenseDmlPerformance.class"): dml.statistics.digest(classes / "LicenseDmlPerformance.class")}})
    helper = {**identity, "schema_version": 1, "launch_token": identity["token"], "launch_sha256": launch_ref["sha256"],
        "boot_id": launch["boot_id"], "nonce": "c" * 32, "helper_pid": identity["pid"], "helper_start_ticks": identity["start_ticks"],
        "jvm_sample_ns": 1000000000}
    helper_ref = save(directory / "p4-helper-clock.json", helper)
    bridge_ref = save(directory / "p4-clock-bridge.json", {**helper, "controller_before_ns": 1000001000,
        "controller_after_ns": 1000002000, "helper_clock": helper_ref})
    warm_start, warm_end = (dml.read_json(directory / ("warmup-" + name + ".json")) for name in ("start", "end"))
    start, end = (dml.read_json(directory / ("measurement-" + name + ".json")) for name in ("start", "end"))
    save(directory / "measurement-ready.json", {**identity, "warmup_start_ns": warm_start["epoch_ns"],
        "warmup_end_ns": warm_end["java_monotonic_ns"], "ready_ns": warm_end["java_monotonic_ns"] + 1})
    for ordinal, name in enumerate(("ready.json", "verification-ready.json", "verification-start.json")):
        save(directory / name, {**identity, "workers_closed": True,
                              "java_monotonic_ns": end["java_monotonic_ns"] + ordinal * 1000})
    cleanup_end = end["request_interval_end_ns"] + 1000000
    save(directory / "lifecycle.json", {**identity, "java_monotonic_ns": cleanup_end - 1,
        "cleanup_end_ns": cleanup_end, "cleanup_confirmed": True, "workers_closed": True})
    completion_ref = save(directory / "p4-completion.json", {"schema_version": 1, "launch_token": identity["token"],
        "launch_sha256": launch_ref["sha256"], "boot_id": launch["boot_id"], "exit_code": 0, "remaining_live_pids": [],
        "helper_pid": identity["pid"], "helper_start_ticks": identity["start_ticks"], "completed_monotonic_ns": cleanup_end + 10000,
        "utc_anchor": launch["utc_anchor"], "bridge": bridge_ref})
    command = [str(runtime / "bin/java"), "-Xmx512m", "-cp", os.pathsep.join([str(classes), bindings["jdbc_driver"]["path"]]),
               "LicenseDmlPerformance", str(directory / "config.json")]
    command_hash = hashlib.sha256(b"\0".join(os.fsencode(item) for item in command) + b"\0").hexdigest()
    save(directory / "dml-process.json", {"pin": {**identity, "exe": str(runtime / "bin/java"), "command_sha256": command_hash},
                                          "expected_launch": {"command_sha256": command_hash}})
    save(directory / "process-lifecycle.json", [{"pid": identity["pid"], "helper": "dml",
        "reason": "OWNED_PARENT_WAIT", "exit_code": 0, "parent_wait_complete": True,
        "controller_monotonic_ns": cleanup_end + 9000}])
    save(directory / "controller.json", {"status": "RAW_WINDOW_COMPLETE", "errors": [], "owned_child_exited": True})
    save(directory / "worker-0-session.json", {**dml.SESSION, "query_timeout": "5", "insert_timeout": "5", "jdk": "17.0.4+8", "driver": "8.0.33"})
    manifest = {"window_directory": str(directory), "launch": launch_ref, "completion": completion_ref}
    for key, kind in (("resources", "resources"), ("license_state", "license_state")):
        raw = root / (kind + ".tsv"); raw.write_text("synthetic offline observer evidence")
        audit = {"status": "VERIFIED", "kind": kind, "launch_sha256": launch_ref["sha256"], "boot_id": launch["boot_id"],
            "coverage_start_monotonic_ns": 0, "coverage_end_monotonic_ns": cleanup_end, "auditor": dml.reference(__file__),
            "raw_artifacts": [dml.reference(raw)], "budget_verified": True, "resource_failures": [],
            "services": {role: {**pin, "artifact": bindings[role + "_artifact"]} for role, pin in cpu.items()},
            "observed_state": value["license_state"] if phase == "AB" else "ORIGINAL_A_NO_LICENSE"}
        manifest[key] = save(root / (kind + ".json"), audit)
    return manifest


class DmlNormalizationTest(unittest.TestCase):
    def test_capacity_aa_and_ab_normalize_with_actual_boundaries_without_qualifying(self):
        for phase in ("CAPACITY", "AA", "AB"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                manifest = normalization_fixture(Path(temporary), phase, formal=True); audit = dml.normalize(manifest)
                self.assertEqual(audit["status"], "VERIFIED"); self.assertFalse(audit["formal_performance_pass"])
                self.assertFalse(audit["formal_shape_met"])
                window = audit["window"]; self.assertEqual(window["monotonic_clock_domain"], "bounded_jvm_mapping")
                self.assertEqual(window["monotonic_mapping_uncertainty_ns"], 500)
                self.assertEqual(set(window["metrics"]), set(dml.statistics.METRICS))
                self.assertEqual("freeze_sha256" in window, phase == "AB")
                self.assertEqual(window["effective_duration_seconds"], 600)

    def test_diagnostic_protocol_evidence_cannot_be_submitted_as_formal_statistics(self):
        for formal, phase in ((False, "AA"), (True, "DIAGNOSTIC")):
            with self.subTest(formal=formal, phase=phase), tempfile.TemporaryDirectory() as temporary:
                manifest = normalization_fixture(Path(temporary), phase, formal=formal)
                audit = dml.normalize(manifest)
                self.assertEqual(audit["status"], "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED")
                self.assertFalse(audit["formal_performance_pass"])

    def test_missing_wait_wrong_session_clock_or_runtime_is_rejected(self):
        for mutation in ("wait", "session", "clock", "config", "process", "cleanup", "warmup", "owner"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); manifest = normalization_fixture(root); directory = root / "window"
                names = {"wait": "process-lifecycle.json", "session": "worker-0-session.json", "clock": "measurement-ready.json",
                         "config": "config.json", "process": "dml-process.json", "cleanup": "lifecycle.json", "warmup": "warmup-end.json",
                         "owner": "owner.json"}
                file = directory / names[mutation]; value = dml.read_json(file)
                if mutation == "wait": value = []
                if mutation == "session": value["group_commit"] = "async_mode"
                if mutation == "clock": value["warmup_start_ns"] = 1
                if mutation == "config": value["concurrency"] = 8
                if mutation == "process": value["pin"]["command_sha256"] = "0" * 64
                if mutation == "cleanup": value["cleanup_confirmed"] = False
                if mutation == "warmup": value["successful_requests"] = 0
                if mutation == "owner": value["identity"]["tablet_ids"] = []
                save(file, value)
                with self.assertRaises(ValueError): dml.normalize(manifest)

    def test_actual_wait_narrows_only_the_offset_interval(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); manifest = normalization_fixture(root, clock_limit=150000000)
            directory = root / "window"; original = dml.normalize(manifest)
            completion = dml.read_json(manifest["completion"]["path"])
            bridge = dml.read_json(completion["bridge"]["path"])
            # Reproduce the observed bridge width and causal overlap without using real window files.
            bridge["controller_before_ns"] = 1000000000 - 10890528
            bridge["controller_after_ns"] = 1000000000 + 112200347
            cleanup_end = dml.read_json(directory / "lifecycle.json")["cleanup_end_ns"]
            wait_file = directory / "process-lifecycle.json"; waits = dml.read_json(wait_file)
            waits[0]["controller_monotonic_ns"] = cleanup_end + 95080861
            save(wait_file, waits)
            completion["completed_monotonic_ns"] = cleanup_end + 95286904
            completion["bridge"] = save(Path(completion["bridge"]["path"]), bridge)
            manifest["completion"] = save(Path(manifest["completion"]["path"]), completion)
            for key in ("resources", "license_state"):
                file = Path(manifest[key]["path"]); observer = dml.read_json(file)
                observer["coverage_end_monotonic_ns"] = completion["completed_monotonic_ns"]
                manifest[key] = save(file, observer)
            audit = dml.normalize(manifest); evidence = audit["clock_causality_audit"]
            self.assertEqual(evidence["original_mapping"]["offset_upper_ns"], 112200347)
            self.assertEqual(evidence["effective_mapping"]["offset_upper_ns"], 95080861)
            self.assertEqual(audit["window"]["metrics"], original["window"]["metrics"])
            self.assertFalse(evidence["raw_receipts_modified"])
            self.assertEqual(audit["status"], "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED")

    def test_wait_clock_and_cleanup_causal_contradictions_are_rejected(self):
        for mutation in ("duplicate_wait", "wrong_role", "wrong_pid", "no_wait_time", "late_wait", "negative_intersection",
                         "wrong_generation", "wrong_namespace", "verification_order", "cleanup_order", "wide_original_bridge",
                         "wait_failed", "wait_incomplete", "still_live"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); manifest = normalization_fixture(root); directory = root / "window"
                file = directory / "process-lifecycle.json"; waits = dml.read_json(file)
                if mutation == "duplicate_wait": waits.append(dict(waits[0]))
                if mutation == "wrong_role": waits[0]["helper"] = "compile"
                if mutation == "wrong_pid": waits[0]["pid"] += 1
                if mutation == "wait_failed": waits[0]["exit_code"] = 2
                if mutation == "wait_incomplete": waits[0]["parent_wait_complete"] = False
                if mutation == "no_wait_time": del waits[0]["controller_monotonic_ns"]
                if mutation == "late_wait": waits[0]["controller_monotonic_ns"] += 100000
                if mutation == "negative_intersection":
                    waits[0]["controller_monotonic_ns"] = dml.read_json(directory / "lifecycle.json")["cleanup_end_ns"]
                save(file, waits)
                if mutation in ("wrong_generation", "wrong_namespace", "verification_order", "cleanup_order"):
                    file = directory / ("verification-start.json" if mutation == "verification_order" else "lifecycle.json")
                    value = dml.read_json(file)
                    if mutation == "wrong_generation": value["start_ticks"] += 1
                    elif mutation == "wrong_namespace": value["namespace"] = "net:[456]"
                    else: value["java_monotonic_ns"] = 1
                    save(file, value)
                if mutation == "still_live":
                    completion = dml.read_json(manifest["completion"]["path"])
                    completion["remaining_live_pids"] = [42]
                    manifest["completion"] = save(Path(manifest["completion"]["path"]), completion)
                if mutation == "wide_original_bridge":
                    completion = dml.read_json(manifest["completion"]["path"])
                    bridge = dml.read_json(completion["bridge"]["path"])
                    bridge["controller_after_ns"] += 100000000
                    completion["bridge"] = save(Path(completion["bridge"]["path"]), bridge)
                    manifest["completion"] = save(Path(manifest["completion"]["path"]), completion)
                with self.assertRaises(ValueError): dml.normalize(manifest)

    def test_resource_and_state_top_level_labels_do_not_replace_raw_coverage(self):
        for mutation in ("resource_failure", "raw_missing", "state", "coverage", "deployed_artifact"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); manifest = normalization_fixture(root, "AB")
                key = "license_state" if mutation == "state" else "resources"
                file = Path(manifest[key]["path"]); value = dml.read_json(file)
                if mutation == "resource_failure": value["resource_failures"] = ["BE_MEMORY_LIMIT"]
                if mutation == "raw_missing": value["raw_artifacts"] = []
                if mutation == "state": value["observed_state"] = "VALID"
                if mutation == "coverage": value["coverage_end_monotonic_ns"] = 1
                if mutation == "deployed_artifact": value["services"]["fe"]["artifact"] = value["services"]["be"]["artifact"]
                manifest[key] = save(file, value)
                with self.assertRaises(ValueError): dml.normalize(manifest)

    def test_ab_freeze_must_be_published_before_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); manifest = normalization_fixture(root, "AB")
            launch = dml.read_json(manifest["launch"]["path"]); publication = dml.read_json(launch["publication"]["path"])
            publication["published_monotonic_ns"] = launch["created_monotonic_ns"] + 1
            launch["publication"] = save(Path(launch["publication"]["path"]), publication)
            with self.assertRaisesRegex(ValueError, "before launch"): dml.validate_launch(launch, profile())

    def test_ab_license_state_cannot_change_from_the_published_cell(self):
        for state in (None, "VALID"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); manifest = normalization_fixture(root, "AB")
                launch = dml.read_json(manifest["launch"]["path"]); frozen = dml.read_json(launch["freeze"]["path"])
                if state is None: del frozen["cell"]["license_state"]
                else: frozen["cell"]["license_state"] = state
                launch["freeze"] = save(Path(launch["freeze"]["path"]), frozen)
                publication = dml.read_json(launch["publication"]["path"]); publication["freeze"] = launch["freeze"]
                launch["publication"] = save(Path(launch["publication"]["path"]), publication)
                with self.assertRaisesRegex(ValueError, "workload differs"):
                    dml.validate_launch(launch, profile())

    def test_actual_class_jdk_and_observer_source_stay_bound_after_normalization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); manifest = normalization_fixture(root); audit = dml.normalize(manifest)
            bound = {item["path"]: item for item in audit["dependency_bindings"]}
            for path in (root / "window/classes/LicenseDmlPerformance.class", root / "offline-jdk/lib/modules", Path(__file__).resolve()):
                self.assertIn(str(path), bound)
            path = root / "offline-jdk/lib/modules"; path.write_text("changed after normalization")
            with self.assertRaisesRegex(ValueError, "digest changed"): dml.verify_reference(bound[str(path)])


if __name__ == "__main__":
    unittest.main()
