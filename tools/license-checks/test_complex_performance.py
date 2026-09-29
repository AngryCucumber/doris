#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Synthetic protocol/oracle tests only: no Java, database, HTTP or browser launch."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

import complex_performance as perf


def profile(kind="cold", concurrency=1):
    return {"schema_version": 1, "profile": perf.PROFILE, "kind": kind, "concurrency": concurrency,
        "qualification": "diagnostic", "seed": 20260922, "rate_per_second": 2.0, "warmup_seconds": 5,
        "duration_seconds": 190 if kind == "hot" else 4, "timeout_seconds": 10, "drain_seconds": 30,
        "prepare_timeout_seconds": 120, "cleanup_timeout_seconds": 30, "coordination_timeout_seconds": 30,
        "max_requests": 10000, "read_account": {"username": "reader", "host": "%", "password_env": "MASSDB_UI_READ_PASSWORD"}}


def save(path, value):
    path.write_text(json.dumps(value)); return perf.reference(path)


def logs(path, value, identity=None):
    definition = perf.oracle.verified_definition(perf.read(perf.oracle.CONTRACT))
    planned = perf.plan(value); schedule = planned["schedule"]; save(path / "arrivals.json", schedule)
    identity = identity or {"pid": 42, "start_ticks": 12, "namespace": "net:[123]", "clock_domain": "offline-clock",
        "launch_token": "a" * 32, "launch_sha256": "b" * 64, "boot_id": perf.statistics.boot_id()}
    intents, requests = [], []; serial = 0; epoch = 10**10; boundaries = {}
    for phase in ("warmup", "measurement"):
        previous = {}; last = 0; event_begin = epoch + 180 * 10**9; event_ack = event_begin + 1000000
        for index, offset in enumerate(schedule[phase + "_offsets_ns"]):
            worker = index % value["concurrency"]; serial += 1; scheduled = epoch + offset
            begin = max(scheduled, previous.get(worker, 0)) + 100
            sql_begin, sql_end = begin + 10, begin + 1000
            if phase == "measurement" and value["kind"] == "hot" and scheduled < event_begin < scheduled + 10**9:
                sql_end = max(sql_end, event_ack + 1000)
            finish = sql_end + 10; previous[worker] = finish; last = max(last, finish)
            model = "changed" if phase == "measurement" and value["kind"] == "hot" and sql_begin > event_ack else "initial"
            rows = [[str(definition[model][name]) for name in definition["columns"]]]
            record = {**identity, "request_id": serial, "phase": phase, "arrival_index": index, "worker": worker,
                "scheduled_ns": scheduled, "request_started_ns": begin, "started_ns": sql_begin, "finished_ns": sql_end,
                "request_finished_ns": finish, "query_sha256_utf8": perf.oracle.FROZEN_QUERY_SHA256,
                "success": True, "sql_success": True, "timed_auxiliary_query_count": 0, "columns_verified": 33,
                "online_model": model, "columns": [{"name": name, "type": "BIGINT"} for name in definition["columns"]],
                "rows": rows, "connection_ns": 0, "session_init_ns": 0, "prepare_ns": 0, "close_ns": 0}
            record["connection_mode"] = "reuse" if value["kind"] == "hot" else "per_request"
            requests.append(record)
            intents.append({key: record[key] for key in ("request_id", "phase", "arrival_index", "worker", "scheduled_ns", "request_started_ns", "clock_domain")})
        seconds = value["warmup_seconds"] if phase == "warmup" else value["duration_seconds"]
        end = max(last, epoch + seconds * 10**9)
        first_cpu = {role: {"pid": pid, "start_ticks": pid + 10, "cpu_seconds": 1.0,
            "sample_started_java_ns": epoch - 500000000, "sample_ended_java_ns": epoch - 499999000} for role, pid in (("fe", 100), ("be", 101))}
        final_cpu = {role: {**item, "cpu_seconds": 1.25, "sample_started_java_ns": end + 1000, "sample_ended_java_ns": end + 2000} for role, item in first_cpu.items()}
        start = {**identity, "epoch_ns": epoch, "java_monotonic_ns": epoch - 499999000, "cpu": first_cpu}
        ended = {**identity, "epoch_ns": epoch, "java_monotonic_ns": end + 1000, "last_request_end_ns": last,
                 "request_interval_end_ns": end, "cpu": final_cpu}
        save(path / (phase + "-start.json"), start); save(path / (phase + "-end.json"), ended)
        boundaries[phase] = (start, ended)
        if phase == "measurement":
            event = {"clock_domain": identity["clock_domain"], "ddl_attempted": False, "ddl_success": False, "status": "NOT_APPLICABLE_COLD"}
            if value["kind"] == "hot": event.update(ddl_attempted=True, ddl_success=True, commit_outcome="ACKNOWLEDGED",
                post_ddl_inspection_success=True, scheduled_ns=event_begin, started_ns=event_begin, commit_ack_ns=event_ack,
                finished_ns=event_ack + 1000, scheduled_offset_seconds=180,
                sql="ALTER VIEW " + perf.oracle.VIEW + " AS SELECT id, grp, v + 1 AS v, payload FROM license_perf.point_rows")
            save(path / "event.json", event)
        epoch = end + 2 * 10**9
    for name, records in (("request-starts.jsonl", intents), ("requests.jsonl", requests)):
        path.joinpath(name).write_text("".join(json.dumps(row) + "\n" for row in records))
    return definition, identity, requests, boundaries


def mutate_request(path, action):
    rows = list(perf.json_lines(path)); action(rows); path.write_text("".join(json.dumps(row) + "\n" for row in rows))


class ComplexProtocolTest(unittest.TestCase):
    def test_current_shapes_preserve_hot_t180_and_long_formal_bounds(self):
        for kind in ("cold", "hot"):
            for concurrency in (1, 8): self.assertTrue(perf.plan(profile(kind, concurrency))["measurement_requests"])
        for key, item in (("concurrency", 32), ("seed", 1), ("duration_seconds", 0), ("max_requests", 100001), ("rate_per_second", float("nan"))):
            value = profile(); value[key] = item
            with self.subTest(key=key), self.assertRaises(ValueError): perf.plan(value)
        value = profile("hot"); value["duration_seconds"] = 180
        with self.assertRaisesRegex(ValueError, "t180"): perf.plan(value)
        value = profile(); value["qualification"] = "formal"
        with self.assertRaisesRegex(ValueError, "too short"): perf.plan(value)
        value.update(warmup_seconds=180, duration_seconds=6000, rate_per_second=2, max_requests=20000)
        self.assertGreater(perf.plan(value)["measurement_requests"], 10000)

    def test_arrivals_are_legacy_contiguous_poisson_not_claimed_java_sequence(self):
        value = profile("hot"); value.update(warmup_seconds=180, duration_seconds=600)
        self.assertEqual(perf.plan(value)["schedule"], perf.legacy.arrivals(2.0, 180, 600, value["max_requests"]))
        other = {**value, "concurrency": 8}
        self.assertEqual(perf.plan(value)["schedule"], perf.plan(other)["schedule"])
        self.assertNotEqual(perf.business_binding(value)["sha256"], perf.business_binding({**value, "drain_seconds": 31})["sha256"])
        self.assertIn("expovariate", perf.plan(value)["algorithm"])

    def test_all_thirty_three_columns_and_hot_before_after_are_verified(self):
        for kind in ("cold", "hot"):
            for concurrency in (1, 8):
                with self.subTest(kind=kind, concurrency=concurrency), tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary); value = profile(kind, concurrency); definition, identity, _, _ = logs(path, value)
                    audit = perf.audit_requests(path, value, definition, identity)
                    self.assertEqual(audit["measurement"]["successful_requests"], perf.plan(value)["measurement_requests"])
                    if kind == "hot":
                        self.assertGreater(audit["measurement"]["models"]["changed"], 0)
                        self.assertEqual(audit["ddl"]["scheduled_ns"], perf.read(path / "measurement-start.json")["epoch_ns"] + 180 * 10**9)

    def test_corruption_observers_missing_receipts_and_foreign_clocks_reject(self):
        for mutation in ("one_column", "mixed_model", "columns", "missing", "duplicate", "query_id", "explain", "clock", "worker", "timing", "error"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary); value = profile("hot", 8); definition, identity, _, _ = logs(path, value)
                def change(rows):
                    row = next(item for item in rows if item["phase"] == "measurement")
                    if mutation == "one_column": row["rows"][0][32] = str(int(row["rows"][0][32]) + 1)
                    if mutation == "mixed_model": row["rows"][0][32] = str(definition["changed"][definition["columns"][32]])
                    if mutation == "columns": row["columns"][0]["name"] = "wrong"
                    if mutation == "missing": rows.pop()
                    if mutation == "duplicate": rows.append(dict(row))
                    if mutation == "query_id": row["query_id"] = "abc-def"
                    if mutation == "explain": row["explain_file"] = "explain.json"
                    if mutation == "clock": row["clock_domain"] = "another-jvm"
                    if mutation == "worker": row["worker"] = (row["worker"] + 1) % 8
                    if mutation == "timing": row["started_ns"] = row["scheduled_ns"] - 1
                    if mutation == "error": row["success"] = False
                mutate_request(path / "requests.jsonl", change)
                with self.assertRaises(ValueError): perf.audit_requests(path, value, definition, identity)

    def test_unknown_early_or_omitted_ddl_and_bad_cpu_reject(self):
        for mutation in ("early", "unknown", "failed", "clock", "offset", "cpu", "end"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary); value = profile("hot"); definition, identity, _, _ = logs(path, value)
                file = path / ("measurement-end.json" if mutation in ("cpu", "end") else "event.json"); item = perf.read(file)
                if mutation == "early": item["started_ns"] -= 1
                if mutation == "unknown": item["commit_outcome"] = "UNKNOWN"
                if mutation == "failed": item["ddl_success"] = False
                if mutation == "clock": item["clock_domain"] = "foreign"
                if mutation == "offset": item["scheduled_offset_seconds"] = 1
                if mutation == "cpu": item["cpu"]["fe"]["start_ticks"] += 1
                if mutation == "end": item["request_interval_end_ns"] -= 1
                save(file, item)
                with self.assertRaises(ValueError): perf.audit_requests(path, value, definition, identity)

    def test_cold_cannot_claim_hot_path_or_timed_query_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); value = profile(); definition, identity, _, _ = logs(path, value)
            event = perf.read(path / "event.json"); event["ddl_attempted"] = True; save(path / "event.json", event)
            with self.assertRaises(ValueError): perf.audit_requests(path, value, definition, identity)

    def test_prepare_refuses_existing_view_without_adopting_or_dropping_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); cluster = path / "cluster.json"; save(cluster, {"namespace": "net:[123]"})
            api = Mock(); api.owned.side_effect = Path; api.save.side_effect = save; api.sha.side_effect = perf.statistics.digest
            guard, sql = Mock(), Mock()
            source = {"n": "1000000", "distinct_ids": "1000000", "min_id": "0", "max_id": "999999",
                      "sum_id": "499999500000", "sum_grp": "511370976", "sum_v": "49999500000", "bad_rows": "0"}
            sql.one.side_effect = [{"success": True, "columns": [{"name": key} for key in source], "rows": [source]},
                                  {"success": True}, {"success": True, "columns": [{"name": "Tables"}], "rows": [{"Tables": "license_complex_view"}]}]
            with self.assertRaisesRegex(ValueError, "existing"):
                perf.prepare_owned_view(api, sql, guard, cluster, path, path / "owner.lock")
            self.assertFalse((path / "owner.lock").exists())
            self.assertFalse(any("DROP" in str(call) or "CREATE VIEW" in str(call) for call in sql.one.call_args_list))

    def test_log_truncation_and_declared_resource_cap_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "raw.jsonl"; path.write_text('{"x":1}')
            with self.assertRaisesRegex(ValueError, "partial"): list(perf.json_lines(path))
            path.write_text('{"x":1}\n')
            with self.assertRaisesRegex(ValueError, "bound"): list(perf.json_lines(path, 1))

    def test_compile_failure_can_clean_only_an_unlaunched_owned_view(self):
        for started in (False, True):
            with self.subTest(started=started), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary); token = "c" * 32; view = "owned definition"
                lock = path / "lock"; lock.write_text(token + "\n")
                owner = {"view_owner_token": token, "initial_show_create_view_sha256": hashlib.sha256(view.encode()).hexdigest()}
                save(path / "view-owner.json", owner)
                save(path / "p4-completion.json", {"remaining_live_pids": [], "helper_pid": None})
                if started: save(path / "complex-process.json", {"pin": {"pid": 42}})
                source = {"n": 1000000, "distinct_ids": 1000000, "min_id": 0, "max_id": 999999,
                          "sum_id": 499999500000, "sum_grp": 511370976, "sum_v": 49999500000, "bad_rows": 0}
                schema = {"success": True, "columns": [{"name": "Create Table"}], "rows": [{"Create Table": "schema"}]}
                prepared = {"create_success": True, "lock_path": str(lock), "token": token, "initial_view": view,
                            "source_before": source, "source_create_before": schema}
                sql, api, guard = Mock(), Mock(), Mock(); api.save.side_effect = save
                sql.one.side_effect = [
                    {"success": True, "columns": [{"name": "View"}, {"name": "Create View"}], "rows": [{"View": "view", "Create View": view}]},
                    {"success": True, "columns": [{"name": name} for name in source], "rows": [{key: str(item) for key, item in source.items()}]}, schema, {"success": True},
                    {"success": True, "columns": [{"name": "Tables"}], "rows": []}]
                if started:
                    with self.assertRaises(ValueError): perf.finish_owned_view(api, sql, guard, path, prepared, False)
                    sql.one.assert_not_called(); self.assertTrue(lock.exists())
                else:
                    result = perf.finish_owned_view(api, sql, guard, path, prepared, False)
                    self.assertFalse(result["helper_was_waited"]); self.assertFalse(lock.exists())


def normalization_fixture(root, phase="DIAGNOSTIC", kind="cold"):
    """Invented protocol bytes for negative tests, never database performance evidence."""
    directory = root / "window"; directory.mkdir(); value = profile(kind)
    workload = save(root / "workload.json", value)
    bindings = {key: perf.reference(path) for key, path in (("runner", perf.SOURCE), ("java_helper", perf.JAVA),
        ("legacy_helper", perf.legacy.JAVA), ("oracle", perf.oracle.__file__), ("lifecycle", perf.lifecycle.__file__),
        ("clock_adapter", perf.clocks.__file__), ("statistics", perf.statistics.__file__))}
    for key in ("jdbc_driver", "fe_artifact", "be_artifact", "environment", "configuration", "fixture", "client"):
        file = root / ("mariadb-java-client-3.0.9.jar" if key == "jdbc_driver" else key)
        file.write_text("SYNTHETIC OFFLINE ONLY " + key); bindings[key] = perf.reference(file)
    runtime = root / "jdk"
    for relative in ("bin/java", "bin/javac", "lib/modules", "release"):
        file = runtime / relative; file.parent.mkdir(parents=True, exist_ok=True); file.write_text("OFFLINE " + relative)
    classes = directory / "classes"; classes.mkdir(); (classes / "LicenseComplexPerformance.class").write_text("OFFLINE not executable")
    frozen = {"config": value, "input_path": workload["path"], "input_sha256": workload["sha256"], "java_home": str(runtime),
        "jdk_runtime": {name: perf.statistics.digest(runtime / name) for name in ("bin/java", "bin/javac", "lib/modules", "release")},
        "source_sha256": {str(path): perf.statistics.digest(path) for path in (perf.SOURCE, perf.JAVA, perf.legacy.JAVA)},
        "dependencies_sha256": {bindings["jdbc_driver"]["path"]: bindings["jdbc_driver"]["sha256"]}}
    build = {"source_commit": "a" * 40}
    for key, field in (("fe_artifact", "fe_sha256"), ("be_artifact", "be_sha256"), ("environment", "environment_sha256"),
                       ("configuration", "configuration_sha256"), ("fixture", "fixture_sha256"), ("client", "client_sha256")):
        build[field] = bindings[key]["sha256"]
    launch = {"schema_version": 1, "phase": phase, "variant": "B" if phase == "AB" else "A", "launch_token": "a" * 32,
        "window_id": "G2-complex-offline", "pair_id": 0, "boot_id": perf.statistics.boot_id(), "created_monotonic_ns": 500000000,
        "utc_anchor": {"before_monotonic_ns": 500000000, "after_monotonic_ns": 500000001, "utc_ns": 1000000000},
        "max_clock_uncertainty_ns": 150000000, "identity": build, "workload": workload, "bindings": bindings,
        "service_start_ticks": {"fe": 110, "be": 111}}
    if phase == "AB":
        freeze = save(root / "freeze.json", {"status": "FROZEN_ELIGIBLE", "identities": {"A": build, "B": build},
            "cell": {"group": "G2", "workload_sha256": perf.business_binding(value)["sha256"], "rate": value["rate_per_second"],
                "concurrency": value["concurrency"], "connection_mode": "reuse" if kind == "hot" else "per_request", "seed": 20260922,
                "warmup_seconds": value["warmup_seconds"], "duration_seconds": value["duration_seconds"],
                "request_count": perf.plan(value)["measurement_requests"], "arrival_schedule_sha256": perf.plan(value)["measurement_schedule_sha256"]}})
        launch.update(freeze=freeze, publication=save(root / "publication.json", {"freeze": freeze, "boot_id": launch["boot_id"],
                                                                              "published_monotonic_ns": 400000000}))
    launch_ref = save(directory / "p4-launch.json", launch)
    identity = {"pid": 42, "start_ticks": 12, "namespace": "net:[123]", "clock_domain": "offline-clock", "schema_version": 1,
        "launch_token": launch["launch_token"], "launch_sha256": launch_ref["sha256"], "boot_id": launch["boot_id"]}
    definition, _, requests, boundaries = logs(directory, value, identity)
    definition_ref = save(directory / "definition.json", definition); arrivals_ref = perf.reference(directory / "arrivals.json")
    cpu = {role: {key: boundaries["warmup"][0]["cpu"][role][key] for key in ("pid", "start_ticks")} for role in ("fe", "be")}
    view = "synthetic initial owned view"
    owner_ref = save(directory / "view-owner.json", {"view_owner_token": "c" * 32, "initial_show_create_view_sha256": hashlib.sha256(view.encode()).hexdigest()})
    config = {"p4_launch": launch_ref, "performance_profile": perf.PROFILE, "mode": "text", "case_id": "LP-007" if kind == "hot" else "LP-006",
        "connection_mode": "reuse" if kind == "hot" else "per_request", "concurrency": value["concurrency"], "cpu_services": cpu,
        "drain_seconds": value["drain_seconds"], "timeout_seconds": value["timeout_seconds"], "request_limit": value["max_requests"],
        "qualification": value["qualification"], "reader_user": value["read_account"]["username"], "reader_password_env": value["read_account"]["password_env"],
        "definition_file": definition_ref["path"], "definition_sha256": definition_ref["sha256"], "arrival_file": arrivals_ref["path"],
        "arrival_sha256": arrivals_ref["sha256"], "view_owner_token": "c" * 32, "owner_record_file": owner_ref["path"],
        "controller_owner_record_sha256": owner_ref["sha256"], "expected_initial_show_create_view_sha256": hashlib.sha256(view.encode()).hexdigest()}
    save(directory / "config.json", config)
    save(directory / "identity.json", {**identity, "java_runtime_version": "17.0.4+8", "performance_profile": perf.PROFILE,
        "query_sha256_utf8": perf.oracle.FROZEN_QUERY_SHA256, "mode": "text", "connection_mode": config["connection_mode"],
        "concurrency": value["concurrency"], "definition_sha256": definition_ref["sha256"], "arrival_sha256": arrivals_ref["sha256"],
        "profile_enabled": False, "timed_query_identity_or_explain_queries": 0})
    save(directory / "helper-identity.json", {"frozen": frozen, "classes": {str(classes / "LicenseComplexPerformance.class"):
                                                                            perf.statistics.digest(classes / "LicenseComplexPerformance.class")}})
    helper = {**identity, "nonce": "c" * 32, "helper_pid": 42, "helper_start_ticks": 12, "jvm_sample_ns": 1000000000}
    helper_ref = save(directory / "p4-helper-clock.json", helper)
    bridge_ref = save(directory / "p4-clock-bridge.json", {**helper, "controller_before_ns": 1000001000,
        "controller_after_ns": 1000002000, "helper_clock": helper_ref})
    warm_start, warm_end = boundaries["warmup"]; start, end = boundaries["measurement"]
    save(directory / "ready.json", {**identity, "java_monotonic_ns": 900000000})
    save(directory / "measurement-ready.json", {**identity, "java_monotonic_ns": warm_end["java_monotonic_ns"] + 1000})
    for worker in range(value["concurrency"]):
        save(directory / f"worker-setup-{worker}.json", {"worker": worker, "success": True, "clock_domain": identity["clock_domain"],
            "connection_mode": config["connection_mode"], "started_ns": 1000, "finished_ns": 2000,
            "connection_ns": 0, "session_init_ns": 0, "prepare_ns": 0})
    finished = end["java_monotonic_ns"] + 100000
    save(directory / "cleanup.json", {"clock_domain": identity["clock_domain"], "started_ns": end["java_monotonic_ns"] + 1000,
        "finished_ns": finished - 1000, "success": True, "reader_threads_terminated": True, "event_thread_terminated": True,
        "cleanup_threads_terminated": True, "remaining_connection_handles": 0, "initial_definition_matches": True, "deadline_exceeded": False})
    save(directory / "summary.json", {"clock_domain": identity["clock_domain"], "success": True, "event_commit_unknown": False,
        "request_intents": len(requests), "completed_receipts": len(requests), "uncompleted_intents": 0})
    save(directory / "p4-helper-finished.json", {**identity, "java_monotonic_ns": finished, "success": True, "workers_closed": True})
    completion_ref = save(directory / "p4-completion.json", {"launch_token": identity["launch_token"], "launch_sha256": launch_ref["sha256"],
        "boot_id": identity["boot_id"], "helper_pid": 42, "helper_start_ticks": 12, "exit_code": 0, "remaining_live_pids": [],
        "completed_monotonic_ns": finished + 10000, "bridge": bridge_ref})
    command = [str(runtime / "bin/java"), "-Xmx512m", "-cp", os.pathsep.join([str(classes), bindings["jdbc_driver"]["path"]]),
               "LicenseComplexPerformance", str(directory / "config.json")]
    command_hash = hashlib.sha256(b"\0".join(os.fsencode(item) for item in command) + b"\0").hexdigest()
    save(directory / "complex-process.json", {"pin": {**identity, "exe": str(runtime / "bin/java"), "command_sha256": command_hash},
                                               "expected_launch": {"command_sha256": command_hash}})
    save(directory / "process-lifecycle.json", [{"helper": "complex", "reason": "OWNED_PARENT_WAIT", "pid": 42, "exit_code": 0,
                                                "parent_wait_complete": True, "controller_monotonic_ns": finished + 9000}])
    save(directory / "controller.json", {"status": "RAW_WINDOW_COMPLETE", "errors": [], "owned_child_exited": True})
    source = {"n": 1000000, "distinct_ids": 1000000, "min_id": 0, "max_id": 999999,
              "sum_id": 499999500000, "sum_grp": 511370976, "sum_v": 49999500000, "bad_rows": 0}
    schema = {"success": True, "columns": [{"name": "Create Table"}], "rows": [{"Create Table": "synthetic source schema"}]}
    save(directory / "preparation.json", {"status": "PREPARED", "create_success": True, "source_before": source,
        "source_create_before": schema, "finished_monotonic_ns": 600000000, "token": "c" * 32, "initial_view": view})
    save(directory / "final-oracle.json", {"status": "OWNED_VIEW_REMOVED_SOURCE_VERIFIED", "source_after": source,
        "source_create_after": schema, "completed_monotonic_ns": finished + 20000, "initial_view_sha256": hashlib.sha256(view.encode()).hexdigest(),
        "owner": owner_ref, "helper_was_waited": True})
    query = {**requests[0], "query_id": "a-b", "query_id_same_connection": True, "query_id_sql": "SELECT last_query_id()", "connection_id": 123}
    query_ref = save(root / "path-query.json", query)
    text = (f"Summary:\n   - Profile ID: a-b\n   - Task State: OK\n   - Sql Statement: {definition['query_sql']}\n"
        "   - Distributed Plan: plan\nExecution Summary:\n   - Parse SQL Time: 1ms\n   - Plan Time: 9ms\n"
        "   - Nereids Analysis Time: 2ms\n   - Nereids Rewrite Time: 3ms\n   - Nereids Optimize Time: N/A\n"
        "   - Nereids Translate Time: 4ms\n   - Is Nereids: Yes\n   - Is Cached: " + ("Yes" if kind == "hot" else "No") + "\n")
    (root / "profile.txt").write_text(text)
    explain_ref = save(root / "explain.json", {"sql": "EXPLAIN PHYSICAL PLAN " + definition["query_sql"],
                                             "rows": ["PhysicalSqlCache" if kind == "hot" else "PhysicalOlapScan"]})
    session_ref = save(root / "path-session.json", {"reader_user": "reader", "current_user": "'reader'@'%'",
        "current_catalog": "internal", "current_database": "license_perf", "connection_id": 123,
        "settings": {"enable_sql_cache": kind == "hot", "enable_query_cache": False,
                     "enable_short_circuit_query": False, "enable_profile": True}})
    manifest = {"window_directory": str(directory), "launch": launch_ref, "completion": completion_ref,
        "path_preflight": save(root / "path.json", {"status": "VERIFIED", "kind": kind, "auditor": perf.reference(__file__),
            "fe_artifact": bindings["fe_artifact"], "service_start_ticks": launch["service_start_ticks"], "completed_monotonic_ns": 700000000,
            "query_receipt": query_ref, "profile_text": perf.reference(root / "profile.txt"), "explain_receipt": explain_ref,
            "session_receipt": session_ref})}
    for key in ("resources", "license_state"):
        raw = root / (key + ".raw"); raw.write_text("OFFLINE fabricated evidence for rejection tests")
        manifest[key] = save(root / (key + ".json"), {"status": "VERIFIED", "kind": key, "launch_sha256": launch_ref["sha256"],
            "boot_id": launch["boot_id"], "coverage_start_monotonic_ns": 0, "coverage_end_monotonic_ns": finished + 20000,
            "auditor": perf.reference(__file__), "raw_artifacts": [perf.reference(raw)], "budget_verified": True, "resource_failures": [],
            "services": {role: {**pin, "artifact": bindings[role + "_artifact"]} for role, pin in cpu.items()},
            "observed_state": "VALID" if phase == "AB" else "ORIGINAL_A_NO_LICENSE"})
    return manifest


class ComplexNormalizationTest(unittest.TestCase):
    def test_coordinated_raw_launch_substitution_cannot_detach_from_actual_bridge(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); manifest = normalization_fixture(root, "AB"); directory = root / "window"
            forged = {"launch_token": "e" * 32, "launch_sha256": "d" * 64, "boot_id": "foreign-boot"}
            for name in ("identity", "ready", "warmup-start", "warmup-end", "measurement-ready", "measurement-start", "measurement-end", "p4-helper-finished"):
                file = directory / (name + ".json"); save(file, {**perf.read(file), **forged})
            mutate_request(directory / "requests.jsonl", lambda rows: [row.update(forged) for row in rows])
            with self.assertRaisesRegex(ValueError, "another launch/boot"): perf.normalize(manifest)

    def test_ab_wrong_order_or_workload_is_rejected_before_launch(self):
        for mutation in ("mode", "seed", "schedule", "late_publication", "drain"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); manifest = normalization_fixture(root, "AB")
                launch = perf.read(manifest["launch"]["path"]); value = perf.read(launch["workload"]["path"])
                frozen = perf.read(launch["freeze"]["path"]); published = perf.read(launch["publication"]["path"])
                if mutation == "mode": frozen["cell"]["connection_mode"] = "reuse"
                if mutation == "seed": frozen["cell"]["seed"] = 1
                if mutation == "schedule": frozen["cell"]["arrival_schedule_sha256"] = "0" * 64
                if mutation == "drain":
                    value["drain_seconds"] += 1; launch["workload"] = save(Path(launch["workload"]["path"]), value)
                launch["freeze"] = save(Path(launch["freeze"]["path"]), frozen); published["freeze"] = launch["freeze"]
                if mutation == "late_publication": published["published_monotonic_ns"] = launch["created_monotonic_ns"] + 1
                launch["publication"] = save(Path(launch["publication"]["path"]), published)
                with self.assertRaises(ValueError): perf.validate_launch(launch, value)

    def test_capacity_aa_ab_and_diagnostic_keep_raw_evidence_and_never_claim_pass(self):
        for phase in ("CAPACITY", "AA", "AB", "DIAGNOSTIC"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                audit = perf.normalize(normalization_fixture(Path(temporary), phase))
                self.assertEqual(audit["status"], "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED")
                self.assertFalse(audit["formal_performance_pass"])
                self.assertEqual("freeze_sha256" in audit["window"], phase == "AB")
                self.assertEqual(audit["window"]["monotonic_mapping_uncertainty_ns"], 500)
                self.assertEqual(set(audit["window"]["metrics"]), set(perf.statistics.METRICS))
                self.assertTrue(any(item["path"].endswith("lib/modules") for item in audit["dependency_bindings"]))

    def test_hot_preflight_and_event_are_separate_from_timed_raw_requests(self):
        with tempfile.TemporaryDirectory() as temporary:
            audit = perf.normalize(normalization_fixture(Path(temporary), kind="hot"))
            self.assertGreater(audit["request_audit"]["measurement"]["models"]["changed"], 0)

    def test_false_windows_configuration_ownership_and_generation_are_rejected(self):
        for mutation in ("wait", "duplicate_wait", "wrong_pid", "cleanup_order", "ready_clock", "worker", "source", "config",
                         "owner", "java_runtime", "class", "cpu_generation", "bridge_width", "wait_intersection", "view_final"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); manifest = normalization_fixture(root); directory = root / "window"
                names = {"wait": "process-lifecycle.json", "duplicate_wait": "process-lifecycle.json", "wrong_pid": "process-lifecycle.json",
                    "wait_intersection": "process-lifecycle.json", "cleanup_order": "cleanup.json", "ready_clock": "measurement-ready.json",
                    "worker": "worker-setup-0.json", "source": "preparation.json", "config": "config.json", "owner": "view-owner.json",
                    "java_runtime": "identity.json", "cpu_generation": "measurement-start.json", "bridge_width": "p4-clock-bridge.json",
                    "view_final": "final-oracle.json"}
                if mutation == "class": (directory / "classes/LicenseComplexPerformance.class").write_text("changed")
                else:
                    path = directory / names[mutation]; item = perf.read(path)
                    if mutation == "wait": item = []
                    if mutation == "duplicate_wait": item.append(dict(item[0]))
                    if mutation == "wrong_pid": item[0]["pid"] += 1
                    if mutation == "wait_intersection": item[0]["controller_monotonic_ns"] = perf.read(directory / "p4-helper-finished.json")["java_monotonic_ns"]
                    if mutation == "cleanup_order": item["started_ns"] = 1
                    if mutation == "ready_clock": item["clock_domain"] = "foreign"
                    if mutation == "worker": item["finished_ns"] = 10**15
                    if mutation == "source": item["source_before"]["bad_rows"] = 1
                    if mutation == "config": item["case_id"] = "LP-007"
                    if mutation == "owner": item["view_owner_token"] = "other"
                    if mutation == "java_runtime": item["java_runtime_version"] = "17.0.8"
                    if mutation == "cpu_generation": item["cpu"]["fe"]["start_ticks"] += 1
                    if mutation == "view_final": item["helper_was_waited"] = False
                    if mutation == "bridge_width": item["controller_after_ns"] += 1000000000
                    ref = save(path, item)
                    if mutation == "bridge_width":
                        completion = perf.read(manifest["completion"]["path"]); completion["bridge"] = ref
                        manifest["completion"] = save(Path(manifest["completion"]["path"]), completion)
                with self.assertRaises(ValueError): perf.normalize(manifest)

    def test_external_resource_state_and_path_failures_never_qualify(self):
        for mutation in ("resource_failure", "missing_coverage", "wrong_state", "late_preflight", "query_identity", "path_cache",
                         "admin_preflight", "wrong_database", "wrong_session_connection"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); manifest = normalization_fixture(root)
                key = "resources" if mutation in ("resource_failure", "missing_coverage") else "license_state" if mutation == "wrong_state" else "path_preflight"
                path = Path(manifest[key]["path"]); item = perf.read(path)
                if mutation == "resource_failure": item["resource_failures"] = ["rss exceeded"]
                if mutation == "missing_coverage": item["coverage_end_monotonic_ns"] = 1
                if mutation == "wrong_state": item["observed_state"] = "VALID"
                if mutation == "late_preflight": item["completed_monotonic_ns"] = 10**15
                if mutation in ("query_identity", "path_cache"):
                    field = "query_receipt" if mutation == "query_identity" else "explain_receipt"
                    nested = Path(item[field]["path"]); raw = perf.read(nested)
                    if mutation == "query_identity": raw["query_id_same_connection"] = False
                    else: raw["rows"] = ["PhysicalSqlCache"]
                    item[field] = save(nested, raw)
                if mutation in ("admin_preflight", "wrong_database", "wrong_session_connection"):
                    nested = Path(item["session_receipt"]["path"]); raw = perf.read(nested)
                    if mutation == "admin_preflight": raw["current_user"] = "'root'@'%'"
                    if mutation == "wrong_database": raw["current_database"] = "other"
                    if mutation == "wrong_session_connection": raw["connection_id"] += 1
                    item["session_receipt"] = save(nested, raw)
                manifest[key] = save(path, item)
                with self.assertRaises(ValueError): perf.normalize(manifest)


JAVA_PROXY_TEST = r'''
import java.lang.reflect.*;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
public final class ComplexOfflineProbe {
    static List<String> statements = new ArrayList<>();
    static int width = 33;
    static Object fallback(Class<?> type) {
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        return null;
    }
    static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler));
    }
    static ResultSet rows(boolean identity) {
        int[] count = {0};
        ResultSetMetaData metadata = proxy(ResultSetMetaData.class, (p,m,a) -> switch (m.getName()) {
            case "getColumnCount" -> identity ? 1 : width;
            case "getColumnLabel" -> "column" + a[0];
            case "getColumnTypeName" -> "BIGINT";
            default -> fallback(m.getReturnType());
        });
        return proxy(ResultSet.class, (p,m,a) -> switch (m.getName()) {
            case "getMetaData" -> metadata;
            case "next" -> count[0]++ == 0;
            case "getString" -> identity ? "a-b" : "1";
            default -> fallback(m.getReturnType());
        });
    }
    static Statement statement() {
        return proxy(Statement.class, (p,m,a) -> {
            if (m.getName().equals("execute")) {
                String sql = (String) a[0]; statements.add(sql); return !sql.startsWith("SET ");
            }
            if (m.getName().equals("executeQuery")) {
                statements.add((String) a[0]); return rows(true);
            }
            if (m.getName().equals("getResultSet")) return rows(false);
            return fallback(m.getReturnType());
        });
    }
    static void check(boolean value) { if (!value) throw new AssertionError(); }
    public static void main(String[] args) throws Exception {
        Connection connection = proxy(Connection.class, (p,m,a) -> m.getName().equals("createStatement")
                ? statement() : fallback(m.getReturnType()));
        Map<String,Object> receipt = new LinkedHashMap<>();
        LicenseComplexPlanningFixture.executeTarget(statement(), "SELECT target", false, receipt);
        check(statements.equals(List.of("SELECT target")) && !receipt.containsKey("query_id")
                && ((List<?>)receipt.get("columns")).size() == 33 && Boolean.TRUE.equals(receipt.get("sql_success")));
        statements.clear(); receipt.clear();
        LicenseComplexPlanningFixture.executeAndIdentify(connection, statement(), "SELECT target", false, 5, receipt);
        check(statements.equals(List.of("SELECT target", "SELECT last_query_id()"))
                && Boolean.TRUE.equals(receipt.get("query_id_same_connection")) && receipt.get("query_id").equals("a-b"));
        for (boolean hot : List.of(false,true)) {
            statements.clear(); LicenseComplexPerformance.initializeSession(connection, hot, 5);
            check(statements.equals(List.of("SET enable_sql_cache=" + hot, "SET enable_query_cache=false",
                    "SET enable_short_circuit_query=false", "SET enable_profile=false")));
        }
        width = 32;
        try { LicenseComplexPlanningFixture.executeTarget(statement(), "SELECT target", false, new LinkedHashMap<>());
              throw new AssertionError("partial target accepted"); }
        catch (IllegalArgumentException expected) { check(expected.getMessage().equals("TARGET_RESULT_WIDTH")); }
        System.out.println("PASS target-only SQL, preserved legacy identity SQL, four exact session settings, partial result refusal");
    }
}
'''


class ComplexJavaOfflineTest(unittest.TestCase):
    @unittest.skipUnless(os.getenv("MASSDB_COMPLEX_TEST_JAVA_HOME") and os.getenv("MASSDB_COMPLEX_TEST_CLASSPATH"),
                         "Explicit exact JDK/dependency locations required for offline proxy compilation")
    def test_real_java_methods_with_local_jdbc_proxies_never_connect(self):
        java = Path(os.environ["MASSDB_COMPLEX_TEST_JAVA_HOME"]) / "bin/java"
        self.assertIn('JAVA_VERSION="17.0.4"', (java.parent.parent / "release").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); file = directory / "ComplexOfflineProbe.java"; file.write_text(JAVA_PROXY_TEST)
            classpath = os.environ["MASSDB_COMPLEX_TEST_CLASSPATH"]
            result = subprocess.run([str(java.with_name("javac")), "-J-Xmx256m", "--release", "17", "-encoding", "UTF-8",
                "-cp", classpath, "-d", temporary, str(perf.legacy.JAVA), str(perf.JAVA), str(file)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(java), "-Xmx128m", "-cp", temporary + os.pathsep + classpath, "ComplexOfflineProbe"],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS target-only SQL", result.stdout)


if __name__ == "__main__":
    unittest.main()
