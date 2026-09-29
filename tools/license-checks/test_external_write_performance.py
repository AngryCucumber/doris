#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Invented offline receipts, never actual SQL/performance evidence or a mock performance run."""

import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import external_write_performance as sink


def profile(concurrency=1):
    return {"schema_version": 1, "profile": sink.PROFILE, "qualification": "diagnostic", "license_state": "VALID",
        "concurrency": concurrency, "rate_per_second": 10., "seed": 20260922, "rows_per_operation": 100,
        "warmup_seconds": 2, "duration_seconds": 3, "timeout_seconds": 5, "drain_seconds": 10,
        "prepare_timeout_seconds": 120, "verify_timeout_seconds": 120, "cleanup_timeout_seconds": 30,
        "coordination_timeout_seconds": 10, "max_requests": 1000, "max_rows": 100000,
        "min_disk_free_bytes": 2 * 1024**3, "max_raw_ledger_bytes": 64 * 1024**2,
        "read_account": {"username": "reader", "host": "%", "password_env": "SINK_READ_PASSWORD"},
        "write_account": {"username": "writer", "host": "%", "password_env": "SINK_WRITE_PASSWORD"},
        "native_account": {"host": "10.254.29.2", "port": 5432, "database": "p4db", "user": "p4fixture", "password_env": "SINK_PG_PASSWORD"},
        "storage_paths": ["/offline-only/postgres/data"], "source_data_sha256": sink.external.MODEL_SHA}


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n"); return sink.ref(path)


def mutate(path, function):
    value = sink.read(path); function(value); save(path, value)


def raw_stat(pid, generation, user, system):
    fields = ["S"] + ["0"] * 49; fields[11] = str(user); fields[12] = str(system); fields[19] = str(generation)
    return f"{pid} (offline fixture) " + " ".join(fields) + "\n"


def row_model(token, request, identifier):
    payload = hashlib.md5(str(identifier).encode(), usedforsecurity=False).hexdigest()
    return f"{token}\t{request}\t{identifier}\t{identifier % 1024}\t{identifier % 100000}\t{payload}\n"


def raw_fixture(directory, value=None, identity=None):
    value = value or profile(); planned = sink.plan(value)
    identity = identity or {"token": "a" * 32}; token = identity["token"]
    services = {role: {"pid": pid, "start_ticks": pid + 10} for role, pid in (("fe", 100), ("be", 101))}
    config = {**value, "catalog": "owned_catalog", "clock_ticks_per_second": 100, "cpu_services": services}
    save(directory / "config.json", config)
    for worker in range(value["concurrency"]):
        save(directory / f"worker-{worker}-session.json", {**identity, "worker": worker, "connections_opened": 1,
            "driver": "3.0.9", "auto_commit": False, "server_connection_id": worker + 200, "socket_local_port": worker + 40000,
            "actual_settings": ["false", "false", "off_mode", "5", "5", "'writer'@'%'", "1"]})
    epoch = 10_000_000_000
    for phase, duration in (("warmup", value["warmup_seconds"]), ("measurement", value["duration_seconds"])):
        selected = planned[phase]; (directory / (phase + "-arrivals.tsv")).write_text(selected["tsv"])
        receipts = [[] for _ in range(value["concurrency"])]; last = epoch; previous = [epoch] * value["concurrency"]
        for sequence, offset in enumerate(selected["arrivals"]):
            worker = sequence % value["concurrency"]; request = selected["first_request"] + sequence
            scheduled = epoch + offset; begin = max(previous[worker], scheduled) + 100; finish = begin + 1000
            previous[worker] = finish; last = max(last, finish)
            sql = (f"INSERT INTO owned_catalog.public.p4_sink_{token}(run_id,request_id,id,grp,v,payload) SELECT '{token}',{request},"
                   "id,grp,v,payload FROM internal.license_perf.point_rows WHERE id >= 0 AND id < 100")
            receipts[worker].append({"worker": worker, "sequence": sequence, "request_id": request, "scheduled_ns": scheduled,
                "started_ns": begin, "finished_ns": finish, "e2e_ns": finish - scheduled, "service_ns": finish - begin,
                "queue_ns": begin - scheduled, "outcome": "ACK", "affected_rows": 0, "execute_calls": 1,
                "server_connection_id": worker + 200, "socket_local_port": worker + 40000, "connection_aborted": False,
                "sql_sha256": hashlib.sha256(sql.encode()).hexdigest(), "error_code": 0, "sql_state": "NONE", "timeout": False})
        for worker, rows in enumerate(receipts):
            (directory / f"{phase}-{worker}.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        end = max(epoch + duration * 10**9, last)
        def cpu(final):
            return {role: {**pin, "raw_stat": raw_stat(pin["pid"], pin["start_ticks"], 200 if final else 100, 20 if final else 10),
                "sample_started_java_ns": end + 1 if final else epoch - 1000,
                "sample_ended_java_ns": end + 50 if final else epoch - 100} for role, pin in services.items()}
        save(directory / (phase + "-start.json"), {**identity, "epoch_ns": epoch, "cpu": cpu(False)})
        save(directory / (phase + "-end.json"), {**identity, "epoch_ns": epoch, "java_monotonic_ns": end + 100,
            "last_request_end_ns": last, "request_interval_end_ns": end, "scheduled_requests": selected["requests"],
            "successful_requests": selected["requests"], "arrival_schedule_sha256": sink.stats.digest(directory / (phase + "-arrivals.tsv")),
            "cpu": cpu(True)})
        epoch = end + 10**9
    text = "".join(row_model(token, request, identifier) for request in range(planned["total_requests"]) for identifier in range(100))
    (directory / "native-target.tsv").write_text(text)
    save(directory / "native-resolution.json", [{"request_id": i, "outcome": "ACK", "rows": 100,
        "ack_upgraded_from_visibility": False, "absence_proves_rollback": False} for i in range(planned["total_requests"])])
    source = {"rows": 1000000, "canonical_sha256": sink.lifecycle.expected_source_digest(), "full_values_verified": True,
              "schema_sha256": "f" * 64}
    summary = {**identity, "source_before": source, "source_after": source,
        "target_after": {"rows": planned["total_requests"] * 100, "canonical_sha256": hashlib.sha256(text.encode()).hexdigest(),
                         "all_acknowledged_batches_verified": True}}
    return value, config, summary


def normalization_fixture(root, concurrency=1):
    directory = root / "window"; directory.mkdir(); p = profile(concurrency)
    workload = save(root / "profile.json", p); bindings = {key: sink.ref(path) for key, path in sink.SOURCES.items()}
    jdk = root / "jdk"; (jdk / "bin").mkdir(parents=True); (jdk / "lib").mkdir()
    for name in ("bin/java", "bin/javac", "lib/modules", "release"):
        (jdk / name).write_text('JAVA_VERSION="17.0.4"' if name == "release" else "synthetic-only " + name)
    jars = {}
    for name in sink.JARS:
        path = root / name; path.write_text("synthetic-only " + name); jars[str(path)] = sink.stats.digest(path)
    bindings.update(jdbc_driver=sink.ref(root / "mariadb-java-client-3.0.9.jar"), postgres_driver=sink.ref(root / "postgresql-42.7.8.jar"))
    prepared = save(root / "prepared.json", {"root": "/offline-only", "postgres": {"ip": "10.254.29.2", "port": 5432,
        "database": "p4db", "user": "p4fixture"}, "driver": {**bindings["postgres_driver"], "bytes": 42}})
    service = {"pid": 103, "start_ticks": 113, "namespace": "net:[123]", "exe": "/synthetic/postgres", "command_sha256": "1" * 64}
    native = {"catalog": "owned_catalog", "source_data_sha256": sink.external.MODEL_SHA, "plan": prepared,
        "service": service, "state": save(root / "native-state.json", {"synthetic_only": True}),
        "resources": {"cpu_affinity": [5], "memory_limit_bytes": 536870912}}
    source_ref = save(root / "external-source.json", native)
    target = {"name": "synthetic-fe", "host": "127.0.0.1", "query_port": 29999}
    configs = {}
    for role in ("fe", "be"):
        path = root / (role + ".conf"); path.write_text("query_port=29999\n" if role == "fe" else "be_port=29998\n")
        configs[role] = sink.ref(path)
    identity = {key: "1" * (40 if key == "source_commit" else 64) for key in sink.stats.IDENTITY_FIELDS}
    for key, field in sink.IDENTITIES.items():
        if key == "environment": content = {"external_source": source_ref}
        elif key == "client": content = {**{name: p[name] for name in ("read_account", "write_account", "native_account")},
                                         "connection_mode": "reuse", "target": target}
        elif key == "configuration": content = {"service_configs": configs}
        elif key == "fixture": content = {"external_source": source_ref, "source_data_sha256": p["source_data_sha256"], "rows_per_operation": 100}
        else: content = {"synthetic_only": key}
        bindings[key] = save(root / (key + ".json"), content); identity[field] = bindings[key]["sha256"]
    launch = {"schema_version": 1, "phase": "AA", "variant": "A", "window_id": "synthetic-sink", "pair_id": 0,
        "launch_token": "a" * 32, "boot_id": sink.stats.boot_id(), "created_monotonic_ns": 9_000_000_000,
        "max_clock_uncertainty_ns": 100, "identity": identity, "bindings": bindings, "workload": workload,
        "service_start_ticks": {"fe": 110, "be": 111}, "external_source": source_ref,
        "target": target, "service_configs": configs,
        "services": {role: {"pid": pid, "start_ticks": pid + 10} for role, pid in (("fe", 100), ("be", 101))},
        "utc_anchor": {"before_monotonic_ns": 9_000_000_000, "after_monotonic_ns": 9_000_000_001, "utc_ns": 1}}
    launch_ref = save(directory / "p4-launch.json", launch)
    actual = {"schema_version": 1, "token": launch["launch_token"], "launch_token": launch["launch_token"],
        "launch_sha256": launch_ref["sha256"], "boot_id": launch["boot_id"], "pid": 42, "start_ticks": 99, "namespace": "net:[123]"}
    _, config, summary = raw_fixture(directory, p, actual)
    config.update(launch=launch_ref, namespace=actual["namespace"], token=actual["token"], table="public.p4_sink_" + actual["token"], target=target)
    save(directory / "config.json", config)
    classes = directory / "classes"; classes.mkdir(); compiled = classes / "LicenseExternalWritePerformance.class"; compiled.write_text("synthetic-only class")
    frozen = {"config": p, "input_path": workload["path"], "input_sha256": workload["sha256"], "java_home": str(jdk),
        "jdk_runtime": {name: sink.stats.digest(jdk / name) for name in ("bin/java", "bin/javac", "lib/modules", "release")},
        "dependencies_sha256": jars, "source_sha256": {str(path): sink.stats.digest(path) for path in sink.SOURCES.values()}}
    save(directory / "helper-identity.json", {"frozen": frozen, "classes": {str(compiled): sink.stats.digest(compiled)}})
    command = [str(jdk / "bin/java"), "-Xmx512m", "-cp", os.pathsep.join([str(classes), *sorted(jars)]),
               "LicenseExternalWritePerformance", str(directory / "config.json")]
    pin = {"pid": 42, "start_ticks": 99, "namespace": actual["namespace"], "exe": str(jdk / "bin/java"),
           "command_sha256": hashlib.sha256(b"\0".join(os.fsencode(item) for item in command) + b"\0").hexdigest()}
    save(directory / "sink-process.json", {"pin": pin, "expected_launch": pin})
    helper_ref = save(directory / "p4-helper-clock.json", {**actual, "helper_pid": 42, "helper_start_ticks": 99,
        "nonce": "b" * 32, "jvm_sample_ns": 9_500_000_000})
    bridge_ref = save(directory / "p4-clock-bridge.json", {**actual, "nonce": "b" * 32,
        "controller_before_ns": 9_500_000_000, "controller_after_ns": 9_500_000_020, "helper_clock": helper_ref})
    start = sink.read(directory / "warmup-start.json"); warm = sink.read(directory / "warmup-end.json")
    end = sink.read(directory / "measurement-end.json")["java_monotonic_ns"]
    save(directory / "ready.json", {**actual, "connections": concurrency, "source_rows_verified": 1000000})
    save(directory / "measurement-ready.json", {**actual, "warmup_start_ns": start["epoch_ns"],
        "warmup_end_ns": warm["java_monotonic_ns"], "ready_ns": warm["java_monotonic_ns"] + 10})
    save(directory / "verification-ready.json", {**actual, "java_monotonic_ns": end + 200, "workers_closed": True})
    save(directory / "verification-start.json", {**actual, "java_monotonic_ns": end + 300})
    for worker in range(concurrency):
        save(directory / f"worker-{worker}-close.json", {**actual, "worker": worker, "server_connection_id": worker + 200,
            "close_started_ns": end + 10, "close_finished_ns": end + 100, "connection_closed": True, "connection_aborted": False})
    save(directory / "lifecycle.json", {**actual, "java_monotonic_ns": end + 400, "cleanup_end_ns": end + 500,
        "workers_closed": True, "cleanup_confirmed": True})
    summary.update(status="RAW_WINDOW_COMPLETE", errors=0, automatic_write_replays=0, cleanup_confirmed=True, table=config["table"])
    save(directory / "summary.json", summary)
    save(directory / "controller.json", {"status": "RAW_WINDOW_COMPLETE", "errors": [], "owned_child_exited": True})
    owner = {**actual, "table": config["table"], "create_acknowledged": True,
        "configuration_sha256": sink.stats.digest(directory / "config.json"), "identity": {"exists": True, "oid": 123,
        "comment": "massdb-p4-owned:" + actual["token"], "columns": sink.SCHEMA, "primary_key": sink.PRIMARY_KEY,
        "schema_sha256": sink.schema_hash()}}
    save(directory / "owner.json", owner); save(directory / "create-intent.json", {**actual, "table": config["table"], "absent_before_create": True})
    save(directory / "native-drop.json", {**actual, "table": config["table"], "before": owner["identity"], "after": {"exists": False},
        "drop_acknowledged": True, "drop_started_ns": end + 410, "drop_ack_ns": end + 420, "absence_confirmed_ns": end + 430})
    save(directory / "process-lifecycle.json", [{"helper": "sink", "reason": "OWNED_PARENT_WAIT", "pid": 42,
        "exit_code": 0, "parent_wait_complete": True, "controller_monotonic_ns": end + 600}])
    completion = save(directory / "p4-completion.json", {**actual, "helper_pid": 42, "helper_start_ticks": 99, "exit_code": 0,
        "remaining_live_pids": [], "completed_monotonic_ns": end + 1000, "bridge": bridge_ref,
        "utc_anchor": {"before_monotonic_ns": end + 1000, "after_monotonic_ns": end + 1001, "utc_ns": 2}})
    for phase in ("before", "after"):
        save(directory / ("disk-" + phase + ".json"), {**actual, "paths": [{"path": name, "usable_bytes": p["min_disk_free_bytes"]}
              for name in p["storage_paths"]]})
    observations = {}
    for kind in ("resources", "license_state"):
        audit = {"kind": kind, "status": "VERIFIED", "launch_sha256": launch_ref["sha256"], "boot_id": launch["boot_id"],
            "coverage_start_monotonic_ns": 9_000_000_000, "coverage_end_monotonic_ns": end + 1000,
            "auditor": sink.ref(__file__), "raw_artifacts": [source_ref], "observed_state": "ORIGINAL_A_NO_LICENSE",
            "resource_failures": [], "budget_verified": True,
            "services": {role: {"pin": pin, "artifact": bindings[role + "_artifact"], "configuration": configs[role]}
                         for role, pin in config["cpu_services"].items()},
            "external_source": {"pin": service, "state": native["state"], "resources": native["resources"], "sample_count": 2,
                "peak_cgroup_memory_bytes": 1000, "cgroup_memory_limit_bytes": 536870912, "cgroup_oom_kill_delta": 0,
                "all_sample_cpu_affinities": [[5]]}}
        observations[kind] = save(root / (kind + ".json"), audit)
    return {"window_directory": str(directory), "launch": launch_ref, "completion": completion, **observations}, p, native


class PlanTests(unittest.TestCase):
    def test_only_retained_concurrency_and_fixed_100_rows_valid_state(self):
        for concurrency in (1, 8): self.assertGreater(sink.plan(profile(concurrency))["measurement"]["requests"], 0)
        for key, item in (("concurrency", 16), ("rows_per_operation", 99), ("seed", 0), ("license_state", "EXPIRED"),
                          ("rate_per_second", float("inf")), ("rate_per_second", True)):
            value = profile(); value[key] = item
            with self.subTest(key=key), self.assertRaises(ValueError): sink.plan(value)

    def test_formal_requires_10000_operations_not_rows(self):
        value = profile(); value.update(qualification="formal", warmup_seconds=180, duration_seconds=600,
            rate_per_second=.5, max_requests=20000, max_rows=2000000, min_disk_free_bytes=4 * 1024**3)
        with self.assertRaisesRegex(ValueError, "10000 complete"): sink.plan(value)
        value["duration_seconds"] = 22000
        self.assertGreaterEqual(sink.plan(value)["measurement"]["requests"], 10000)

    def test_business_hash_binds_drivers_native_account_rows_and_timeout(self):
        value = profile(); before = sink.business_binding(value)
        value.update(rate_per_second=12., duration_seconds=9)
        self.assertEqual(before, sink.business_binding(value))
        for key, item in (("drain_seconds", 20), ("timeout_seconds", 8), ("concurrency", 8)):
            changed = profile(); changed[key] = item; self.assertNotEqual(before, sink.business_binding(changed))
        changed = profile(); changed["native_account"]["password_env"] = "DIFFERENT_NATIVE_ACCOUNT"
        self.assertNotEqual(before, sink.business_binding(changed))

    def test_resource_reservations_are_not_a_qualification_waiver(self):
        for key, item in (("max_rows", 200), ("min_disk_free_bytes", 1024**3), ("max_raw_ledger_bytes", 1024)):
            changed = profile(); changed[key] = item
            with self.subTest(key=key), self.assertRaises(ValueError): sink.plan(changed)

    def test_formal_uses_actual_frozen_tsv_not_python_reference_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); value = profile(); planned = sink.plan(value)
            workload = save(directory / "profile.json", value)
            launch = {"phase": "AB", "workload": workload}
            with self.assertRaisesRegex(ValueError, "predeclared actual"): sink.declared_schedule(launch, value)
            declared = {"schema_version": 1, "workload_sha256": workload["sha256"]}
            for phase in ("warmup", "measurement"):
                lines = planned[phase]["tsv"].splitlines(True)
                parts = lines[1].rstrip("\n").split("\t"); parts[1] = str(int(parts[1]) + 1); lines[1] = "\t".join(parts) + "\n"
                path = directory / (phase + "-arrivals.tsv"); path.write_text("".join(lines)); declared[phase] = sink.ref(path)
            launch["arrival_schedule"] = save(directory / "declared.json", declared)
            self.assertEqual(sink.declared_schedule(launch, value, directory), declared)
            self.assertNotEqual(declared["measurement"]["sha256"], planned["measurement"]["reference_schedule_sha256"])
            # A different Java stream still matching the independent tolerance may not replace the frozen bytes.
            live = directory / "live"; live.mkdir()
            for phase in ("warmup", "measurement"): (live / (phase + "-arrivals.tsv")).write_text(planned[phase]["tsv"])
            with self.assertRaisesRegex(ValueError, "predeclared bytes"): sink.declared_schedule(launch, value, live)


class RawTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.directory = Path(self.temp.name)
        self.profile, self.config, self.summary = raw_fixture(self.directory)

    def row_mutation(self, action):
        path = self.directory / "measurement-0.jsonl"; rows = [json.loads(line) for line in path.read_text().splitlines()]
        action(rows[0]); path.write_text("".join(json.dumps(row) + "\n" for row in rows))

    def test_ack_zero_with_all_100_native_rows_is_real_success_boundary(self):
        actual = sink.audit_requests(self.directory, self.profile)
        result = sink.audit_models(self.directory, self.profile, self.summary, actual)
        self.assertEqual(result["native_rows"], len(actual["outcomes"]) * 100)
        self.assertFalse(result["online_visibility_claim"])

    def test_sql_autocommit_one_accepts_actual_false_driver_flag_without_rewriting(self):
        path = self.directory / "worker-0-session.json"
        actual = sink.audit_requests(self.directory, self.profile)
        self.assertFalse(sink.read(path)["auto_commit"])
        self.assertGreater(actual["phases"]["measurement"]["successful_requests"], 0)
        mutate(path, lambda row: row.update(auto_commit=True))
        self.assertEqual(sink.audit_requests(self.directory, self.profile), actual)

    def test_driver_flag_never_substitutes_for_actual_server_autocommit(self):
        path = self.directory / "worker-0-session.json"; original = sink.read(path)
        for flag, server in ((True, "0"), (False, "0"), (True, "true"), (False, None)):
            value = copy.deepcopy(original); value["auto_commit"] = flag; value["actual_settings"][6] = server
            save(path, value)
            with self.subTest(flag=flag, server=server), self.assertRaisesRegex(ValueError, "account/session"):
                sink.audit_requests(self.directory, self.profile)
        value = copy.deepcopy(original); value["actual_settings"].pop(); save(path, value)
        with self.assertRaisesRegex(ValueError, "account/session"): sink.audit_requests(self.directory, self.profile)
        value = copy.deepcopy(original); value["auto_commit"] = "false"; save(path, value)
        with self.assertRaisesRegex(ValueError, "account/session"): sink.audit_requests(self.directory, self.profile)

    def test_business_identity_binds_server_variable_and_driver_flag_distinction(self):
        binding = sink.business_binding(self.profile)
        self.assertEqual(binding["fields"]["commit_evidence"], {
            "server_variable_autocommit": "1", "driver_getAutoCommit": "recorded_boolean_not_server_commit_proof",
            "independent_native_full_model": "required_post_window"})
        old = dict(binding["fields"]); old.pop("commit_evidence")
        self.assertNotEqual(binding["sha256"], hashlib.sha256(json.dumps(old, sort_keys=True, separators=(",", ":")).encode()).hexdigest())

    def test_unknown_visible_rows_are_never_upgraded_to_ack(self):
        self.row_mutation(lambda row: row.update(outcome="UNKNOWN"))
        mutate(self.directory / "measurement-end.json", lambda value: value.update(successful_requests=value["successful_requests"] - 1))
        actual = sink.audit_requests(self.directory, self.profile)
        self.assertEqual(actual["phases"]["measurement"]["error_count"], 1)
        with self.assertRaises(ValueError): sink.audit_models(self.directory, self.profile, self.summary, actual)

    def test_fabricated_100_update_count_and_extra_execute_reject(self):
        for key, item in (("affected_rows", 100), ("execute_calls", 2), ("server_connection_id", 999),
                          ("socket_local_port", 99), ("sql_sha256", "0" * 64), ("timeout", True)):
            raw_fixture(self.directory, self.profile)
            self.row_mutation(lambda row: row.update({key: item}))
            with self.subTest(key=key), self.assertRaises(ValueError): sink.audit_requests(self.directory, self.profile)

    def test_native_wrong_payload_duplicate_missing_and_foreign_request_reject(self):
        original = (self.directory / "native-target.tsv").read_text()
        cases = [original.replace("cfcd208495d565ef66e7dff9f98764da", "0" * 32, 1),
                 original.splitlines(True)[0] + original, "".join(original.splitlines(True)[1:]),
                 original.replace("\t0\t0\t0\t0\t", "\t999999\t0\t0\t0\t", 1)]
        actual = sink.audit_requests(self.directory, self.profile)
        for case in cases:
            (self.directory / "native-target.tsv").write_text(case)
            with self.assertRaises(ValueError): sink.audit_models(self.directory, self.profile, self.summary, actual)

    def test_queue_cpu_denominator_and_source_model_cannot_be_invented(self):
        self.row_mutation(lambda row: row.update(queue_ns=-1))
        with self.assertRaises(ValueError): sink.audit_requests(self.directory, self.profile)
        raw_fixture(self.directory, self.profile)
        mutate(self.directory / "measurement-end.json", lambda value: value.update(request_interval_end_ns=value["request_interval_end_ns"] - 1))
        with self.assertRaises(ValueError): sink.audit_requests(self.directory, self.profile)
        raw_fixture(self.directory, self.profile); actual = sink.audit_requests(self.directory, self.profile)
        self.summary["source_after"] = {"rows": 1000000, "canonical_sha256": "0" * 64, "full_values_verified": True}
        with self.assertRaises(ValueError): sink.audit_models(self.directory, self.profile, self.summary, actual)


class NormalizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.manifest, self.profile, self.native = normalization_fixture(self.root)
        self.directory = Path(self.manifest["window_directory"])
        # Shared catalog provenance verifier has its own actual-byte unit fixtures. Only that existing
        # dependency is substituted; every new sink input binding, clock, request and native row audit runs.
        self.addCleanup(patch.stopall)
        patch.object(sink.external, "external_source", return_value=self.native).start()
        patch.object(sink.external, "source_references", return_value=[self.native["plan"], self.native["state"]]).start()

    def test_complete_new_auditor_returns_diagnostic_only(self):
        result = sink.normalize(self.manifest)
        self.assertEqual(result["status"], "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED")
        self.assertFalse(result["formal_shape_met"]); self.assertFalse(result["formal_performance_pass"])
        self.assertEqual(result["window"]["successful_requests"], sink.plan(self.profile)["measurement"]["requests"])

    def test_missing_wait_other_helper_and_reversed_cleanup_reject(self):
        path = self.directory / "process-lifecycle.json"; original = sink.read(path)
        for values in ([], [{**original[0], "pid": 999}], [{**original[0], "helper": "recovery"}], [{**original[0], "parent_wait_complete": False}]):
            save(path, values)
            with self.assertRaises(ValueError): sink.normalize(self.manifest)
        save(path, original)
        mutate(self.directory / "lifecycle.json", lambda value: value.update(cleanup_end_ns=1))
        with self.assertRaises(ValueError): sink.normalize(self.manifest)

    def test_native_owner_source_account_and_dependency_changes_reject(self):
        path = self.directory / "owner.json"; original = sink.read(path)
        mutate(path, lambda value: value["identity"].update(comment="foreign owner"))
        with self.assertRaises(ValueError): sink.normalize(self.manifest)
        save(path, original)
        mutate(self.directory / "worker-0-session.json", lambda value: value["actual_settings"].__setitem__(5, "root@%"))
        with self.assertRaises(ValueError): sink.normalize(self.manifest)

    def test_resources_must_cover_cpu_lead_in_and_whole_native_process_group(self):
        resource = self.manifest["resources"]; original = sink.read(resource["path"])
        value = copy.deepcopy(original); value["coverage_start_monotonic_ns"] = 10_000_000_000
        self.manifest["resources"] = save(Path(resource["path"]), value)
        with self.assertRaises(ValueError): sink.normalize(self.manifest)
        value = copy.deepcopy(original); value["external_source"]["cgroup_oom_kill_delta"] = 1
        self.manifest["resources"] = save(Path(resource["path"]), value)
        with self.assertRaises(ValueError): sink.normalize(self.manifest)

    def test_wait_can_tighten_mapping_but_never_contradict_original(self):
        end = sink.read(self.directory / "lifecycle.json")["cleanup_end_ns"]
        mutate(self.directory / "process-lifecycle.json", lambda rows: rows[0].update(controller_monotonic_ns=end + 5))
        actual = sink.normalize(self.manifest)
        self.assertEqual(actual["clock_causality_audit"]["effective_mapping"]["offset_upper_ns"], 5)
        mutate(self.directory / "process-lifecycle.json", lambda rows: rows[0].update(controller_monotonic_ns=end - 1))
        with self.assertRaises(ValueError): sink.normalize(self.manifest)

    def test_actual_launch_identity_cannot_be_replaced_with_consistent_raw_alias(self):
        for name in ("ready.json", "warmup-start.json", "warmup-end.json", "measurement-ready.json", "measurement-start.json",
                     "measurement-end.json", "verification-ready.json", "verification-start.json", "lifecycle.json", "summary.json"):
            mutate(self.directory / name, lambda value: value.update(launch_token="b" * 32, launch_sha256="c" * 64))
        with self.assertRaises(ValueError): sink.normalize(self.manifest)

    def test_changed_class_bytes_do_not_reuse_normalized_evidence(self):
        sink.normalize(self.manifest)
        (self.directory / "classes/LicenseExternalWritePerformance.class").write_text("changed synthetic class")
        with self.assertRaises(ValueError): sink.normalize(self.manifest)

    def test_session_close_and_native_drop_have_actual_launch_identity(self):
        for name in ("worker-0-session.json", "worker-0-close.json", "native-drop.json"):
            path = self.directory / name; original = sink.read(path)
            mutate(path, lambda value: value.update(token="b" * 32, boot_id="other-boot"))
            with self.subTest(name=name), self.assertRaises(ValueError): sink.normalize(self.manifest)
            save(path, original)

    def test_actual_catalog_token_and_fe_cannot_change_beneath_frozen_identity(self):
        path = self.directory / "config.json"; original = sink.read(path)
        for key, value in (("catalog", "other_catalog"), ("token", "c" * 32),
                           ("target", {**original["target"], "query_port": 30000})):
            save(path, {**original, key: value})
            # Recompute owner config binding to ensure this is the launch->actual check, not only a stale digest.
            mutate(self.directory / "owner.json", lambda owner: owner.update(configuration_sha256=sink.stats.digest(path)))
            with self.subTest(key=key), self.assertRaises(ValueError): sink.normalize(self.manifest)
        save(path, original)

    def test_same_columns_without_original_primary_key_are_not_owned_schema(self):
        mutate(self.directory / "owner.json", lambda owner: owner["identity"].update(primary_key="PRIMARY KEY (id)"))
        with self.assertRaises(ValueError): sink.normalize(self.manifest)



# Explicit runtime enables an actual Java reflection/proxy test without constructing a SQL client.
NATIVE_IDENTITY_TEST = r"""
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.lang.reflect.*;
import java.sql.*;
import java.util.concurrent.atomic.AtomicInteger;
public final class NativeIdentitySelfTest {
    static final ObjectMapper JSON = new ObjectMapper();
    static Method identity, failure;
    static int checks;
    static final String SECRET = "DO_NOT_ARCHIVE_DRIVER_SQL_PASSWORD";
    static final ObjectNode ACCOUNT = JSON.createObjectNode().put("user","p4fixture").put("database","p4db")
            .put("host","10.254.29.2").put("port",5432);
    static void assertTrue(boolean value) { if (!value) throw new AssertionError("Native identity regression"); }
    static ResultSet rows(Object[] values, int count) {
        AtomicInteger index = new AtomicInteger();
        return (ResultSet) Proxy.newProxyInstance(NativeIdentitySelfTest.class.getClassLoader(), new Class<?>[]{ResultSet.class}, (p,m,a)-> {
            if (m.getName().equals("next")) return index.getAndIncrement() < count;
            if (m.getName().equals("getString") || m.getName().equals("getInt")) return values[(Integer)a[0]-1];
            throw new AssertionError("Unexpected ResultSet operation");
        });
    }
    static void checkIdentity(Object[] values, int count, boolean expected) throws Exception {
        try { identity.invoke(null, rows(values,count), ACCOUNT); assertTrue(expected); }
        catch (InvocationTargetException caught) {
            assertTrue(!expected && caught.getCause() instanceof IllegalStateException);
            ObjectNode report=JSON.createObjectNode(); failure.invoke(null,report,"failure",caught.getCause());
            assertTrue(report.path("failure_reason").asText().equals("ACTUAL_NATIVE_SERVER"));
            assertTrue(!report.toString().contains(SECRET));
        }
        checks++;
    }
    public static void main(String[] args) throws Exception {
        Class<?> helper=Class.forName("LicenseExternalWritePerformance");
        identity=helper.getDeclaredMethod("verifyNativeIdentity",ResultSet.class,JsonNode.class); identity.setAccessible(true);
        failure=helper.getDeclaredMethod("recordFailure",ObjectNode.class,String.class,Exception.class); failure.setAccessible(true);
        Object[] valid={"p4fixture","p4db","10.254.29.2",5432};
        checkIdentity(valid,1,true);
        for(int column=0;column<4;column++) {
            Object[] wrong=valid.clone(); wrong[column]=column==3?5433:"wrong"; checkIdentity(wrong,1,false);
        }
        Object[] masked=valid.clone(); masked[2]="10.254.29.2/32"; checkIdentity(masked,1,false);
        Object[] missing=valid.clone(); missing[2]=null; checkIdentity(missing,1,false);
        checkIdentity(valid,0,false); checkIdentity(valid,2,false);
        ObjectNode report=JSON.createObjectNode();
        failure.invoke(null,report,"failure",new SQLException(SECRET,"08006",42));
        assertTrue(report.path("failure_sql_state").asText().equals("08006") && report.path("failure_error_code").asInt()==42
                && !report.has("failure_reason") && !report.toString().contains(SECRET)); checks++;
        report=JSON.createObjectNode(); failure.invoke(null,report,"failure",new IllegalStateException(SECRET));
        assertTrue(!report.has("failure_reason") && !report.toString().contains(SECRET)); checks++;
        report=JSON.createObjectNode(); failure.invoke(null,report,"cleanup_failure",new SQLException(SECRET,SECRET,99));
        assertTrue(report.path("cleanup_failure_sql_state").asText().equals("NONE") && !report.toString().contains(SECRET)); checks++;
        Method require=helper.getDeclaredMethod("require",boolean.class,String.class); require.setAccessible(true);
        try { require.invoke(null,false,"NATIVE_DROP_UNCONFIRMED"); throw new AssertionError(); }
        catch(InvocationTargetException caught) {
            report=JSON.createObjectNode(); failure.invoke(null,report,"cleanup_failure",caught.getCause());
            assertTrue(report.path("cleanup_failure_reason").asText().equals("NATIVE_DROP_UNCONFIRMED")); checks++;
        }
        System.out.println("NATIVE_IDENTITY_AND_SAFE_DIAGNOSTICS_CHECKS="+checks);
    }
}
"""


@unittest.skipUnless(os.environ.get("MASSDB_EXTERNAL_WRITE_JAVA_TEST_RUNTIME"), "Explicit actual JDK/JAR freeze required")
class NativeIdentityJavaTest(unittest.TestCase):
    def test_native_identity_and_safe_failure_diagnostics(self):
        runtime = sink.read(Path(os.environ["MASSDB_EXTERNAL_WRITE_JAVA_TEST_RUNTIME"]))
        java_home = Path(runtime["java_home"])
        for name, digest in runtime["jdk_runtime"].items():
            self.assertEqual(sink.stats.digest(java_home / name), digest)
        for path, digest in runtime["dependencies_sha256"].items():
            self.assertEqual(sink.stats.digest(path), digest)
        selected = os.environ.get("MASSDB_EXTERNAL_WRITE_JAVA_TEST_OUTPUT")
        with tempfile.TemporaryDirectory(prefix="external-write-native-identity-") as temporary:
            output = Path(selected or temporary)
            if selected: output.mkdir(parents=True, exist_ok=False)
            helper = output / "NativeIdentitySelfTest.java"; helper.write_text(NATIVE_IDENTITY_TEST)
            classes = output / "classes"; classes.mkdir()
            classpath = os.pathsep.join([str(classes), *sorted(runtime["dependencies_sha256"])])
            environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
            command = [str(java_home / "bin/javac"), "-J-Xmx256m", "--release", "17", "-encoding", "UTF-8", "-cp", classpath,
                       "-d", str(classes), str(sink.JAVA_SOURCE), str(helper)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=60, env=environment)
            (output / "compile.log").write_text(compiled.stdout + compiled.stderr)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(java_home / "bin/java"), "-Xmx256m", "-cp", classpath, "NativeIdentitySelfTest"],
                                      capture_output=True, text=True, timeout=30, env=environment)
            (output / "selftest.log").write_text(executed.stdout + executed.stderr)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertEqual(executed.stdout.strip(), "NATIVE_IDENTITY_AND_SAFE_DIAGNOSTICS_CHECKS=13")
            (output / "completion.json").write_text(json.dumps({"compile_exit_code": compiled.returncode,
                "selftest_exit_code": executed.returncode, "checks": 13, "sql_requests": 0,
                "source": sink.ref(sink.JAVA_SOURCE), "test": sink.ref(Path(__file__)), "formal_performance_pass": False}) + "\n")


if __name__ == "__main__": unittest.main()
