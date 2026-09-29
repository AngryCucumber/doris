#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline counterexamples. Synthetic receipts never count as actual external performance."""

import base64
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

import external_read_performance as scanner


def profile(concurrency=1):
    return {"schema_version": 1, "profile": scanner.PROFILE, "qualification": "diagnostic", "seed": 20260922,
            "source_kind": "s3_tvf", "source_data_sha256": "a" * 64, "column_types": [-5, 4, -5, 12], "concurrency": concurrency, "rate": 5.5, "warmup_seconds": 2,
            "duration_seconds": 3, "drain_seconds": 5, "max_requests": 1000, "max_raw_ledger_bytes": 67108864}


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n"); return scanner.reference(path)


def mutate(path, function):
    value = scanner.read_json(path); function(value); save(path, value)


def mutate_row(path, function):
    values = [json.loads(line) for line in path.read_text().splitlines()]
    function(values); path.write_text("".join(json.dumps(value) + "\n" for value in values))


def raw_stat(pid, start, user, system):
    fields = ["S"] + ["0"] * 49
    fields[11], fields[12], fields[19] = str(user), str(system), str(start)
    return f"{pid} (synthetic worker) " + " ".join(fields) + "\n"


def operation(directory, phase, worker, sequence, types, sql_sha):
    return {"rows_verified": 1000000, "rows_observed": 1000000,
        "complete_unordered_set": {"rows": 1000000, "distinct_ids": 1000000, "min_id": 0, "max_id": 999999,
            "sum_id": 499999500000, "sum_grp": 511370976, "sum_v": 49999500000, "null_fields": 0,
            "sha256_sorted_actual_rows": scanner.MODEL_SHA},
        "sql_sha256": sql_sha, "execute_calls": 1, "server_connection_id": worker+101,
        "socket_local_port": 40000+worker, "socket_remote_port": 30000, "driver_query_timeout_seconds": 0,
        "column_labels": scanner.LABELS, "column_types": types, "fetch_size": 1024, "streaming": True,
        "result_class": "org.mariadb.jdbc.client.result.StreamingResult", "statement_class": "org.mariadb.jdbc.Statement",
        "connection_reused": True, "result_closed": True, "statement_closed": True, "connection_aborted": False}


def source_fixture(root, p):
    objects = [{"key": f"lp008/part-{i:05d}.parquet", "bytes": 1000+i, "sha256": f"{i:064x}"} for i in range(100)]
    p["source_data_sha256"] = hashlib.sha256(json.dumps(objects, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    pin = {"pid": 103, "start_ticks": 1003, "namespace": "net:[5678]", "exe": "/synthetic/minio", "command_sha256": "b"*64}
    plan = save(root/'external-plan.json', {"total_rows": 1000000,
        "canonical_objects": [{**item, "rows": 10000} for item in objects],
        "minio": {"ip": "10.254.29.6", "port": 9000, "source_bucket": "offline-only"}})
    source = {"schema_version": 1, "source_kind": "s3_tvf", "source_data_sha256": p["source_data_sha256"],
        "uri": "http://10.254.29.6:9000/offline-only/lp008/*.parquet", "service": pin,
        "resources": {"cpu_affinity": [5], "memory_limit_bytes": 536870912}, "plan": plan,
        "state": save(root/'source-state.json', {"status": "ATTACHED_PRIVATE_POINT_LINK", "process": pin}),
        "metadata_evidence": save(root/'source-metadata.json', {"status": "ACTUAL_JDBC_METADATA_VERIFIED_NO_DATA_ROWS",
            "actual_exit_code": 0, "driver": "3.0.9", "sources": [{"kind": kind, "columns": [
                {"label": label, "jdbc_type": typ, "type_name": name} for label, typ, name in
                zip(scanner.LABELS, scanner.COLUMN_TYPES, ('BIGINT', 'INTEGER', 'BIGINT', 'VARCHAR'))]}
                for kind in ('catalog', 's3_tvf')]}),
        "native_evidence": save(root/'source-native.json', {"status": "NATIVE_S3_ALL_BYTES_VERIFIED", "rows": 1000000, "objects": objects, "plan": plan}),
        "reachability": save(root/'source-reachability.json', {"status": "ORIGINAL_A_CATALOG_AND_S3_REACHABILITY_VERIFIED",
            "source_rows": 1000000, "external_plan": plan, "queries": [{"source_kind": kind, "status": "AGGREGATE_MODEL_VERIFIED"} for kind in ('catalog','s3_tvf')]})}
    props = {"uri": source['uri'], "format": "parquet", "s3.access_key": "OFFLINE_TEST_ACCESS",
             "s3.secret_key": "OFFLINE_ONLY_TEST_SECRET", "s3.region": "us-east-1", "use_path_style": "true"}
    sql = 'SELECT id, grp, v, payload FROM s3(' + ', '.join(f'"{key}" = "{value}"' for key,value in props.items()) + ')'
    private = root/'query.private.json'; save(private, {"source_kind": "s3_tvf", "sql": sql}); private.chmod(0o600)
    return scanner.reference(private), save(root/'source.json', source), hashlib.sha256(sql.encode()).hexdigest()


def fixture(root, concurrency=1):
    directory = root / "raw"; directory.mkdir()
    p = profile(concurrency); private, external, sql_sha = source_fixture(root, p)
    workload = save(root / "profile.json", p)
    # This synthetic identity exercises binding checks only. No file is an executable or real DB package.
    jdk = root / "jdk"
    for name in ("bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so", "release"):
        path = jdk / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('JAVA_VERSION="17.0.4"\n' if name == "release" else "synthetic " + name)
    jars = []
    for name in sorted(scanner.EXPECTED_JARS):
        jar = root / name; jar.write_text("synthetic, never executed"); jars.append(scanner.reference(jar))
    classes = root / "classes"; classes.mkdir()
    for name in ("LicenseExternalReadPerformance.class", "LicenseExternalReadPerformance$Session.class",
                 "LicenseExternalReadPerformance$RowOracle.class"):
        (classes / name).write_text("synthetic, never executed")
    runtime = {"schema_version": 1, "main_class": "LicenseExternalReadPerformance", "java_home": str(jdk),
        "classes_directory": str(classes), "sources": {key: scanner.reference(value) for key, value in scanner.SOURCES.items()},
        "jdk": {name: scanner.reference(jdk / name) for name in ("bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so", "release")},
        "jars": jars, "classes": [scanner.reference(path) for path in sorted(classes.iterdir())]}
    runtime_ref = save(root / "runtime.json", runtime)
    identity = {"source_commit": "a" * 40}; bindings = dict(runtime["sources"])
    for key, field in scanner.IDENTITIES.items():
        path = root / (key + ".txt"); path.write_text("synthetic " + key)
        if key == 'environment': save(path, {'scope': 'SYNTHETIC_ONLY', 'external_source': external})
        if key == 'fixture': save(path, {'external_source': external, 'model_sha256': scanner.MODEL_SHA,
                                        'source_data_sha256': p['source_data_sha256']})
        if key == 'client': save(path, {'user': 'root', 'password_env': 'MASSDB_TEST_PASSWORD', 'private_query': private,
                                       'sql_sha256': sql_sha, 'connection_mode': 'reuse_jdbc_streaming'})
        bindings[key] = scanner.reference(path); identity[field] = bindings[key]["sha256"]
    services, configs = {}, {}
    for index, role in enumerate(("fe", "be")):
        services[role] = {"pid": 100 + index, "start_ticks": 1000 + index, "namespace": "net:[1234]",
                          "exe": "/synthetic/" + role, "command_sha256": "b" * 64}
        path = root / (role + ".conf"); path.write_text(f"{'query_port' if role == 'fe' else 'be_port'} = {30000 + index}\n")
        configs[role] = scanner.reference(path)
    launch = {"schema_version": 1, "phase": "AA", "variant": "A", "window_id": "synthetic-scanner", "pair_id": 0,
        "identity": identity, "bindings": bindings, "workload": workload, "max_clock_uncertainty_ns": 100,
        "coordination_seconds": 10, "context_deadline_monotonic_ns": 20_000_000_000, "services": services,
        "private_query": private, "external_source": external, "service_configs": configs, "endpoints": {"query_port": 30000,
        "user": "root", "password_env": "MASSDB_TEST_PASSWORD"}, "runtime": runtime_ref, "launch_token": "c" * 64,
        "boot_id": "synthetic-boot", "created_monotonic_ns": 9_000_000_000, "namespace": "net:[1234]", "host_namespace": "net:[999]",
        "utc_anchor": {"before_monotonic_ns": 9_000_000_000, "utc_ns": 1, "after_monotonic_ns": 9_000_000_001}}
    launch_ref = save(directory / "p4-launch.json", launch)
    config = {**launch["endpoints"], "profile": p, "launch": launch_ref, "namespace": launch["namespace"], "host_namespace": launch["host_namespace"],
              "services": services, "clock_ticks_per_second": 100, "coordination_seconds": 10}
    copied = directory/"query.private.json"; copied.write_bytes(Path(private["path"]).read_bytes()); copied.chmod(0o600)
    config.update(private_query=scanner.reference(copied), sql_sha256=sql_sha)
    save(directory / "config.json", config)
    command = scanner.command_for(runtime, directory / "config.json")
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
    planned = scanner.plan(p); epoch = 10_000_000_000; calls = [0] * concurrency; last_phase_end = None
    for phase, seconds in (("warmup", 2), ("measurement", 3)):
        schedule = planned[phase]; (directory / (phase + "-arrivals.tsv")).write_text(schedule["tsv"])
        rows = [[] for _ in range(concurrency)]; previous = [epoch] * concurrency; last = epoch
        for index, offset in enumerate(schedule["offsets"]):
            worker = index % concurrency; calls[worker] += 1; scheduled = epoch + offset
            started = max(previous[worker], scheduled) + 1000; ended = started + 1_000_000
            previous[worker] = ended; last = max(last, ended)
            row = operation(directory, phase, worker, index, p["column_types"], sql_sha)
            row.update(sequence=index, worker=worker, scheduled_ns=scheduled, started_ns=started, finished_ns=ended,
                e2e_ns=ended-scheduled, service_ns=ended-started, queue_ns=started-scheduled, status="READ_PASS",
                session_id=worker, session_call=calls[worker],
                dispatch_deadline_ns=started+120*10**9, dispatch_deadline_exceeded=False)
            rows[worker].append(row)
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
        save(directory / f"session-{worker}-open.json", {"worker": worker, "session_id": worker, "jdbc_connections_opened": 1,
            "opened_ns": 9_100_000_000, "driver_class": "org.mariadb.jdbc.Driver", "driver_version": "3.0.9",
            "connection_class": "org.mariadb.jdbc.Connection", "client_class": "org.mariadb.jdbc.client.impl.StandardClient",
            "server_connection_id": worker+101, "cache_readback": scanner.business_binding(p)['fields']['session']})
        mutate(directory / f"session-{worker}-open.json", lambda value: value.update(socket_local_port=40000+worker, socket_remote_port=30000))
        save(directory / f"session-{worker}-close.json", {"worker": worker, "close_started_ns": end+10,
            "close_finished_ns": end+100, "jdbc_connection_closed": True, "jdbc_connections_closed": 1, "connection_aborted": False})
    save(directory / "lifecycle.json", {**actual, "cleanup_end_ns": end + 200, "sessions_closed": True, "workers_stopped": True})
    save(directory / "summary.json", {**actual, "status": "RAW_WINDOW_COMPLETE", "errors": 0, "harness_retries": 0, "cleanup_confirmed": True})
    completion = {**actual, "schema_version": 1, "exit_code": 0, "parent_wait_complete": True, "remaining_live_pids": [],
        "controller_errors": [], "completed_monotonic_ns": end + 10000, "bridge": bridge_ref,
        "utc_anchor": {"before_monotonic_ns": end + 10000, "utc_ns": 10, "after_monotonic_ns": end + 10001}}
    completion_ref = save(directory / "p4-completion.json", completion)
    return {"window_directory": str(directory), "launch": launch_ref, "completion": completion_ref}, p, config


class InputTests(unittest.TestCase):
    def test_only_actual_catalog_s3_and_retained_concurrency(self):
        for kind in ('catalog', 's3_tvf'):
            for concurrency in (1, 8):
                p = profile(concurrency); p['source_kind'] = kind
                self.assertEqual(scanner.validate_profile(p), p)
        for key, value in (('source_kind', 'other'), ('concurrency', 16), ('seed', 0), ('rate', True),
                           ('rate', float('inf')), ('column_types', [-5, 4, -5, 99])):
            p = profile(); p[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): scanner.validate_profile(p)

    def test_formal_needs_10000_complete_queries_not_rows(self):
        p = profile(); p.update(qualification='formal')
        with self.assertRaisesRegex(ValueError, 'cannot be shortened'): scanner.plan(p)
        p.update(warmup_seconds=180, duration_seconds=600, rate=.1, max_requests=20000)
        with self.assertRaisesRegex(ValueError, '10000 complete'): scanner.plan(p)
        p['duration_seconds'] = 110000
        self.assertGreaterEqual(scanner.plan(p)['measurement']['requests'], 10000)

    def test_business_hash_preserves_sql_schema_source_driver_but_not_window_or_rate(self):
        p = profile(); before = scanner.business_binding(p)
        p.update(rate=1.5, duration_seconds=20)
        self.assertEqual(scanner.business_binding(p), before)
        for key, value in (('source_kind', 'catalog'), ('source_data_sha256', 'b'*64),
                           ('concurrency', 8), ('drain_seconds', 10)):
            p = profile(); p[key] = value
            self.assertNotEqual(scanner.business_binding(p), before)
        self.assertEqual(before['fields']['driver']['fetch_size'], 1024)

    def test_independent_complete_four_column_model(self):
        self.assertEqual(scanner.verify_model(), 'b2b90b17ef5b149fa1deca05a37b48198d0e709790be44ea2ecb80979d9cef7c')

    def test_fractional_arrivals_are_not_floored(self):
        p = profile(); first = scanner.plan(p); p['rate'] = 5
        self.assertNotEqual(scanner.plan(p)['measurement']['sha256'], first['measurement']['sha256'])
        self.assertEqual(first['warmup']['offsets'], first['measurement']['offsets'][:first['warmup']['requests']])

    def test_hidden_jvm_options_cannot_change_heap_classpath_or_logging(self):
        for name in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS'):
            with patch.dict(os.environ, {name: '-Dsynthetic.option=1'}):
                with self.assertRaisesRegex(ValueError, 'Unfrozen Java environment'): scanner.check_jvm_environment()


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest, self.profile, self.config = fixture(self.root)
        self.directory = Path(self.manifest['window_directory'])

    def audit(self): return scanner.normalize(self.manifest)

    def row_mutation(self, action, worker=0):
        mutate_row(self.directory / f'measurement-{worker}.jsonl', lambda rows: action(rows[0]))

    def update_launch(self, action):
        path = self.directory / 'p4-launch.json'; value = scanner.read_json(path); action(value)
        self.manifest['launch'] = save(path, value)

    def add_observer(self):
        launch = scanner.read_json(self.manifest['launch']['path']); source = scanner.read_json(launch['external_source']['path'])
        warm = scanner.read_json(self.directory/'warmup-start.json'); end = scanner.read_json(self.directory/'measurement-end.json')
        value = {'status': 'VERIFIED', 'launch_sha256': self.manifest['launch']['sha256'], 'boot_id': launch['boot_id'],
            'coverage_start_monotonic_ns': min(v['sample_started_java_ns'] for v in warm['cpu'].values()),
            'coverage_end_monotonic_ns': end['java_monotonic_ns']+20, 'resource_failures': [], 'budget_verified': True,
            'observed_license_state': 'ORIGINAL_A_NO_LICENSE', 'raw_artifacts': [launch['external_source']],
            'auditor': scanner.reference(__file__), 'services': {role: {'pin': launch['services'][role],
                'artifact': launch['bindings'][role+'_artifact'], 'configuration': launch['service_configs'][role]}
                for role in ('fe', 'be')}, 'external_source': {'pin': source['service'], 'state': source['state'],
                'resources': source['resources'], 'sample_count': 2, 'peak_rss_bytes': 100000,
                'cgroup_memory_limit_bytes': 536870912, 'peak_cgroup_memory_bytes': 1000000,
                'cgroup_oom_kill_delta': 0, 'all_sample_cpu_affinities': [[5]]}}
        self.manifest['observer'] = save(self.root/'observer.json', value)
        return value

    def test_complete_synthetic_receipts_are_diagnostic_and_do_not_publish_sql_credentials(self):
        actual = self.audit()
        self.assertEqual(actual['status'], 'DIAGNOSTIC_VERIFIED_NOT_QUALIFIED')
        self.assertFalse(actual['formal_performance_pass'])
        public = json.dumps(actual)
        self.assertNotIn('OFFLINE_ONLY_TEST_SECRET', public)
        self.assertNotIn('OFFLINE_TEST_ACCESS', public)
        self.assertGreater(actual['window']['successful_requests'], 0)

    def test_c8_requires_distinct_connection_ids_and_all_workers(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest, _, _ = fixture(Path(temp), 8)
            self.assertEqual(scanner.normalize(manifest)['status'], 'DIAGNOSTIC_VERIFIED_NOT_QUALIFIED')
            path = Path(manifest['window_directory']) / 'session-1-open.json'
            mutate(path, lambda value: value.update(server_connection_id=101))
            with self.assertRaises(ValueError): scanner.normalize(manifest)

    def test_column_structure_cannot_change(self):
        self.row_mutation(lambda value: value.update(column_types=[-5, 4, -5, 1]))
        with self.assertRaisesRegex(ValueError, 'schema'): self.audit()

    def test_all_four_actual_columns_and_complete_digest_required(self):
        self.row_mutation(lambda value: value['complete_unordered_set'].update(sum_grp=0))
        with self.assertRaisesRegex(ValueError, 'four-column'): self.audit()

    def test_missing_million_rows_fails(self):
        self.row_mutation(lambda value: value.update(rows_verified=999999))
        with self.assertRaisesRegex(ValueError, 'million-row'): self.audit()

    def test_aggregate_result_cannot_replace_streaming_result(self):
        self.row_mutation(lambda value: value.update(result_class='org.mariadb.jdbc.client.result.CompleteResult', streaming=False))
        with self.assertRaisesRegex(ValueError, 'stream'): self.audit()

    def test_same_connection_object_claim_without_server_id_is_rejected(self):
        self.row_mutation(lambda value: value.update(server_connection_id=9999))
        with self.assertRaisesRegex(ValueError, 'reuse'): self.audit()

    def test_result_close_ack_required(self):
        self.row_mutation(lambda value: value.update(result_closed=False))
        with self.assertRaisesRegex(ValueError, 'closure'): self.audit()

    def test_session_close_ack_required(self):
        mutate(self.directory/'session-0-close.json', lambda value: value.update(jdbc_connection_closed=False))
        with self.assertRaisesRegex(ValueError, 'close'): self.audit()

    def test_all_three_caches_readback_must_be_disabled(self):
        mutate(self.directory/'session-0-open.json', lambda value: value['cache_readback'].update(enable_file_cache=True))
        with self.assertRaisesRegex(ValueError, 'readback'): self.audit()

    def test_missing_statement_execute_receipt_is_rejected(self):
        self.row_mutation(lambda value: value.update(execute_calls=0))
        with self.assertRaisesRegex(ValueError, 'execute'): self.audit()

    def test_queue_cannot_be_removed_from_e2e(self):
        self.row_mutation(lambda value: value.update(e2e_ns=value['service_ns']))
        with self.assertRaisesRegex(ValueError, 'E2E'): self.audit()

    def test_dispatch_deadline_exceeded_is_not_a_success(self):
        self.row_mutation(lambda value: value.update(dispatch_deadline_exceeded=True))
        with self.assertRaisesRegex(ValueError, 'deadline'): self.audit()

    def test_missing_terminal_request_is_rejected(self):
        mutate_row(self.directory/'measurement-0.jsonl', lambda rows: rows.pop())
        with self.assertRaisesRegex(ValueError, 'missing completion'): self.audit()

    def test_errors_and_timeouts_are_counted_and_never_qualified(self):
        self.row_mutation(lambda value: value.update(status='ERROR', error_class='java.sql.SQLTimeoutException',
            error_code='READ_OR_ORACLE_OR_CLOSE_FAILURE', timeout=True))
        path = self.directory/'measurement-end.json'; end = scanner.read_json(path)
        end['successful_requests'] -= 1; save(path, end)
        raw = scanner.audit_requests(self.directory, self.profile, self.config)
        self.assertEqual(raw['measurement']['error_count'], 1)
        self.assertEqual(raw['measurement']['timeout_count'], 1)
        with self.assertRaisesRegex(ValueError, 'failures preserved'): self.audit()

    def test_qps_includes_complete_drain_interval(self):
        mutate(self.directory/'measurement-end.json', lambda value: value.update(request_interval_end_ns=value['request_interval_end_ns']-1))
        with self.assertRaisesRegex(ValueError, 'denominator'): self.audit()

    def test_cpu_boundaries_enclose_all_requests(self):
        mutate(self.directory/'measurement-end.json', lambda value: value['cpu']['fe'].update(sample_started_java_ns=1))
        with self.assertRaisesRegex(ValueError, 'CPU sample'): self.audit()

    def test_parent_wait_cannot_be_inferred_from_summary(self):
        path = Path(self.manifest['completion']['path']); value = scanner.read_json(path); value['parent_wait_complete'] = False
        self.manifest['completion'] = save(path, value)
        with self.assertRaisesRegex(ValueError, 'parent wait'): self.audit()

    def test_source_change_invalidates_runtime_and_evidence(self):
        with patch.dict(scanner.SOURCES, {'runner': self.root/'different.py'}):
            (self.root/'different.py').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'source drift'): self.audit()

    def test_private_sql_mode_and_hash_are_enforced(self):
        (self.root/'query.private.json').chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'mode0600'): self.audit()

    def test_private_sql_change_not_hidden_by_public_template(self):
        mutate(self.directory/'query.private.json', lambda value: value.update(sql='SELECT 1'))
        with self.assertRaisesRegex(ValueError, 'Private SQL'): self.audit()

    def test_inline_secret_context_rejected(self):
        context = scanner.read_json(self.manifest['launch']['path']); context['password'] = 'OFFLINE_SECRET'
        with self.assertRaisesRegex(ValueError, 'unknown fields'): scanner.validate_context(context, self.profile)

    def test_external_native_object_changed_is_rejected(self):
        source = scanner.read_json(self.root/'source.json'); native = scanner.read_json(source['native_evidence']['path'])
        native['objects'][0]['sha256'] = 'f'*64
        source['native_evidence'] = save(Path(source['native_evidence']['path']), native)
        context = scanner.read_json(self.manifest['launch']['path']); context['external_source'] = save(self.root/'source.json', source)
        with self.assertRaisesRegex(ValueError, 'object bytes'): scanner.external_source(context, self.profile)

    def test_another_private_source_or_query_injection_rejected(self):
        context = scanner.read_json(self.manifest['launch']['path'])
        private = scanner.read_json(self.root/'query.private.json'); private['sql'] += '; SELECT 1'
        context['private_query'] = save(self.root/'query.private.json', private)
        with self.assertRaisesRegex(ValueError, 'fixed full read'): scanner.private_query(context, self.profile)

    def test_private_catalog_requires_exact_predeclared_table(self):
        context = scanner.read_json(self.manifest['launch']['path']); source = scanner.read_json(self.root/'source.json')
        source['catalog'] = 'example_catalog'; context['external_source'] = save(self.root/'source.json', source)
        self.profile['source_kind'] = 'catalog'
        context['private_query'] = save(self.root/'query.private.json', {'source_kind': 'catalog',
            'sql': 'SELECT id, grp, v, payload FROM example_catalog.public.source_rows'})
        self.assertEqual(set(scanner.private_query(context, self.profile)), {'sql_sha256'})
        context['private_query'] = save(self.root/'query.private.json', {'source_kind': 'catalog', 'sql': 'SELECT COUNT(*) FROM example_catalog.public.source_rows'})
        with self.assertRaisesRegex(ValueError, 'fixed full read'): scanner.private_query(context, self.profile)

    def test_observer_covers_actual_cpu_boundaries_as_well_as_requests(self):
        value = self.add_observer(); self.audit()
        value['coverage_start_monotonic_ns'] = scanner.read_json(self.directory/'warmup-start.json')['epoch_ns']
        self.manifest['observer'] = save(self.root/'observer.json', value)
        with self.assertRaisesRegex(ValueError, 'observation incomplete'): self.audit()

    def test_observer_must_include_trailing_cpu_sample(self):
        value = self.add_observer()
        value['coverage_end_monotonic_ns'] = scanner.read_json(self.directory/'measurement-end.json')['request_interval_end_ns']+20
        self.manifest['observer'] = save(self.root/'observer.json', value)
        with self.assertRaisesRegex(ValueError, 'observation incomplete'): self.audit()

    def test_external_parent_rss_cannot_hide_cgroup_child_oom(self):
        value = self.add_observer(); value['external_source']['cgroup_oom_kill_delta'] = 1
        self.manifest['observer'] = save(self.root/'observer.json', value)
        with self.assertRaisesRegex(ValueError, 'cgroup'): self.audit()

    def test_external_observer_wrong_source_lifetime_is_rejected(self):
        value = self.add_observer(); value['external_source']['pin']['start_ticks'] += 1
        self.manifest['observer'] = save(self.root/'observer.json', value)
        with self.assertRaisesRegex(ValueError, 'External source actual process'): self.audit()

    def test_ab_requires_matching_source_kind_case_and_prelaunch_publication(self):
        context = scanner.read_json(self.manifest['launch']['path']); planned = scanner.plan(self.profile)['measurement']
        frozen = {'status': 'FROZEN_ELIGIBLE', 'identities': {'A': context['identity']}, 'cell': {
            'group': 'G2', 'case_id': 'LP-008', 'connection_mode': 'reuse_jdbc_streaming',
            'workload_sha256': scanner.business_binding(self.profile)['sha256'], 'rate': self.profile['rate'],
            'concurrency': 1, 'seed': 20260922, 'warmup_seconds': 2, 'duration_seconds': 3,
            'request_count': planned['requests'], 'arrival_schedule_sha256': planned['sha256']}}
        context.update(phase='AB', freeze=save(self.root/'freeze.json', frozen))
        context['publication'] = save(self.root/'freeze.json.published.json', {'freeze': context['freeze'],
            'boot_id': context['boot_id'], 'published_monotonic_ns': context['created_monotonic_ns']-1})
        scanner.validate_context(context, self.profile)
        frozen['cell']['case_id'] = 'LP-005'; context['freeze'] = save(self.root/'freeze.json', frozen)
        context['publication'] = save(self.root/'freeze.json.published.json', {'freeze': context['freeze'],
            'boot_id': context['boot_id'], 'published_monotonic_ns': context['created_monotonic_ns']-1})
        with self.assertRaisesRegex(ValueError, 'A/B business'): scanner.validate_context(context, self.profile)

    def test_wide_classpath_cannot_enable_unfrozen_driver_loggers(self):
        runtime = scanner.read_json(self.root/'runtime.json'); extra = self.root/'unexpected-logger.jar'; extra.write_text('synthetic')
        runtime['jars'].append(scanner.reference(extra))
        with self.assertRaisesRegex(ValueError, 'exactly the frozen'): scanner.check_runtime(runtime)

    def test_frozen_identity_cannot_keep_same_sha_but_change_reader_user(self):
        context = scanner.read_json(self.manifest['launch']['path']); context['endpoints']['user'] = 'another_reader'
        with self.assertRaisesRegex(ValueError, 'Client identity'): scanner.validate_context(context, self.profile)

    def test_frozen_environment_cannot_ignore_changed_source_ref(self):
        context = scanner.read_json(self.manifest['launch']['path'])
        context['external_source'] = save(self.root/'same-source-another-path.json', scanner.read_json(self.root/'source.json'))
        with self.assertRaisesRegex(ValueError, 'Environment identity'): scanner.validate_context(context, self.profile)

    def test_handshake_id_cannot_hide_changed_physical_socket(self):
        self.row_mutation(lambda value: value.update(socket_local_port=12345))
        with self.assertRaisesRegex(ValueError, 'reuse'): self.audit()

    def test_private_preparation_reads_only_path_and_returns_no_sql_or_secret(self):
        path = self.root/'s3-client.private.json'
        save(path, {'endpoint': 'http://10.254.29.6:9000', 'region': 'us-east-1',
                    'access_key': 'OFFLINE_TEST_ACCESS', 'secret_key': 'OFFLINE_ONLY_TEST_SECRET'}); path.chmod(0o600)
        output = self.root/'prepared.private.json'
        binding = scanner.prepare_private_query(scanner.reference(self.root/'source.json'), output, path)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(set(binding), {'path', 'sha256'})
        self.assertNotIn('OFFLINE_ONLY_TEST_SECRET', json.dumps(binding))
        context = scanner.read_json(self.manifest['launch']['path']); context['private_query'] = binding
        self.assertEqual(scanner.private_query(context, self.profile)['sql_sha256'], self.config['sql_sha256'])
        with self.assertRaises(FileExistsError): scanner.prepare_private_query(scanner.reference(self.root/'source.json'), output, path)

    def test_private_preparation_rejects_world_readable_configuration(self):
        path = self.root/'s3-client.json'; save(path, {'secret_key': 'OFFLINE'}); path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'mode0600'):
            scanner.prepare_private_query(scanner.reference(self.root/'source.json'), self.root/'new.private.json', path)

    def test_actual_metadata_preflight_required_and_not_used_as_result_oracle(self):
        source = scanner.read_json(self.root/'source.json'); value = scanner.read_json(source['metadata_evidence']['path'])
        value['sources'][0]['columns'][3]['jdbc_type'] = 1
        source['metadata_evidence'] = save(Path(source['metadata_evidence']['path']), value)
        context = scanner.read_json(self.manifest['launch']['path']); context['external_source'] = save(self.root/'source.json', source)
        with self.assertRaisesRegex(ValueError, 'metadata preflight'): scanner.external_source(context, self.profile)


if __name__ == '__main__':
    unittest.main(verbosity=2)
