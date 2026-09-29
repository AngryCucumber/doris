#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Current G2 complex SQL: explicit owned preparation, original workers/DDL, independent raw audit."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import time
from types import SimpleNamespace
import uuid

import complex_planning_fixture as legacy
import complex_planning_oracle as oracle
import p4_jdbc_evidence as clocks
import p4_statistics as statistics
import ui_background_fixture as lifecycle

SOURCE = Path(__file__).resolve()
JAVA = SOURCE.with_name("LicenseComplexPerformance.java")
PROFILE = "g2_complex_performance_v1"
ARRIVAL_ALGORITHM = "python_random_mt19937_expovariate_contiguous_warmup_v1"
MAX_LOG = 512 * 1024**2
require, read, reference, verify = statistics.require, statistics.read_json, statistics.reference, statistics.verify_reference
BOUNDS = {"warmup_seconds": (1, 1800), "duration_seconds": (1, 86400), "timeout_seconds": (1, 30),
          "drain_seconds": (1, 120), "prepare_timeout_seconds": (120, 3600), "cleanup_timeout_seconds": (30, 60),
          "coordination_timeout_seconds": (10, 1800), "max_requests": (2, 100000)}


def validate(value):
    require(set(value) == set(BOUNDS) | {"schema_version", "profile", "kind", "concurrency", "qualification",
        "rate_per_second", "seed", "read_account"}, "Complex profile fields differ")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["profile"] == PROFILE
            and type(value["seed"]) is int and value["seed"] == 20260922,
            "Complex fixed identity differs")
    require(value["kind"] in ("cold", "hot") and type(value["concurrency"]) is int and value["concurrency"] in (1, 8)
            and value["qualification"] in ("diagnostic", "formal"), "Complex representative shape invalid")
    for key, (low, high) in BOUNDS.items():
        require(type(value[key]) is int and low <= value[key] <= high, "Complex bound invalid: " + key)
    require(value["qualification"] == "diagnostic" or value["warmup_seconds"] >= 180 and value["duration_seconds"] >= 600,
            "Complex formal window too short")
    require(value["kind"] == "cold" or value["duration_seconds"] > 180, "Hot diagnostic cannot move or omit t180 event")
    rate = value["rate_per_second"]
    require(type(rate) in (int, float) and math.isfinite(rate) and 0 < rate <= 1000, "Complex rate invalid")
    require(rate * (value["warmup_seconds"] + value["duration_seconds"]) < value["max_requests"] * .95,
            "Complex client arrival cap exceeded; not a database capacity result")
    account = value["read_account"]
    require(isinstance(account, dict) and set(account) == lifecycle.ACCOUNT_KEYS
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", account["username"])
            and re.fullmatch(r"[A-Za-z0-9_.%:-]{1,128}", account["host"])
            and re.fullmatch(r"MASSDB_[A-Z0-9_]+_PASSWORD", account["password_env"]), "Complex reader must use explicit identity/secret reference")
    return value


def plan(value):
    validate(value)
    generator = random.Random(20260922)
    warm = legacy.offsets(generator, value["rate_per_second"], value["warmup_seconds"], value["max_requests"])
    measured = legacy.offsets(generator, value["rate_per_second"], value["duration_seconds"], value["max_requests"] - len(warm))
    require(warm and measured, "Complex windows require actual arrivals")
    if value["kind"] == "hot":
        require(measured[0] < 180 * 10**9 < measured[-1], "Hot arrivals must straddle fixed t180 event")
    schedule = {"schema_version": 1, "seed": 20260922, "rate_per_second": value["rate_per_second"],
                "warmup_seconds": value["warmup_seconds"], "window_seconds": value["duration_seconds"],
                "warmup_offsets_ns": warm, "measurement_offsets_ns": measured}
    return {"schedule": schedule, "algorithm": ARRIVAL_ALGORITHM,
            "total_requests": len(warm) + len(measured), "measurement_requests": len(measured),
            "measurement_schedule_sha256": hashlib.sha256(json.dumps(measured, separators=(",", ":")).encode()).hexdigest(),
            "formal_performance_pass": False}


def business_binding(value):
    validate(value)
    fields = {key: value[key] for key in ("profile", "kind", "concurrency", "seed", "timeout_seconds",
              "drain_seconds", "max_requests", "read_account")}
    fields.update(query_sha256=oracle.FROZEN_QUERY_SHA256, event_offset_seconds=180 if value["kind"] == "hot" else None,
        connection_mode="reuse" if value["kind"] == "hot" else "per_request", query_mode="text",
        sql_cache=value["kind"] == "hot", query_cache=False, profile_enabled=False,
        arrival_algorithm=ARRIVAL_ALGORITHM, driver="mariadb-java-client-3.0.9.jar", log_bound_per_file_bytes=MAX_LOG)
    return {"sha256": hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "fields": fields}


def freeze(api, profile_path, cluster, resources):
    profile_path = api.owned(profile_path); value = validate(api.read_json(profile_path)); plan(value)
    java = Path(cluster["java_home"]).resolve(strict=True); package = Path(cluster["package"]).resolve(strict=True)
    require('JAVA_VERSION="17.0.4"' in (java / "release").read_text() and api.ROOT in java.parents
            and api.ROOT in package.parents and resources["rss_limit_mib"] >= 1024, "Complex runtime/resource identity invalid")
    dependencies = []
    for pattern in ("mariadb-java-client-3.0.9.jar", "jackson-core-*.jar", "jackson-databind-*.jar", "jackson-annotations-*.jar"):
        found = list((package / "fe/lib").glob(pattern)); require(len(found) == 1, "Ambiguous complex dependency")
        dependencies.extend(found)
    sources = (SOURCE, JAVA, legacy.JAVA, Path(legacy.__file__), Path(oracle.__file__), Path(lifecycle.__file__),
               Path(clocks.__file__), Path(statistics.__file__), Path(legacy.support.__file__))
    return {"input_path": str(profile_path), "input_sha256": api.sha(profile_path), "config": value,
        "java_home": str(java), "jdk_runtime": {name: api.sha(java / name) for name in ("bin/java", "bin/javac", "lib/modules", "release")},
        "dependencies_sha256": {str(path): api.sha(path) for path in dependencies},
        "source_sha256": {str(path): api.sha(path) for path in sources}, "business_workload_sha256": business_binding(value)["sha256"]}


def prepare_owned_view(api, sql, guard, cluster_path, output, lock_path):
    """sql.one is an existing bounded, real SQL executor. This function performs no implicit launch."""
    output = api.owned(output); lock = api.owned(lock_path); guard.check()
    token = uuid.uuid4().hex; cluster = read(cluster_path)
    require(not lock.exists(), "Complex view lock exists; refuse takeover")
    with lock.open("x") as stream: stream.write(token + "\n")
    context = {"schema_version": 1, "token": token, "lock_path": str(lock), "cluster_record": reference(cluster_path),
               "namespace": cluster["namespace"], "create_attempted": False, "create_success": False,
               "started_monotonic_ns": time.monotonic_ns()}
    path = output / "preparation.json"; api.save(path, context)
    try:
        context["source_before"] = legacy.source_integrity(sql)
        context["source_create_before"] = sql.one("SHOW CREATE TABLE license_perf.point_rows")
        tables = legacy.support.rows(sql.one("SHOW TABLES FROM license_perf"))
        require(not any("license_complex_view" in row.values() for row in tables), "Refuse existing fixed-name view")
        context["create_attempted"] = True; api.save(path, context)
        sql.one(legacy.CREATE_VIEW); context["create_success"] = True
        initial = legacy.view_definition(sql); context["initial_view"] = initial
        owner = {"schema_version": 1, "view": oracle.VIEW, "view_owner_token": token,
            "namespace": cluster["namespace"], "cluster_record_sha256": api.sha(cluster_path), "create_success": True,
            "initial_show_create_view_sha256": hashlib.sha256(initial.encode()).hexdigest(), "create_sql": legacy.CREATE_VIEW}
        api.save(output / "view-owner.json", owner)
        guard.check(); context["finished_monotonic_ns"] = time.monotonic_ns(); context["status"] = "PREPARED"
        api.save(path, context); return context
    except BaseException as error:
        context["status"] = "FAILED_PREPARATION_RETAINED"; context["error_class"] = type(error).__name__
        api.save(path, context)
        # An unacknowledged CREATE cannot safely be adopted or dropped. Retain the lock and evidence.
        if not context["create_attempted"] and lock.read_text() == token + "\n": lock.unlink()
        raise


def finish_owned_view(api, sql, guard, output, prepared, helper_started=True):
    guard.check(); output = Path(output); lock = Path(prepared["lock_path"])
    require(prepared["create_success"] is True and lock.read_text() == prepared["token"] + "\n", "Complex cleanup owner missing")
    owner = read(output / "view-owner.json")
    require(owner["view_owner_token"] == prepared["token"] and owner["initial_show_create_view_sha256"]
            == hashlib.sha256(prepared["initial_view"].encode()).hexdigest(), "Complex cleanup owner changed")
    # The actual helper must first finish restoring the original view. Never race a live DDL thread.
    completion = read(output / "p4-completion.json")
    require(completion["remaining_live_pids"] == [], "Complex parent has not reaped its child")
    if helper_started:
        cleanup = read(output / "cleanup.json")
        waits = [item for item in read(output / "process-lifecycle.json") if item.get("helper") == "complex"
                 and item.get("reason") == "OWNED_PARENT_WAIT"]
        require(len(waits) == 1 and waits[0]["pid"] == completion["helper_pid"]
                and waits[0]["parent_wait_complete"] is True and waits[0]["exit_code"] == completion["exit_code"],
                "Complex cleanup has no actual helper wait")
        require(cleanup["success"] is True and cleanup["reader_threads_terminated"] is True
                and cleanup["event_thread_terminated"] is True and cleanup["cleanup_threads_terminated"] is True
                and cleanup["remaining_connection_handles"] == 0, "Complex helper did not quiesce")
    else:
        require(completion["helper_pid"] is None and not (output / "complex-process.json").exists(),
                "Cannot claim an actually launched helper never started")
    current = legacy.view_definition(sql); require(current == prepared["initial_view"], "Complex view not restored to owner definition")
    source = legacy.source_integrity(sql); schema = sql.one("SHOW CREATE TABLE license_perf.point_rows")
    require(source == prepared["source_before"] and legacy.support.rows(schema)
            == legacy.support.rows(prepared["source_create_before"]), "Complex complete source/schema changed")
    sql.one("DROP VIEW " + oracle.VIEW)
    require(not any("license_complex_view" in row.values() for row in legacy.support.rows(sql.one("SHOW TABLES FROM license_perf"))),
            "Complex owned view remains")
    guard.check(); require(lock.read_text() == prepared["token"] + "\n", "Complex lock changed before release"); lock.unlink()
    result = {"status": "OWNED_VIEW_REMOVED_SOURCE_VERIFIED", "source_after": source, "source_create_after": schema,
        "initial_view_sha256": hashlib.sha256(current.encode()).hexdigest(), "owner": reference(output / "view-owner.json"),
        "completed_monotonic_ns": time.monotonic_ns(), "helper_was_waited": helper_started}
    api.save(output / "final-oracle.json", result); return result


def validate_launch(launch, value):
    require(launch["schema_version"] == 1 and launch["phase"] in ("CAPACITY", "AA", "AB", "DIAGNOSTIC")
            and launch["variant"] in ("A", "B") and (launch["phase"] not in ("CAPACITY", "AA") or launch["variant"] == "A"),
            "Complex launch phase invalid")
    require(re.fullmatch(r"[a-f0-9]{32}", launch["launch_token"]) and launch["boot_id"] == statistics.boot_id()
            and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", launch["window_id"]) and type(launch["pair_id"]) is int
            and launch["pair_id"] >= 0 and type(launch["created_monotonic_ns"]) is int, "Complex launch identity invalid")
    clocks.utc_anchor(launch["utc_anchor"]); statistics.validate_identity(launch["identity"])
    require(read(verify(launch["workload"])) == value, "Complex launched another workload")
    bindings = launch["bindings"]
    required = {"runner", "java_helper", "legacy_helper", "oracle", "lifecycle", "clock_adapter", "statistics",
                "jdbc_driver", "fe_artifact", "be_artifact", "environment", "configuration", "fixture", "client"}
    require(set(bindings) == required, "Complex execution bindings incomplete")
    for item in bindings.values(): verify(item)
    for key, path in (("runner", SOURCE), ("java_helper", JAVA), ("legacy_helper", legacy.JAVA), ("oracle", oracle.__file__),
                      ("lifecycle", lifecycle.__file__), ("clock_adapter", clocks.__file__), ("statistics", statistics.__file__)):
        require(bindings[key] == reference(path), "Complex executed source changed: " + key)
    require(Path(bindings["jdbc_driver"]["path"]).name == "mariadb-java-client-3.0.9.jar", "Complex fixed JDBC driver differs")
    for key, name in (("fe_artifact", "fe_sha256"), ("be_artifact", "be_sha256"), *[(key, key + "_sha256") for key in
                     ("environment", "configuration", "fixture", "client")]):
        require(bindings[key]["sha256"] == launch["identity"][name], "Complex identity does not bind " + key)
    if launch["phase"] == "AB":
        frozen, publication = (read(verify(launch[key])) for key in ("freeze", "publication"))
        require(frozen["status"] == "FROZEN_ELIGIBLE" and frozen["identities"][launch["variant"]] == launch["identity"]
                and publication["freeze"] == launch["freeze"] and publication["boot_id"] == launch["boot_id"]
                and publication["published_monotonic_ns"] <= launch["created_monotonic_ns"], "Complex AB not frozen before launch")
        expected = {"group": "G2", "workload_sha256": business_binding(value)["sha256"], "rate": value["rate_per_second"],
                    "concurrency": value["concurrency"], "connection_mode": "reuse" if value["kind"] == "hot" else "per_request",
                    "seed": 20260922, "warmup_seconds": value["warmup_seconds"], "duration_seconds": value["duration_seconds"],
                    "request_count": plan(value)["measurement_requests"], "arrival_schedule_sha256": plan(value)["measurement_schedule_sha256"]}
        require(all(frozen["cell"].get(key) == item for key, item in expected.items()), "Complex frozen AB cell differs")
    else: require("freeze" not in launch and "publication" not in launch, "Complex non-AB launch claims a freeze")
    return launch


class ComplexPerformance(lifecycle.Background):
    """Owned single JVM window; caller supplies the established SQL executor and real outer guard."""

    def __init__(self, api, plan_input, guard, target, admin, deadline, cpu_services, launch, sql, cluster_path, lock_path):
        frozen = plan_input["complex"]; value = validate(frozen["config"]); validate_launch(launch, value)
        # Reuse only the owned process lifecycle; the synthetic alias selects no write requests or permissions.
        inherited = {**frozen, "config": {**value, "write_account": value["read_account"]}}
        super().__init__(api, {**plan_input, "background": inherited}, guard, target, {"id": "complex"}, admin, deadline)
        self.frozen = frozen; self.profile = value; self.sql = sql; self.cluster_path = Path(cluster_path); self.lock_path = lock_path
        self.launch = launch; self.token = launch["launch_token"]
        require(set(cpu_services) == {"fe", "be"} and cpu_services["fe"]["pid"] != cpu_services["be"]["pid"]
                and all(api.same(pin) for pin in cpu_services.values()), "Complex CPU pins missing/distinctness invalid")
        require(all(any(all(owned.get(key) == pin.get(key) for key in ("pid", "start_ticks", "namespace", "exe", "command_sha256"))
                    for owned in self.config["cluster_pins"]) for pin in cpu_services.values()), "Complex CPU pins not cluster members")
        require(all(launch["service_start_ticks"][role] == pin["start_ticks"] for role, pin in cpu_services.items()),
                "Complex CPU pins differ from launched service generations")
        require(launch["bindings"]["jdbc_driver"]["path"] in frozen["dependencies_sha256"]
                and frozen["dependencies_sha256"][launch["bindings"]["jdbc_driver"]["path"]] == launch["bindings"]["jdbc_driver"]["sha256"],
                "Complex launched JDBC driver differs from frozen dependency")
        cluster = read(self.cluster_path)
        require(all(pin["namespace"] == cluster["namespace"] for pin in cpu_services.values())
                and cpu_services["fe"]["exe"] == str((Path(frozen["java_home"]) / "bin/java").resolve())
                and api.sha(Path(cpu_services["be"]["exe"])) == launch["bindings"]["be_artifact"]["sha256"],
                "Complex CPU role executable/namespace differs")
        require(target["host"] == "127.0.0.1" and target["query_port"] == cluster["query_port"],
                "Complex legacy JDBC endpoint must match the owned local FE")
        self.cpu_services = cpu_services; self.prepared = None
        api.save(self.output / "p4-launch.json", launch); self.launch_ref = reference(self.output / "p4-launch.json")
        self.admin = admin

    def start(self):
        lifecycle.verify_frozen(self.api, self.frozen)
        self.prepared = prepare_owned_view(self.api, self.sql, self.guard, self.cluster_path, self.output, self.lock_path)
        definition = oracle.verified_definition(read(oracle.CONTRACT)); schedule = plan(self.profile)["schedule"]
        self.api.save(self.output / "definition.json", definition); self.api.save(self.output / "arrivals.json", schedule)
        cluster = read(self.cluster_path); owner = read(self.output / "view-owner.json")
        value = self.profile
        self.config = {"performance_profile": PROFILE, "qualification": value["qualification"],
            "case_id": "LP-007" if value["kind"] == "hot" else "LP-006", "mode": "text",
            "connection_mode": "reuse" if value["kind"] == "hot" else "per_request", "concurrency": value["concurrency"],
            "reader_user": value["read_account"]["username"], "reader_password_env": value["read_account"]["password_env"],
            "admin_user": self.admin["username"], "admin_password_env": self.admin["password_env"],
            "timeout_seconds": value["timeout_seconds"], "drain_seconds": value["drain_seconds"],
            "cleanup_seconds": value["cleanup_timeout_seconds"], "request_limit": value["max_requests"],
            "profile_every_n": 20000, "profile_overlap_limit": 64, "query_port": cluster["query_port"],
            "namespace": cluster["namespace"], "host_namespace": cluster["host_namespace"],
            "service_pins": [self.api.proc(os.getpid()), *self.guard.pins], "output_directory": str(self.output),
            "definition_file": str(self.output / "definition.json"), "definition_sha256": reference(self.output / "definition.json")["sha256"],
            "arrival_file": str(self.output / "arrivals.json"), "arrival_sha256": reference(self.output / "arrivals.json")["sha256"],
            "owner_record_file": str(self.output / "view-owner.json"), "controller_owner_record_sha256": reference(self.output / "view-owner.json")["sha256"],
            "view_owner_token": owner["view_owner_token"], "expected_initial_show_create_view_sha256": owner["initial_show_create_view_sha256"],
            "stop_file": str(self.output / "stop"), "p4_launch": self.launch_ref, "cpu_services": self.cpu_services,
            "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"), "coordination_timeout_seconds": value["coordination_timeout_seconds"]}
        self.api.save(self.config_path, self.config)
        classes = self.output / "classes"; classes.mkdir()
        self.classpath = os.pathsep.join([str(classes), *sorted(self.frozen["dependencies_sha256"])])
        java = Path(self.frozen["java_home"]) / "bin/java"; deadline = min(self.whole_deadline, time.monotonic() + 120)
        try:
            self._launch([java.with_name("javac"), "-J-Xmx256m", "--release", "17", "-encoding", "UTF-8", "-cp", self.classpath,
                          "-d", classes, legacy.JAVA, JAVA], "compile", deadline)
            self._await(lambda: self.process.poll() is not None, deadline); require(self.process.returncode == 0, "Complex compilation failed")
        finally: lifecycle.reap_owned(self.api, self.process, self.pin, deadline, self._process_event)
        lifecycle.verify_frozen(self.api, self.frozen)
        self.api.save(self.output / "helper-identity.json", {"frozen": self.frozen,
            "classes": {str(path): self.api.sha(path) for path in classes.glob("*.class")}})
        deadline = min(self.whole_deadline, time.monotonic() + value["prepare_timeout_seconds"])
        self._launch([java, "-Xmx512m", "-cp", self.classpath, "LicenseComplexPerformance", self.config_path], "complex", deadline)
        self.work_pin = dict(self.pin)
        self._await(lambda: (self.output / "ready.json").exists(), deadline)
        self._check_receipt(read(self.output / "ready.json"))

    def _check_receipt(self, value):
        require(value["launch_token"] == self.token and value["launch_sha256"] == self.launch_ref["sha256"]
                and value["pid"] == self.work_pin["pid"] and value["start_ticks"] == self.work_pin["start_ticks"]
                and value["namespace"] == self.work_pin["namespace"], "Complex receipt belongs to another helper")

    def release_warmup(self):
        self.check(); require(not (self.output / "clock-request.json").exists(), "Complex warmup already released")
        nonce = uuid.uuid4().hex; before = time.monotonic_ns()
        self.api.save(self.output / "clock-request.json", {"token": self.token, "nonce": nonce})
        self._await(lambda: (self.output / "p4-helper-clock.json").exists(),
                    min(self.whole_deadline, time.monotonic() + self.profile["coordination_timeout_seconds"]))
        helper = read(self.output / "p4-helper-clock.json"); after = time.monotonic_ns(); self._check_receipt(helper)
        bridge = {"schema_version": 1, "launch_token": self.token, "launch_sha256": self.launch_ref["sha256"],
            "boot_id": self.launch["boot_id"], "nonce": nonce, "controller_before_ns": before, "controller_after_ns": after,
            "helper_clock": reference(self.output / "p4-helper-clock.json")}
        clocks.clock_bridge(self.launch, self.launch_ref, bridge, helper)
        self.api.save(self.output / "p4-clock-bridge.json", bridge)
        self.api.save(self.output / "clock-ack.json", {"token": self.token, "nonce": nonce})

    def release_measurement(self):
        self.check(); self._check_receipt(read(self.output / "measurement-ready.json"))
        require(not (self.output / "measurement-release.json").exists(), "Complex measurement already released")
        self.api.save(self.output / "measurement-release.json", {"token": self.token, "controller_monotonic_ns": time.monotonic_ns()})

    def finish(self):
        if self.finished: return read(self.output / "controller.json")
        self.finished = True; failures = []; clean = False
        deadline = self.whole_deadline
        try: self._await(lambda: self.process.poll() is not None, deadline)
        except BaseException as error:
            failures.append(lifecycle.process_error(error, "complex_wait")); (self.output / "stop").touch(exist_ok=True)
        finally:
            try: clean = lifecycle.reap_owned(self.api, self.process, self.pin, deadline, self._process_event)
            except BaseException as error: failures.append(lifecycle.process_error(error, "complex_reap"))
        completion = {"schema_version": 1, "launch_token": self.token, "launch_sha256": self.launch_ref["sha256"],
            "boot_id": self.launch["boot_id"], "helper_pid": self.work_pin["pid"] if self.work_pin else None,
            "helper_start_ticks": self.work_pin["start_ticks"] if self.work_pin else None,
            "exit_code": self.process.returncode if self.process else None, "completed_monotonic_ns": time.monotonic_ns(),
            "remaining_live_pids": [] if clean else ["UNPROVEN_EXIT"]}
        if (self.output / "p4-clock-bridge.json").exists(): completion["bridge"] = reference(self.output / "p4-clock-bridge.json")
        self.api.save(self.output / "p4-completion.json", completion)
        final = None
        if clean and self.prepared:
            try: final = finish_owned_view(self.api, self.sql, self.guard, self.output, self.prepared, self.work_pin is not None)
            except BaseException as error: failures.append(lifecycle.process_error(error, "complex_view_cleanup"))
        try: lifecycle.verify_frozen(self.api, self.frozen); self.guard.check()
        except BaseException as error: failures.append(lifecycle.process_error(error, "complex_frozen_inputs"))
        summary = read(self.output / "summary.json") if (self.output / "summary.json").exists() else {}
        report = {"status": "RAW_WINDOW_COMPLETE" if clean and final and not failures and completion["exit_code"] == 0
            and summary.get("success") is True else "INVALID_WINDOW", "errors": failures, "summary": summary,
            "owned_child_exited": clean, "cleanup_confirmed": final is not None, "rss_peak_mib_sampled": self.peak,
            "formal_performance_pass": False}
        self.api.save(self.output / "controller.json", report); return report


def json_lines(path, maximum=MAX_LOG):
    path = Path(path); require(path.is_file() and path.stat().st_size <= maximum, "Complex raw log missing or over bound")
    with path.open("rb") as stream:
        for line in stream:
            require(line.endswith(b"\n") and len(line) <= 16384, "Complex partial/oversized raw receipt")
            yield json.loads(line)


def percentile(values, fraction):
    ordered = sorted(values); require(ordered, "Complex metric has no successful samples")
    index = (len(ordered) - 1) * fraction; lower = int(index)
    return ordered[lower] + (ordered[min(lower + 1, len(ordered) - 1)] - ordered[lower]) * (index - lower)


def audit_requests(directory, value, definition, identity):
    planned = plan(value); schedule = planned["schedule"]
    require(read(directory / "arrivals.json") == schedule, "Complex arrival sequence changed")
    event = read(directory / "event.json")
    if value["kind"] == "hot":
        start = read(directory / "measurement-start.json")
        require(event["clock_domain"] == identity["clock_domain"] and event["sql"] ==
                "ALTER VIEW " + oracle.VIEW + " AS SELECT id, grp, v + 1 AS v, payload FROM license_perf.point_rows"
                and event["scheduled_ns"] == start["epoch_ns"] + 180 * 10**9
                and event["scheduled_offset_seconds"] == 180 and event["ddl_attempted"] is True
                and event["ddl_success"] is True and event["commit_outcome"] == "ACKNOWLEDGED"
                and event["post_ddl_inspection_success"] is True
                and event["scheduled_ns"] <= event["started_ns"] <= event["commit_ack_ns"] <= event["finished_ns"],
                "Complex fixed DDL event missing, early, uncertain or incomplete")
    else:
        require(event["ddl_attempted"] is False and event["ddl_success"] is False and event["status"] == "NOT_APPLICABLE_COLD",
                "Cold complex window ran a DDL event")
        event = None
    intents = {}; expected = {}
    for phase in ("warmup", "measurement"):
        start = read(directory / (phase + "-start.json"))
        for index, offset in enumerate(schedule[phase + "_offsets_ns"]): expected[(phase, index)] = start["epoch_ns"] + offset
    for item in json_lines(directory / "request-starts.jsonl"):
        key = (item["phase"], item["arrival_index"]); identifier = item["request_id"]
        require(type(identifier) is int and identifier > 0 and identifier not in intents and key in expected
                and item["scheduled_ns"] == expected[key] and item["clock_domain"] == identity["clock_domain"],
                "Complex raw intent identity/schedule changed")
        intents[identifier] = item
    require(len(intents) == len(expected), "Complex missing request intents")
    phase_rows = {phase: {"latencies": [], "services": [], "queues": [], "last": 0,
                  "models": {"initial": 0, "changed": 0}, "relations": {}} for phase in ("warmup", "measurement")}
    seen = set(); seen_positions = set(); previous = {}
    for item in json_lines(directory / "requests.jsonl"):
        identifier = item["request_id"]; phase = item["phase"]; key = (phase, item["arrival_index"])
        require(identifier in intents and identifier not in seen and key not in seen_positions and key in expected,
                "Complex duplicate or foreign completion")
        intent = intents[identifier]; worker = item["worker"]
        require(type(worker) is int and worker == item["arrival_index"] % value["concurrency"]
                and all(item[name] == intent[name] for name in ("phase", "arrival_index", "worker", "scheduled_ns", "request_started_ns"))
                and all(item[name] == identity[name] for name in ("pid", "start_ticks", "namespace", "clock_domain", "launch_token", "launch_sha256", "boot_id")),
                "Complex request belongs to another worker/lifetime")
        ordered = [item["scheduled_ns"], item["request_started_ns"], item["started_ns"], item["finished_ns"], item["request_finished_ns"]]
        require(all(type(number) is int for number in ordered) and ordered == sorted(ordered)
                and previous.get((phase, worker), 0) <= item["request_started_ns"], "Complex request/worker timing invalid")
        require(item["success"] is True and item["sql_success"] is True and item["timed_auxiliary_query_count"] == 0
                and item["connection_mode"] == ("reuse" if value["kind"] == "hot" else "per_request")
                and not any(key in item for key in ("query_id", "query_id_lookup_ns", "explain_file", "sample_profile", "error_class"))
                and item["query_sha256_utf8"] == oracle.FROZEN_QUERY_SHA256, "Complex timed observer SQL or request failure")
        relation = oracle.verify_request(item, definition, event if phase == "measurement" else None)
        require(item["columns_verified"] == 33 and item["online_model"] == relation["matched_model"], "Complex online/offline model differs")
        for name in ("connection_ns", "session_init_ns", "prepare_ns", "close_ns"):
            require(type(item[name]) is int and 0 <= item[name] <= item["request_finished_ns"] - item["request_started_ns"],
                    "Complex connection timing invalid")
            if value["kind"] == "hot": require(item[name] == 0, "Hot complex request opened a new connection")
        seen.add(identifier); seen_positions.add(key); previous[(phase, worker)] = item["request_finished_ns"]
        values = phase_rows[phase]; values["last"] = max(values["last"], item["request_finished_ns"])
        values["latencies"].append((item["request_finished_ns"] - item["scheduled_ns"]) / 1e6)
        values["services"].append((item["request_finished_ns"] - item["request_started_ns"]) / 1e6)
        values["queues"].append((item["request_started_ns"] - item["scheduled_ns"]) / 1e6)
        values["models"][relation["matched_model"]] += 1
        values["relations"][relation["phase"]] = values["relations"].get(relation["phase"], 0) + 1
    require(len(seen) == len(expected) and seen_positions == set(expected), "Complex complete arrival/intent/terminal coverage missing")
    results = {}
    for phase, values in phase_rows.items():
        start, end = (read(directory / (phase + "-" + name + ".json")) for name in ("start", "end"))
        seconds = value["warmup_seconds"] if phase == "warmup" else value["duration_seconds"]
        boundary = max(values["last"], start["epoch_ns"] + seconds * 10**9)
        require(end["epoch_ns"] == start["epoch_ns"] and end["last_request_end_ns"] == values["last"]
                and end["request_interval_end_ns"] == boundary and end["java_monotonic_ns"] >= boundary,
                "Complex actual window does not enclose every response")
        count = len(values["latencies"]); duration = (boundary - start["epoch_ns"]) / 1e9
        result = {"scheduled_requests": count, "observed_requests": count, "successful_requests": count,
            "error_count": 0, "timeout_count": 0, "retry_count": 0, "effective_duration_seconds": duration,
            "success_qps": count / duration, "p95_ms": percentile(values["latencies"], .95),
            "p99_ms": percentile(values["latencies"], .99), "service_p95_ms": percentile(values["services"], .95),
            "service_p99_ms": percentile(values["services"], .99), "queue_p95_ms": percentile(values["queues"], .95),
            "queue_p99_ms": percentile(values["queues"], .99), "models": values["models"], "relations": values["relations"]}
        for role in ("fe", "be"):
            first, final = start["cpu"][role], end["cpu"][role]
            require(first["pid"] == final["pid"] and first["start_ticks"] == final["start_ticks"]
                    and first["sample_started_java_ns"] <= first["sample_ended_java_ns"] <= start["epoch_ns"]
                    and boundary <= final["sample_started_java_ns"] <= final["sample_ended_java_ns"], "Complex CPU sample/lifetime invalid")
            delta = final["cpu_seconds"] - first["cpu_seconds"]
            require(math.isfinite(delta) and delta >= 0, "Complex CPU counter invalid")
            result[role + "_cpu_seconds_per_success"] = delta / count
        results[phase] = result
    if event:
        require(results["measurement"]["relations"].get("completed_before_ddl", 0) > 0
                and results["measurement"]["relations"].get("started_after_commit_ack", 0) > 0,
                "Complex event lacks actual before/after business results")
        results["ddl"] = {"scheduled_ns": event["scheduled_ns"], "started_ns": event["started_ns"],
            "commit_ack_ns": event["commit_ack_ns"], "scheduling_delay_ns": event["started_ns"] - event["scheduled_ns"],
            "commit_elapsed_ns": event["commit_ack_ns"] - event["started_ns"], "snapshot_time_inferred": False}
    return results


def verify_path_preflight(binding, launch, value, definition, warm_lower):
    """A separate real preflight executor supplies same-connection query-ID/Profile/EXPLAIN evidence."""
    proof = read(verify(binding)); verify(proof["auditor"])
    require(proof["status"] == "VERIFIED" and proof["kind"] == value["kind"]
            and proof["fe_artifact"] == launch["bindings"]["fe_artifact"]
            and proof["service_start_ticks"] == launch["service_start_ticks"]
            and launch["created_monotonic_ns"] <= proof["completed_monotonic_ns"] <= warm_lower,
            "Complex real path preflight not bound to this deployment/before warmup")
    query = read(verify(proof["query_receipt"])); explain = read(verify(proof["explain_receipt"]))
    session = read(verify(proof["session_receipt"])); account = value["read_account"]
    actual_user = re.fullmatch(r"(?:'([A-Za-z][A-Za-z0-9_]{0,63})'|([A-Za-z][A-Za-z0-9_]{0,63}))@(?:'([^']+)'|([^']+))",
                               session["current_user"])
    require(actual_user is not None and (actual_user[1] or actual_user[2]) == account["username"]
            and (actual_user[3] or actual_user[4]) == account["host"] and session["reader_user"] == account["username"]
            and session["current_catalog"] == "internal" and session["current_database"] == "license_perf"
            and type(session["connection_id"]) is int and session["connection_id"] > 0
            and session["connection_id"] == query["connection_id"]
            and session["settings"] == {"enable_sql_cache": value["kind"] == "hot", "enable_query_cache": False,
                                       "enable_short_circuit_query": False, "enable_profile": True},
            "Complex cache preflight must use the measured reader/catalog/database and session settings")
    actual = oracle.read_values(query["columns"], query["rows"])
    require(actual == definition["initial"] and query["query_sha256_utf8"] == oracle.FROZEN_QUERY_SHA256
            and query["query_id_same_connection"] is True and query["query_id_sql"] == "SELECT last_query_id()",
            "Complex preflight complete oracle or same-connection query identity missing")
    oracle.verify_profile(Path(verify(proof["profile_text"])).read_text(), query["query_id"], definition["query_sql"], cached=value["kind"] == "hot")
    require(isinstance(explain["rows"], list) and explain["rows"] and all(isinstance(row, str) for row in explain["rows"])
            and explain["sql"] == "EXPLAIN PHYSICAL PLAN " + definition["query_sql"], "Complex preflight EXPLAIN missing")
    cached = any("PhysicalSqlCache" in row for row in explain["rows"])
    require(cached == (value["kind"] == "hot"), "Complex actual cache path differs")
    return proof


def normalize(manifest):
    directory = Path(manifest["window_directory"]).resolve()
    def raw_files():
        return [reference(path) for path in sorted(directory.iterdir()) if path.is_file() and path.suffix in (".json", ".jsonl")]
    before = raw_files(); helper_identity = read(directory / "helper-identity.json"); frozen = helper_identity["frozen"]
    lifecycle.verify_frozen(SimpleNamespace(sha=statistics.digest), frozen)
    require(set(frozen["jdk_runtime"]) == {"bin/java", "bin/javac", "lib/modules", "release"}
            and all(str(path) in frozen["source_sha256"] for path in (SOURCE, JAVA, legacy.JAVA))
            and str(directory / "classes/LicenseComplexPerformance.class") in helper_identity["classes"], "Complex runtime/classes missing")
    for path, digest in helper_identity["classes"].items(): require(statistics.digest(path) == digest, "Complex class bytes changed")
    value = validate(frozen["config"]); definition = oracle.verified_definition(read(oracle.CONTRACT))
    require(read(directory / "definition.json") == definition and read(verify({"path": frozen["input_path"], "sha256": frozen["input_sha256"]})) == value,
            "Complex independent definition/profile differs")
    launch_ref = manifest["launch"]; launch = read(verify(launch_ref)); validate_launch(launch, value)
    config = read(directory / "config.json"); identity = read(directory / "identity.json")
    require(identity["launch_token"] == launch["launch_token"] and identity["launch_sha256"] == launch_ref["sha256"]
            and identity["boot_id"] == launch["boot_id"], "Complex raw identity belongs to another launch/boot")
    require(config["p4_launch"] == launch_ref == reference(directory / "p4-launch.json")
            and config["performance_profile"] == PROFILE and config["mode"] == "text"
            and config["connection_mode"] == business_binding(value)["fields"]["connection_mode"]
            and config["concurrency"] == value["concurrency"] and config["drain_seconds"] == value["drain_seconds"]
            and config["timeout_seconds"] == value["timeout_seconds"] and config["request_limit"] == value["max_requests"]
            and config["qualification"] == value["qualification"]
            and config["case_id"] == ("LP-007" if value["kind"] == "hot" else "LP-006")
            and config["reader_user"] == value["read_account"]["username"]
            and config["reader_password_env"] == value["read_account"]["password_env"]
            and identity["java_runtime_version"] == "17.0.4+8"
            and identity["profile_enabled"] is False and identity["timed_query_identity_or_explain_queries"] == 0,
            "Complex actual performance/session configuration differs")
    for name, field in (("definition", "definition"), ("arrivals", "arrival")):
        require(Path(config[field + "_file"]).resolve() == directory / (name + ".json")
                and config[field + "_sha256"] == identity[field + "_sha256"] == statistics.digest(directory / (name + ".json")),
                "Complex actual definition/schedule binding differs")
    require(identity["performance_profile"] == PROFILE and identity["query_sha256_utf8"] == oracle.FROZEN_QUERY_SHA256
            and identity["mode"] == "text" and identity["concurrency"] == value["concurrency"]
            and identity["connection_mode"] == config["connection_mode"], "Complex helper identity differs")
    process = read(directory / "complex-process.json"); pin = process["pin"]
    require(all(identity[key] == pin[key] for key in ("pid", "start_ticks", "namespace")), "Complex helper lifetime differs")
    command = [str(Path(frozen["java_home"]) / "bin/java"), "-Xmx512m", "-cp",
        os.pathsep.join([str(directory / "classes"), *sorted(frozen["dependencies_sha256"])]), "LicenseComplexPerformance", str(directory / "config.json")]
    command_hash = hashlib.sha256(b"\0".join(os.fsencode(item) for item in command) + b"\0").hexdigest()
    require(pin["command_sha256"] == process["expected_launch"]["command_sha256"] == command_hash
            and pin["exe"] == str((Path(frozen["java_home"]) / "bin/java").resolve()), "Complex actual command differs")
    completion = read(verify(manifest["completion"]))
    require(completion["launch_token"] == launch["launch_token"] and completion["launch_sha256"] == launch_ref["sha256"]
            and completion["boot_id"] == launch["boot_id"] and completion["helper_pid"] == pin["pid"]
            and completion["helper_start_ticks"] == pin["start_ticks"] and completion["exit_code"] == 0
            and completion["remaining_live_pids"] == [], "Complex helper completion missing")
    bridge = read(verify(completion["bridge"])); helper = read(verify(bridge["helper_clock"]))
    require(helper["helper_pid"] == pin["pid"] and helper["helper_start_ticks"] == pin["start_ticks"]
            and helper["clock_domain"] == identity["clock_domain"], "Complex foreign clock helper")
    original_mapping = clocks.clock_bridge(launch, launch_ref, bridge, helper)
    waits = [item for item in read(directory / "process-lifecycle.json") if item.get("helper") == "complex"
             and item.get("reason") == "OWNED_PARENT_WAIT"]
    require(len(waits) == 1 and waits[0]["pid"] == pin["pid"] and waits[0]["exit_code"] == 0
            and waits[0]["parent_wait_complete"] is True and type(waits[0].get("controller_monotonic_ns")) is int
            and bridge["controller_after_ns"] <= waits[0]["controller_monotonic_ns"] <= completion["completed_monotonic_ns"],
            "Complex actual parent wait missing or reordered")
    required = ("ready.json", "warmup-start.json", "warmup-end.json", "measurement-ready.json", "measurement-start.json",
                "measurement-end.json", "p4-helper-finished.json")
    for name in required:
        item = read(directory / name)
        require(all(item[key] == identity[key] for key in ("pid", "start_ticks", "namespace", "clock_domain",
                    "launch_token", "launch_sha256", "boot_id")), "Complex raw receipt from another launch")
    audit = audit_requests(directory, value, definition, identity)
    warm_start, warm_end, ready, start, end, finished = (read(directory / name) for name in
        ("warmup-start.json", "warmup-end.json", "measurement-ready.json", "measurement-start.json", "measurement-end.json", "p4-helper-finished.json"))
    require(len(list(directory.glob("worker-setup-*.json"))) == value["concurrency"], "Complex worker setup set differs")
    legacy.setup_audit(directory, identity, {"warmup_start_ns": warm_start["epoch_ns"]},
                       {"concurrency": value["concurrency"], "connection_mode": config["connection_mode"]})
    cleanup = read(directory / "cleanup.json"); summary = read(directory / "summary.json"); control = read(directory / "controller.json")
    require(helper["jvm_sample_ns"] <= warm_start["epoch_ns"] <= warm_end["java_monotonic_ns"]
            <= ready["java_monotonic_ns"] <= start["epoch_ns"] <= end["java_monotonic_ns"]
            <= cleanup["started_ns"] <= cleanup["finished_ns"] <= finished["java_monotonic_ns"], "Complex warmup/cleanup ordering invalid")
    require(cleanup["clock_domain"] == summary["clock_domain"] == identity["clock_domain"] and cleanup["success"] is True
            and all(cleanup[key] is True for key in ("reader_threads_terminated", "event_thread_terminated", "cleanup_threads_terminated", "initial_definition_matches"))
            and cleanup["remaining_connection_handles"] == 0 and cleanup["deadline_exceeded"] is False
            and summary["success"] is True and summary["event_commit_unknown"] is False
            and summary["request_intents"] == summary["completed_receipts"] == plan(value)["total_requests"]
            and summary["uncompleted_intents"] == 0 and finished["success"] is True and finished["workers_closed"] is True
            and control["status"] == "RAW_WINDOW_COMPLETE" and not control["errors"] and control["owned_child_exited"] is True,
            "Complex incomplete/failed lifecycle cannot qualify")
    upper = min(original_mapping["offset_upper_ns"], waits[0]["controller_monotonic_ns"] - finished["java_monotonic_ns"])
    lower = original_mapping["offset_lower_ns"]; require(lower <= upper, "Complex clock/actual wait contradict")
    offset = (lower + upper) // 2
    mapping = {**original_mapping, "offset_upper_ns": upper, "estimated_offset_ns": offset, "uncertainty_ns": max(offset - lower, upper - offset)}
    warm_lower = warm_start["epoch_ns"] + lower
    observed_lower = min(item["sample_started_java_ns"] for item in warm_start["cpu"].values()) + lower
    observed_upper = max(end["java_monotonic_ns"], *[item["sample_ended_java_ns"] for item in end["cpu"].values()]) + upper
    require(warm_lower >= launch["created_monotonic_ns"], "Complex launch cannot be proven before warmup")
    prepared, final, owner = (read(directory / name) for name in ("preparation.json", "final-oracle.json", "view-owner.json"))
    expected_source = {"n": 1000000, "distinct_ids": 1000000, "min_id": 0, "max_id": 999999,
                       "sum_id": 499999500000, "sum_grp": 511370976, "sum_v": 49999500000, "bad_rows": 0}
    require(prepared["status"] == "PREPARED" and prepared["create_success"] is True
            and prepared["source_before"] == expected_source and final["helper_was_waited"] is True
            and prepared["finished_monotonic_ns"] <= warm_lower and final["completed_monotonic_ns"] >= completion["completed_monotonic_ns"]
            and final["status"] == "OWNED_VIEW_REMOVED_SOURCE_VERIFIED" and final["source_after"] == prepared["source_before"]
            and legacy.support.rows(final["source_create_after"]) == legacy.support.rows(prepared["source_create_before"])
            and owner["view_owner_token"] == prepared["token"] == config["view_owner_token"]
            and owner["initial_show_create_view_sha256"] == final["initial_view_sha256"]
            == hashlib.sha256(prepared["initial_view"].encode()).hexdigest(), "Complex owned source/view final oracle incomplete")
    require(Path(config["owner_record_file"]).resolve() == directory / "view-owner.json"
            and config["controller_owner_record_sha256"] == reference(directory / "view-owner.json")["sha256"]
            and final["owner"] == reference(directory / "view-owner.json")
            and config["expected_initial_show_create_view_sha256"] == owner["initial_show_create_view_sha256"],
            "Complex owner binding differs")
    preflight = verify_path_preflight(manifest["path_preflight"], launch, value, definition, warm_lower)
    external = []
    for key in ("resources", "license_state"):
        proof = read(verify(manifest[key])); verify(proof["auditor"])
        require(proof["status"] == "VERIFIED" and proof["kind"] == key and proof["launch_sha256"] == launch_ref["sha256"]
                and proof["boot_id"] == launch["boot_id"] and proof["coverage_start_monotonic_ns"] <= observed_lower
                and proof["coverage_end_monotonic_ns"] >= observed_upper and proof["raw_artifacts"], "Complex external observation missing")
        for item in proof["raw_artifacts"]: verify(item)
        if key == "resources":
            require(proof["resource_failures"] == [] and proof["budget_verified"] is True, "Complex resource failure cannot qualify")
            for role in ("fe", "be"):
                deployed = proof["services"][role]
                require(deployed["artifact"] == launch["bindings"][role + "_artifact"]
                        and deployed["pid"] == config["cpu_services"][role]["pid"]
                        and deployed["start_ticks"] == config["cpu_services"][role]["start_ticks"] == launch["service_start_ticks"][role],
                        "Complex CPU/resource service lifetime differs")
                for boundary in (warm_start, warm_end, start, end):
                    require(all(boundary["cpu"][role][field] == deployed[field] for field in ("pid", "start_ticks")), "Complex CPU attribution differs")
        else: require(proof["observed_state"] == ("ORIGINAL_A_NO_LICENSE" if launch["variant"] == "A" else "VALID"), "Complex actual state differs")
        external.append(proof)
    measured = audit["measurement"]
    window = {"window_id": launch["window_id"], "pair_id": launch["pair_id"], "variant": launch["variant"], "boot_id": launch["boot_id"],
        "identity": launch["identity"], "workload_sha256": business_binding(value)["sha256"], "arrival_schedule_sha256": plan(value)["measurement_schedule_sha256"],
        "rate": value["rate_per_second"], "warmup_seconds": value["warmup_seconds"], "duration_seconds": value["duration_seconds"],
        "warmup_start_monotonic_ns": warm_start["epoch_ns"] + offset, "warmup_end_monotonic_ns": warm_end["java_monotonic_ns"] + offset,
        "start_monotonic_ns": start["epoch_ns"] + offset, "end_monotonic_ns": end["request_interval_end_ns"] + offset,
        "monotonic_clock_domain": "bounded_jvm_mapping", "monotonic_mapping": mapping, "monotonic_mapping_uncertainty_ns": mapping["uncertainty_ns"],
        **{key: measured[key] for key in ("effective_duration_seconds", "scheduled_requests", "observed_requests", "successful_requests", "error_count", "timeout_count", "retry_count")},
        "oracle_verified": True, "cleanup_verified": True, "cpu_boundary_verified": True,
        "metrics": {key: measured[key] for key in statistics.METRICS}}
    dependencies = [launch["workload"], *launch["bindings"].values(), reference(oracle.CONTRACT), preflight["auditor"], *[item["auditor"] for item in external]]
    for files in (helper_identity["classes"], frozen["source_sha256"], frozen["dependencies_sha256"]):
        dependencies.extend({"path": str(Path(path).resolve()), "sha256": digest} for path, digest in files.items())
    dependencies.extend({"path": str((Path(frozen["java_home"]) / path).resolve()), "sha256": digest} for path, digest in frozen["jdk_runtime"].items())
    if launch["phase"] == "AB":
        require(read(verify(launch["publication"]))["published_monotonic_ns"] <= warm_lower, "Complex warmup predates published freeze")
        window.update(freeze_sha256=launch["freeze"]["sha256"], freeze_publication_sha256=launch["publication"]["sha256"])
        dependencies += [launch["freeze"], launch["publication"]]
    after = raw_files(); require(before == after, "Complex raw files changed during independent audit")
    raw = {item["path"]: item for item in after}
    for item in (manifest["launch"], manifest["completion"], completion["bridge"], bridge["helper_clock"], manifest["path_preflight"],
                 preflight["query_receipt"], preflight["profile_text"], preflight["explain_receipt"], preflight["session_receipt"],
                 manifest["resources"], manifest["license_state"],
                 *[item for proof in external for item in proof["raw_artifacts"]]):
        verify(item); raw[item["path"]] = item
    dependencies = list({item["path"]: item for item in dependencies}.values())
    for item in dependencies: verify(item)
    qualified_shape = value["qualification"] == "formal" and launch["phase"] != "DIAGNOSTIC"
    return {"status": "VERIFIED" if qualified_shape else "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED", "window": window,
        "auditor": reference(SOURCE), "raw_artifacts": list(raw.values()), "dependency_bindings": dependencies,
        "request_audit": audit, "clock_causality_audit": {"original_mapping": original_mapping, "wait": waits[0], "effective_mapping": mapping},
        "formal_shape_met": qualified_shape and measured["successful_requests"] >= 10000, "formal_performance_pass": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("mode", choices=("plan", "normalize"))
    parser.add_argument("--input", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(); require(not args.output.exists(), "Never overwrite complex evidence")
    if args.mode == "normalize": require(Path(read(args.input)["window_directory"]).resolve() not in args.output.resolve().parents,
                                         "Complex normalized output must remain outside raw directory")
    result = plan(read(args.input)) if args.mode == "plan" else normalize(read(args.input))
    with args.output.open("x") as stream: json.dump(result, stream, indent=2, allow_nan=False); stream.write("\n")
    args.output.chmod(0o600); print(json.dumps({"status": result.get("status", "PLANNED_NOT_RUN"), "output": reference(args.output)}))


if __name__ == "__main__":
    main()
