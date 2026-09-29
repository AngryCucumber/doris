#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""One owned G2 Flight window, or offline plan/compile/audit. Never qualifies performance by itself."""

import argparse
import csv
import functools
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time

import p4_jdbc_evidence as clocks
import p4_jdbc_lifecycle as lifecycle
import p4_statistics as statistics

SOURCE = Path(__file__).resolve()
JAVA = SOURCE.with_name("LicenseFlightPerformance.java")
FIXTURE = SOURCE.with_name("LicenseFlightFixture.java")
PROFILE = "g2_flight_v1"
MODEL_SHA = "d07f615ccea4c0f21cc4a7505c400a0b47d454eaa06521092e607aa646c21a68"
SCHEMA = "Schema<id: Int(64, true) not null, payload: Utf8>"
require = statistics.require
read_json = statistics.read_json
reference = statistics.reference
verify_reference = statistics.verify_reference
publish = lifecycle.publish
BOUNDS = {"warmup_seconds": (1, 7200), "duration_seconds": (1, 86400), "drain_seconds": (1, 3600),
          "max_requests": (2, 250000)}
SOURCES = {"runner": SOURCE, "java_helper": JAVA, "flight_fixture": FIXTURE,
           "clock_adapter": Path(clocks.__file__), "lifecycle": Path(lifecycle.__file__),
           "statistics": Path(statistics.__file__)}
IDENTITIES = {"fe_artifact": "fe_sha256", "be_artifact": "be_sha256", "environment": "environment_sha256",
              "configuration": "configuration_sha256", "fixture": "fixture_sha256", "client": "client_sha256"}


def validate_profile(value):
    require(isinstance(value, dict) and set(value) == set(BOUNDS) | {"schema_version", "profile", "qualification",
            "seed", "batch_size", "concurrency", "rate"}, "Flight profile has missing or extra fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["profile"] == PROFILE,
            "Flight schema/profile invalid")
    require(type(value["seed"]) is int and value["seed"] == 20260922, "Flight seed changed")
    require(type(value["batch_size"]) is int and value["batch_size"] in (1024, 8192)
            and type(value["concurrency"]) is int and value["concurrency"] in (1, 8), "Flight retained G2 matrix changed")
    for key, (low, high) in BOUNDS.items():
        require(type(value[key]) is int and low <= value[key] <= high, "Flight bound invalid: " + key)
    require(type(value["rate"]) in (int, float) and math.isfinite(value["rate"]) and 0 < value["rate"] <= 1000,
            "Flight arrival rate invalid")
    require(value["qualification"] in ("diagnostic", "formal"), "Flight qualification invalid")
    require(value["qualification"] != "formal" or value["warmup_seconds"] >= 180 and value["duration_seconds"] >= 600,
            "Flight formal duration cannot be shortened")
    require(value["rate"] * max(value["warmup_seconds"], value["duration_seconds"]) < value["max_requests"] * .95,
            "Flight expected arrivals exceed frozen bound")
    return value


def arrivals(rate, seconds, maximum):
    """Independent Java Random model; numerical cross-language comparison permits at most 1 ns."""
    state = (20260922 ^ 0x5DEECE66D) & ((1 << 48) - 1)
    def bits(count):
        nonlocal state
        state = (state * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return state >> (48 - count)
    elapsed, result = 0.0, []
    while True:
        uniform = ((bits(26) << 27) + bits(27)) / float(1 << 53)
        if uniform == 0: continue
        elapsed += -math.log(uniform) * 1e9 / rate
        if elapsed >= seconds * 1e9: return result
        require(len(result) < maximum, "Flight generated arrivals exceed bound")
        result.append(int(elapsed))


def plan(profile):
    validate_profile(profile); result = {}
    for phase, key in (("warmup", "warmup_seconds"), ("measurement", "duration_seconds")):
        offsets = arrivals(profile["rate"], profile[key], profile["max_requests"])
        require(offsets, "Flight phase has no scheduled operations")
        text = "sequence\toffset_ns\n" + "".join(f"{index}\t{offset}\n" for index, offset in enumerate(offsets))
        result[phase] = {"offsets": offsets, "requests": len(offsets), "tsv": text,
                         "sha256": hashlib.sha256(text.encode()).hexdigest()}
    require(profile["qualification"] != "formal" or result["measurement"]["requests"] >= 10000,
            "Formal Flight needs at least 10000 complete logical queries, never Arrow rows or batches")
    return result


def business_binding(profile):
    validate_profile(profile)
    fields = {key: profile[key] for key in ("profile", "seed", "batch_size", "concurrency", "drain_seconds", "max_requests")}
    fields.update(case_id="LP-010", connection_mode="reuse_fe_and_be_channels", rows_per_operation=1000000,
                  model_sha256=MODEL_SHA, schema=SCHEMA, source="license_perf.point_rows",
                  sql="ORDER BY id; batch_size selected; short circuit/sql cache/query cache disabled; query_timeout=60",
                  fresh_fe_ticket_each_operation=True, rpc_timeouts_seconds={"fe_execute": 90, "be_stream": 90},
                  arrival_model="JavaRandom20260922_StrictMathPoisson_v1", complete_oracle_in_service_time=True)
    return {"sha256": hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "fields": fields}


@functools.lru_cache(maxsize=1)
def verify_model():
    checksum = hashlib.sha256()
    for identifier in range(1000000):
        payload = hashlib.md5(str(identifier).encode("ascii"), usedforsecurity=False).hexdigest()
        checksum.update(f"{identifier},{payload}\n".encode("ascii"))
    require(checksum.hexdigest() == MODEL_SHA, "Independent complete Flight model digest differs")
    return MODEL_SHA


def raw_bindings(directory):
    result = []
    for path in sorted(Path(directory).rglob("*")):
        require(not path.is_symlink(), "Flight raw symlink is not an independent receipt")
        if path.is_file(): result.append(reference(path))
    return result


def check_runtime(runtime):
    require(runtime["schema_version"] == 1 and runtime["main_class"] == "LicenseFlightPerformance",
            "Flight compiled runtime invalid")
    require(set(runtime["sources"]) == set(SOURCES), "Flight runtime source set changed")
    for key, source in SOURCES.items(): require(runtime["sources"][key] == reference(source), "Flight source drift: " + key)
    require(set(runtime["jdk"]) == {"bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so", "release"},
            "Flight JDK runtime incomplete")
    for refs in (runtime["sources"].values(), runtime["jdk"].values(), runtime["jars"], runtime["classes"]):
        for item in refs: verify_reference(item)
    require(runtime["jars"] and len({item["path"] for item in runtime["jars"]}) == len(runtime["jars"]),
            "Flight dependency set empty/duplicated")
    names = {Path(item["path"]).name for item in runtime["classes"]}
    require({"LicenseFlightPerformance.class", "LicenseFlightPerformance$Session.class",
             "LicenseFlightFixture.class", "LicenseFlightFixture$Session.class"} <= names, "Flight compiled ABI missing")
    java_home = Path(runtime["java_home"]).resolve()
    require('JAVA_VERSION="17.0.4"' in verify_reference(runtime["jdk"]["release"]).read_text(), "Flight requires JDK 17.0.4")
    require(all(item == reference(java_home / key) for key, item in runtime["jdk"].items()), "Flight JDK path mismatch")
    classes = Path(runtime["classes_directory"]).resolve()
    require({item["path"] for item in runtime["classes"]} == {str(path.resolve()) for path in classes.rglob("*.class")},
            "Flight unbound compiled class or removed class")
    return [*runtime["sources"].values(), *runtime["jdk"].values(), *runtime["jars"], *runtime["classes"]]


def compile_helper(spec, output):
    """Offline compiler; caller owns affinity/scheduling. It never constructs a Flight Session."""
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=False)
    require(set(spec) == {"java_home", "jars"}, "Flight compiler input changed")
    java_home = Path(spec["java_home"]).resolve(strict=True)
    jars = sorted({str(Path(path).resolve(strict=True)) for path in spec["jars"]})
    require(jars and len(jars) == len(spec["jars"]) and all(Path(path).suffix == ".jar" for path in jars),
            "Flight installed jar list missing/duplicated")
    classes = output / "classes"; classes.mkdir()
    runtime = {"schema_version": 1, "main_class": "LicenseFlightPerformance", "java_home": str(java_home),
               "classes_directory": str(classes), "sources": {key: reference(value) for key, value in SOURCES.items()},
               "jdk": {key: reference(java_home / key) for key in ("bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so", "release")},
               "jars": [reference(path) for path in jars]}
    require('JAVA_VERSION="17.0.4"' in (java_home / "release").read_text(), "Flight requires JDK 17.0.4")
    command = [str(java_home / "bin/javac"), "-J-Xmx256m", "--release", "17", "-encoding", "UTF-8", "-cp",
               os.pathsep.join(jars), "-d", str(classes), str(JAVA), str(FIXTURE)]
    with (output / "compile.log").open("x") as log:
        child = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
        try: child.wait(timeout=120)
        finally: reap(child)
    publish(output / "compile-completion.json", {"pid": child.pid, "exit_code": child.returncode,
            "parent_wait_complete": True, "remaining_live_pids": [], "network_clients_created": 0})
    require(child.returncode == 0, "Flight helper compilation failed")
    runtime["classes"] = [reference(path) for path in sorted(classes.rglob("*.class"))]
    check_runtime(runtime); publish(output / "runtime.json", runtime)
    return reference(output / "runtime.json")


def pin(pid):
    proc = Path("/proc", str(pid)); raw = (proc / "stat").read_text(); fields = raw[raw.rfind(")") + 1:].split()
    require(fields[0] not in ("Z", "X"), "Flight service/helper is not alive")
    return {"pid": pid, "start_ticks": int(fields[19]), "namespace": os.readlink(proc / "ns/net"),
            "exe": os.readlink(proc / "exe"), "command_sha256": hashlib.sha256((proc / "cmdline").read_bytes()).hexdigest()}


def check_services(context):
    require(set(context["services"]) == {"fe", "be"}, "Flight service roles incomplete")
    require(context["services"]["fe"]["pid"] != context["services"]["be"]["pid"], "Flight service roles alias")
    namespace = os.readlink("/proc/self/ns/net")
    for role, actual in context["services"].items():
        require(pin(actual["pid"]) == actual and actual["namespace"] == namespace, "Flight actual service pin changed: " + role)
    return namespace


def validate_context(context, profile, runtime=None, live=False):
    require(context["schema_version"] == 1 and context["phase"] in ("DIAGNOSTIC", "CAPACITY", "AA", "AB")
            and context["variant"] in ("A", "B"), "Flight actual phase/variant invalid")
    require(context["phase"] not in ("AA", "CAPACITY") or context["variant"] == "A", "Flight A-only phase cannot run B")
    require(isinstance(context["window_id"], str) and context["window_id"] and type(context["pair_id"]) is int
            and context["pair_id"] >= 0, "Flight window identity missing")
    statistics.validate_identity(context["identity"])
    require(set(context["bindings"]) == set(IDENTITIES) | set(SOURCES), "Flight launch bindings incomplete")
    for key, source in SOURCES.items(): require(context["bindings"][key] == reference(source), "Flight actual source differs: " + key)
    for key, field in IDENTITIES.items():
        verify_reference(context["bindings"][key])
        require(context["bindings"][key]["sha256"] == context["identity"][field], "Flight identity differs: " + key)
    require(read_json(verify_reference(context["workload"])) == profile, "Flight launch profile differs")
    require(type(context["max_clock_uncertainty_ns"]) is int and 0 < context["max_clock_uncertainty_ns"] <= 10**9,
            "Flight missing bounded clock uncertainty")
    require(type(context["coordination_seconds"]) is int and 1 <= context["coordination_seconds"] <= 300,
            "Flight coordination bound invalid")
    require(type(context["context_deadline_monotonic_ns"]) is int, "Flight missing launch deadline")
    if live:
        now = time.monotonic_ns()
        require(now < context["context_deadline_monotonic_ns"] <= now + 300 * 10**9, "Flight launch context expired/unbounded")
        check_services(context)
    require(set(context["endpoints"]) == {"fe_flight_port", "be_flight_port", "user", "password_env"},
            "Flight endpoint profile incomplete")
    for role in ("fe", "be"):
        value = context["endpoints"][role + "_flight_port"]
        require(type(value) is int and 0 < value < 65536, "Flight endpoint invalid")
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", context["endpoints"]["password_env"])
            and re.fullmatch(r"[A-Za-z0-9_@.:-]{1,128}", context["endpoints"]["user"]), "Flight account reference invalid")
    require(set(context["service_configs"]) == {"fe", "be"}, "Flight actual configuration refs missing")
    for role, binding in context["service_configs"].items():
        text = verify_reference(binding).read_text()
        ports = re.findall(r"(?m)^arrow_flight_sql_port\s*=\s*(\d+)\s*$", text)
        require(len(ports) == 1 and int(ports[0]) == context["endpoints"][role + "_flight_port"],
                "Flight configured endpoint differs: " + role)
    if runtime is not None: check_runtime(runtime)
    if context["phase"] == "AB":
        frozen, publication = (read_json(verify_reference(context[key])) for key in ("freeze", "publication"))
        require(frozen["status"] == "FROZEN_ELIGIBLE" and frozen["identities"][context["variant"]] == context["identity"]
                and publication["freeze"] == context["freeze"], "Flight A/B freeze identity invalid")
        cell = frozen["cell"]; scheduled = plan(profile)["measurement"]
        require(cell["group"] == "G2" and cell["case_id"] == "LP-010"
                and cell["workload_sha256"] == business_binding(profile)["sha256"]
                and cell["rate"] == profile["rate"] and cell["concurrency"] == profile["concurrency"]
                and cell["seed"] == 20260922 and cell["warmup_seconds"] == profile["warmup_seconds"]
                and cell["duration_seconds"] == profile["duration_seconds"]
                and cell["request_count"] == scheduled["requests"] and cell["arrival_schedule_sha256"] == scheduled["sha256"]
                and cell["connection_mode"] == "reuse_fe_and_be_channels", "Flight frozen A/B business/schedule differs")
        if "created_monotonic_ns" in context:
            require(publication["boot_id"] == context["boot_id"]
                    and publication["published_monotonic_ns"] <= context["created_monotonic_ns"], "Flight A/B freeze published after launch")
    else:
        require("freeze" not in context and "publication" not in context, "Flight A-only phase claims A/B freeze")
    return context


def reap(child):
    """Only our direct Popen process group; never signal a service or an arbitrary recorded PID."""
    if child.poll() is None:
        try: os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=10)
    else: child.wait()


def acquire_process(child, command, deadline):
    """Popen creation is not the execution identity: require actual exe and the complete argv digest."""
    expected_exe = str(Path(command[0]).resolve())
    expected_command = hashlib.sha256(b"\0".join(os.fsencode(value) for value in command) + b"\0").hexdigest()
    while time.monotonic() < deadline:
        require(child.poll() is None, "Flight child exited before actual execution identity")
        actual = pin(child.pid)
        if actual["exe"] == expected_exe and actual["command_sha256"] == expected_command:
            return actual
        time.sleep(.002)
    raise statistics.EvidenceError("Flight owned child never executed the frozen command")


def command_for(runtime, config_path):
    return [str(Path(runtime["java_home"]) / "bin/java"), "-Xms256m", "-Xmx1024m", "-XX:MaxDirectMemorySize=2147483648",
            "--add-opens=java.base/java.nio=ALL-UNNAMED", "-cp",
            os.pathsep.join([runtime["classes_directory"], *[item["path"] for item in runtime["jars"]]]),
            "LicenseFlightPerformance", str(config_path)]


def run_window(profile_ref, context, runtime_ref, output, stop_file=None):
    """Execute only when explicitly called. Caller enters the owned namespace and runs one service group."""
    profile = validate_profile(read_json(verify_reference(profile_ref))); plan(profile); verify_model()
    runtime = read_json(verify_reference(runtime_ref)); validate_context(context, profile, runtime, live=True)
    require(context["workload"] == profile_ref, "Flight run profile ref differs")
    directory = Path(output).resolve(); directory.mkdir(parents=True, exist_ok=False)
    launch = dict(context)
    launch.update(launch_token=secrets.token_hex(32), boot_id=statistics.boot_id(), created_monotonic_ns=time.monotonic_ns(),
                  utc_anchor=lifecycle.anchor(), runtime=runtime_ref, namespace=os.readlink("/proc/self/ns/net"))
    validate_context(launch, profile, runtime, live=True)
    publish(directory / "p4-launch.json", launch); launch_ref = reference(directory / "p4-launch.json")
    config = {**context["endpoints"], "profile": profile, "launch": launch_ref, "namespace": launch["namespace"],
              "services": context["services"], "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
              "coordination_seconds": context["coordination_seconds"]}
    publish(directory / "config.json", config); config_ref = reference(directory / "config.json")
    dependencies = [launch_ref, config_ref, runtime_ref, profile_ref, *context["bindings"].values(),
                    *context["service_configs"].values(), *check_runtime(runtime)]
    if launch["phase"] == "AB": dependencies += [launch["freeze"], launch["publication"]]
    child = None; actual = None; bridge = None; request = None; errors = []; warm_verified = False
    deadline = time.monotonic() + profile["warmup_seconds"] + profile["duration_seconds"] + 2 * profile["drain_seconds"] + 480
    def check():
        require(time.monotonic() < deadline, "Flight absolute client deadline exceeded")
        require(stop_file is None or not Path(stop_file).exists(), "Flight own-client stop requested")
        check_services(context)
        # Large JDK/jar content is checked at start and finish, outside measurement; do not poll SHA every 10 ms.
        require(statistics.digest(launch_ref["path"]) == launch_ref["sha256"], "Flight launch changed")
    try:
        with (directory / "client.log").open("x") as log:
            child = subprocess.Popen(command_for(runtime, directory / "config.json"), stdout=log, stderr=log, start_new_session=True)
            actual = acquire_process(child, command_for(runtime, directory / "config.json"), min(deadline, time.monotonic() + 5))
            publish(directory / "process.json", {"pin": actual, "command": command_for(runtime, directory / "config.json")})
            while child.poll() is None:
                check()
                if bridge is None:
                    require(time.monotonic_ns() < launch["context_deadline_monotonic_ns"], "Flight context expired before warmup")
                    ready_path = directory / "p4-clock-ready.json"
                    if request is None and ready_path.exists():
                        ready = read_json(ready_path)
                        require(ready["helper_pid"] == actual["pid"] and ready["helper_start_ticks"] == actual["start_ticks"]
                                and ready["launch_token"] == launch["launch_token"] and ready["launch_sha256"] == launch_ref["sha256"],
                                "Flight ready identity differs")
                        request = {"launch_token": launch["launch_token"], "launch_sha256": launch_ref["sha256"],
                                   "nonce": secrets.token_hex(32), "ready_nonce": ready["ready_nonce"]}
                        before = time.monotonic_ns(); publish(directory / "clock-request.json", request)
                    helper_path = directory / "p4-helper-clock.json"
                    if request is not None and helper_path.exists():
                        helper = read_json(helper_path); after = time.monotonic_ns()
                        require(helper["helper_pid"] == actual["pid"] and helper["helper_start_ticks"] == actual["start_ticks"],
                                "Flight clock helper changed")
                        bridge = {"schema_version": 1, "launch_token": launch["launch_token"], "launch_sha256": launch_ref["sha256"],
                                  "boot_id": launch["boot_id"], "nonce": request["nonce"], "controller_before_ns": before,
                                  "controller_after_ns": after, "helper_clock": reference(helper_path)}
                        mapping = clocks.clock_bridge(launch, launch_ref, bridge, helper)
                        for binding in dependencies: verify_reference(binding)
                        require(time.monotonic_ns() < launch["context_deadline_monotonic_ns"], "Flight ACK context expired")
                        publish(directory / "p4-clock-bridge.json", bridge)
                        publish(directory / "clock-ack.json", {**request, "helper_clock_sha256": bridge["helper_clock"]["sha256"],
                                "bridge_sha256": statistics.digest(directory / "p4-clock-bridge.json")})
                elif not warm_verified and (directory / "measurement-ready.json").exists():
                    ready = read_json(directory / "measurement-ready.json")
                    require(ready["warmup_start_ns"] + mapping["offset_upper_ns"] <= launch["context_deadline_monotonic_ns"],
                            "Flight actual warmup exceeds context lifetime")
                    warm_verified = True
                time.sleep(.01)
            child.wait()
    except BaseException as error:
        errors.append({"stage": "run", "error_class": type(error).__name__})
    finally:
        if child is not None:
            try: reap(child)
            except BaseException as error: errors.append({"stage": "reap", "error_class": type(error).__name__})
        try:
            for binding in dependencies: verify_reference(binding)
            check_services(context)
            summary = read_json(directory / "summary.json")
            cleanup = read_json(directory / "lifecycle.json")
            require(summary["status"] == "RAW_WINDOW_COMPLETE" and summary["errors"] == 0
                    and summary["cleanup_confirmed"] is True and cleanup["sessions_closed"] is True
                    and cleanup["workers_stopped"] is True, "Flight helper rejected its read/close evidence")
        except BaseException as error: errors.append({"stage": "bindings_or_helper_evidence", "error_class": type(error).__name__})
        if bridge is not None:
            try:
                cleanup = read_json(directory / "lifecycle.json")
                until = cleanup["cleanup_end_ns"] + mapping["offset_upper_ns"]
                require(until - time.monotonic_ns() <= 2 * launch["max_clock_uncertainty_ns"], "Flight cleanup clock beyond bounded wait")
                while time.monotonic_ns() < until: time.sleep(min(.01, (until - time.monotonic_ns()) / 1e9))
            except (OSError, ValueError, KeyError, TypeError) as error:
                errors.append({"stage": "cleanup", "error_class": type(error).__name__})
        remaining = []
        if actual is not None:
            try:
                if lifecycle.start_ticks(actual["pid"]) == actual["start_ticks"]: remaining.append(actual["pid"])
            except FileNotFoundError: pass
        completion = {"schema_version": 1, "launch_token": launch["launch_token"], "launch_sha256": launch_ref["sha256"],
                      "boot_id": launch["boot_id"], "helper_pid": actual["pid"] if actual else None,
                      "helper_start_ticks": actual["start_ticks"] if actual else None,
                      "exit_code": child.returncode if child else None, "parent_wait_complete": child is not None and child.returncode is not None,
                      "completed_monotonic_ns": time.monotonic_ns(), "utc_anchor": lifecycle.anchor(),
                      "remaining_live_pids": remaining, "controller_errors": errors}
        if bridge is not None: completion["bridge"] = reference(directory / "p4-clock-bridge.json")
        publish(directory / "p4-completion.json", completion)
    return {"status": "RAW_WINDOW_COMPLETE" if completion["exit_code"] == 0 and not errors and not remaining else "INVALID_WINDOW",
            "launch": launch_ref, "completion": reference(directory / "p4-completion.json"),
            "window_directory": str(directory), "formal_performance_pass": False}


def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered: return None
    index = (len(ordered) - 1) * fraction; lower = int(index)
    return ordered[lower] + (ordered[min(lower + 1, len(ordered) - 1)] - ordered[lower]) * (index - lower)


def cpu_ticks(value, pin_value, hz):
    raw = value["raw_stat"]; fields = raw[raw.rfind(")") + 1:].split()
    require(int(raw[:raw.find(" ")]) == value["pid"] == pin_value["pid"]
            and int(fields[19]) == value["start_ticks"] == pin_value["start_ticks"] and fields[0] not in ("Z", "X"),
            "Flight CPU raw lifetime differs")
    require(type(hz) is int and hz > 0, "Flight CPU clock ticks missing")
    return int(fields[11]) + int(fields[12])


def audit_requests(directory, profile, config):
    planned = plan(profile); derived = {}; tickets = set(); calls = [0] * profile["concurrency"]
    for phase, length in (("warmup", profile["warmup_seconds"]), ("measurement", profile["duration_seconds"])):
        expected = planned[phase]
        with (directory / (phase + "-arrivals.tsv")).open() as stream:
            arrival_rows = list(csv.DictReader(stream, delimiter="\t"))
        require(len(arrival_rows) == expected["requests"], "Flight missing/excess arrivals")
        offsets = []
        for index, (row, offset) in enumerate(zip(arrival_rows, expected["offsets"])):
            require(set(row) == {"sequence", "offset_ns"} and int(row["sequence"]) == index
                    and abs(int(row["offset_ns"]) - offset) <= 1, "Flight arrival changed")
            offsets.append(int(row["offset_ns"]))
        start, end = (read_json(directory / (phase + "-" + point + ".json")) for point in ("start", "end"))
        epoch = start["epoch_ns"]; last = epoch; seen = set(); latency = []; service = []; queue = []; errors = 0; timeouts = 0
        require(type(epoch) is int and epoch > 0 and end["epoch_ns"] == epoch, "Flight epoch changed")
        for worker in range(profile["concurrency"]):
            previous = epoch
            with (directory / f"{phase}-{worker}.jsonl").open() as stream:
                for line in stream:
                    row = json.loads(line); sequence = row["sequence"]
                    require(type(sequence) is int and 0 <= sequence < len(offsets) and sequence not in seen
                            and sequence % profile["concurrency"] == worker and row["worker"] == worker, "Flight duplicate/foreign receipt")
                    seen.add(sequence); scheduled, started, finished = (row[key] for key in ("scheduled_ns", "started_ns", "finished_ns"))
                    require(all(type(value) is int for value in (scheduled, started, finished)) and scheduled == epoch + offsets[sequence]
                            and finished >= started >= max(scheduled, previous) and row["e2e_ns"] == finished - scheduled
                            and row["service_ns"] == finished - started and row["queue_ns"] == started - scheduled,
                            "Flight queue/service/E2E receipt differs")
                    previous = finished; last = max(last, finished)
                    if row.get("fe_execute_calls") == 1:
                        calls[worker] += 1
                        require(row["session_id"] == worker and row["session_call"] == calls[worker], "Flight session call sequence changed")
                    if row["status"] != "READ_PASS":
                        require(row["status"] == "ERROR" and row["error_class"] and row["error_code"], "Flight unknown error receipt")
                        errors += 1; timeouts += row.get("flight_error_code") in ("TIMED_OUT", "DEADLINE_EXCEEDED")
                        continue
                    require(row["session_id"] == worker and row["session_call"] == calls[worker] and row["fe_execute_calls"] == 1
                            and row["backend_channels_created"] == (1 if calls[worker] == 1 else 0)
                            and row["frontend_channel_reused"] is True and row["backend_channel_reused"] is True
                            and row["stream_close_completed"] is True, "Flight channel reuse/fresh FE execute/stream close unproven")
                    require(row["rows"] == row["rows_verified"] == row["complete_model_rows"] == 1000000
                            and row["sha256"] == MODEL_SHA and row["schema"] == SCHEMA
                            and row["requested_session_batch_size"] == profile["batch_size"], "Flight complete million-row oracle differs")
                    batches = row["actual_record_batch_rows"]
                    require(isinstance(batches, list) and 0 < len(batches) <= 20000
                            and all(type(value) is int and 0 <= value <= 1000000 for value in batches)
                            and sum(batches) == 1000000, "Flight actual record batches incomplete")
                    first = row["first_record_batch"]; vectors = first["vectors"]
                    require(first["batch_index"] == 0 and first["rows"] == batches[0] and first["schema"] == SCHEMA
                            and len(vectors) == 2
                            and [(item["name"], item["vector_class"], item["arrow_type"]) for item in vectors]
                            == [("id", "org.apache.arrow.vector.BigIntVector", "Int(64, true)"),
                                ("payload", "org.apache.arrow.vector.VarCharVector", "Utf8")], "Flight exact vector schema changed")
                    require(row["endpoint"] == f"grpc+tcp://127.0.0.1:{config['be_flight_port']}", "Flight BE endpoint differs")
                    ticket = row["ticket_sha256"]
                    require(re.fullmatch(r"[0-9a-f]{64}", ticket) and ticket not in tickets, "Flight reused/invalid FE ticket")
                    tickets.add(ticket)
                    require(0 <= row["elapsed_nanos_with_complete_oracle"] <= row["elapsed_nanos_with_oracle_and_diagnostics"]
                            <= row["service_ns"], "Flight complete oracle outside service interval")
                    latency.append(row["e2e_ns"] / 1e6); service.append(row["service_ns"] / 1e6); queue.append(row["queue_ns"] / 1e6)
        require(len(seen) == len(offsets), "Flight missing completion receipts")
        interval_end = max(epoch + length * 10**9, last)
        require(end["last_request_end_ns"] == last and end["request_interval_end_ns"] == interval_end
                and end["java_monotonic_ns"] >= interval_end and end["scheduled_requests"] == len(seen)
                and end["successful_requests"] == len(latency)
                and end["arrival_schedule_sha256"] == statistics.digest(directory / (phase + "-arrivals.tsv")),
                "Flight summary/denominator differs from complete raw window")
        seconds = (interval_end - epoch) / 1e9; cpus = {}
        for role in ("fe", "be"):
            first, final = start["cpu"][role], end["cpu"][role]
            require(first["sample_started_java_ns"] <= first["sample_ended_java_ns"] <= epoch
                    and final["sample_ended_java_ns"] >= final["sample_started_java_ns"] >= interval_end,
                    "Flight CPU sample does not enclose all requests")
            delta = cpu_ticks(final, config["services"][role], config["clock_ticks_per_second"]) - cpu_ticks(first, config["services"][role], config["clock_ticks_per_second"])
            require(delta >= 0, "Flight CPU counter decreased")
            cpus[role + "_cpu_seconds_per_success"] = delta / config["clock_ticks_per_second"] / len(latency) if latency else None
        derived[phase] = {"scheduled_requests": len(seen), "observed_requests": len(seen), "successful_requests": len(latency),
            "error_count": errors, "timeout_count": timeouts, "retry_count": 0, "effective_duration_seconds": seconds,
            "arrival_schedule_sha256": end["arrival_schedule_sha256"], "success_qps": len(latency) / seconds,
            "p95_ms": percentile(latency, .95), "p99_ms": percentile(latency, .99),
            "service_p95_ms": percentile(service, .95), "service_p99_ms": percentile(service, .99),
            "queue_p95_ms": percentile(queue, .95), "queue_p99_ms": percentile(queue, .99), **cpus}
    return derived


def normalize(manifest):
    directory = Path(manifest["window_directory"]).resolve(); before = raw_bindings(directory)
    launch_ref = manifest["launch"]; launch = read_json(verify_reference(launch_ref))
    require(launch_ref == reference(directory / "p4-launch.json"), "Flight launch from another window")
    config = read_json(directory / "config.json"); profile = validate_profile(config["profile"]); plan(profile); verify_model()
    runtime = read_json(verify_reference(launch["runtime"])); dependencies = check_runtime(runtime)
    validate_context(launch, profile, runtime)
    require(config["launch"] == launch_ref and config["services"] == launch["services"] and config["namespace"] == launch["namespace"]
            and all(config[key] == value for key, value in launch["endpoints"].items()), "Flight actual helper configuration differs")
    completion = read_json(verify_reference(manifest["completion"])); process = read_json(directory / "process.json")
    for key in ("launch_token", "boot_id"):
        require(completion[key] == launch[key], "Flight completion from another launch")
    require(completion["launch_sha256"] == launch_ref["sha256"] and completion["exit_code"] == 0
            and completion["parent_wait_complete"] is True and completion["remaining_live_pids"] == []
            and not completion["controller_errors"], "Flight actual parent wait/exit failed")
    clocks.utc_anchor(launch["utc_anchor"]); clocks.utc_anchor(completion["utc_anchor"])
    bridge = read_json(verify_reference(completion["bridge"])); helper = read_json(verify_reference(bridge["helper_clock"]))
    require(all(helper[key] == completion[key] for key in ("helper_pid", "helper_start_ticks"))
            and helper["helper_pid"] == process["pin"]["pid"] and helper["helper_start_ticks"] == process["pin"]["start_ticks"],
            "Flight waited process differs from clock helper")
    command = command_for(runtime, directory / "config.json")
    require(process["command"] == command and process["pin"]["command_sha256"] == hashlib.sha256(
            b"\0".join(os.fsencode(value) for value in command) + b"\0").hexdigest()
            and process["pin"]["exe"] == str((Path(runtime["java_home"]) / "bin/java").resolve())
            and process["pin"]["namespace"] == helper["namespace"] == launch["namespace"], "Flight actual helper command/namespace differs")
    mapping = clocks.clock_bridge(launch, launch_ref, bridge, helper); offset = mapping["estimated_offset_ns"]
    expected_identity = {key: helper[key] for key in ("launch_token", "launch_sha256", "boot_id", "helper_pid", "helper_start_ticks", "namespace")}
    for name in ("p4-clock-ready.json", "warmup-start.json", "warmup-end.json", "measurement-ready.json",
                 "measurement-start.json", "measurement-end.json", "lifecycle.json", "summary.json"):
        actual = read_json(directory / name)
        require(all(actual.get(key) == value for key, value in expected_identity.items()), "Flight receipt identity differs: " + name)
    requests = audit_requests(directory, profile, config)
    require(all(value["error_count"] == 0 for value in requests.values()), "Flight warmup/measured failures preserved")
    warm_start, warm_end, ready, start, end, cleanup, summary = (read_json(directory / name) for name in (
        "warmup-start.json", "warmup-end.json", "measurement-ready.json", "measurement-start.json",
        "measurement-end.json", "lifecycle.json", "summary.json"))
    warm = warm_start["epoch_ns"]; warm_finished = warm_end["java_monotonic_ns"]
    require(helper["jvm_sample_ns"] <= warm <= warm_finished <= ready["ready_ns"] <= start["epoch_ns"]
            and ready["warmup_start_ns"] == warm and ready["warmup_end_ns"] == warm_finished
            and warm_finished - warm >= profile["warmup_seconds"] * 10**9, "Flight actual warmup missing/overlapping")
    lower = warm + mapping["offset_lower_ns"]; upper = end["request_interval_end_ns"] + mapping["offset_upper_ns"]
    require(lower >= launch["created_monotonic_ns"]
            and warm + mapping["offset_upper_ns"] <= launch["context_deadline_monotonic_ns"], "Flight actual warmup predates/exceeds launch")
    require(cleanup["cleanup_end_ns"] >= end["java_monotonic_ns"] and cleanup["sessions_closed"] is True
            and cleanup["workers_stopped"] is True and summary["cleanup_confirmed"] is True
            and summary["status"] == "RAW_WINDOW_COMPLETE" and summary["errors"] == 0 and summary["harness_retries"] == 0
            and cleanup["cleanup_end_ns"] + mapping["offset_upper_ns"] <= completion["completed_monotonic_ns"],
            "Flight cleanup/wait ordering failed")
    for worker in range(profile["concurrency"]):
        opened, closed = (read_json(directory / f"session-{worker}-{point}.json") for point in ("open", "close"))
        require(opened["worker"] == opened["session_id"] == closed["worker"] == worker
                and opened["frontend_channels"] == 1 and opened["opened_ns"] <= helper["jvm_sample_ns"]
                and end["java_monotonic_ns"] <= closed["close_started_ns"] <= closed["close_finished_ns"] <= cleanup["cleanup_end_ns"]
                and closed["frontend_channels_closed"] == 1
                and closed["backend_channels_closed"] == (1 if worker < max(requests["warmup"]["scheduled_requests"], requests["measurement"]["scheduled_requests"]) else 0)
                and closed["channels_and_allocator_closed"] is True, "Flight persistent session open/close receipt missing")
    raw_extra = [manifest["launch"], manifest["completion"], completion["bridge"], bridge["helper_clock"]]
    # This narrow observer contract is supplied by the outer real-window controller, never inferred from config.
    formal = profile["qualification"] == "formal" and launch["phase"] != "DIAGNOSTIC"
    if formal or "observer" in manifest:
        observer = read_json(verify_reference(manifest["observer"]))
        require(observer["status"] == "VERIFIED" and observer["launch_sha256"] == launch_ref["sha256"]
                and observer["boot_id"] == launch["boot_id"] and observer["coverage_start_monotonic_ns"] <= lower
                and observer["coverage_end_monotonic_ns"] >= upper and observer["resource_failures"] == []
                and observer["budget_verified"] is True
                and observer["observed_license_state"] == ("ORIGINAL_A_NO_LICENSE" if launch["variant"] == "A" else "VALID"),
                "Flight resource/license observation incomplete")
        require(observer["raw_artifacts"], "Flight observer has no original data")
        for role in ("fe", "be"):
            require(observer["services"][role]["pin"] == launch["services"][role]
                    and observer["services"][role]["artifact"] == launch["bindings"][role + "_artifact"]
                    and observer["services"][role]["configuration"] == launch["service_configs"][role],
                    "Flight observer did not bind actual deployed binary/config")
        raw_extra += [manifest["observer"], *observer["raw_artifacts"]]; dependencies += [observer["auditor"]]
    measured = requests["measurement"]
    window = {"window_id": launch["window_id"], "pair_id": launch["pair_id"], "variant": launch["variant"],
        "boot_id": launch["boot_id"], "identity": launch["identity"], "workload_sha256": business_binding(profile)["sha256"],
        "arrival_schedule_sha256": measured["arrival_schedule_sha256"], "rate": profile["rate"],
        "warmup_seconds": profile["warmup_seconds"], "duration_seconds": profile["duration_seconds"],
        "warmup_start_monotonic_ns": warm + offset, "warmup_end_monotonic_ns": warm_finished + offset,
        "start_monotonic_ns": start["epoch_ns"] + offset, "end_monotonic_ns": end["request_interval_end_ns"] + offset,
        "monotonic_clock_domain": "bounded_jvm_mapping", "monotonic_mapping": mapping,
        "monotonic_mapping_uncertainty_ns": mapping["uncertainty_ns"], "effective_duration_seconds": measured["effective_duration_seconds"],
        **{key: measured[key] for key in ("scheduled_requests", "observed_requests", "successful_requests", "error_count", "timeout_count", "retry_count")},
        "oracle_verified": True, "cleanup_verified": True, "cpu_boundary_verified": True,
        "metrics": {key: measured[key] for key in statistics.METRICS}}
    dependencies += [launch["runtime"], launch["workload"], *launch["bindings"].values(), *launch["service_configs"].values()]
    if launch["phase"] == "AB":
        publication = read_json(verify_reference(launch["publication"]))
        require(publication["published_monotonic_ns"] <= lower, "Flight warmup precedes publication")
        window.update(freeze_sha256=launch["freeze"]["sha256"], freeze_publication_sha256=launch["publication"]["sha256"])
        dependencies += [launch["freeze"], launch["publication"]]
    after = raw_bindings(directory); require(before == after, "Flight raw changed during audit")
    raw = {item["path"]: item for item in after + raw_extra}
    dependencies = list({item["path"]: item for item in dependencies}.values())
    for item in [*raw.values(), *dependencies]: verify_reference(item)
    return {"status": "VERIFIED" if formal else "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED", "window": window,
            "auditor": reference(SOURCE), "raw_artifacts": list(raw.values()), "dependency_bindings": dependencies,
            "request_audit": requests, "formal_shape_met": formal and measured["successful_requests"] >= 10000,
            "formal_performance_pass": False,
            "scope": "One complete million-row query is one operation; independent capacity/A/A/A/B qualification remains external"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "compile", "run", "normalize"))
    parser.add_argument("--input", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = read_json(args.input)
        if args.mode == "compile":
            result = compile_helper(value, args.output)
        elif args.mode == "run":
            result = run_window(value["workload"], value["context"], value["runtime"], args.output, value.get("stop_file"))
        else:
            require(not args.output.exists(), "Never overwrite Flight evidence")
            if args.mode == "normalize":
                require(Path(value["window_directory"]).resolve() not in args.output.resolve().parents,
                        "Flight audit must be outside raw directory")
                result = normalize(value)
            else: result = {"business": business_binding(value), "plan": plan(value), "formal_performance_pass": False}
            publish(args.output, result)
        print(json.dumps({"status": result.get("status", "OFFLINE_COMPLETE"), "output": str(args.output), "formal_performance_pass": False}))
        return 2 if result.get("status") == "INVALID_WINDOW" else 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "REJECTED", "error_class": type(error).__name__, "reason": str(error),
                          "formal_performance_pass": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
