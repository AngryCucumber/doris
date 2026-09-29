#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Run a predeclared rate sweep; distinguish delivered load from a bounded SLO capacity.

Uses the existing JDBC runner and its isolated-service checks. Never starts/stops FE/BE.
Pilot results only select inputs for confirmation; they cannot establish capacity or pass A/B.
"""

import argparse
import csv
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import struct
import sys
import time

import run_performance_baseline as baseline

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "run_performance_baseline.py"
CONTRACT = HERE.parents[1] / "docs/license-performance-cases-20260922.json"


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def freeze_bindings(args, workload):
    contract, _, selection = baseline.contract_inputs(workload, CONTRACT)
    paths = {"template": args.workload, "runner": RUNNER,
             "jdbc_helper": HERE / "LicenseJdbcBaseline.java", "contract": contract, "controller": Path(__file__),
             "jdbc_jar": args.jdbc_jar, "java": args.java_home / "bin/java", "javac": args.java_home / "bin/javac"}
    if selection["mode"] == "current_retained_scope":
        paths["current_plan"] = baseline.CURRENT_PLAN
    paths.update({name: Path(workload["build_identity"][name]) for name in ("fe_artifact", "be_artifact")})
    return {name: {"path": str(path.resolve()), "sha256": digest(path)} for name, path in paths.items()}


def check_bindings(bindings):
    differences = []
    for name, binding in bindings.items():
        try:
            if digest(binding["path"]) != binding["sha256"]:
                differences.append(name + ": digest changed")
        except OSError:
            differences.append(name + ": unavailable")
    return differences


def baseline_identity(workload, bindings, required=False):
    value = workload.get("p4_baseline_identity")
    if value is None and not required:
        return None
    fields = {"source_commit", "fe_sha256", "be_sha256", "environment_sha256", "configuration_sha256",
              "fixture_sha256", "client_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Current confirmation requires complete p4_baseline_identity")
    for key, item in value.items():
        length = 40 if key == "source_commit" else 64
        if type(item) is not str or len(item) != length or any(char not in "0123456789abcdef" for char in item):
            raise ValueError("Invalid baseline identity digest: " + key)
    if value["source_commit"] != workload["build_identity"]["baseline_source_commit"] \
            or value["fe_sha256"] != bindings["fe_artifact"]["sha256"] \
            or value["be_sha256"] != bindings["be_artifact"]["sha256"]:
        raise ValueError("Baseline identity differs from actual frozen executable artifacts")
    return value


def read_json(path):
    return json.loads(path.read_text())


def raw_artifact_bindings(directory):
    bindings = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("Trial artifact must not be a symlink")
        if path.is_file():
            bindings.append({"path": str(path.resolve()), "sha256": digest(path)})
    return bindings


def verify_vector(directory, name, width, maximum, expected_count=None):
    path = directory / name
    data = path.read_bytes()
    if len(data) % width or (expected_count is not None and len(data) != expected_count * width):
        raise ValueError(name + ": invalid count/encoding")
    calculated = hashlib.sha256(data).hexdigest()
    if path.with_name(name + ".sha256").read_text().strip() != calculated:
        raise ValueError(name + ": digest mismatch")
    previous = -1
    for value, in struct.iter_unpack(">q" if width == 8 else ">i", data):
        if not 0 <= value < maximum or (width == 8 and value < previous):
            raise ValueError(name + ": invalid value/order")
        previous = value
    return data, calculated


def verify_window(directory, reported, workload, expected_start_ticks):
    """Recompute evidence from complete CSV/binary files, not helper success flags."""
    if read_json(directory / "summary.json") != reported:
        raise ValueError("Window summary differs from top-level report")
    if reported.get("process_exit_code") != 0 or reported.get("watchdog_expired") \
            or reported.get("client_failure") or not reported.get("cpu_boundary_verified"):
        raise ValueError("Incomplete client/CPU lifecycle")
    arrivals, arrival_hash = verify_vector(directory, "arrivals.bin", 8, workload["duration_seconds"] * 10**9)
    warmup, warmup_hash = verify_vector(directory, "warmup-arrivals.bin", 8, workload["warmup_seconds"] * 10**9)
    count = len(arrivals) // 8
    if count <= 0 or int((directory / "arrival-count").read_text()) != count:
        raise ValueError("Invalid actual request count")
    if not reported.get("schedule_hash_matches_helper") or reported.get("arrival_seed") != workload["seed"] \
            or reported.get("arrival_schedule_sha256") != arrival_hash \
            or reported.get("warmup_arrival_schedule_sha256") != warmup_hash:
        raise ValueError("Arrival schedule is not bound to the frozen input")
    point = workload.get("point_key_workload")
    key_data = None
    key_hashes = None
    if point:
        oracle = read_json(directory / "point-result-oracle.json")
        if (reported.get("point_result_oracle") != oracle
                or oracle.get("algorithm") != "lowercase_md5_ascii_decimal_id"
                or oracle.get("comparison_inside_request_timing") is not True
                or oracle.get("precomputation_before_connections") is not True):
            raise ValueError("Point payload oracle is missing or differs from the executed helper")
        key_data, key_hash = verify_vector(directory, "point-keys.bin", 4, 1000000, count)
        warmup_keys, warmup_key_hash = verify_vector(directory, "warmup-point-keys.bin", 4, 1000000, len(warmup) // 8)
        unique_keys = {value[0] for data in (key_data, warmup_keys) for value in struct.iter_unpack(">i", data)}
        if oracle.get("unique_precomputed_keys") != len(unique_keys):
            raise ValueError("Point payload oracle does not cover all measured and warmup keys")
        metadata = reported.get("point_keys", {})
        if reported.get("query_workload_kind") != "uniform_point_keys" or not metadata.get("hashes_verified") \
                or metadata.get("count") != count or metadata.get("seed") != point["seed"] \
                or metadata.get("mode") != point["mode"] or metadata.get("range_inclusive") != [0, 999999] \
                or metadata.get("sha256") != key_hash or metadata.get("warmup_sha256") != warmup_key_hash:
            raise ValueError("Point key identity/count/digest mismatch")
        key_hashes = [key_hash, warmup_key_hash]
    elif reported.get("query_workload_kind") != "static_query_vector":
        raise ValueError("Unexpected query generator")
    expected_oracles = [{"query_index": index,
                         "sha256": hashlib.sha256(baseline.encode_result_oracle(query)).hexdigest(),
                         "columns": len(query["expected_result"]["columns"]), "rows": query["expected_rows"],
                         "ordered": query["expected_result"].get("ordered", True),
                         "comparison_inside_request_timing": True}
                        for index, query in enumerate(workload.get("queries", [])) if "expected_result" in query]
    if expected_oracles and reported.get("static_result_oracles") != expected_oracles:
        raise ValueError("Static full-result oracle differs from frozen input")
    if reported.get("connection_mode") != workload.get("connection_mode", "reuse"):
        raise ValueError("Connection mode mismatch")
    start = read_json(directory / "measurement-start.json")
    end = read_json(directory / "measurement-end.json")
    lifecycle = read_json(directory / "lifecycle.json")
    boundary = baseline.boundary_evidence(start, end, lifecycle)
    resources = read_json(directory / "resources.json")
    if not boundary["verified"] or resources["cpu"] != {"start": start["cpu"], "end": end["cpu"]}:
        raise ValueError("CPU boundary counters or lifecycle mismatch")
    if resources.get("boundary") != boundary:
        raise ValueError("Recorded CPU boundary differs from actual boundary files")
    for name in ("fe", "be"):
        if start["cpu"][name]["start_ticks"] != expected_start_ticks[name]:
            raise ValueError("Service process changed during calibration")
    paths = sorted(directory.glob("worker-*.csv"))
    expected_names = {"worker-%d.csv" % index for index in range(workload["concurrency"])}
    if {path.name for path in paths} != expected_names:
        raise ValueError("Missing or unexpected worker CSV")
    seen = bytearray(count)
    latencies = []
    last = 0
    for path in paths:
        worker = int(path.stem.split("-")[1])
        previous = -1
        with path.open() as stream:
            for row in csv.DictReader(stream):
                index = int(row["index"])
                if not 0 <= index < count or seen[index] or index <= previous \
                        or index % workload["concurrency"] != worker:
                    raise ValueError("Duplicate, reordered, or out-of-range request index")
                seen[index] = 1
                previous = index
                scheduled, begin, finish = (int(row[name]) for name in ("scheduled_ns", "start_ns", "end_ns"))
                if scheduled != struct.unpack_from(">q", arrivals, index * 8)[0] or not scheduled <= begin <= finish:
                    raise ValueError("Request timestamp/schedule mismatch")
                query_index = 0 if point else index % len(workload["queries"])
                expected_rows = 1 if point else workload["queries"][query_index]["expected_rows"]
                if int(row["query_index"]) != query_index or row["error_code"] != "0" \
                        or row["sql_state"] != "00000" \
                        or int(row["rows"]) != expected_rows:
                    raise ValueError("Failed request or query/result identity mismatch")
                if point and int(row["point_key"]) != struct.unpack_from(">i", key_data, index * 4)[0]:
                    raise ValueError("Executed point key differs from saved sequence")
                latencies.append((finish - scheduled) / 1e6)
                last = max(last, finish)
    if seen.count(0):
        raise ValueError("Missing request indices")
    if end["last_request_end_ns"] != start["epoch_ns"] + last \
            or end["request_interval_end_ns"] != start["epoch_ns"] + max(workload["duration_seconds"] * 10**9, last):
        raise ValueError("CPU interval does not cover the actual final request")
    seconds = max(workload["duration_seconds"], last / 1e9)
    derived = {"scheduled_requests": count, "observed_requests": count, "successful_requests": count,
               "missing_requests": 0, "errors": {}, "p99_ms": baseline.quantile(latencies, .99),
               "p95_ms": baseline.quantile(latencies, .95), "effective_duration_seconds": seconds,
               "drain_seconds": max(0, seconds - workload["duration_seconds"]), "success_qps": count / seconds}
    for key, value in derived.items():
        if type(value) is float:
            observed = reported.get(key)
            if type(observed) not in (int, float) or not math.isfinite(observed) \
                    or not math.isclose(value, observed, rel_tol=1e-12, abs_tol=1e-12):
                raise ValueError("Reported " + key + " differs from raw requests")
        elif reported.get(key) != value:
            raise ValueError("Reported " + key + " differs from raw requests")
    for name in ("fe", "be"):
        expected_cpu = (end["cpu"][name]["cpu_seconds"] - start["cpu"][name]["cpu_seconds"]) / count
        observed_cpu = reported.get(name + "_cpu_seconds_per_success")
        if type(observed_cpu) not in (int, float) or not math.isfinite(observed_cpu) \
                or not math.isclose(expected_cpu, observed_cpu, rel_tol=1e-12, abs_tol=1e-12):
            raise ValueError("Reported CPU per success differs from raw counters")
        derived[name + "_cpu_seconds_per_success"] = expected_cpu
    if workload.get("contract_group"):
        verify_driver_evidence(directory, reported, workload, count, len(warmup) // 8)
    derived.update(arrival_sha256=arrival_hash, warmup_arrival_sha256=warmup_hash, key_hashes=key_hashes,
                   cpu_boundary_verified=True)
    return derived


def verify_driver_evidence(directory, reported, workload, measured_count, warmup_count):
    """Bind actual statement instances/classes and execute counts; never infer FE fast-branch reachability."""
    records = [read_json(directory / ("driver-worker-%d.json" % worker))
               for worker in range(workload["concurrency"])]
    if records != reported.get("driver_evidence"):
        raise ValueError("Actual driver evidence differs from summary")
    query_count = 1 if workload.get("point_key_workload") else len(workload["queries"])
    reuse = workload.get("connection_mode", "reuse") == "reuse"
    for worker, record in enumerate(records):
        if record.get("worker") != worker or record.get("connection_mode") != ("reuse" if reuse else "per_request") \
                or not record.get("driver_class") or not record.get("connection_classes"):
            raise ValueError("Missing actual driver/connection identity")
        worker_requests = [len(range(worker, count, workload["concurrency"]))
                           for count in (warmup_count, measured_count)]
        if sum(record["connection_classes"].values()) != (1 if reuse else sum(worker_requests)):
            raise ValueError("Actual connection count differs from the declared mode")
        queries = record.get("queries", [])
        if len(queries) != query_count:
            raise ValueError("Driver query count mismatch")
        for index, query in enumerate(queries):
            counts = [sum(1 for request in range(worker, count, workload["concurrency"])
                          if request % query_count == index) for count in (warmup_count, measured_count)]
            prepared = (workload["point_key_workload"]["mode"] == "prepared" if workload.get("point_key_workload")
                        else workload["queries"][index].get("mode", "text") == "prepared")
            if query.get("query_index") != index or query.get("prepared") is not prepared \
                    or query.get("warmup_execute_attempts") != counts[0] \
                    or query.get("measured_execute_attempts") != counts[1] \
                    or query.get("statement_count") != (1 if reuse else sum(counts)) \
                    or query.get("same_reused_statement") is not reuse \
                    or (sum(counts) and not query.get("statement_classes")):
                raise ValueError("Statement preparation/execution/reuse evidence mismatch")
            if sum(query["statement_classes"].values()) != query["statement_count"]:
                raise ValueError("Statement class counts differ from prepared handle counts")
            if prepared and query["statement_count"] and (
                    record["driver_class"] != "org.mariadb.jdbc.Driver"
                    or set(query["statement_classes"]) != {"org.mariadb.jdbc.ServerPreparedStatement"}):
                raise ValueError("Current prepared workload did not use the frozen server-prepared driver class")


def verify_trial(directory, report, workload, frozen, input_path):
    audit = {"valid": False, "windows": [], "errors": [], "scope": "Raw artifacts and frozen input bindings"}
    try:
        raw_before = raw_artifact_bindings(directory)
        if workload.get("contract_group") and read_json(directory / "report.json") != report:
            raise ValueError("Disk trial report differs from supplied report")
        if read_json(directory / "workload.json") != workload:
            raise ValueError("Actual workload differs from frozen trial")
        identity = read_json(directory / "identity.json")
        bindings = frozen["bindings"]
        for field, name in (("runner_sha256", "runner"), ("java_helper_sha256", "jdbc_helper"),
                            ("jdbc_sha256", "jdbc_jar"), ("performance_contract_sha256", "contract")):
            if identity.get(field) != bindings[name]["sha256"]:
                raise ValueError("Actual " + name + " identity differs from frozen input")
        if identity.get("workload_sha256") != digest(input_path) or identity.get("build_identity") != workload["build_identity"]:
            raise ValueError("Actual workload/build identity mismatch")
        if workload.get("contract_group") and identity.get("contract_selection") != frozen.get("contract_selection"):
            raise ValueError("Actual current contract selection differs from frozen input")
        if workload.get("contract_group") and (identity.get("business_workload_binding")
                != baseline.business_workload_binding(workload)
                or identity["business_workload_binding"] != frozen.get("business_workload_binding")):
            raise ValueError("Actual canonical business workload differs from frozen input")
        for name in ("fe_artifact", "be_artifact"):
            if identity.get("artifact_sha256", {}).get(name) != bindings[name]["sha256"]:
                raise ValueError("Actual executable artifact changed")
        windows = report.get("windows", [])
        if len(windows) != workload["pairs"] * 2:
            raise ValueError("Not every frozen window completed")
        for index, window in enumerate(windows):
            audit["windows"].append(verify_window(directory / ("window-%02d" % index), window, workload,
                                                   frozen["service_start_ticks"]))
        if not report.get("identical_arrival_schedules_across_windows") \
                or len({w["arrival_sha256"] for w in audit["windows"]}) != 1 \
                or len({w["warmup_arrival_sha256"] for w in audit["windows"]}) != 1:
            raise ValueError("Window schedules differ")
        if workload.get("point_key_workload") and (
                not report.get("identical_point_key_sequences_across_windows")
                or len({tuple(w["key_hashes"]) for w in audit["windows"]}) != 1):
            raise ValueError("Window point key sequences differ")
        raw_after = raw_artifact_bindings(directory)
        if raw_before != raw_after:
            raise ValueError("Raw trial artifacts changed during independent verification")
        audit["raw_artifact_bindings"] = raw_after
        audit["valid"] = True
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        audit["errors"].append(type(error).__name__ + ": " + str(error))
    return audit


def assess(report, p99_slo_ms, max_drain_seconds, expected_windows, require_sample_floor=False, evidence=None):
    """A failed or incomplete measurement is never an upper capacity bound."""
    if not evidence or evidence.get("valid") is not True:
        return "invalid_trial"
    windows = evidence.get("windows", [])
    if len(windows) != expected_windows or len(report.get("windows", [])) != expected_windows or not windows:
        return "invalid_trial"
    for window in windows:
        counts = [window.get(key) for key in ("scheduled_requests", "observed_requests", "successful_requests")]
        if any(type(value) is not int or value <= 0 for value in counts) or len(set(counts)) != 1 \
                or window.get("missing_requests") != 0 or window.get("errors") \
                or window.get("cpu_boundary_verified") is not True:
            return "invalid_trial"
        if require_sample_floor and counts[0] < 10000:
            return "invalid_trial"
        if any(type(window.get(key)) not in (int, float) or not math.isfinite(window[key]) or window[key] < 0
               for key in ("p99_ms", "drain_seconds")):
            return "invalid_trial"
    return ("within_slo" if all(w["p99_ms"] <= p99_slo_ms
                               and w["drain_seconds"] <= max_drain_seconds for w in windows)
            else "outside_slo")


def capacity_bracket(trials, mode, confirmation_shape_met, expected_rates):
    valid = [t for t in trials if t["assessment"] in ("within_slo", "outside_slo")]
    failures = [t["rate"] for t in valid if t["assessment"] == "outside_slo"]
    passes = [t["rate"] for t in valid if t["assessment"] == "within_slo"]
    nonmonotonic = bool(failures and any(rate > min(failures) for rate in passes))
    lower = max(passes) if passes else None
    upper = min((rate for rate in failures if lower is not None and rate > lower), default=None)
    width = 100.0 * (upper - lower) / lower if lower and upper else None
    complete = bool(trials) and [t["rate"] for t in trials] == expected_rates
    all_valid = complete and len(valid) == len(trials)
    qualified = (mode == "confirm" and confirmation_shape_met and all_valid and not nonmonotonic
                 and width is not None and width <= 1.0)
    return {"largest_tested_rate_within_slo": lower, "smallest_tested_rate_outside_slo_above_it": upper,
            "bracket_width_percent_of_lower_bound": width, "required_bracket_width_percent": 1.0,
            "nonmonotonic_response": nonmonotonic, "all_planned_trials_completed": complete,
            "all_trials_valid": all_valid,
            "confirmation_shape_met": confirmation_shape_met, "capacity_bracket_established": qualified,
            "candidate_rates_30_60_85_percent": ([lower * fraction for fraction in (.30, .60, .85)]
                                                if qualified else None),
            "scope": "Observed offered-rate bracket under the frozen P99/drain SLO, not a theoretical maximum",
            "release_performance_pass": False, "AA_precision_proven": False}


def live_group_members(group):
    members = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group and int(fields[3]) == group and fields[0] not in ("Z", "X"):
                members.append(int(path.name))
        except (OSError, ValueError, IndexError):
            continue
    return members


@contextmanager
def shield_cleanup_signals():
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    # Defer, rather than discard, cancellation received while reaping a client group.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def terminate_client(process, grace_seconds=5, kill_grace_seconds=5):
    """Only our start_new_session group; an exited leader does not imply exited descendants."""
    result = {"process_group": process.pid, "term_sent": False, "kill_sent": False, "remaining_live_pids": []}
    with shield_cleanup_signals():
        for number, grace, field in ((signal.SIGTERM, grace_seconds, "term_sent"),
                                     (signal.SIGKILL, kill_grace_seconds, "kill_sent")):
            if not live_group_members(process.pid):
                break
            try:
                os.killpg(process.pid, number)
                result[field] = True
            except ProcessLookupError:
                break
            deadline = time.monotonic() + grace
            while live_group_members(process.pid) and time.monotonic() < deadline:
                process.poll()  # Reap the leader while separately checking its descendants.
                time.sleep(.02)
        process.poll()
        result["remaining_live_pids"] = live_group_members(process.pid)
    return result


class CalibrationInterrupted(Exception):
    def __init__(self, number):
        self.number = number
        super().__init__("Calibration interrupted by signal " + str(number))


@contextmanager
def interrupt_handlers():
    pending = [None]
    def interrupted(number, frame):
        # Do not raise between fork/exec and assigning Popen: the child must first become owned by finally.
        pending[0] = number
    def checkpoint():
        if pending[0] is not None:
            raise CalibrationInterrupted(pending[0])
    signals = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
    previous = {number: signal.signal(number, interrupted) for number in signals}
    try:
        yield checkpoint
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def parse_rates(value):
    """Permit a precise low-rate bracket while retaining historical integer trial names."""
    try:
        values = [float(item) for item in value.split(",")]
    except (TypeError, ValueError):
        raise ValueError("Rates must be comma-separated positive finite numbers") from None
    if not values or any(not math.isfinite(item) or not 0 < item <= 100000 for item in values) \
            or values != sorted(set(values)):
        raise ValueError("Rates must be unique, increasing, positive finite numbers at most 100000")
    return [int(item) if item.is_integer() else item for item in values]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--rates", required=True, help="Ascending comma-separated rates, frozen before execution")
    parser.add_argument("--p99-slo-ms", type=float, required=True)
    parser.add_argument("--max-drain-seconds", type=float, default=1.0)
    parser.add_argument("--mode", choices=("pilot", "confirm"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--jdbc-jar", type=Path, required=True)
    args = parser.parse_args()
    try:
        rates = parse_rates(args.rates)
    except ValueError as error:
        parser.error(str(error))
    if not 0 < args.p99_slo_ms <= 60000 or not 0 <= args.max_drain_seconds <= 30:
        parser.error("Invalid explicit latency/drain SLO")
    workload = json.loads(args.workload.read_text())
    baseline.check_workload(workload)
    _, shape, selection = baseline.contract_inputs(workload, CONTRACT)
    shape_met = (workload["pairs"] >= 5 and workload["warmup_seconds"] >= shape["warmup_seconds"]
                 and workload["duration_seconds"] >= shape["duration_seconds_per_window"])
    if args.mode == "confirm" and not shape_met:
        parser.error("Confirmation requires at least five pairs and the original case warmup/duration")
    if args.mode == "confirm" and workload.get("contract_group") and not workload.get("business_workload_sha256"):
        parser.error("Current confirmation requires the controller's canonical business_workload_sha256")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    bindings = freeze_bindings(args, workload)
    frozen = {"mode": args.mode, "rates": rates, "p99_slo_ms": args.p99_slo_ms,
              "max_drain_seconds": args.max_drain_seconds, "template": workload,
              "started_at_utc": datetime.now(timezone.utc).isoformat(), "bindings": bindings,
              "service_start_ticks": {name: baseline.process_sample(info["pid"])["start_ticks"]
                                      for name, info in workload["services"].items()},
              "scope": "Predeclared single case/concurrency/connection-mode sweep; no candidate B",
              "watchdog": "Bounded wall time stops only this trial's client process group"}
    if workload.get("contract_group"):
        frozen.update(phase="A_ONLY", current_group=workload["contract_group"], cell_id=workload["cell_id"],
                      contract_selection=selection, business_workload_sha256=workload.get("business_workload_sha256"),
                      business_workload_binding=baseline.business_workload_binding(workload),
                      baseline_identity=baseline_identity(workload, bindings, required=args.mode == "confirm"))
    write_json(output / "frozen-inputs.json", frozen)
    trials = []
    interrupted = None
    exit_code = 0
    with interrupt_handlers() as check_interrupt:
        try:
            for rate in rates:
                check_interrupt()
                drift = check_bindings(bindings)
                check_interrupt()
                if drift:
                    trials.append({"rate": rate, "assessment": "invalid_trial", "frozen_input_errors": drift})
                    exit_code = 2
                    break
                candidate = dict(workload, rate=rate)
                # parse_rates preserves ints; float str round-trips without merging nearby rates.
                stem = "rate-" + str(rate)
                path = output / (stem + ".json")
                write_json(path, candidate)
                directory = output / stem
                command = [sys.executable, str(RUNNER), "--workload", str(path), "--output", str(directory),
                           "--java-home", str(args.java_home.resolve()), "--jdbc-jar", str(args.jdbc_jar.resolve())]
                coordination = workload.get("coordination_timeout_seconds", 30)
                drain = workload.get("drain_timeout_seconds", max(30, 2 * workload["timeout_seconds"]))
                deadline = time.monotonic() + 120 + workload["pairs"] * 2 * (
                    workload["warmup_seconds"] + workload["duration_seconds"] + 2 * drain + 4 * coordination + 10)
                timed_out = False
                process = None
                cleanup = None
                with (output / (stem + ".log")).open("w") as log:
                    try:
                        process = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
                        check_interrupt()
                        while process.poll() is None:
                            check_interrupt()
                            if time.monotonic() >= deadline:
                                timed_out = True
                                break
                            time.sleep(.2)
                    finally:
                        if process is not None:
                            cleanup = terminate_client(process)
                check_interrupt()
                report_path = directory / "report.json"
                try:
                    report = read_json(report_path) if report_path.exists() else {}
                except (OSError, ValueError):
                    report = {}
                # Includes the final trial. A file change cannot be accepted just because no next rate exists.
                drift = check_bindings(bindings)
                check_interrupt()
                audit = verify_trial(directory, report, candidate, frozen, path)
                check_interrupt()
                if drift:
                    audit["valid"] = False
                    audit["errors"].extend(drift)
                if cleanup and cleanup["remaining_live_pids"]:
                    audit["valid"] = False
                    audit["errors"].append("Trial process group still has live members")
                if process.returncode == 0 and cleanup and cleanup.get("term_sent"):
                    audit["valid"] = False
                    audit["errors"].append("Exited runner left orphaned client processes requiring cleanup")
                write_json(output / (stem + "-artifact-audit.json"), audit)
                assessment = (assess(report, args.p99_slo_ms, args.max_drain_seconds, workload["pairs"] * 2,
                                     require_sample_floor=args.mode == "confirm", evidence=audit)
                              if process.returncode == 0 and not timed_out else "invalid_trial")
                trial = {"rate": rate, "assessment": assessment, "exit_code": process.returncode,
                         "watchdog_terminated": timed_out, "cleanup": cleanup,
                         "report": str(report_path) if report else None,
                         "artifact_audit": str(output / (stem + "-artifact-audit.json")),
                         "frozen_input_errors": drift,
                         "window_p99_ms": [w.get("p99_ms") for w in report.get("windows", [])]}
                trials.append(trial)
                write_json(output / "report.json", {"frozen_inputs": frozen, "trials": trials,
                           "bracket": capacity_bracket(trials, args.mode, shape_met, rates)})
                print(json.dumps(trial), flush=True)
                if assessment == "invalid_trial":
                    exit_code = 2
                    break
        except (CalibrationInterrupted, KeyboardInterrupt) as error:
            number = error.number if isinstance(error, CalibrationInterrupted) else signal.SIGINT
            interrupted = {"signal": number, "active_rate": rate if "rate" in locals() else None,
                           "cleanup": cleanup if "cleanup" in locals() else None}
            exit_code = 128 + number
    # A signal may arrive between trials; it never promotes a previous partial result to a capacity claim.
    bracket = capacity_bracket(trials, args.mode, shape_met, rates)
    if interrupted:
        bracket["capacity_bracket_established"] = False
        bracket["candidate_rates_30_60_85_percent"] = None
    write_json(output / "report.json", {"frozen_inputs": frozen, "trials": trials, "bracket": bracket,
               "interrupted": interrupted, "exit_code": exit_code})
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
