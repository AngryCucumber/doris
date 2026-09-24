#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Run an explicit isolated, read-only JDBC A/A baseline; never start/stop services.

Requires an existing JDK 17 and local MariaDB JDBC JAR. No network dependency install.
One workload is one LP case/subcase, never evidence for all 26 release cases.
"""

import argparse
import base64
import csv
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).with_name("LicenseJdbcBaseline.java")
SUPPORTED = {"LP-%03d" % n for n in (1, 2, 3, 4, 5, 6, 7, 9)}
PERFORMANCE_CONTRACT = ROOT / "docs/license-performance-cases-20260922.json"


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def quantile(values, q):
    if not values:
        return None
    values = sorted(values)
    position = (len(values) - 1) * q
    low = int(position)
    return values[low] + (values[min(low + 1, len(values) - 1)] - values[low]) * (position - low)


def analyze_windows(windows, seed):
    metrics = {"success_qps": 1.0, "p95_ms": 2.0, "p99_ms": 2.0,
               "fe_cpu_seconds_per_success": 1.0, "be_cpu_seconds_per_success": 1.0}
    results = {}
    rng = random.Random(seed)
    for metric, precision_target in metrics.items():
        paired = []
        for index in range(0, len(windows), 2):
            a, b = windows[index].get(metric), windows[index + 1].get(metric)
            if a is None or b is None or a + b <= 0:
                continue
            paired.append(200.0 * (b - a) / (a + b))
        if len(paired) < 5:
            results[metric] = {"status": "insufficient_pairs", "pairs": len(paired)}
            continue
        means = sorted(statistics.fmean(rng.choices(paired, k=len(paired))) for _ in range(10000))
        low, high = quantile(means, 0.025), quantile(means, 0.975)
        radius = (high - low) / 2.0
        status = "precision_met" if radius <= precision_target else "precision_insufficient"
        if low > 0 or high < 0:
            status = "AA_directional_drift"
        results[metric] = {"pairs": len(paired), "paired_relative_differences_percent": paired,
                           "mean_percent": statistics.fmean(paired), "bootstrap_95_percent_interval": [low, high],
                           "confidence_radius_percent": radius, "absolute_AA_p95_noise_percent": quantile(
                               [abs(v) for v in paired], 0.95), "precision_target_percent": precision_target,
                           "status": status}
        if metric == "success_qps":
            results[metric]["scope"] = "Fixed-offer successful delivery rate; not sustainable capacity precision"
    return results


def check_workload(workload):
    if workload.get("profile") != "checkout_isolated":
        raise ValueError("An explicit checkout_isolated profile is required")
    host = ipaddress.ip_address(workload["host"])
    if not host.is_loopback:
        raise ValueError("This runner only connects to explicitly supplied loopback test services")
    if not 1 <= workload["port"] <= 65535 or workload["case_id"] not in SUPPORTED:
        raise ValueError("Unsupported port or LP case for this JDBC runner")
    if not re.fullmatch(r"[A-Za-z0-9_]*", workload.get("database", "")):
        raise ValueError("Use a simple isolated database name")
    for key in ("duration_seconds", "pairs", "rate", "concurrency", "timeout_seconds"):
        if not isinstance(workload[key], int) or workload[key] <= 0:
            raise ValueError(key + " must be a positive integer")
    if workload.get("connection_mode", "reuse") not in ("reuse", "per_request"):
        raise ValueError("connection_mode must be reuse or per_request")
    if not isinstance(workload["warmup_seconds"], int) or workload["warmup_seconds"] < 0:
        raise ValueError("warmup_seconds must be a non-negative integer")
    if type(workload.get("seed")) is not int or not -(1 << 63) <= workload["seed"] < (1 << 63):
        raise ValueError("seed must be an explicit signed 64-bit integer")
    for key in ("coordination_timeout_seconds", "drain_timeout_seconds"):
        if key in workload and (type(workload[key]) is not int or not 1 <= workload[key] <= 3600):
            raise ValueError(key + " must be between 1 and 3600 seconds")
    point = workload.get("point_key_workload")
    if point is not None:
        if not isinstance(point, dict) or workload.get("queries") or set(point) != {"table", "mode", "seed"}:
            raise ValueError("Use either static queries or a controlled point_key_workload with table/mode/seed")
        if not isinstance(point["table"], str) or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?", point["table"]):
            raise ValueError("Point table must be a simple optionally database-qualified identifier")
        if point["mode"] not in ("text", "prepared") or type(point["seed"]) is not int \
                or not -(1 << 63) <= point["seed"] < (1 << 63):
            raise ValueError("Point mode and explicit signed 64-bit seed are required")
    elif not 1 <= len(workload.get("queries", [])) <= 10000:
        raise ValueError("Expected 1..10000 fixed read queries or point_key_workload")
    for query in workload.get("queries", []):
        sql = query["sql"].strip()
        if not re.match(r"^(SELECT|SHOW|DESC|DESCRIBE|EXPLAIN)\b", sql, re.I):
            raise ValueError("This runner only supports read/metadata queries; setup SQL is separate")
        if ";" in sql or re.search(r"\b(INTO\s+OUTFILE|EXPORT)\b", sql, re.I):
            raise ValueError("Multi-statement or export SQL is not a baseline read query")
        if query.get("mode", "text") not in ("text", "prepared") or query["expected_rows"] < 0:
            raise ValueError("Invalid query mode/expected rows")
        for value in query.get("parameters", []):
            if value is not None and type(value) not in (int, str):
                raise ValueError("Prepared parameters support integer/string/null")
        if query.get("parameters") and query.get("mode") != "prepared":
            raise ValueError("Parameters require prepared mode")
    for sql in workload.get("session_sql", []):
        if not re.match(r"^SET\s+(?:SESSION\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=", sql, re.I) or ";" in sql:
            raise ValueError("Only explicit SET session assignments are supported")
    for name in ("fe", "be"):
        service_root = Path(workload["services"][name]["root"]).resolve()
        if service_root == ROOT or ROOT not in service_root.parents:
            raise ValueError("Service roots must be test installations inside this checkout")
        pid = workload["services"][name]["pid"]
        process = Path("/proc") / str(pid)
        command = (process / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        cwd = (process / "cwd").resolve()
        if str(service_root) not in command and cwd != service_root and service_root not in cwd.parents:
            raise ValueError(name + " PID does not belong to the explicit checkout test installation")
    check_service_endpoints(workload)
    for name in ("fe_artifact", "be_artifact"):
        if not Path(workload["build_identity"][name]).is_file():
            raise ValueError("Missing actual artifact: " + name)
    if not re.fullmatch(r"[0-9a-f]{40}", workload["build_identity"]["baseline_source_commit"]):
        raise ValueError("baseline_source_commit must be an actual 40-character git commit")


def check_service_endpoints(workload):
    """Loopback identifies our services only inside their namespace and on the owned FE's configured port."""
    client_namespace = os.readlink("/proc/self/ns/net")
    for name in ("fe", "be"):
        pid = workload["services"][name]["pid"]
        if os.readlink("/proc/%d/ns/net" % pid) != client_namespace:
            raise ValueError("Client, FE and BE must share the same network namespace")
    configuration = Path(workload["services"]["fe"]["root"]) / "conf/fe.conf"
    assignments = []
    for line in configuration.read_text().splitlines():
        if re.match(r"^\s*query_port\s*=", line):
            match = re.fullmatch(r"\s*query_port\s*=\s*([0-9]+)\s*(?:#.*)?", line)
            if not match:
                raise ValueError("Owned FE must declare a literal numeric query_port")
            assignments.append(int(match.group(1)))
    if len(assignments) != 1 or assignments[0] != workload["port"]:
        raise ValueError("Workload port must equal the single explicit query_port in the owned FE conf/fe.conf")


def process_sample(pid):
    fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    return {"cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
            "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE"), "start_ticks": int(fields[19])}


def summarize(directory, requested, duration, cpu):
    latencies, service, queue = [], [], []
    connection_phases = {name: [] for name in ("connection_ns", "session_init_ns", "prepare_ns", "execute_ns", "close_ns")}
    errors = {}
    last = 0
    observed = 0
    for path in directory.glob("worker-*.csv"):
        with path.open() as stream:
            for row in csv.DictReader(stream):
                observed += 1
                begin, end, scheduled = (int(row[k]) for k in ("start_ns", "end_ns", "scheduled_ns"))
                last = max(last, end)
                if row["error_code"] != "0":
                    key = row["error_code"] + "/" + row["sql_state"]
                    errors[key] = errors.get(key, 0) + 1
                    continue
                latencies.append((end - scheduled) / 1e6)
                service.append((end - begin) / 1e6)
                queue.append((begin - scheduled) / 1e6)
                for name, values in connection_phases.items():
                    if name in row:
                        values.append(int(row[name]) / 1e6)
    seconds = max(duration, last / 1e9)
    result = {"scheduled_requests": requested, "observed_requests": observed, "successful_requests": len(latencies),
              "errors": errors, "missing_requests": requested - observed, "effective_duration_seconds": seconds,
              "drain_seconds": max(0, seconds - duration), "success_qps": len(latencies) / seconds,
              "p50_ms": quantile(latencies, .5), "p95_ms": quantile(latencies, .95),
              "p99_ms": quantile(latencies, .99), "service_p99_ms": quantile(service, .99),
              "client_queue_p99_ms": quantile(queue, .99), "p99_sample_floor_met": len(latencies) >= 10000}
    result["per_request_connection_phase_ms"] = {
        name.removesuffix("_ns"): {"p50": quantile(values, .5), "p95": quantile(values, .95),
                                   "p99": quantile(values, .99), "samples": len(values)}
        for name, values in connection_phases.items() if values}
    for name in ("fe", "be"):
        start, end = cpu["start"].get(name), cpu["end"].get(name)
        compatible = start and end and start["start_ticks"] == end["start_ticks"]
        result[name + "_cpu_seconds_per_success"] = ((end["cpu_seconds"] - start["cpu_seconds"]) / len(latencies)
                                                      if compatible and latencies else None)
    return result


def read_json_if_present(path):
    return json.loads(path.read_text()) if path.is_file() else None


def acknowledge(path):
    temporary = path.with_suffix(".tmp")
    temporary.write_text("acknowledged\n")
    temporary.replace(path)


def boundary_evidence(start, end, lifecycle):
    """Keep CPU sampling in the helper's timestamp domain and expose padding, not guessed alignment."""
    result = {"verified": False, "start": start, "end": end, "lifecycle": lifecycle,
              "clock": "All *_ns fields use this helper JVM's System.nanoTime; not wall time",
              "cpu_boundary": "Counters captured immediately before releasing requests and after their interval; "
                              "reused connection/statement cleanup waits for coordinator acknowledgement",
              "padding_ns": {}}
    if not start or not end or not lifecycle or not lifecycle.get("completed"):
        return result
    epoch = start["epoch_ns"]
    valid = (epoch == end["epoch_ns"] and end["last_request_end_ns"] <= end["request_interval_end_ns"]
             <= end["measurement_end_ns"] <= lifecycle["cleanup_start_ns"] <= lifecycle["cleanup_end_ns"])
    for name in ("fe", "be"):
        first, last = start["cpu"].get(name), end["cpu"].get(name)
        if not first or not last:
            valid = False
            continue
        valid = valid and (first["start_ticks"] == last["start_ticks"]
                           and first["sample_started_ns"] <= first["sample_ended_ns"] <= epoch
                           and end["request_interval_end_ns"] <= last["sample_started_ns"]
                           <= last["sample_ended_ns"] <= end["measurement_end_ns"]
                           and last["cpu_seconds"] >= first["cpu_seconds"])
        result["padding_ns"][name] = {
            "before_requests_upper_bound": epoch - first["sample_started_ns"],
            "after_requests_upper_bound": last["sample_ended_ns"] - end["request_interval_end_ns"]}
    result["verified"] = bool(valid)
    return result


def run_window(workload, output, java, jar, classes):
    output.mkdir()
    queries = output / "queries.tsv"
    with queries.open("w") as stream:
        for query in workload.get("queries", []):
            fields = [base64.b64encode(query["sql"].encode()).decode(), query.get("mode", "text"),
                      str(query["expected_rows"])]
            for value in query.get("parameters", []):
                fields.append("n" if value is None else "i" + str(value) if type(value) is int
                              else "s" + base64.b64encode(value.encode()).decode())
            stream.write("\t".join(fields) + "\n")
    session = output / "session.txt"
    session.write_text("\n".join(base64.b64encode(q.encode()).decode() for q in workload.get("session_sql", [])))
    host = workload["host"]
    if ":" in host:
        host = "[" + host + "]"
    settings = {key: workload[key] for key in ("concurrency", "rate", "duration_seconds", "warmup_seconds", "timeout_seconds", "user", "seed")}
    settings["connection_mode"] = workload.get("connection_mode", "reuse")
    coordination = workload.get("coordination_timeout_seconds", 30)
    drain = workload.get("drain_timeout_seconds", max(30, 2 * workload["timeout_seconds"]))
    settings.update(coordination_timeout_seconds=coordination, drain_timeout_seconds=drain,
                    clock_ticks_per_second=os.sysconf("SC_CLK_TCK"), page_size=os.sysconf("SC_PAGE_SIZE"),
                    fe_pid=workload["services"]["fe"]["pid"], be_pid=workload["services"]["be"]["pid"])
    point = workload.get("point_key_workload")
    if point:
        settings.update(point_table=point["table"], point_mode=point["mode"], point_seed=point["seed"])
    settings.update(queries=queries, session=session, output=output,
                    url="jdbc:mariadb://%s:%s/%s" % (host, workload["port"], workload.get("database", "")))
    properties = output / "window.properties"
    properties.write_text("\n".join(str(key) + "=" + str(value).replace("\\", "\\\\") for key, value in settings.items()))
    env = dict(os.environ)
    env["MASSDB_BASELINE_PASSWORD"] = os.environ.get(workload.get("password_env", "MASSDB_BASELINE_PASSWORD"), "")
    samples, cpu, last_sample = [], {"start": {}, "end": {}}, 0
    start_boundary, end_boundary = None, None
    coordinator_events = {}
    watchdog_expired = False
    deadline = time.monotonic() + workload["warmup_seconds"] + workload["duration_seconds"] + 2 * drain + 4 * coordination + 10
    with (output / "client.log").open("w") as log:
        process = subprocess.Popen([str(java), "-cp", str(classes) + os.pathsep + str(jar),
                                    "LicenseJdbcBaseline", str(properties)], stdout=log, stderr=log, env=env)
        try:
            while process.poll() is None:
                now = time.monotonic()
                if now > deadline:
                    watchdog_expired = True
                    process.terminate()
                    break
                if (output / "measurement-ready.json").exists() and not (output / "measurement-start-ack").exists():
                    coordinator_events["start_ack_monotonic_seconds"] = now
                    acknowledge(output / "measurement-start-ack")
                if start_boundary is None:
                    start_boundary = read_json_if_present(output / "measurement-start.json")
                    if start_boundary:
                        cpu["start"] = start_boundary["cpu"]
                if end_boundary is None:
                    end_boundary = read_json_if_present(output / "measurement-end.json")
                    if end_boundary:
                        cpu["end"] = end_boundary["cpu"]
                        coordinator_events["end_ack_monotonic_seconds"] = now
                        acknowledge(output / "measurement-end-ack")
                if start_boundary and not end_boundary and now - last_sample >= 1:
                    sample = {name: process_sample(info["pid"]) for name, info in workload["services"].items()}
                    samples.append({"monotonic_seconds": now, **sample})
                    last_sample = now
                time.sleep(.01 if not start_boundary or end_boundary else .05)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            process.wait(timeout=2)
    # On premature failure retain any published boundaries without inventing an end sample.
    start_boundary = start_boundary or read_json_if_present(output / "measurement-start.json")
    end_boundary = end_boundary or read_json_if_present(output / "measurement-end.json")
    cpu = {"start": start_boundary["cpu"] if start_boundary else {},
           "end": end_boundary["cpu"] if end_boundary else {}}
    boundary = boundary_evidence(start_boundary, end_boundary, read_json_if_present(output / "lifecycle.json"))
    (output / "resources.json").write_text(json.dumps({"cpu": cpu, "samples": samples,
        "boundary": boundary, "coordinator_events": coordinator_events}, indent=2) + "\n")
    count_file = output / "arrival-count"
    requested = int(count_file.read_text()) if count_file.exists() else 0
    result = summarize(output, requested, workload["duration_seconds"], cpu)
    result["arrival_process"] = "Poisson exponential interarrivals via java.util.Random and StrictMath.log"
    result["arrival_seed"] = workload["seed"]
    result["arrival_schedule_sha256"] = sha(output / "arrivals.bin") if count_file.exists() else None
    result["warmup_arrival_schedule_sha256"] = sha(output / "warmup-arrivals.bin") if count_file.exists() else None
    result["schedule_hash_matches_helper"] = (count_file.exists()
        and result["arrival_schedule_sha256"] == (output / "arrivals.bin.sha256").read_text().strip()
        and result["warmup_arrival_schedule_sha256"]
        == (output / "warmup-arrivals.bin.sha256").read_text().strip())
    result["connection_mode"] = workload.get("connection_mode", "reuse")
    result["connection_cost_boundary"] = ("Each scheduled request opens, initializes, prepares/binds, executes, fetches and closes its own connection; all inside start/end"
        if result["connection_mode"] == "per_request" else "Fixed worker connections initialized/prepared before timed window; start/end retains execute/fetch boundary")
    result["process_exit_code"] = process.returncode
    result["cpu_boundary_verified"] = boundary["verified"]
    result["cpu_boundary_padding_ns"] = boundary["padding_ns"]
    result["watchdog_expired"] = watchdog_expired
    result["client_failure"] = read_json_if_present(output / "client-failure.json")
    result["fixed_rate_success_qps_is_capacity"] = False
    result["query_workload_kind"] = "uniform_point_keys" if point else "static_query_vector"
    if point:
        oracle = read_json_if_present(output / "point-result-oracle.json")
        result["point_result_oracle"] = oracle
        result["point_keys"] = {
            "seed": point["seed"], "range_inclusive": [0, 999999],
            "generator": "java.util.Random(seed XOR 0xD1B54A32D192ED03).nextInt(1000000)",
            "warmup_seed": "seed XOR 0x9E3779B97F4A7C15", "encoding": "big-endian signed int32",
            "generation_boundary": "Complete measured and warmup key sequences generated before connection setup",
            "execution_boundary": "Text SQL construction or prepared dynamic bind inside each request start/end",
            "mode": point["mode"], "count": requested,
            "sha256": sha(output / "point-keys.bin") if (output / "point-keys.bin").exists() else None,
            "warmup_sha256": sha(output / "warmup-point-keys.bin") if (output / "warmup-point-keys.bin").exists() else None}
        result["point_keys"]["hashes_verified"] = all(
            (output / name).is_file() and (output / (name + ".sha256")).is_file()
            and sha(output / name) == (output / (name + ".sha256")).read_text().strip()
            for name in ("point-keys.bin", "warmup-point-keys.bin"))
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jdbc-jar", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    workload = json.loads(args.workload.read_text())
    check_workload(workload)
    java, javac = args.java_home / "bin/java", args.java_home / "bin/javac"
    if not args.jdbc_jar.is_file() or not java.is_file() or not javac.is_file():
        raise ValueError("Actual local JDBC JAR and full JDK are required")
    if args.validate_only:
        print(json.dumps({"status": "inputs_valid", "case_id": workload["case_id"], "services_started": False}))
        return 0
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "workload.json").write_text(json.dumps(workload, ensure_ascii=False, indent=2) + "\n")
    java_version = subprocess.run([str(java), "-version"], capture_output=True, text=True, check=True).stderr
    if not re.search(r'version "17(?:\.|\")', java_version):
        raise ValueError("The frozen first-release baseline requires the explicitly selected JDK 17 runtime")
    identity = {"started_at_utc": datetime.now(timezone.utc).isoformat(), "kernel": platform.platform(),
                "cpu_count": os.cpu_count(), "affinity": sorted(os.sched_getaffinity(0)),
                "java_version": java_version,
                "workload_sha256": sha(args.workload), "runner_sha256": sha(__file__), "java_helper_sha256": sha(SOURCE),
                "jdbc_sha256": sha(args.jdbc_jar), "build_identity": workload["build_identity"],
                "artifact_sha256": {name: sha(workload["build_identity"][name]) for name in ("fe_artifact", "be_artifact")},
                "baseline_kind": "A/A_only", "candidate_B_measured": False}
    performance = json.loads(PERFORMANCE_CONTRACT.read_text())
    case = next(item for item in performance["cases"] if item["id"] == workload["case_id"])
    minimum_warmup = case["load_shape"]["warmup_seconds"]
    minimum_duration = case["load_shape"]["duration_seconds_per_window"]
    identity["performance_contract_sha256"] = sha(PERFORMANCE_CONTRACT)
    identity["frozen_case_load_shape"] = case["load_shape"]
    (output / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    classes = output / "classes"
    classes.mkdir()
    subprocess.run([str(javac), "--release", "17", "-d", str(classes), str(SOURCE)], check=True)
    windows = []
    for index in range(workload["pairs"] * 2):
        result = run_window(workload, output / ("window-%02d" % index), java, args.jdbc_jar.resolve(), classes)
        windows.append(result)
        print(json.dumps({"completed_window": index + 1, "case_id": workload["case_id"],
                          "successes": result["successful_requests"], "errors": result["errors"],
                          "p99_ms": result["p99_ms"]}), flush=True)
        if result["process_exit_code"] != 0:
            break
    analysis = analyze_windows(windows, workload.get("seed", 20260922)) if len(windows) % 2 == 0 else {}
    matching_schedules = (bool(windows) and windows[0]["arrival_schedule_sha256"] is not None
                          and len({w["arrival_schedule_sha256"] for w in windows}) == 1
                          and len({w["warmup_arrival_schedule_sha256"] for w in windows}) == 1)
    matching_point_keys = (not workload.get("point_key_workload") or (bool(windows)
                           and all(w.get("point_keys", {}).get("hashes_verified") for w in windows)
                           and len({w["point_keys"]["sha256"] for w in windows}) == 1
                           and len({w["point_keys"]["warmup_sha256"] for w in windows}) == 1))
    eligible = (len(windows) >= 10 and workload["warmup_seconds"] >= minimum_warmup
                and workload["duration_seconds"] >= minimum_duration and matching_schedules and matching_point_keys
                and all(w["p99_sample_floor_met"] and not w["errors"] and not w["missing_requests"]
                        and w["process_exit_code"] == 0 and w["schedule_hash_matches_helper"]
                        and w["cpu_boundary_verified"] for w in windows)
                and all(v["status"] == "precision_met" for v in analysis.values()))
    report = {"case_id": workload["case_id"], "scope": "single_read_only_subcase_AA_baseline",
              "status": "AA_precision_established" if eligible else "inconclusive",
              "runtime_license_enforcement_proven": False, "candidate_B_measured": False,
              "connection_mode": workload.get("connection_mode", "reuse"),
              "release_performance_pass": False, "all_26_cases_measured": False,
              "sustainable_capacity_measured": False, "capacity_precision_established": False,
              "identical_arrival_schedules_across_windows": matching_schedules,
              "identical_point_key_sequences_across_windows": matching_point_keys,
              "minimum_warmup_seconds": minimum_warmup, "minimum_duration_seconds": minimum_duration,
              "windows": windows, "analysis": analysis,
              "limitations": ["No FE classification/admission code has been inferred from SQL timing",
                              "Fixed-rate QPS is not sustainable capacity; separate rate sweeps are required",
                              "Cache/point-plan/fanout path reachability needs independent actual profiles",
                              "JVM allocation/GC, IO/network and all future candidate scenarios need their own evidence",
                              "CPU boundaries exclude reused connection cleanup; measured padding is in resources.json",
                              "Short/warmup/sample/precision failures remain inconclusive, never release passes"]}
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"report": str(output / "report.json"), "status": report["status"]}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, FileNotFoundError) as exception:
        print("Baseline input error: " + str(exception), file=sys.stderr)
        sys.exit(2)
