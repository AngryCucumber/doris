#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Plan or measure instrumented P1 primitive subsets; never report a complete LP023/release pass."""

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

import calibrate_read_capacity as lifecycle
import license_payload_fixture as fixtures
import run_performance_baseline as statistics_tools

HERE = Path(__file__).resolve().parent
CONTRACT = HERE.parents[1] / "docs/license-performance-cases-20260922.json"
PROBE = HERE / "LicensePrimitiveCostProbe.java"
HOT = ("harness_input_control", "snapshot_status_long_valid", "trusted_clock_seconds",
       "snapshot_status_live_clock_valid")
VALIDATION = "license_verification_management"
REJECTION = "license_rejection_management"
THREADS = (1, 8, 32)
TARGETS = {"operation_rate": 1.0, "cpu_ns_per_operation": 1.0, "p95_ns": 2.0, "p99_ns": 2.0}
EXPECTED_CPU_AFFINITY = "0-4"


def matrix():
    return [{"operation": name, "threads": threads, "payload_bytes": size}
            for name in (*HOT, VALIDATION, REJECTION)
            for size in ((256,) if name == REJECTION else (512,) if name == "harness_input_control" else fixtures.SIZES)
            for threads in THREADS]


def histogram_quantile(buckets, quantile):
    count = sum(bucket[3] for bucket in buckets)
    if count <= 0:
        raise ValueError("Latency histogram is empty")
    target = max(1, math.ceil(quantile * count))
    cumulative = 0
    for _index, lower, upper, frequency in buckets:
        cumulative += frequency
        if cumulative >= target:
            return [lower, upper]
    raise ValueError("Incomplete latency histogram")


def bucket_bounds(index):
    shift = max(0, index // 2048 - 1)
    lower = (index - shift * 2048) << shift
    return lower, lower + (1 << shift) - 1


def cpu_set(text):
    if not isinstance(text, str) or not text:
        raise ValueError("Missing actual CPUs_allowed_list")
    cpus = set()
    for part in text.split(","):
        interval = part.split("-")
        if len(interval) not in (1, 2) or any(not value.isdigit() for value in interval):
            raise ValueError("Invalid CPUs_allowed_list")
        low, high = int(interval[0]), int(interval[-1])
        if not 0 <= low <= high <= 65535:
            raise ValueError("Invalid CPU range")
        cpus.update(range(low, high + 1))
    return cpus


def compiled_class_inventory(directory):
    """Bind every class in the first classpath entry, including nested classes and added shadows."""
    directory = Path(directory)
    if directory.is_symlink() or any(path.is_symlink() for path in directory.rglob("*")):
        raise ValueError("Compiled classpath must not contain untracked symlink targets")
    directory = directory.resolve()
    result = {str(path.relative_to(directory)): lifecycle.digest(path)
              for path in sorted(directory.rglob("*.class")) if path.is_file()}
    if "LicensePrimitiveCostProbe.class" not in result:
        raise ValueError("Compiled primitive probe is missing")
    return result


def check_frozen_inputs(report):
    differences = lifecycle.check_bindings(report["frozen_inputs"])
    clock = report.get("latency_clock")
    if clock is not None:
        try:
            if clock_environment() != clock["environment"]:
                differences.append("Latency clock environment changed")
        except OSError:
            differences.append("Latency clock environment is unavailable")
    compiled = report.get("compiled_classpath")
    if compiled is None:
        differences.append("Compiled first classpath entry has not been frozen")
    else:
        try:
            if compiled_class_inventory(compiled["directory"]) != compiled["classes_sha256"]:
                differences.append("Compiled first classpath entry changed, including its class inventory")
        except (OSError, ValueError) as error:
            differences.append("Compiled first classpath entry unavailable: " + str(error))
    return differences


def verify_window(raw, config):
    if raw.get("operation") != config["operation"] or raw.get("threads") != config["threads"]:
        raise ValueError("Window differs from frozen operation/thread count")
    if raw.get("java_runtime") != config["expected_java_runtime"] or raw.get("clock_suspect_at_end") is not False:
        raise ValueError("JDK runtime or clock state differs from the frozen input")
    expected_cpus = cpu_set(config["expected_cpu_affinity"])
    if expected_cpus != cpu_set(EXPECTED_CPU_AFFINITY):
        raise ValueError("Requested affinity differs from the predeclared CPU0-4 profile")
    for field in ("actual_cpu_affinity_before", "actual_cpu_affinity_after"):
        if cpu_set(raw.get(field)) != expected_cpus:
            raise ValueError("Actual process CPUs_allowed_list differs from the frozen profile")
    measured = raw["measurement"]
    for phase_name in ("warmup", "measurement"):
        phase = raw[phase_name]
        if phase.get("completed") is not True or phase.get("error_class") is not None:
            raise ValueError("Incomplete primitive phase")
        workers = phase["workers"]
        count = phase["operations"]
        minimum = config["minimum_operations" if phase_name == "measurement" else "warmup_operations"]
        duration = config["duration_nanos" if phase_name == "measurement" else "warmup_nanos"]
        epoch, last = phase["epoch_ns"], phase["last_request_end_ns"]
        if len(workers) != config["threads"] or count < minimum or count != sum(w["operations"] for w in workers):
            raise ValueError("Missing workers or operations")
        for index, worker in enumerate(workers):
            quota = minimum // len(workers) + (index < minimum % len(workers))
            if (worker["operations"] < max(1, quota)
                    or not epoch <= worker["first_start_ns"] <= worker["last_end_ns"] <= last
                    or worker["last_end_ns"] < epoch + duration):
                raise ValueError("Worker did not meet its minimum count/duration or time boundary")
            for field in ("cpus_allowed_list_before", "cpus_allowed_list_after"):
                if cpu_set(worker.get(field)) != expected_cpus:
                    raise ValueError("Actual worker CPUs_allowed_list differs from the frozen profile")
        if last != max(w["last_end_ns"] for w in workers):
            raise ValueError("Last request boundary mismatch")
        if not (phase["cpu_start_sample_begin_ns"] <= phase["cpu_start_sample_end_ns"] <= epoch <= last
                <= phase["cpu_end_sample_begin_ns"] <= phase["cpu_end_sample_end_ns"] <= phase["cleanup_end_ns"]):
            raise ValueError("CPU/request/cleanup boundaries are misordered")
        if not 0 <= phase["process_cpu_start_ns"] <= phase["process_cpu_end_ns"] or phase["worker_allocated_bytes"] < 0:
            raise ValueError("Resource counters regressed")
    buckets = measured["latency_histogram"]
    previous = -1
    for index, lower, upper, count in buckets:
        if (any(type(value) is not int for value in (index, lower, upper, count))
                or not previous < index < 131072 or (lower, upper) != bucket_bounds(index) or count <= 0):
            raise ValueError("Malformed latency histogram bucket")
        previous = index
    if sum(bucket[3] for bucket in buckets) != measured["operations"]:
        raise ValueError("Histogram does not cover every measured operation")
    count = measured["operations"]
    elapsed = measured["last_request_end_ns"] - measured["epoch_ns"]
    if elapsed <= 0:
        raise ValueError("Empty measurement interval")
    result = {"operations": count, "elapsed_ns": elapsed, "operation_rate": count * 1e9 / elapsed,
              "elapsed_ns_per_operation": elapsed / count,
              "cpu_ns_per_operation": (measured["process_cpu_end_ns"] - measured["process_cpu_start_ns"]) / count,
              "allocated_bytes_per_operation": measured["worker_allocated_bytes"] / count,
              "successful_operations": 0 if config["operation"] == REJECTION else count,
              "expected_rejections": count if config["operation"] == REJECTION else 0,
              "successful_operations_per_second": 0 if config["operation"] == REJECTION else count * 1e9 / elapsed,
              "expected_rejections_per_second": count * 1e9 / elapsed if config["operation"] == REJECTION else 0,
              "histogram_operations": sum(bucket[3] for bucket in buckets), "cpu_boundary_verified": True,
              "cpu_padding_before_upper_ns": measured["epoch_ns"] - measured["cpu_start_sample_begin_ns"],
              "cpu_padding_after_upper_ns": measured["cpu_end_sample_end_ns"] - measured["last_request_end_ns"],
              "gc_collections": measured["gc_collections"], "gc_millis": measured["gc_millis"],
              "rss_peak_process_lifetime_bytes": measured["memory_after"]["VmHWM"],
              "actual_cpu_affinity_verified_at_process_and_worker_boundaries": True,
              "management_queue_wait_ms": None, "client_end_to_end_including_queue_measured": False}
    for q, name in ((.5, "p50_ns"), (.95, "p95_ns"), (.99, "p99_ns")):
        bounds = histogram_quantile(buckets, q)
        result[name] = statistics.fmean(bounds)
        result[name + "_bounds"] = bounds
    return result


def clock_environment():
    return {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "time_namespace": os.readlink("/proc/self/ns/time"),
            "clocksource": Path("/sys/devices/system/clocksource/clocksource0/current_clocksource").read_text().strip()}


def clock_capability(path):
    """Accept the local architected-counter observation, not clock_getres or minimum call time alone."""
    value = json.loads(path.read_text())
    observed = value.get("observed", {})
    environment = clock_environment()
    frequency = observed.get("architected_counter_frequency_hz")
    if (value.get("status") != "CAPABILITY_OBSERVED_NOT_PERFORMANCE_PASS"
            or observed.get("status") != "CLOCK_CAPABILITY_OBSERVED"
            or observed.get("architecture") != "aarch64"
            or environment["clocksource"] != "arch_sys_counter"
            or any(value.get(key) != expected for key, expected in environment.items())
            or type(frequency) is not int or not 0 < frequency <= 10**12
            or observed.get("architected_counter_period_ns_numerator") != 1000000000
            or observed.get("architected_counter_period_ns_denominator") != frequency):
        raise ValueError("Unsupported or stale latency clock capability")
    commands = value.get("commands", [])
    probes = [command for command in commands if command.get("name") == "probe"]
    if (len(probes) != 1 or probes[0].get("returncode") != 0
            or probes[0].get("real_parent_wait") is not True):
        raise ValueError("Clock probe lacks successful actual parent wait")
    raw = path.parent / "probe.stdout"
    if lifecycle.digest(raw) != probes[0].get("stdout_sha256") or json.loads(raw.read_text()) != observed:
        raise ValueError("Clock probe raw evidence differs")
    return {"environment": environment, "counter_frequency_hz": frequency,
            "duration_quantization_uncertainty_ns": 1e9 / frequency + 1,
            "scope": "One counter period plus1ns integer rounding for a two-read duration; "
                     "not a bound on timer-call overhead, scheduling jitter or clock frequency accuracy",
            "clock_getres_is_not_physical_resolution": True,
            "receipt": str(path), "raw_probe": str(raw)}


def precision(windows, seed, clock_uncertainty_ns=None):
    """Retain histogram and counter quantization; unknown clocks cannot qualify short latency."""
    if clock_uncertainty_ns is not None and (type(clock_uncertainty_ns) not in (int, float)
            or not math.isfinite(clock_uncertainty_ns) or clock_uncertainty_ns <= 0):
        raise ValueError("Clock uncertainty must be finite and positive")
    results = {}
    rng = random.Random(seed)
    for metric, target in TARGETS.items():
        latency = metric in ("p95_ns", "p99_ns")
        differences = []
        for index in range(0, len(windows) - 1, 2):
            a, b = windows[index], windows[index + 1]
            al, au = a.get(metric + "_bounds", [a[metric], a[metric]])
            bl, bu = b.get(metric + "_bounds", [b[metric], b[metric]])
            if latency and clock_uncertainty_ns is not None:
                al, au = max(0, al - clock_uncertainty_ns), au + clock_uncertainty_ns
                bl, bu = max(0, bl - clock_uncertainty_ns), bu + clock_uncertainty_ns
            if au + bu <= 0:
                continue
            differences.append([200 * (bl - au) / (bl + au), 200 * (bu - al) / (bu + al)])
        if len(differences) < 5:
            results[metric] = {"status": "insufficient_pairs", "pairs": len(differences),
                               "precision_target_percent": target}
            continue
        low_means, high_means = [], []
        for _ in range(10000):
            sample = rng.choices(differences, k=len(differences))
            low_means.append(statistics.fmean(pair[0] for pair in sample))
            high_means.append(statistics.fmean(pair[1] for pair in sample))
        low = statistics_tools.quantile(low_means, .025)
        high = statistics_tools.quantile(high_means, .975)
        radius = (high - low) / 2
        status = "precision_met" if radius <= target else "precision_insufficient"
        if low > 0 or high < 0:
            status = "AA_directional_drift"
        if latency and clock_uncertainty_ns is None and status == "precision_met":
            status = "clock_resolution_unverified"
        results[metric] = {"status": status, "pairs": len(differences), "precision_target_percent": target,
                           "bootstrap_95_percent_interval": [low, high], "confidence_radius_percent": radius,
                           "paired_difference_bounds_percent": differences}
        if latency:
            results[metric]["clock_quantization_uncertainty_ns"] = clock_uncertainty_ns
            results[metric]["clock_quantization_included"] = clock_uncertainty_ns is not None
    return results


def validate_fixtures(directory):
    report = json.loads((directory / "report.json").read_text())
    if report.get("status") != "FIXTURE_PASS":
        raise ValueError("Input fixtures must pass the actual issuer/Java oracle first")
    paths = {"fixture_report": directory / "report.json", "fixture_public_key": directory / "ephemeral-public.spki.der"}
    for name, size in [("valid-%d" % size, size) for size in fixtures.SIZES] + [("invalid-256", 256)]:
        matches = [entry for entry in report["fixtures"] if entry["name"] == name]
        if len(matches) != 1:
            raise ValueError("Missing or duplicate signed fixture")
        entry = matches[0]
        payload, certificate = directory / (name + ".json"), directory / (name + ".jws")
        if (len(payload.read_bytes()) != size or fixtures.sha256(payload.read_bytes()) != entry["payload_sha256"]
                or fixtures.sha256(certificate.read_bytes()) != entry["certificate_sha256"]):
            raise ValueError("Signed fixture size/hash differs from its oracle report")
        if fixtures.issuer._decode(certificate.read_text().split(".")[1]) != payload.read_bytes():
            raise ValueError("Fixture JWS payload mismatch")
        if name.startswith("valid-"):
            fixtures.issuer.validate_claims(fixtures.issuer.parse_json(payload.read_bytes()))
            if entry["production_java_result"].get("query_status") != "VALID":
                raise ValueError("Positive fixture is not VALID in its oracle evidence")
        elif (entry["production_java_result"] != {"verified": False, "error_code": "INVALID_CLAIMS"}
              or entry.get("independent_openssl_signature_valid") is not True):
            raise ValueError("Negative fixture lacks precise rejection and authentic signature evidence")
        paths[name + "_payload"], paths[name + "_jws"] = payload, certificate
    return paths


def run_owned(command, log, timeout, checkpoint):
    process = None
    cleanup = None
    original_error = None
    original_traceback = None
    cleanup_error = None
    exit_before_cleanup = None
    receipt_path = log.with_name(log.name + ".cleanup.json")
    deadline = time.monotonic() + timeout
    try:
        with log.open("w") as stream:
            process = subprocess.Popen([str(part) for part in command], stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            while process.poll() is None:
                checkpoint()
                if time.monotonic() >= deadline:
                    raise TimeoutError("Primitive child exceeded the frozen window watchdog")
                time.sleep(.05)
            checkpoint()
    except BaseException as error:
        original_error, original_traceback = error, error.__traceback__
    finally:
        if process is not None:
            try:
                exit_before_cleanup = process.poll()
                cleanup = lifecycle.terminate_client(process)
            except BaseException as error:
                cleanup_error = type(error).__name__ + ": " + str(error)
                # The original failure remains primary even if cleanup itself fails.
                cleanup = {"process_group": process.pid, "term_sent": None, "kill_sent": None,
                           "remaining_live_pids": None}
                try:
                    cleanup["remaining_live_pids"] = lifecycle.live_group_members(process.pid)
                except BaseException as inspection:
                    cleanup["inspection_error"] = type(inspection).__name__ + ": " + str(inspection)
    if original_error is None:
        try:
            checkpoint()  # Includes a deferred signal received during the cleanup's signal shield.
        except BaseException as error:
            original_error, original_traceback = error, error.__traceback__
    receipt = {"started_process_group": process.pid if process is not None else None,
               "exit_code_before_cleanup": exit_before_cleanup,
               "exit_code_after_cleanup": process.returncode if process is not None else None,
               "original_error": None if original_error is None else
                   {"class": type(original_error).__name__, "message": str(original_error)},
               "watchdog_expired": isinstance(original_error, TimeoutError),
               "cleanup": cleanup, "cleanup_error": cleanup_error,
               "finished_at_utc": datetime.now(timezone.utc).isoformat()}
    failed_cleanup = cleanup_error is not None or (cleanup is not None and cleanup["remaining_live_pids"] != [])
    if original_error is None and (process is None or process.returncode or failed_cleanup or cleanup["term_sent"]):
        original_error = RuntimeError("Primitive child failed or left processes behind; original output preserved")
    try:
        lifecycle.write_json(receipt_path, receipt)
    except BaseException as error:
        receipt["receipt_write_error"] = type(error).__name__ + ": " + str(error)
        if original_error is None:
            original_error = RuntimeError("Could not persist child cleanup receipt")
    if original_error is not None:
        # Keep this evidence available to the top-level report even if the receipt write failed.
        original_error.cleanup_receipt = receipt
        original_error.cleanup_receipt_path = str(receipt_path)
        raise original_error.with_traceback(original_traceback)
    return cleanup


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "smoke", "measure"), default="plan")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--fe-lib", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--smoke-cell", help="operation,threads,payload_bytes; only for a diagnostic smoke")
    parser.add_argument("--pairs", type=int)
    parser.add_argument("--duration-seconds", type=float)
    parser.add_argument("--minimum-operations", type=int)
    parser.add_argument("--warmup-seconds", type=float)
    parser.add_argument("--window-timeout-seconds", type=int, default=1800)
    parser.add_argument("--expected-java-runtime", default="17.0.4+8")
    parser.add_argument("--clock-capability", type=Path,
                        help="Local counter capability receipt; absent evidence cannot qualify latency precision")
    args = parser.parse_args(argv)
    smoke = args.mode == "smoke"
    defaults = {"pairs": 1 if smoke else 5, "duration_seconds": .05 if smoke else 60,
                "minimum_operations": 100 if smoke else 1000000, "warmup_seconds": .02 if smoke else 15}
    for name, default in defaults.items():
        if getattr(args, name) is None:
            setattr(args, name, default)
    if (not 1 <= args.pairs <= 30 or not .001 <= args.duration_seconds <= 3600
            or not 1 <= args.minimum_operations <= 100000000 or not 0 <= args.warmup_seconds <= 3600
            or not 10 <= args.window_timeout_seconds <= 7200):
        parser.error("Invalid or unbounded window shape")
    if not smoke and (args.pairs < 5 or args.duration_seconds < 60 or args.minimum_operations < 1000000):
        parser.error("Measurement/plan retains >=5 pairs, >=60 seconds and >=1,000,000 operations per window")
    cells = matrix()
    if smoke:
        if not args.smoke_cell:
            parser.error("Smoke requires one explicit --smoke-cell")
        try:
            name, threads, size = args.smoke_cell.split(",")
            cell = {"operation": name, "threads": int(threads), "payload_bytes": int(size)}
        except (ValueError, TypeError):
            parser.error("Smoke cell must be operation,threads,payload_bytes")
        if cell not in cells:
            parser.error("Smoke cell is outside the frozen P1 primitive matrix")
        cells = [cell]
    elif args.smoke_cell:
        parser.error("Partial cell selection is diagnostic only")
    for name in ("output", "fixtures", "java_home", "fe_lib", "artifact"):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"status": "PLANNED", "mode": args.mode, "case_id": "LP-023", "release_performance_pass": False,
              "LP023_complete": False, "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "missing_scope": ["P3 classification cache hit/miss and 1/64/4096 dependency matrix",
                                "P2/P3 FE admission, management queue, import persistence and end-to-end paths",
                                "FE/BE deployment resource metrics and full LP023 release evidence"],
              "measurement_scope": "Instrumented closed-loop P1 primitive calls, not SQL capacity or queued FE requests",
              "latency_scope": "nanoTime interval around invoke, including dispatch/state assertion/checksum/bookkeeping; "
                               "histogram update, operation counter, loop condition and next-call scheduling excluded",
              "throughput_cpu_scope": "epoch to last invoke completion includes intervening histogram/loop/scheduling; "
                                      "process CPU also includes final histogram, affinity check, latch and boundary padding",
              "instrumentation": "No control subtraction; latency and throughput/CPU have distinct boundaries",
              "raw_distribution": "Every measured operation in a bounded histogram; exact returned integer below4096ns, "
                                  "<=0.049% bucket width above; hardware clock resolution is accounted separately",
              "parameters": {**defaults, **{key: getattr(args, key) for key in defaults},
                             "cpu_affinity": EXPECTED_CPU_AFFINITY, "expected_java_runtime": args.expected_java_runtime,
                             "window_timeout_seconds": args.window_timeout_seconds, "seed": 20260922},
              "planned_cells": cells, "windows_per_cell": args.pairs * 2, "cells": [],
              "confirmed_windows": 0, "active_window": None,
              "process_liveness_requires_independent_verification": True,
              "precision_targets_percent": TARGETS, "frozen_inputs": {}}
    exit_code = 0
    try:
        paths = validate_fixtures(args.fixtures)
        report["latency_clock"] = None
        if args.clock_capability is not None:
            report["latency_clock"] = clock_capability(args.clock_capability.resolve())
            paths["latency_clock_receipt"] = args.clock_capability.resolve()
            paths["latency_clock_raw_probe"] = Path(report["latency_clock"]["raw_probe"])
        paths.update(artifact=args.artifact, controller=Path(__file__), probe=PROBE, contract=CONTRACT,
                     java=args.java_home / "bin/java", javac=args.java_home / "bin/javac",
                     lifecycle=Path(lifecycle.__file__), statistics=Path(statistics_tools.__file__))
        jars = []
        for name in ("jackson-core", "jackson-databind", "jackson-annotations"):
            matches = list(args.fe_lib.glob(name + "-*.jar"))
            if len(matches) != 1:
                raise ValueError("Expected one FE dependency: " + name)
            paths[name] = matches[0]
            jars.append(matches[0])
        report["frozen_inputs"] = {name: {"path": str(path), "sha256": lifecycle.digest(path)}
                                   for name, path in paths.items()}
        lifecycle.write_json(args.output / "manifest.json", report)
        if args.mode != "plan":
            classes = args.output / "probe-classes"
            classes.mkdir()
            classpath = os.pathsep.join(str(path) for path in [classes, args.artifact, *jars])
            with lifecycle.interrupt_handlers() as checkpoint:
                report.update(status="RUNNING", phase="compilation",
                              last_checkpoint_at_utc=datetime.now(timezone.utc).isoformat())
                lifecycle.write_json(args.output / "report.json", report)
                run_owned([args.java_home / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-cp",
                           classpath, "-d", classes, PROBE], args.output / "compile.log", 60, checkpoint)
                report["compiled_classpath"] = {"directory": str(classes),
                                                "classes_sha256": compiled_class_inventory(classes)}
                drift = check_frozen_inputs(report)
                if drift:
                    raise ValueError("Frozen input drift during compilation: " + "; ".join(drift))
                lifecycle.write_json(args.output / "runtime-manifest.json", report)
                for cell_index, cell in enumerate(cells):
                    entry = {**cell, "windows": []}
                    report["cells"].append(entry)
                    for window in range(args.pairs * 2):
                        checkpoint()
                        drift = check_frozen_inputs(report)
                        if drift:
                            raise ValueError("Frozen input drift: " + "; ".join(drift))
                        directory = args.output / ("cell-%02d-window-%02d" % (cell_index, window))
                        directory.mkdir()
                        certificate = "invalid-256" if cell["operation"] == REJECTION else "valid-%d" % cell["payload_bytes"]
                        config = {**cell, "public_key": str(paths["fixture_public_key"]),
                                  "certificate": str(paths[certificate + "_jws"]),
                                  "expected_java_runtime": args.expected_java_runtime,
                                  "expected_cpu_affinity": EXPECTED_CPU_AFFINITY,
                                  "minimum_operations": args.minimum_operations,
                                  "duration_nanos": int(args.duration_seconds * 1e9),
                                  "warmup_nanos": int(args.warmup_seconds * 1e9),
                                  "warmup_operations": 100 if smoke else 10000,
                                  "timeout_seconds": args.window_timeout_seconds}
                        config_path = directory / "config.json"
                        lifecycle.write_json(config_path, config)
                        raw_path = directory / "raw.json"
                        report.update(phase="window", active_window={"cell_index": cell_index,
                                      "window_index": window, "directory": str(directory),
                                      "config_sha256": lifecycle.digest(config_path)},
                                      last_checkpoint_at_utc=datetime.now(timezone.utc).isoformat())
                        lifecycle.write_json(args.output / "report.json", report)
                        run_owned(["taskset", "--cpu-list", "0-4", args.java_home / "bin/java", "-Xms512m",
                                   "-Xmx512m", "-XX:+UseG1GC", "-cp", classpath, "LicensePrimitiveCostProbe",
                                   config_path], raw_path, args.window_timeout_seconds, checkpoint)
                        drift = check_frozen_inputs(report)
                        if drift:
                            raise ValueError("Frozen input drift: " + "; ".join(drift))
                        summary = verify_window(json.loads(raw_path.read_text()), config)
                        lifecycle.write_json(directory / "summary.json", summary)
                        entry["windows"].append({"raw": str(raw_path), "summary": summary})
                        report.update(confirmed_windows=report["confirmed_windows"] + 1, active_window=None,
                                      phase="between_windows",
                                      last_checkpoint_at_utc=datetime.now(timezone.utc).isoformat())
                        lifecycle.write_json(args.output / "report.json", report)
                    clock_uncertainty = (report["latency_clock"]["duration_quantization_uncertainty_ns"]
                                         if report["latency_clock"] is not None else None)
                    entry["precision"] = precision([window["summary"] for window in entry["windows"]],
                                                   20260922, clock_uncertainty)
                    lifecycle.write_json(args.output / "report.json", report)
                report["status"] = "SMOKE_COMPLETE" if smoke else "P1_SUBSET_MEASURED"
                report["P1_subset_precision_met"] = not smoke and all(
                    metric["status"] == "precision_met" for entry in report["cells"] for metric in entry["precision"].values())
    except (Exception, KeyboardInterrupt) as error:
        report.update(status="FAILED", error=type(error).__name__ + ": " + str(error))
        if hasattr(error, "cleanup_receipt"):
            report["failed_child_cleanup"] = error.cleanup_receipt
            report["failed_child_cleanup_path"] = error.cleanup_receipt_path
        exit_code = 2
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        report["phase"] = "finished"
        lifecycle.write_json(args.output / "report.json", report)
    print(json.dumps({"status": report["status"], "report": str(args.output / "report.json"),
                      "LP023_complete": False, "release_performance_pass": False}))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
