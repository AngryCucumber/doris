#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""A-only Flight/scanner/external-read capacity sweeps using complete protocol windows.

The original services and compiled protocol runtime must already exist. This tool
owns only its per-window observer and the clients owned by the protocol runner.
Capacity confirmation does not establish the later A/A precision or A/B gates.
"""

import argparse
import copy
from decimal import Decimal
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
import zipfile

import calibrate_read_capacity as legacy
import p4_statistics as stats
import resource_observer
import stream_load_fixture

SOURCE = Path(__file__).resolve()
PROTOCOLS = {"flight": ("flight_performance", "G2", "reuse_fe_and_be_channels"),
             "scanner": ("external_scanner_performance", "G3", "http_keep_alive_original_scanner"),
             "external_read": ("external_read_performance", "G2", "reuse_jdbc_streaming")}
require, read, ref, verify = stats.require, stats.read_json, stats.reference, stats.verify_reference
RESERVED = {"schema_version", "phase", "variant", "window_id", "pair_id", "workload", "runtime", "launch_token",
            "boot_id", "created_monotonic_ns", "namespace", "utc_anchor", "context_deadline_monotonic_ns", "freeze", "publication"}


def publish(path, value):
    path = Path(path)
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    return ref(path)


def protocol(name):
    require(name in PROTOCOLS, "Unsupported capacity protocol; HTTP/DML/complex are not connected")
    return importlib.import_module(PROTOCOLS[name][0])


def validate_observer(value):
    require(set(value) == {"cluster_record", "client_cpus", "server_cpus", "interval_seconds", "http_timeout_seconds",
                          "max_gap_seconds", "start_timeout_seconds", "finish_timeout_seconds", "max_log_bytes",
                          "client_sample_seconds", "client_max_gap_seconds", "rss_limits_bytes", "max_samples", "min_free_disk_bytes"}, "Observer input fields differ")
    verify(value["cluster_record"])
    for name in ("client_cpus", "server_cpus"):
        cpus = value[name]
        require(isinstance(cpus, list) and cpus and all(type(cpu) is int and cpu >= 0 for cpu in cpus)
                and cpus == sorted(set(cpus)), "Explicit observer/server CPU set required")
    require(not set(value["client_cpus"]) & set(value["server_cpus"]), "Client and server CPUs overlap")
    for key in ("interval_seconds", "http_timeout_seconds", "max_gap_seconds", "start_timeout_seconds",
                "finish_timeout_seconds", "client_sample_seconds", "client_max_gap_seconds"):
        stats.numeric(value[key], key, strictly_positive=True)
    require(1 <= value["interval_seconds"] <= 60 and .05 <= value["http_timeout_seconds"] <= 5
            and value["max_gap_seconds"] >= value["interval_seconds"]
            and value["client_max_gap_seconds"] >= value["client_sample_seconds"], "Existing observer limits violated")
    require(type(value["max_log_bytes"]) is int and value["max_log_bytes"] > 0, "Explicit observation file bound required")
    require(set(value["rss_limits_bytes"]) == {"fe", "be", "observer", "client"}
            and all(type(item) is int and item > 0 for item in value["rss_limits_bytes"].values()), "Explicit sampled RSS limits required")


def external_plan_command(runtime, profile_path, output):
    module = protocol("external_read")
    return module.command_for(runtime, profile_path)[:-1] + ["--plan", str(profile_path), str(output)]


def declared_external_schedule(receipt_ref, profile, runtime_ref):
    """Only a bounded original Java plan receipt supplies actual schedule bytes."""
    module = protocol("external_read"); receipt_path = verify(receipt_ref); receipt = read(receipt_path)
    runtime = read(verify(runtime_ref)); module.check_runtime(runtime)
    require(receipt["schema_version"] == 1 and receipt["runtime"] == runtime_ref
            and read(verify(receipt["profile"])) == profile, "Declared Java schedule runtime/profile differs")
    require(receipt["exit_code"] == 0 and receipt["parent_wait_complete"] is True and not receipt["remaining_live_pids"]
            and not receipt["errors"] and receipt["boot_id"] == stats.boot_id(), "Actual Java plan did not complete")
    require(type(receipt["started_monotonic_ns"]) is int and type(receipt["completed_monotonic_ns"]) is int
            and 0 < receipt["started_monotonic_ns"] <= receipt["completed_monotonic_ns"], "Actual Java plan lifetime invalid")
    directory = receipt_path.parent
    command = external_plan_command(runtime, verify(receipt["profile"]), directory / "plan")
    require(receipt["command"] == command and receipt["pin"]["exe"] == str((Path(runtime["java_home"]) / "bin/java").resolve())
            and type(receipt["pin"]["pid"]) is int and receipt["pin"]["pid"] > 0
            and type(receipt["pin"]["start_ticks"]) is int and receipt["pin"]["start_ticks"] > 0
            and receipt["pin"]["command_sha256"] == hashlib.sha256(b"\0".join(os.fsencode(part) for part in command) + b"\0").hexdigest(),
            "Actual Java plan process/command differs")
    result = {"receipt": receipt_ref, "profile": receipt["profile"], "runtime": runtime_ref}
    for name in ("warmup", "measurement", "metadata"):
        path = directory / "plan" / ("plan.json" if name == "metadata" else name + "-arrivals.tsv")
        require(receipt[name] == ref(path), "Declared Java plan artifact path/bytes differ")
        result[name] = receipt[name]
    require(read(verify(result["metadata"])) == {"network_clients_created": 0, "formal_performance_pass": False},
            "Actual Java plan-only branch receipt missing")
    reference = module.plan(profile)
    for phase in ("warmup", "measurement"):
        path = verify(result[phase]); require(path.stat().st_size <= 100 + 64 * profile["max_requests"], "Declared schedule exceeds row bound")
        lines = path.read_text().splitlines(); require(lines and lines[0] == "sequence\toffset_ns", "Declared schedule header differs")
        values = [line.split("\t") for line in lines[1:]]
        require(len(values) == reference[phase]["requests"], "Declared Java schedule count differs from independent model")
        previous = -1
        for index, (row, expected) in enumerate(zip(values, reference[phase]["offsets"])):
            require(len(row) == 2 and row[0] == str(index) and re.fullmatch(r"[0-9]+", row[1]), "Declared Java schedule indices invalid")
            offset = int(row[1])
            require(previous <= offset and abs(offset - expected) <= 1, "Declared Java schedule exceeds 1ns independent reference bound")
            previous = offset
    return result


def generate_external_schedules(spec, output):
    """Explicit offline Java --plan action. Never creates a database/network client."""
    require(set(spec) == {"runtime", "profile_template", "rates", "timeout_seconds"}, "Schedule-only fields differ")
    require(type(spec["timeout_seconds"]) is int and 1 <= spec["timeout_seconds"] <= 300, "Bounded plan timeout required")
    module = protocol("external_read"); module.check_jvm_environment()
    runtime = read(verify(spec["runtime"])); dependencies = module.check_runtime(runtime)
    template = read(verify(spec["profile_template"])); rates = spec["rates"]
    require(isinstance(rates, list) and rates and all(type(rate) in (int, float) and math.isfinite(rate) and rate > 0 for rate in rates)
            and rates == sorted(set(rates)), "Declared schedule rates invalid")
    output = stream_load_fixture.owned(output); output.mkdir(parents=True, exist_ok=False); receipts = []
    with legacy.interrupt_handlers() as checkpoint:
        for index, rate in enumerate(rates):
            checkpoint(); profile = {**template, "rate": rate}; module.plan(profile)
            directory = output / ("rate-%d" % index); directory.mkdir()
            profile_ref = publish(directory / "profile.json", profile)
            command = external_plan_command(runtime, profile_ref["path"], directory / "plan")
            child = None; actual = None; errors = []; started = time.monotonic_ns()
            deadline = time.monotonic() + spec["timeout_seconds"]
            try:
                for item in [spec["runtime"], spec["profile_template"], *dependencies]: verify(item)
                with (directory / "java-plan.log").open("x") as log:
                    child = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
                    actual = module.acquire_process(child, command, min(deadline, time.monotonic() + 5))
                    while child.poll() is None:
                        checkpoint(); require(time.monotonic() < deadline, "Java plan timeout")
                        time.sleep(.01)
                    child.wait()
            except BaseException as error:
                errors.append(type(error).__name__)
            finally:
                if child is not None:
                    try:
                        legacy.terminate_client(child); child.wait(timeout=5)
                    except BaseException as error: errors.append(type(error).__name__)
                try:
                    for item in [spec["runtime"], spec["profile_template"], profile_ref, *dependencies]: verify(item)
                except BaseException as error: errors.append(type(error).__name__)
                receipt = {"schema_version": 1, "profile": profile_ref, "runtime": spec["runtime"], "command": command,
                    "pin": actual, "boot_id": stats.boot_id(), "started_monotonic_ns": started,
                    "completed_monotonic_ns": time.monotonic_ns(), "exit_code": child.returncode if child else None,
                    "parent_wait_complete": child is not None and child.returncode is not None,
                    "remaining_live_pids": legacy.live_group_members(child.pid) if child else [], "errors": errors}
                for name in ("warmup", "measurement", "metadata"):
                    path = directory / "plan" / ("plan.json" if name == "metadata" else name + "-arrivals.tsv")
                    if path.is_file(): receipt[name] = ref(path)
                receipt_ref = publish(directory / "completion.json", receipt)
            checkpoint()
            declared_external_schedule(receipt_ref, profile, spec["runtime"]); receipts.append(receipt_ref)
    result = {"status": "ACTUAL_JAVA_SCHEDULES_READY_NOT_PERFORMANCE", "arrival_schedules": receipts,
              "formal_performance_pass": False}
    publish(output / "report.json", result); return result


def prepare_plan(spec):
    """Pure file/shape checks. No compiler, live guard, observer, socket, or service action."""
    external = spec.get("protocol") == "external_read"
    require(set(spec) == {"schema_version", "run_id", "protocol", "mode", "cell_id", "rates", "pairs", "slo",
                          "profile_template", "context_template", "runtime", "observer", "deadline_seconds"}
            | ({"arrival_schedules"} if external else set()), "Capacity fields differ")
    require(spec["schema_version"] == 1 and spec["mode"] in ("pilot", "confirm"), "Capacity schema/mode invalid")
    module = protocol(spec["protocol"]); _, group, connection = PROTOCOLS[spec["protocol"]]
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", spec["run_id"]) and spec["cell_id"].startswith(group + "-"), "Capacity case identity invalid")
    rates = spec["rates"]
    require(isinstance(rates, list) and len(rates) >= 2 and all(type(rate) in (int, float)
            and math.isfinite(rate) and rate > 0 for rate in rates) and rates == sorted(set(rates)), "Predeclare ascending finite rates")
    require(type(spec["pairs"]) is int and spec["pairs"] >= (5 if spec["mode"] == "confirm" else 1), "Invalid independent pair count")
    slo = spec["slo"]
    require(set(slo) == {"p99_ms", "max_drain_seconds", "max_error_rate", "max_timeout_rate"}
            and slo["max_error_rate"] == slo["max_timeout_rate"] == 0, "Unexpected errors/timeouts never establish capacity")
    require(0 < stats.numeric(slo["p99_ms"], "P99 SLO") <= 60000
            and 0 <= stats.numeric(slo["max_drain_seconds"], "drain SLO") <= 30, "Existing capacity SLO bounds differ")
    stats.numeric(spec["deadline_seconds"], "absolute own-client deadline", strictly_positive=True)
    validate_observer(spec["observer"])
    template = read(verify(spec["profile_template"])); base = read(verify(spec["context_template"]))
    require(not RESERVED & set(base), "Context template contains per-window or B fields")
    allowed_base = {"identity", "bindings", "services", "service_configs", "endpoints", "max_clock_uncertainty_ns", "coordination_seconds"}
    if spec["protocol"] in ("scanner", "external_read"): allowed_base.add("host_namespace")
    if external: allowed_base.update(("external_source", "private_query"))
    require(set(base) == allowed_base, "Unexpected context template fields; inline secrets are not supported")
    stats.validate_identity(base["identity"])
    runtime = read(verify(spec["runtime"])); runtime_bindings = module.check_runtime(runtime)
    if external:
        require(isinstance(spec["arrival_schedules"], list) and len(spec["arrival_schedules"]) == len(rates),
                "External read requires a predeclared actual Java schedule for every rate")
        source = module.external_source(base, template)
        require(not set(source["resources"]["cpu_affinity"]) & set(spec["observer"]["client_cpus"] + spec["observer"]["server_cpus"]),
                "External source CPUs overlap client/FE/BE")
    require(spec["mode"] != "confirm" or template["qualification"] == "formal", "Short diagnostic profiles cannot be upgraded to confirmed capacity")
    profiles = []
    for index, rate in enumerate(rates):
        value = {**template, "rate": rate}; module.validate_profile(value)
        schedule = module.plan(value)["measurement"]
        require(spec["mode"] != "confirm" or schedule["requests"] >= 10000,
                "Extend the predeclared duration until every confirmed rate schedules >=10000 complete operations")
        selected = {"profile": value, "request_count": schedule["requests"], "arrival_schedule_sha256": schedule["sha256"]}
        if external:
            selected["actual_schedule"] = declared_external_schedule(spec["arrival_schedules"][index], value, spec["runtime"])
            selected["reference_schedule_sha256"] = schedule["sha256"]
            selected["arrival_schedule_sha256"] = selected["actual_schedule"]["measurement"]["sha256"]
        profiles.append(selected)
    horizon = template["warmup_seconds"] + template["duration_seconds"] + 2 * template["drain_seconds"] + 480
    observer_seconds = horizon + spec["observer"]["start_timeout_seconds"] + spec["observer"]["finish_timeout_seconds"]
    resource_observer.validate_window_limits(observer_seconds, spec["observer"]["interval_seconds"],
        {key: spec["observer"][key] for key in ("max_samples", "max_log_bytes", "min_free_disk_bytes")})
    business = module.business_binding(template)
    require(business["fields"]["connection_mode"] == connection, "Protocol connection mode changed")
    paths = {"controller": SOURCE, "legacy_capacity": Path(legacy.__file__), "statistics": Path(stats.__file__),
             "observer": Path(resource_observer.__file__), "checkout_guard": Path(stream_load_fixture.__file__),
             "installed_slot_guard": Path(importlib.import_module("external_scanner_performance").__file__),
             **{name: path for name, path in zip(("current_plan", "current_contract"), stats.CONTRACTS)}}
    bindings = {key: ref(path) for key, path in paths.items()}
    bindings.update({"protocol_" + key: ref(path) for key, path in module.SOURCES.items()})
    bindings.update(base["bindings"])
    bindings.update({"service_config_" + key: item for key, item in base["service_configs"].items()})
    bindings.update({"runtime_dependency_%d" % index: item for index, item in enumerate(runtime_bindings)})
    bindings.update(profile_template=spec["profile_template"], context_template=spec["context_template"],
                    runtime=spec["runtime"], cluster_record=spec["observer"]["cluster_record"])
    if external:
        bindings.update(external_source=base["external_source"], private_query=base["private_query"])
        bindings.update({"external_source_%d" % index: item for index, item in enumerate(module.source_references(base))})
        for index, selected in enumerate(profiles):
            bindings.update({"schedule_%d_%s" % (index, key): item for key, item in selected["actual_schedule"].items()})
    for item in bindings.values(): verify(item)
    # Field validation requires an actual profile reference, but neither this method nor
    # module.validate_context(live=False) contacts FE/BE. Per-rate refs are published by run().
    probe = {**base, "schema_version": 1, "phase": "CAPACITY", "variant": "A", "window_id": "plan-only", "pair_id": 0,
             "workload": spec["profile_template"], "context_deadline_monotonic_ns": 1}
    module.validate_context(probe, template, runtime, live=False)
    return {"schema_version": 1, "phase": "A_ONLY", "mode": spec["mode"], "current_group": group, "cell_id": spec["cell_id"],
            "rates": rates, "p99_slo_ms": slo["p99_ms"], "max_drain_seconds": slo["max_drain_seconds"],
            "baseline_identity": base["identity"], "business_workload_sha256": business["sha256"], "business_binding": business,
            "template": {"pairs": spec["pairs"], "concurrency": template["concurrency"], "connection_mode": connection,
                         "warmup_seconds": template["warmup_seconds"], "duration_seconds": template["duration_seconds"]},
            "profiles": profiles, "bindings": bindings, "spec": spec, "window_horizon_seconds": horizon,
            "observer_seconds": observer_seconds, "minimum_planned_seconds": len(rates) * 2 * spec["pairs"]
                         * (template["warmup_seconds"] + template["duration_seconds"]),
            "precision_policy": {"separate_formal_AA_required": True, "confidence": .95,
                                 "limits_percent": {key: limit for key, (_, limit) in stats.METRICS.items()}},
            "formal_performance_pass": False}


def check_bindings(frozen):
    for item in frozen["bindings"].values(): verify(item)


def capacity_windows(audits, frozen, trial_index, publication_ns, previous_upper=0):
    """Verify independence and shape without rejecting a genuine complete SLO miss."""
    expected = frozen["profiles"][trial_index]; profile = expected["profile"]
    require(len(audits) == 2 * frozen["template"]["pairs"], "Missing independent capacity pair/windows")
    derived, seen_raw, seen_ids = [], set(), set()
    for slot, audit in enumerate(audits):
        formal = profile["qualification"] == "formal"
        require(audit["status"] == ("VERIFIED" if formal else "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED"), "Protocol audit qualification differs from declared profile")
        require(frozen["mode"] != "confirm" or formal and audit["formal_shape_met"] is True, "Diagnostic/incomplete evidence cannot establish confirmed capacity")
        window = audit["window"]
        require(window["variant"] == "A" and window["pair_id"] == slot // 2 and window["boot_id"] == frozen["boot_id"]
                and window["identity"] == frozen["baseline_identity"] and window["window_id"] not in seen_ids,
                "Wrong variant, independent pair, boot or baseline identity")
        seen_ids.add(window["window_id"])
        require(not any(key in window for key in ("freeze_sha256", "freeze_publication_sha256")), "Capacity evidence contains an A/B freeze")
        for key in ("rate", "warmup_seconds", "duration_seconds"):
            require(window[key] == profile[key], "Capacity shape changed: " + key)
        require(window["workload_sha256"] == frozen["business_workload_sha256"]
                and window["arrival_schedule_sha256"] == expected["arrival_schedule_sha256"], "Capacity business/schedule differs")
        count = window["successful_requests"]
        require(type(count) is int and count >= (10000 if frozen["mode"] == "confirm" else 1) and count == expected["request_count"]
                == window["scheduled_requests"] == window["observed_requests"], "Missing or insufficient complete business operations")
        require(all(window[key] == 0 for key in ("error_count", "timeout_count", "retry_count"))
                and all(window[key] is True for key in ("oracle_verified", "cleanup_verified", "cpu_boundary_verified")), "Failed result/CPU/cleanup evidence")
        mapping = window["monotonic_mapping"]
        low, mid, high = [mapping[key] for key in ("offset_lower_ns", "estimated_offset_ns", "offset_upper_ns")]
        uncertainty = window["monotonic_mapping_uncertainty_ns"]
        require(window["monotonic_clock_domain"] == "bounded_jvm_mapping" and all(type(x) is int for x in (low, mid, high, uncertainty))
                and low <= mid <= high and uncertainty == max(mid - low, high - mid), "Capacity clock mapping invalid")
        warm, warm_end, start, end = [window[key] for key in ("warmup_start_monotonic_ns", "warmup_end_monotonic_ns", "start_monotonic_ns", "end_monotonic_ns")]
        require(all(type(x) is int for x in (warm, warm_end, start, end)) and 0 <= warm <= warm_end <= start < end
                and warm_end - warm >= profile["warmup_seconds"] * 10**9
                and end - start >= profile["duration_seconds"] * 10**9
                and warm - uncertainty >= max(publication_ns, previous_upper), "Capacity warmup incomplete, overlapping or predates A-only freeze")
        previous_upper = end + uncertainty
        seconds = stats.numeric(window["effective_duration_seconds"], "effective duration", strictly_positive=True)
        require(math.isclose(seconds, (end - start) / 1e9, rel_tol=1e-12, abs_tol=1e-9), "Capacity denominator differs from actual interval")
        metrics = window["metrics"]; require(set(metrics) == set(stats.METRICS), "Missing primary metrics")
        for key, number in metrics.items(): stats.numeric(number, key, strictly_positive=True)
        require(metrics["p95_ms"] <= metrics["p99_ms"] and math.isclose(metrics["success_qps"], count / seconds, rel_tol=1e-9), "Capacity latency order/QPS wrong")
        require(audit["raw_artifacts"], "Capacity lacks raw evidence")
        require(audit["auditor"] == frozen["bindings"]["protocol_runner"], "Capacity used a different protocol auditor")
        verify(audit["auditor"])
        for item in audit["dependency_bindings"]: verify(item)
        for item in audit["raw_artifacts"]:
            identity = stats.file_identity(verify(item)); require(identity not in seen_raw, "Raw capacity windows reused an artifact/inode")
            seen_raw.add(identity)
        derived.append({"scheduled_requests": count, "observed_requests": count, "successful_requests": count,
                        "missing_requests": 0, "errors": {}, "cpu_boundary_verified": True,
                        "effective_duration_seconds": seconds, "drain_seconds": seconds - profile["duration_seconds"], **metrics})
    return derived, previous_upper, seen_raw


def assess(windows, frozen):
    return "within_slo" if all(value["p99_ms"] <= frozen["p99_slo_ms"] and value["drain_seconds"] <= frozen["max_drain_seconds"]
                               for value in windows) else "outside_slo"


def capacity_bracket(trials, mode, shape, rates):
    result = legacy.capacity_bracket(trials, mode, shape, rates)
    lower, upper = result["largest_tested_rate_within_slo"], result["smallest_tested_rate_outside_slo_above_it"]
    if lower is not None and upper is not None:
        # Preserve the exact declared decimal 1% boundary; binary 1.01-1 must
        # not add an accidental failure or expand the mathematical threshold.
        width = 100 * (Decimal(str(upper)) - Decimal(str(lower))) / Decimal(str(lower))
        result["bracket_width_percent_of_lower_bound"] = float(width)
        qualified = mode == "confirm" and shape and result["all_trials_valid"] and not result["nonmonotonic_response"] and width <= 1
        result["capacity_bracket_established"] = qualified
        result["candidate_rates_30_60_85_percent"] = [lower * part for part in (.30, .60, .85)] if qualified else None
    return result


def samples(path, maximum):
    path = Path(path)
    if not path.exists(): return []
    require(path.stat().st_size <= maximum, "Observer/client ledger exceeded frozen bound")
    return [json.loads(line) for line in path.read_bytes().splitlines(keepends=True) if line.endswith(b"\n")]


def last_sample(path, maximum):
    path = Path(path)
    if not path.exists(): return None
    size = path.stat().st_size; require(size <= maximum, "Observer log exceeded bound")
    with path.open("rb") as stream:
        offset = max(0, size - 2 * resource_observer.P4_MAX_SAMPLE_BYTES)
        stream.seek(offset); data = stream.read()
    lines = data.splitlines(keepends=True)
    if offset and lines: lines.pop(0)
    complete = [line for line in lines if line.endswith(b"\n")]
    return json.loads(complete[-1]) if complete else None


def iter_samples(path, maximum):
    path = Path(path); require(path.stat().st_size <= maximum, "Raw observation exceeded frozen bound")
    with path.open("rb") as stream:
        while True:
            line = stream.readline(resource_observer.P4_MAX_SAMPLE_BYTES + 1)
            if not line: break
            require(len(line) <= resource_observer.P4_MAX_SAMPLE_BYTES and line.endswith(b"\n"), "Partial or oversized observation record")
            yield json.loads(line)


def rss(pid):
    value = Path("/proc", str(pid), "status").read_text()
    match = re.search(r"(?m)^VmRSS:\s+(\d+) kB$", value)
    require(match is not None, "Missing actual process RSS")
    return int(match[1]) * 1024


def helper_memory(module, pin):
    """A naturally exited child may be a zombie until its owning runner waits it."""
    try:
        require(module.pin(pin["pid"]) == pin, "Owned helper PID generation changed")
        return {"pin": pin, "rss_bytes": rss(pin["pid"])}, "LIVE"
    except (FileNotFoundError, ProcessLookupError, ValueError):
        try:
            raw = Path("/proc", str(pin["pid"]), "stat").read_text()
        except FileNotFoundError:
            return None, "NO_LONGER_PRESENT"
        fields = raw[raw.rfind(")") + 1:].split()
        require(int(fields[19]) == pin["start_ticks"], "Owned helper PID generation changed at exit")
        require(fields[0] in ("Z", "X"), "Unexpected live helper identity/RSS failure")
        return None, "EXIT_OBSERVED_UNREAPED"


def external_source_sample(module, context):
    """Sample only the already owned source process and its complete container cgroup."""
    started = time.monotonic_ns(); source = read(verify(context["external_source"]))
    actual = module.pin(source["service"]["pid"]); settings = source["resources"]
    require(actual == source["service"] and sorted(os.sched_getaffinity(actual["pid"])) == settings["cpu_affinity"],
            "External source process/CPU changed")
    state = read(verify(source["state"])); identifier = state["container_id"]
    require(re.fullmatch(r"[a-f0-9]{64}", identifier), "External source container identity invalid")
    line = Path("/proc", str(actual["pid"]), "cgroup").read_text().strip()
    require(line == "0::/system.slice/docker-" + identifier + ".scope", "External source actual cgroup changed")
    group = Path("/sys/fs/cgroup") / line.partition("0::/")[2]
    def counters(name):
        return {key: int(value) for key, value in (row.split() for row in (group / name).read_text().splitlines())}
    result = {"sample_started_monotonic_ns": started, "pin": actual,
        "cpu_affinity": sorted(os.sched_getaffinity(actual["pid"])), "rss_bytes": rss(actual["pid"]),
        "cgroup_path": str(group), "cgroup_memory_current_bytes": int((group / "memory.current").read_text()),
        "cgroup_memory_peak_bytes": int((group / "memory.peak").read_text()),
        "cgroup_memory_limit_bytes": int((group / "memory.max").read_text()),
        "cgroup_memory_swap_max": (group / "memory.swap.max").read_text().strip(),
        "cgroup_oom_kill": counters("memory.events")["oom_kill"],
        "cgroup_cpu_max": (group / "cpu.max").read_text().split(), "cgroup_cpu_stat": counters("cpu.stat")}
    require(result["cgroup_memory_limit_bytes"] == settings["memory_limit_bytes"]
            and 0 <= result["cgroup_memory_current_bytes"] <= result["cgroup_memory_peak_bytes"] <= settings["memory_limit_bytes"]
            and result["rss_bytes"] <= settings["memory_limit_bytes"] and result["cgroup_memory_swap_max"] == "0",
            "External source cgroup memory/swap limit changed")
    quota = result["cgroup_cpu_max"]
    require(len(quota) == 2 and quota[0].isdigit() and quota[1].isdigit() and 0 < int(quota[0]) == int(quota[1]),
            "External source CPU quota changed")
    require(module.pin(actual["pid"]) == actual, "External source changed during sample")
    result["sample_ended_monotonic_ns"] = time.monotonic_ns()
    return result


def audit_external_samples(path, settings, source, before, after, lower, upper):
    """Independent saved-record replay, including complete cgroup memory and CPU counters."""
    state = read(verify(source["state"])); identifier = state["container_id"]
    require(re.fullmatch(r"[a-f0-9]{64}", identifier), "External source container identity invalid")
    expected_group = "/sys/fs/cgroup/system.slice/docker-" + identifier + ".scope"
    limit = source["resources"]["memory_limit_bytes"]
    previous = first = last = None; count = 0; peak_rss = peak_memory = 0
    first_oom = before["cgroup_oom_kill"]
    for snapshot in (before, after):
        require(snapshot["cpu_affinity"] == source["resources"]["cpu_affinity"]
                and snapshot["cgroup_memory_limit_bytes"] == limit and snapshot["cgroup_memory_swap_max"] == "0"
                and type(snapshot["rss_bytes"]) is int and 0 <= snapshot["rss_bytes"] <= limit
                and 0 <= snapshot["cgroup_memory_current_bytes"] <= snapshot["cgroup_memory_peak_bytes"] <= limit,
                "External source snapshot resource budget differs")
        quota = snapshot["cgroup_cpu_max"]
        require(len(quota) == 2 and all(isinstance(value, str) and value.isdigit() for value in quota)
                and 0 < int(quota[0]) == int(quota[1]), "External source snapshot CPU quota differs")
    for row in iter_samples(path, settings["max_log_bytes"]):
        sample = row.get("external_source"); require(isinstance(sample, dict), "Missing external source sample")
        start, end = sample["sample_started_monotonic_ns"], sample["sample_ended_monotonic_ns"]
        require(type(start) is int and type(end) is int and start <= end <= row["monotonic_ns"], "External sample timestamp invalid")
        if previous is not None:
            require(previous["sample_ended_monotonic_ns"] <= start
                    and start - previous["sample_started_monotonic_ns"] <= settings["client_max_gap_seconds"] * 10**9,
                    "External source sample gap/order invalid")
        require(sample["pin"] == source["service"] and sample["cpu_affinity"] == source["resources"]["cpu_affinity"]
                and sample["cgroup_path"] == expected_group and sample["cgroup_memory_limit_bytes"] == limit
                and sample["cgroup_memory_swap_max"] == "0" and sample["cgroup_oom_kill"] == first_oom,
                "External source identity/budget/OOM changed")
        for key in ("rss_bytes", "cgroup_memory_current_bytes", "cgroup_memory_peak_bytes", "cgroup_oom_kill"):
            require(type(sample[key]) is int and sample[key] >= 0, "External source counter invalid")
        require(sample["rss_bytes"] <= limit and sample["cgroup_memory_current_bytes"] <= sample["cgroup_memory_peak_bytes"] <= limit,
                "External source memory budget exceeded")
        quota = sample["cgroup_cpu_max"]
        require(len(quota) == 2 and all(isinstance(item, str) and item.isdigit() for item in quota)
                and 0 < int(quota[0]) == int(quota[1]), "External source CPU quota differs")
        counters = sample["cgroup_cpu_stat"]
        require({"usage_usec", "user_usec", "system_usec"} <= set(counters)
                and all(type(value) is int and value >= 0 for value in counters.values()), "External source CPU counters missing")
        if previous is not None:
            require(counters.keys() == previous["cgroup_cpu_stat"].keys()
                    and all(value >= previous["cgroup_cpu_stat"][key] for key, value in counters.items())
                    and sample["cgroup_memory_peak_bytes"] >= previous["cgroup_memory_peak_bytes"], "External source counters reset")
        first = first or sample; previous = last = sample; count += 1
        peak_rss = max(peak_rss, sample["rss_bytes"]); peak_memory = max(peak_memory, sample["cgroup_memory_peak_bytes"])
    require(count >= 2 and first["sample_ended_monotonic_ns"] <= lower <= upper <= last["sample_started_monotonic_ns"],
            "External source lacks full warmup/CPU interval coverage")
    require(before["pin"] == after["pin"] == source["service"] and before["cgroup_path"] == after["cgroup_path"] == expected_group
            and before["sample_ended_monotonic_ns"] <= first["sample_started_monotonic_ns"]
            and last["sample_ended_monotonic_ns"] <= after["sample_started_monotonic_ns"]
            and after["cgroup_oom_kill"] == first_oom, "External source snapshot lifetime/OOM changed")
    require(before["cgroup_cpu_stat"].keys() == first["cgroup_cpu_stat"].keys() == after["cgroup_cpu_stat"].keys()
            and all(0 <= before["cgroup_cpu_stat"][key] <= first["cgroup_cpu_stat"][key]
                    <= last["cgroup_cpu_stat"][key] <= after["cgroup_cpu_stat"][key] for key in first["cgroup_cpu_stat"])
            and before["cgroup_memory_peak_bytes"] <= first["cgroup_memory_peak_bytes"]
                    <= last["cgroup_memory_peak_bytes"] <= after["cgroup_memory_peak_bytes"],
            "External source counters changed outside sampled interval")
    return {"pin": source["service"], "state": source["state"], "resources": source["resources"], "sample_count": count,
            "peak_rss_bytes": peak_rss, "cgroup_memory_limit_bytes": limit, "peak_cgroup_memory_bytes": peak_memory,
            "cgroup_oom_kill_delta": 0, "all_sample_cpu_affinities": [source["resources"]["cpu_affinity"]],
            "coverage_start_monotonic_ns": first["sample_ended_monotonic_ns"],
            "coverage_end_monotonic_ns": last["sample_started_monotonic_ns"], "cgroup_path": expected_group,
            "cgroup_cpu_start": first["cgroup_cpu_stat"], "cgroup_cpu_end": last["cgroup_cpu_stat"]}


def owned_snapshot(frozen, module):
    spec = frozen["spec"]; settings = spec["observer"]; base = read(verify(spec["context_template"]))
    state = read(verify(settings["cluster_record"])); installation = stream_load_fixture.owned(state["installation"])
    module.check_services(base)
    require(state["namespace"] == os.readlink("/proc/self/ns/net") != state["host_namespace"]
            and sorted(os.sched_getaffinity(0)) == settings["client_cpus"] == sorted(os.sched_getaffinity(os.getpid())), "Root must enter the frozen private namespace/client CPUs")
    guard = module if spec["protocol"] == "external_read" else importlib.import_module("external_scanner_performance")
    guard.check_installed_slots(base, read(verify(spec["runtime"])))
    for role in ("fe", "be"):
        require(int((installation / role / "bin" / (role + ".pid")).read_text()) == base["services"][role]["pid"]
                and sorted(os.sched_getaffinity(base["services"][role]["pid"])) == settings["server_cpus"], "Actual original service PID/affinity differs")
        require(ref(installation / role / "conf" / (role + ".conf")) == base["service_configs"][role]
                and base["service_configs"][role]["sha256"] == state["config_sha256"][role], "Actual original service configuration differs")
    with zipfile.ZipFile(verify(base["bindings"]["fe_artifact"])) as archive:
        require(not any(name.startswith("org/apache/doris/massdb/license/") for name in archive.namelist()), "Capacity must use original A without license implementation")
    check_bindings(frozen)
    result = {"boot_id": stats.boot_id(), "namespace": state["namespace"], "pins": base["services"],
            "artifacts": {role: base["bindings"][role + "_artifact"] for role in ("fe", "be")},
            "configurations": base["service_configs"], "actual_client_cpus": sorted(os.sched_getaffinity(0)),
            "observed_monotonic_ns": time.monotonic_ns(), "original_A_no_license_classes": True}
    if spec["protocol"] == "external_read":
        result["external_source"] = external_source_sample(module, base)
    return result


class ObserverWindow:
    """Concrete root adapter: existing owned /metrics observer, sampled RSS, actual wait.

    All limits come from frozen inputs. No FE/BE start, stop, mutation or fixture SQL.
    """
    def __init__(self, frozen, module, directory, stop_file, checkpoint=lambda: None):
        self.frozen, self.module, self.directory, self.stop_file = frozen, module, Path(directory), Path(stop_file)
        self.settings = frozen["spec"]["observer"]; self.process = self.log = self.thread = self.pin = None
        self.done = threading.Event(); self.failures = []; self.wait_receipt = None
        self.checkpoint = checkpoint; self.last_client_sample_ns = 0; self.last_external_sample_start_ns = 0
        self.sample_ready = threading.Event()
        self.external_context = read(verify(frozen["spec"]["context_template"])) if frozen["spec"]["protocol"] == "external_read" else None

    def start(self):
        self.checkpoint()
        self.before = owned_snapshot(self.frozen, self.module); publish(self.directory / "before.json", self.before)
        command = [sys.executable, str(Path(resource_observer.__file__).resolve()), "--cluster-record", self.settings["cluster_record"]["path"],
                   "--output", str(self.directory / "observer"), "--duration-seconds", str(self.frozen["observer_seconds"]),
                   "--interval-seconds", str(self.settings["interval_seconds"]), "--http-timeout-seconds", str(self.settings["http_timeout_seconds"]),
                   "--p4-long-window", "--max-samples", str(self.settings["max_samples"]),
                   "--max-log-bytes", str(self.settings["max_log_bytes"]), "--min-free-disk-bytes", str(self.settings["min_free_disk_bytes"])]
        self.log = (self.directory / "observer.log").open("x")
        self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        self.pin = self.module.acquire_process(self.process, command, time.monotonic() + 10)
        publish(self.directory / "observer-launch.json", {"pin": self.pin, "command": command, "source": ref(resource_observer.__file__)})
        deadline = time.monotonic() + self.settings["start_timeout_seconds"]
        while len(samples(self.directory / "observer/samples.jsonl", self.settings["max_log_bytes"])) < 2:
            self.checkpoint()
            require(not self.stop_file.exists() and self.process.poll() is None and time.monotonic() < deadline, "Observer readiness failed")
            time.sleep(.05)
        self.thread = threading.Thread(target=self.monitor, name="capacity-own-client-rss", daemon=True); self.thread.start()
        while not self.sample_ready.wait(.05):
            self.checkpoint()
            require(not self.failures and time.monotonic() < deadline, "Client resource monitor did not produce its initial sample")

    def monitor(self):
        try:
            with (self.directory / "client-resources.jsonl").open("x") as stream:
                while not self.done.is_set():
                    self.checkpoint()
                    require(self.process.poll() is None, "Observer exited during client window")
                    require(time.monotonic_ns() < self.frozen["absolute_deadline_monotonic_ns"], "Frozen run deadline reached")
                    helper = None; helper_state = "NOT_YET_LAUNCHED"; process_file = self.directory / "window/process.json"
                    if process_file.exists():
                        pin = read(process_file)["pin"]
                        helper, helper_state = helper_memory(self.module, pin)
                    combined = rss(os.getpid()) + (helper["rss_bytes"] if helper else 0)
                    require(combined <= self.settings["rss_limits_bytes"]["client"], "Sampled own-client RSS exceeded frozen limit")
                    row = {"combined_rss_bytes": combined, "helper": helper, "helper_state": helper_state}
                    if self.external_context is not None:
                        row["external_source"] = external_source_sample(self.module, self.external_context)
                        self.last_external_sample_start_ns = row["external_source"]["sample_started_monotonic_ns"]
                    row["monotonic_ns"] = time.monotonic_ns()
                    stream.write(json.dumps(row) + "\n"); stream.flush()
                    self.last_client_sample_ns = row["monotonic_ns"]; self.sample_ready.set()
                    require(stream.tell() <= self.settings["max_log_bytes"], "Client samples exceeded frozen bound")
                    require((self.directory / "observer/samples.jsonl").stat().st_size <= self.settings["max_log_bytes"], "Observer log exceeded frozen bound")
                    self.done.wait(self.settings["client_sample_seconds"])
        except BaseException as error:
            self.failures.append(type(error).__name__ + ": " + str(error)); self.stop_file.touch(exist_ok=True)

    def close(self, complete):
        """Always reap the owned observer, even after a changed binding or invalid raw file."""
        with legacy.shield_cleanup_signals():
            self._close(complete)

    def _close(self, complete):
        try:
            if complete and self.process is not None:
                after_wait = time.monotonic_ns(); deadline = time.monotonic() + self.settings["finish_timeout_seconds"]
                while True:
                    final = last_sample(self.directory / "observer/samples.jsonl", self.settings["max_log_bytes"])
                    if (final and final["started_monotonic_ns"] >= after_wait and self.last_client_sample_ns >= after_wait
                            and (self.external_context is None or self.last_external_sample_start_ns >= after_wait)): break
                    require(self.process.poll() is None and time.monotonic() < deadline, "Observer missing complete post-client sample")
                    time.sleep(.05)
        except BaseException as error:
            self.failures.append(type(error).__name__ + ": " + str(error))
        finally:
            self.done.set()
            if self.thread is not None:
                self.thread.join(timeout=self.settings["client_sample_seconds"] + 5)
                if self.thread.is_alive(): self.failures.append("ClientMonitorDidNotStop")
            if self.process is not None:
                try:
                    if self.process.poll() is None: self.process.send_signal(signal.SIGTERM)
                    self.process.wait(timeout=self.settings["finish_timeout_seconds"])
                except BaseException as error:
                    self.failures.append(type(error).__name__ + ": " + str(error))
                finally:
                    # The shared cleanup helper owns only this new observer process group.
                    try: legacy.terminate_client(self.process)
                    except BaseException as error: self.failures.append(type(error).__name__ + ": " + str(error))
                    self.wait_receipt = {"pid": self.process.pid, "actual_exit_code": self.process.returncode,
                        "parent_wait_complete": self.process.returncode is not None, "remaining_live_pids": legacy.live_group_members(self.process.pid),
                        "completed_monotonic_ns": time.monotonic_ns(), "failures": self.failures}
                    publish(self.directory / "observer-completion.json", self.wait_receipt)
            if self.log is not None: self.log.close()

    def audit(self, raw):
        publish(self.directory / "after.json", owned_snapshot(self.frozen, self.module))
        return publish(self.directory / "observer-audit.json", audit_observation(raw, self.directory, self.frozen, self.module))


def audit_client_samples(path, settings, helper_pin, lower, upper, certain_lower, certain_upper):
    saw_helper = False; previous_ns = None; first_client = None
    for row in iter_samples(path, settings["max_log_bytes"]):
        timestamp = row["monotonic_ns"]
        require(type(timestamp) is int and row["combined_rss_bytes"] <= settings["rss_limits_bytes"]["client"], "Sampled client resource/timestamp invalid")
        if previous_ns is not None:
            require(0 <= timestamp - previous_ns <= settings["client_max_gap_seconds"] * 10**9, "Client resource sample gap invalid")
        first_client = timestamp if first_client is None else first_client
        previous_ns = row["monotonic_ns"]
        require(not certain_lower <= timestamp <= certain_upper or row["helper"] is not None, "Missing helper sample inside certain active interval")
        if row["helper"] is not None:
            require(row["helper_state"] == "LIVE" and row["helper"]["pin"] == helper_pin
                    and row["helper"]["rss_bytes"] <= row["combined_rss_bytes"], "Client sample belongs to another helper")
            saw_helper = True
        else:
            require(row["helper_state"] in ("NOT_YET_LAUNCHED", "NO_LONGER_PRESENT", "EXIT_OBSERVED_UNREAPED"), "Unknown helper absence state")
    require(saw_helper and first_client <= lower and previous_ns >= upper, "No complete actual owned-client RSS coverage")


def audit_observation(raw, directory, frozen, module):
    """Recompute observer evidence from saved complete records; no live target access."""
    directory = Path(directory); settings = frozen["spec"]["observer"]
    before, after, waited = [read(directory / name) for name in ("before.json", "after.json", "observer-completion.json")]
    launched = read(directory / "observer-launch.json"); launch = read(verify(raw["launch"]))
    window = Path(raw["window_directory"])
    bridge, helper = read(window / "p4-clock-bridge.json"), read(window / "p4-helper-clock.json")
    mapping = module.clocks.clock_bridge(launch, raw["launch"], bridge, helper)
    start, end = read(window / "warmup-start.json"), read(window / "measurement-end.json")
    lower = min(start["epoch_ns"], *[value["sample_started_java_ns"] for value in start["cpu"].values()]) + mapping["offset_lower_ns"]
    upper = max(end["request_interval_end_ns"], *[value["sample_ended_java_ns"] for value in end["cpu"].values()]) + mapping["offset_upper_ns"]
    summary = read(directory / "observer/summary.json")
    require(not waited["failures"] and waited["actual_exit_code"] == 143 and waited["parent_wait_complete"]
            and not waited["remaining_live_pids"] and waited["pid"] == launched["pin"]["pid"], "Observer did not cleanly wait143")
    require(launched["source"] == frozen["bindings"]["observer"] and summary["status"] == "INTERRUPTED"
            and summary["signal_number"] == signal.SIGTERM and summary["skipped_schedule_slots"] == 0,
            "Observer source, signal or skipped schedule invalid")
    limits = resource_observer.validate_window_limits(frozen["observer_seconds"], settings["interval_seconds"],
        {key: settings[key] for key in ("max_samples", "max_log_bytes", "min_free_disk_bytes")})
    require(summary["duration_seconds"] == frozen["observer_seconds"] and summary["interval_seconds"] == settings["interval_seconds"]
            and summary["p4_long_window_limits"] == limits
            and summary["raw_sample_bytes_written"] == (directory / "observer/samples.jsonl").stat().st_size,
            "Actual observer schedule/resource policy differs from freeze")
    require(summary["observer_cpu_affinity"] == settings["client_cpus"]
            and summary["observer_peak_rss_bytes"] <= settings["rss_limits_bytes"]["observer"], "Observer affinity/RSS differs")
    require(before["pins"] == after["pins"] == launch["services"] and before["configurations"] == after["configurations"] == launch["service_configs"]
            and before["artifacts"] == after["artifacts"] == {role: launch["bindings"][role + "_artifact"] for role in ("fe", "be")}
            and before["boot_id"] == after["boot_id"] == launch["boot_id"] == frozen["boot_id"]
            and before["original_A_no_license_classes"] is True and after["original_A_no_license_classes"] is True
            and before["observed_monotonic_ns"] <= lower <= upper <= after["observed_monotonic_ns"], "Service/state lifetime changed")
    first = previous = last = None; count = 0
    for row in iter_samples(directory / "observer/samples.jsonl", settings["max_log_bytes"]):
        require(not row["errors"] and row["sample_index"] == count
                and row["scheduled_offset_seconds"] == count * settings["interval_seconds"]
                and row["started_monotonic_ns"] <= row["finished_monotonic_ns"], "Observer raw sample identity/error invalid")
        if previous is not None:
            require(previous["finished_monotonic_ns"] <= row["started_monotonic_ns"]
                    and row["started_monotonic_ns"] - previous["started_monotonic_ns"] <= settings["max_gap_seconds"] * 10**9, "Observer sample gap/order invalid")
        for role in ("fe", "be"):
            actual = row["processes"][role]
            require(actual["pid"] == before["pins"][role]["pid"] and actual["start_ticks"] == before["pins"][role]["start_ticks"]
                    and actual["rss_bytes"] <= settings["rss_limits_bytes"][role]
                    and actual["metrics"]["http_status"] == 200, "Actual service sample invalid")
        first = first or row; previous = last = row; count += 1
    require(count == summary["samples"] and first is not None and first["finished_monotonic_ns"] <= lower
            and last["started_monotonic_ns"] >= upper and summary["samples_sha256"] == stats.digest(directory / "observer/samples.jsonl"), "Observer count/digest/coverage invalid")
    audit_client_samples(directory / "client-resources.jsonl", settings, read(window / "process.json")["pin"], lower, upper,
                         start["epoch_ns"] + mapping["offset_upper_ns"], end["request_interval_end_ns"] + mapping["offset_lower_ns"])
    files = ("before.json", "after.json", "observer-launch.json", "observer-completion.json", "observer/summary.json", "observer/samples.jsonl", "client-resources.jsonl")
    result = {"status": "VERIFIED", "launch_sha256": raw["launch"]["sha256"], "boot_id": launch["boot_id"],
        "coverage_start_monotonic_ns": first["finished_monotonic_ns"], "coverage_end_monotonic_ns": last["started_monotonic_ns"],
        "resource_failures": [], "budget_verified": True, "observed_license_state": "ORIGINAL_A_NO_LICENSE", "auditor": ref(SOURCE),
        "raw_artifacts": [ref(directory / name) for name in files],
        "services": {role: {"pin": before["pins"][role], "artifact": before["artifacts"][role], "configuration": before["configurations"][role]} for role in ("fe", "be")},
        "settings": settings, "formal_performance_pass": False,
        "scope": "Actual sampled resource budgets and process/metric coverage; CPU-per-operation uses the protocol JVM boundary counters.",
        "unqualified": ["continuous RSS ceilings", "complete allocation distributions", "all-RPC wire attribution"]}
    if frozen["spec"]["protocol"] == "external_read":
        source = read(verify(launch["external_source"]))
        result["external_source"] = audit_external_samples(directory / "client-resources.jsonl", settings, source,
            before["external_source"], after["external_source"], lower, upper)
    return result


def execution_window_id(frozen, index, slot, phase_bindings):
    return "%s-%s-%s-r%d-p%d-s%d" % (frozen["spec"]["run_id"], phase_bindings["freeze"]["sha256"],
        phase_bindings["publication"]["sha256"], index, slot // 2, slot % 2)


def trial_audit(manifests, audits, frozen, index, publication_ns, previous_upper=0, phase_bindings=None):
    windows, upper, identities = capacity_windows(audits, frozen, index, publication_ns, previous_upper)
    bindings = []
    require(phase_bindings is not None, "Capacity phase bindings missing")
    for slot, (manifest, audit) in enumerate(zip(manifests, audits)):
        raw = read(verify(manifest)); launch = read(verify(raw["launch"]))
        if frozen["spec"]["protocol"] == "external_read":
            declared = frozen["profiles"][index]["actual_schedule"]
            for phase in ("warmup", "measurement"):
                require(ref(Path(raw["window_directory"]) / (phase + "-arrivals.tsv"))["sha256"] == declared[phase]["sha256"],
                        "Executed Java schedule differs from its predeclared actual bytes")
        require(launch["phase"] == "CAPACITY" and launch["variant"] == "A"
                and launch["window_id"] == audit["window"]["window_id"] == execution_window_id(frozen, index, slot, phase_bindings),
                "Trial did not execute the prepublished A-only capacity freeze")
        plan_ref = ref(Path(raw["window_directory"]).parent / "capacity-launch.json"); plan = read(plan_ref["path"])
        require(plan["phase_bindings"] == phase_bindings
                and publication_ns <= plan["created_monotonic_ns"] <= launch["created_monotonic_ns"]
                and all(launch[key] == value for key, value in plan["context"].items()), "Actual protocol launch differs from its capacity plan")
        bindings.extend([manifest, plan_ref, audit["auditor"], *audit["raw_artifacts"], *audit["dependency_bindings"]])
    bindings += list(phase_bindings.values())
    unique = {str(verify(item)): item for item in bindings}
    return {"valid": True, "errors": [], "windows": windows, "raw_artifact_bindings": list(unique.values()),
            "manifests": manifests, "last_window_upper_monotonic_ns": upper}, identities


def run(spec, output):
    """Concrete direct execution. Caller already owns and starts original A and its fixture."""
    with legacy.interrupt_handlers() as checkpoint:
        return _run(spec, output, checkpoint)


def _run(spec, output, checkpoint):
    checkpoint()
    frozen = prepare_plan(spec); module = protocol(spec["protocol"])
    output = stream_load_fixture.owned(output); output.mkdir(parents=True, exist_ok=False)
    stop_file = output / "stop"; trials = []; errors = []; previous_upper = 0; seen_raw = set()
    frozen.update(boot_id=stats.boot_id(), created_monotonic_ns=time.monotonic_ns(),
                  absolute_deadline_monotonic_ns=time.monotonic_ns() + int(spec["deadline_seconds"] * 10**9))
    for index, value in enumerate(frozen["profiles"]):
        value["reference"] = publish(output / ("profile-%d.json" % index), value["profile"])
        frozen["bindings"]["executed_profile_%d" % index] = value["reference"]
    frozen_ref = publish(output / "frozen-inputs.json", frozen)
    publication = {"freeze": frozen_ref, "boot_id": frozen["boot_id"], "published_monotonic_ns": time.monotonic_ns()}
    publication_ref = publish(output / "frozen-inputs.published.json", publication)
    phase_bindings = {"freeze": frozen_ref, "publication": publication_ref}
    base = read(verify(spec["context_template"]))
    try:
        for rate_index, selected in enumerate(frozen["profiles"]):
            directory = output / ("rate-%d" % rate_index); directory.mkdir()
            manifests, audits = [], []; trial_errors = []
            try:
                for slot in range(2 * spec["pairs"]):
                    checkpoint()
                    require(not stop_file.exists() and time.monotonic_ns() < frozen["absolute_deadline_monotonic_ns"], "Own-client stop/deadline before next window")
                    verify(frozen_ref); verify(publication_ref); check_bindings(frozen)
                    case = directory / ("window-%03d" % slot); case.mkdir()
                    observer = ObserverWindow(frozen, module, case, stop_file, checkpoint); raw = None
                    try:
                        observer.start()
                        checkpoint()
                        context = {**base, "schema_version": 1, "phase": "CAPACITY", "variant": "A", "workload": selected["reference"],
                            "window_id": execution_window_id(frozen, rate_index, slot, phase_bindings),
                            "pair_id": slot // 2, "context_deadline_monotonic_ns": time.monotonic_ns() + 300 * 10**9}
                        publish(case / "capacity-launch.json", {"phase_bindings": phase_bindings, "context": context,
                                                                 "created_monotonic_ns": time.monotonic_ns()})
                        raw = module.run_window(selected["reference"], context, spec["runtime"], case / "window", stop_file)
                    finally:
                        observer.close(raw is not None and raw.get("status") == "RAW_WINDOW_COMPLETE")
                    checkpoint()
                    require(raw is not None and raw["status"] == "RAW_WINDOW_COMPLETE", "Incomplete client is not a capacity upper bound")
                    observer_ref = observer.audit(raw)
                    manifest = {**raw, "observer": observer_ref}
                    manifest_ref = publish(case / "normalization-input.json", manifest)
                    audit = module.normalize(manifest); audit_ref = publish(case / "audit.json", audit)
                    manifests.append(manifest_ref); audits.append(audit)
                    publish(case / "window.json", {**audit["window"], "evidence": audit_ref})
                    # Preserve each terminal result before beginning another independent window.
                    publish(output / ("checkpoint-r%d-w%d.json" % (rate_index, slot)),
                            {"phase": "A_ONLY", "rate": selected["profile"]["rate"], "completed_windows": slot + 1,
                             "last_manifest": manifest_ref, "formal_performance_pass": False})
                audit, raw_ids = trial_audit(manifests, audits, frozen, rate_index, publication["published_monotonic_ns"], previous_upper, phase_bindings)
                require(not seen_raw & raw_ids, "Another capacity rate reused raw window evidence")
                seen_raw.update(raw_ids); previous_upper = audit["last_window_upper_monotonic_ns"]
                audit["raw_artifact_bindings"] += [ref(directory / ("window-%03d/audit.json" % slot)) for slot in range(len(audits))]
                assessment = assess(audit["windows"], frozen)
            except BaseException as error:
                trial_errors.append({"class": type(error).__name__, "reason": str(error)})
                audit = {"valid": False, "errors": trial_errors, "manifests": manifests, "windows": [], "raw_artifact_bindings": []}
                assessment = "invalid_trial"
            audit_path = directory / "artifact-audit.json"; publish(audit_path, audit)
            trial = {"rate": selected["profile"]["rate"], "exit_code": 0 if not trial_errors else 2,
                     "watchdog_terminated": False, "frozen_input_errors": [], "assessment": assessment,
                     "artifact_audit": str(audit_path), "errors": trial_errors}
            trials.append(trial)
            if trial_errors: break
        verify(frozen_ref); verify(publication_ref); check_bindings(frozen)
    except BaseException as error:
        errors.append({"class": type(error).__name__, "reason": str(error)})
    shape = spec["pairs"] >= 5
    bracket = capacity_bracket(trials, spec["mode"], shape, spec["rates"])
    if errors:
        bracket["capacity_bracket_established"] = False; bracket["candidate_rates_30_60_85_percent"] = None
    status = ("CAPACITY_CONFIRMED" if bracket["capacity_bracket_established"] else "PILOT_COMPLETE_NOT_QUALIFIED"
              if spec["mode"] == "pilot" and bracket["all_trials_valid"] and not errors else "INCONCLUSIVE")
    report = {"schema_version": 1, "status": status,
              "frozen_inputs": frozen, "freeze": frozen_ref, "publication": publication_ref,
              "trials": trials, "bracket": bracket, "errors": errors, "formal_performance_pass": False,
              "scope": "Original A complete-query SLO capacity only; separate A/A precision and published A/B comparison remain required."}
    publish(output / "report.json", report)
    return report


def verify_report(path):
    """Read-only original protocol normalization plus capacity/observer audit; no live probes."""
    report = read(path); frozen = report["frozen_inputs"]
    require(read(verify(report["freeze"])) == frozen, "Capacity frozen file differs from report")
    publication = read(verify(report["publication"]))
    require(publication["freeze"] == report["freeze"] and publication["boot_id"] == frozen["boot_id"]
            and publication["published_monotonic_ns"] >= frozen["created_monotonic_ns"], "Capacity publication invalid")
    require(frozen["phase"] == "A_ONLY" and frozen["boot_id"] == stats.boot_id(), "Capacity phase/clock identity differs")
    rebuilt_plan = prepare_plan(frozen["spec"])
    declared_plan = {key: copy.deepcopy(value) for key, value in frozen.items()
                     if key not in ("boot_id", "created_monotonic_ns", "absolute_deadline_monotonic_ns")}
    for value in declared_plan["profiles"]: value.pop("reference", None)
    declared_plan["bindings"] = {key: value for key, value in declared_plan["bindings"].items() if not key.startswith("executed_profile_")}
    require(declared_plan == rebuilt_plan, "Capacity derived policy differs from the predeclared spec")
    check_bindings(frozen); module = protocol(frozen["spec"]["protocol"])
    previous_upper = 0; raw_ids = set(); rebuilt = []
    for index, trial in enumerate(report["trials"]):
        require(index < len(frozen["rates"]) and trial["rate"] == frozen["rates"][index], "Capacity rate order changed")
        saved = read(trial["artifact_audit"])
        require(saved["valid"] is True and not saved["errors"] and trial["exit_code"] == 0
                and not trial["watchdog_terminated"] and not trial["frozen_input_errors"], "Invalid trial cannot be upgraded")
        audits = []
        for manifest_ref in saved["manifests"]:
            manifest = read(verify(manifest_ref)); case = Path(manifest["window_directory"]).parent
            require(read(verify(manifest["observer"])) == audit_observation(manifest, case, frozen, module), "Observer audit differs from original raw")
            audit = module.normalize(manifest)
            require(audit == read(case / "audit.json"), "Protocol audit differs from original raw")
            audits.append(audit)
        derived, identities = trial_audit(saved["manifests"], audits, frozen, index, publication["published_monotonic_ns"], previous_upper,
                                          {"freeze": report["freeze"], "publication": report["publication"]})
        require(not raw_ids & identities and saved["windows"] == derived["windows"]
                and saved["last_window_upper_monotonic_ns"] == derived["last_window_upper_monotonic_ns"], "Capacity windows reused/changed")
        raw_ids.update(identities); previous_upper = derived["last_window_upper_monotonic_ns"]
        for item in saved["raw_artifact_bindings"]: verify(item)
        require({(item["path"], item["sha256"]) for item in derived["raw_artifact_bindings"]}
                <= {(item["path"], item["sha256"]) for item in saved["raw_artifact_bindings"]}, "Capacity discarded raw bindings")
        outcome = assess(derived["windows"], frozen); require(outcome == trial["assessment"], "Capacity SLO outcome changed")
        rebuilt.append({**trial, "assessment": outcome})
    bracket = capacity_bracket(rebuilt, frozen["mode"], frozen["template"]["pairs"] >= 5, frozen["rates"])
    require(not report["errors"] and bracket == report["bracket"], "Capacity bracket differs from original complete windows")
    status = ("CAPACITY_CONFIRMED" if bracket["capacity_bracket_established"] else "PILOT_COMPLETE_NOT_QUALIFIED"
              if frozen["mode"] == "pilot" and bracket["all_trials_valid"] else "INCONCLUSIVE")
    return {"status": status,
            "report": ref(path), "bracket": bracket, "formal_performance_pass": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("schedule", "plan", "run", "verify"))
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "schedule": result = generate_external_schedules(read(args.input), args.output)
    elif args.mode == "run": result = run(read(args.input), args.output)
    else:
        result = prepare_plan(read(args.input)) if args.mode == "plan" else verify_report(args.input)
        publish(args.output, result)
    print(json.dumps({"status": result.get("status", "PLANNED_NOT_EXECUTED"), "output": str(args.output), "formal_performance_pass": False}))
    pilot_completed = args.mode == "run" and result["frozen_inputs"]["mode"] == "pilot" and not result["errors"] and result["bracket"]["all_trials_valid"]
    return 0 if args.mode in ("schedule", "plan") or result["status"] == "CAPACITY_CONFIRMED" or pilot_completed else 2


if __name__ == "__main__":
    raise SystemExit(main())
