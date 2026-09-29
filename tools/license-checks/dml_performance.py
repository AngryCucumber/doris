#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""One independently auditable G4 DML window; import/plan/audit never access a database."""

import argparse
import base64
import csv
from decimal import Decimal
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
from types import SimpleNamespace
import uuid

import dml_transaction_fixture as semantics
import p4_jdbc_evidence as clocks
import p4_statistics as statistics
import ui_background_fixture as lifecycle

SOURCE = Path(__file__).resolve()
JAVA_SOURCE = SOURCE.with_name("LicenseDmlPerformance.java")
PROFILE = "g4_dml_v1"
require = statistics.require
reference = statistics.reference
verify_reference = statistics.verify_reference
read_json = statistics.read_json
SESSION = {"auto_commit": True, "enable_sql_cache": "false", "enable_query_cache": "false", "group_commit": "off_mode",
           "enable_insert_strict": "true", "enable_unique_key_partial_update": "false"}
BOUNDS = {"warmup_seconds": (1, 1800), "duration_seconds": (1, 7200), "timeout_seconds": (1, 30),
          "drain_seconds": (1, 120), "prepare_timeout_seconds": (120, 3600), "verify_timeout_seconds": (120, 3600),
          "cleanup_timeout_seconds": (30, 120), "coordination_timeout_seconds": (10, 1800),
          "max_requests": (2, 500000), "max_rows": (200, 50000000), "min_disk_free_bytes": (1024**3, 1024**4)}


def validate_config(value):
    require(isinstance(value, dict) and set(value) == set(BOUNDS) | {"schema_version", "profile", "operation", "concurrency",
        "qualification", "license_state", "rate_per_second", "seed", "rows_per_operation", "read_account", "write_account",
        "storage_paths"}, "DML input has missing or extra fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["profile"] == PROFILE
            and value["seed"] == 20260922 and type(value["seed"]) is int and type(value["rows_per_operation"]) is int
            and value["rows_per_operation"] == 100, "DML fixed input changed")
    require(value["operation"] in ("insert_select", "update", "delete") and type(value["concurrency"]) is int
            and value["concurrency"] in (1, 8), "DML operation/concurrency invalid")
    require(value["qualification"] in ("formal", "diagnostic") and value["license_state"] in ("VALID", "EXPIRED"),
            "DML qualification/state invalid")
    for key, (low, high) in BOUNDS.items():
        require(type(value[key]) is int and low <= value[key] <= high, "DML bound invalid: " + key)
    require(value["qualification"] == "diagnostic" or value["warmup_seconds"] >= 180 and value["duration_seconds"] >= 600,
            "DML formal window too short")
    rate = value["rate_per_second"]
    require(type(rate) in (int, float) and math.isfinite(rate) and 0 < rate <= 1000, "DML rate invalid")
    require(value["max_rows"] >= value["max_requests"] * 100
            and value["min_disk_free_bytes"] >= value["max_rows"] * 1024 + 1024**3, "DML data/disk reservation too small")
    require(rate * (value["warmup_seconds"] + value["duration_seconds"]) < value["max_requests"] * .95,
            "DML expected arrivals exceed frozen resource bound")
    require(isinstance(value["storage_paths"], list) and 1 <= len(value["storage_paths"]) <= 8
            and len(set(value["storage_paths"])) == len(value["storage_paths"])
            and all(isinstance(path, str) and Path(path).is_absolute() for path in value["storage_paths"]), "DML storage paths invalid")
    old = {key: bounds[0] for key, bounds in lifecycle.BOUNDS.items()}
    old.update(schema_version=1, seed=20260922, rate_basis="explicit_functional_input_not_capacity_qualification",
               read_account=value["read_account"], write_account=value["write_account"])
    lifecycle.validate_config(old)
    return value


def plan(value):
    validate_config(value)
    warm = lifecycle.current_arrivals(value["rate_per_second"], value["warmup_seconds"])
    measured = lifecycle.current_arrivals(value["rate_per_second"], value["duration_seconds"])
    require(warm and measured and len(warm) + len(measured) <= value["max_requests"], "DML generated arrival bound exceeded")
    result, base = {}, 0
    for name, schedule in (("warmup", warm), ("measurement", measured)):
        text = "sequence\toffset_ns\tfirst_id\trows\n" + "".join(
            f"{index}\t{offset}\t{(base + index) * 100}\t100\n" for index, offset in enumerate(schedule))
        result[name] = {"arrivals": schedule, "first_domain": base, "requests": len(schedule),
                        "schedule_sha256": hashlib.sha256(text.encode()).hexdigest(), "tsv": text}
        base += len(schedule)
    result.update(total_requests=base, target_rows_bound=base * 100, formal_performance_pass=False)
    return result


def business_binding(value):
    validate_config(value)
    fields = {key: value[key] for key in ("profile", "operation", "concurrency", "seed", "rows_per_operation",
        "max_requests", "max_rows", "min_disk_free_bytes", "timeout_seconds", "drain_seconds", "read_account", "write_account")}
    fields.update(connection_mode="reuse", sql_semantics="standalone_autocommit_text_unique_100_row_domains",
                  oracle="id_mod1024_mod100000_MD5_and_update_plus1000000_u_prefix_v1",
                  source_rows=1000000, source_table="license_perf.point_rows")
    return {"sha256": hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "fields": fields}


def freeze(api, path, cluster, resources, driver):
    path = api.owned(path); profile = validate_config(api.read_json(path)); plan(profile)
    java = Path(cluster["java_home"]).resolve(strict=True); package = Path(cluster["package"]).resolve(strict=True)
    driver = Path(driver).resolve(strict=True)
    require(api.ROOT in java.parents and api.ROOT in package.parents and driver.is_file(),
            "DML runtime must belong to checkout and the frozen driver must exist")
    require(driver.name == semantics.DRIVER_NAME and 'JAVA_VERSION="17.0.4"' in (java / "release").read_text(),
            "DML requires actual JDK 17.0.4 and MySQL Connector/J 8.0.33")
    dependencies = [driver]
    for prefix in ("jackson-core", "jackson-databind", "jackson-annotations"):
        found = list((package / "fe/lib").glob(prefix + "-*.jar")); require(len(found) == 1, "Packaged Jackson is ambiguous")
        dependencies.extend(found)
    for item in profile["storage_paths"]:
        actual = api.owned(Path(item)).resolve(strict=True)
        require(actual.is_dir() and str(actual) == item, "DML storage path must be an actual owned directory")
    require(resources["rss_limit_mib"] >= 1024 and resources["cpus"], "DML client resource budget missing")
    return {"input_path": str(path), "input_sha256": api.sha(path), "config": profile, "java_home": str(java),
        "jdk_runtime": {name: api.sha(java / name) for name in ("bin/java", "bin/javac", "lib/modules", "release")},
        "dependencies_sha256": {str(path): api.sha(path) for path in dependencies},
        "source_sha256": {str(path): api.sha(path) for path in (SOURCE, JAVA_SOURCE, Path(semantics.__file__),
            Path(lifecycle.__file__), Path(clocks.__file__), Path(statistics.__file__))},
        "business_workload_sha256": business_binding(profile)["sha256"], "scope": "G4 single DML window, no automatic performance qualification"}


def csv_rows(path):
    with Path(path).open(newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered: return None
    position = (len(ordered) - 1) * fraction; lower = int(position)
    return ordered[lower] + (ordered[min(lower + 1, len(ordered) - 1)] - ordered[lower]) * (position - lower)


def ack_info(encoded):
    require(isinstance(encoded, str) and len(encoded) <= 5500, "DML ACK information exceeds bound")
    try: text = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeError): raise statistics.EvidenceError("DML ACK encoding invalid") from None
    values = {}
    for key in ("txnId", "label", "status"):
        matches = re.findall("'" + key + "':'([^']*)'", text)
        require(len(matches) == 1, "DML ACK field missing/duplicated")
        values[key] = matches[0]
    require(re.fullmatch(r"[1-9][0-9]{0,18}", values["txnId"]) and re.fullmatch(r"[A-Za-z0-9_]{1,128}", values["label"])
            and values["status"] in ("VISIBLE", "COMMITTED"), "DML ACK transaction is not committed")
    return values


def audit_requests(directory, profile, summary):
    """Independently rederive both schedules, receipt completeness, time and transaction uniqueness."""
    planned = plan(profile); results, all_outcomes, transactions, labels = {}, [], set(), set()
    fields = {"sequence", "domain", "scheduled_ns", "started_ns", "finished_ns", "e2e_ns", "outcome", "affected_rows",
              "sql_state", "error_code", "ok_info_b64"}
    for phase in ("warmup", "measurement"):
        schedule = planned[phase]; arrivals = csv_rows(directory / (phase + "-arrivals.tsv"))
        require(len(arrivals) == schedule["requests"], "DML arrival count changed")
        for index, (row, expected) in enumerate(zip(arrivals, schedule["arrivals"])):
            require(set(row) == {"sequence", "offset_ns", "first_id", "rows"} and int(row["sequence"]) == index
                    and abs(int(row["offset_ns"]) - expected) <= 1 and int(row["rows"]) == 100
                    and int(row["first_id"]) == (schedule["first_domain"] + index) * 100, "DML schedule/domain changed")
        actual_hash = statistics.digest(directory / (phase + "-arrivals.tsv"))
        require(actual_hash == summary[phase + "_schedule_sha256"], "DML arrival digest changed")
        start, end = (read_json(directory / (phase + "-" + name + ".json")) for name in ("start", "end"))
        epoch = start["epoch_ns"]
        require(type(epoch) is int and epoch > 0 and end["epoch_ns"] == epoch, "DML epoch invalid")
        seen = bytearray(schedule["requests"]); outcomes = [None] * len(seen); latencies, services, queues = [], [], []
        last, failures, timeouts = epoch, 0, 0
        for worker in range(profile["concurrency"]):
            previous_end = 0
            for row in csv_rows(directory / f"{phase}-{worker}.tsv"):
                require(set(row) == fields, "DML receipt columns changed")
                values = {}
                for key in ("sequence", "domain", "scheduled_ns", "started_ns", "finished_ns", "e2e_ns", "affected_rows", "error_code"):
                    require(re.fullmatch(r"-?[0-9]{1,20}", row[key]), "DML receipt integer invalid"); values[key] = int(row[key])
                index = values["sequence"]
                require(0 <= index < len(seen) and not seen[index] and index % profile["concurrency"] == worker
                        and values["domain"] == schedule["first_domain"] + index, "DML duplicate or overlapping domain")
                require(values["scheduled_ns"] == epoch + int(arrivals[index]["offset_ns"])
                        and values["finished_ns"] >= values["started_ns"] >= previous_end
                        and values["e2e_ns"] == values["finished_ns"] - values["scheduled_ns"], "DML request timing invalid")
                previous_end = values["finished_ns"]; last = max(last, previous_end); seen[index] = 1
                outcome = row["outcome"]; outcomes[index] = outcome
                require(outcome in ("ACK", "ACK_INVALID", "UNKNOWN", "NOT_SENT", "ERROR"), "Unknown DML outcome")
                require(re.fullmatch(r"NONE|[A-Za-z0-9]{1,5}", row["sql_state"]), "Unsafe DML SQL state")
                if outcome == "ACK":
                    require(values["affected_rows"] == 100 and values["started_ns"] >= values["scheduled_ns"]
                            and values["error_code"] == 0 and row["sql_state"] == "NONE", "DML ACK row count/error changed")
                    info = ack_info(row["ok_info_b64"])
                    require(info["txnId"] not in transactions and info["label"] not in labels, "DML reused transaction/label")
                    transactions.add(info["txnId"]); labels.add(info["label"])
                    latencies.append(values["e2e_ns"] / 1e6); services.append((values["finished_ns"] - values["started_ns"]) / 1e6)
                    queues.append((values["started_ns"] - values["scheduled_ns"]) / 1e6)
                else:
                    failures += 1; timeouts += row["sql_state"] in ("HYT00", "HYT01") or values["error_code"] == 1205
        require(all(seen), "DML missing raw completion")
        duration = profile["warmup_seconds"] if phase == "warmup" else profile["duration_seconds"]
        cutoff = epoch + duration * 10**9
        require(end["last_request_end_ns"] == last and end["request_interval_end_ns"] == max(last, cutoff)
                and end["java_monotonic_ns"] >= max(last, cutoff), "DML actual complete interval differs")
        require(end["scheduled_requests"] == len(seen) and end["successful_requests"] == len(latencies), "DML summary counts differ")
        seconds = (max(last, cutoff) - epoch) / 1e9; cpu = {}
        for role in ("fe", "be"):
            first, final = start["cpu"][role], end["cpu"][role]
            require(first["pid"] == final["pid"] and first["start_ticks"] == final["start_ticks"], "DML CPU lifetime changed")
            require(first["sample_started_java_ns"] <= first["sample_ended_java_ns"] <= epoch
                    and final["sample_ended_java_ns"] >= final["sample_started_java_ns"] >= max(last, cutoff), "DML CPU enclosure invalid")
            delta = final["cpu_seconds"] - first["cpu_seconds"]
            require(type(delta) in (int, float) and math.isfinite(delta) and delta >= 0, "DML CPU counter invalid")
            cpu[role + "_cpu_seconds_per_success"] = delta / len(latencies) if latencies else None
        results[phase] = {"scheduled_requests": len(seen), "observed_requests": len(seen), "successful_requests": len(latencies),
            "missing_requests": 0, "error_count": failures, "timeout_count": timeouts, "outcomes": outcomes,
            "arrival_sha256": actual_hash, "effective_duration_seconds": seconds, "drain_seconds": seconds - duration,
            "success_qps": len(latencies) / seconds, "p95_ms": percentile(latencies, .95), "p99_ms": percentile(latencies, .99),
            "service_p95_ms": percentile(services, .95), "service_p99_ms": percentile(services, .99),
            "queue_p95_ms": percentile(queues, .95), "queue_p99_ms": percentile(queues, .99), **cpu, "cpu_boundary_verified": True,
            "errors": [] if failures == 0 else ["DML_REQUEST_FAILURES"], "original_outcomes_preserved": True}
        all_outcomes.extend(outcomes)
    return {"phases": results, "outcomes": all_outcomes, "planned": planned, "formal_performance_pass": False}


def expected_target(kind, resolutions):
    digest = hashlib.sha256(); count = 0
    for domain, item in enumerate(resolutions):
        require(item["domain"] == domain and item["rows"] in (0, 100) and type(item["rows"]) is int,
                "DML partial/missing domain")
        committed = item["observed_committed"]
        require(type(committed) is bool and item["unknown_absence_is_rollback_proof"] is False, "DML uncertainty policy changed")
        expected_count = (100 if committed else 0) if kind == "insert_select" else (0 if committed else 100) if kind == "delete" else 100
        version = 1 if kind == "update" and committed else 0
        require(item["rows"] == expected_count and item["version"] == (version if expected_count else -1), "DML observed final version invalid")
        outcome = item["request_outcome"]
        require(outcome in ("ACK", "ACK_INVALID", "UNKNOWN", "NOT_SENT", "ERROR"), "Unknown DML original outcome")
        require(outcome != "ACK" or committed, "DML ACK final model not committed")
        require(outcome not in ("NOT_SENT", "ERROR") or not committed, "DML unsent domain changed")
        for identifier, group, value, payload in semantics.rows(domain * 100, domain * 100 + expected_count, bool(version)):
            digest.update(f"{identifier}\t{group}\t{value}\t{payload}\n".encode("ascii")); count += 1
    return {"rows": count, "canonical_sha256": digest.hexdigest(), "full_values_verified": True, "exact_id_domains_verified": True}


def audit_models(directory, profile, summary, requests):
    total = len(requests["outcomes"]); before = []
    for domain in range(total):
        before.append({"domain": domain, "rows": 0 if profile["operation"] == "insert_select" else 100,
            "version": -1 if profile["operation"] == "insert_select" else 0, "observed_committed": False,
            "request_outcome": "NOT_SENT", "unknown_absence_is_rollback_proof": False})
    require(summary["target_before"] == expected_target(profile["operation"], before), "DML prebuilt complete input differs")
    resolutions = read_json(directory / "batch-resolution.json")
    require(isinstance(resolutions, list) and len(resolutions) == total, "DML resolution count changed")
    require([item["request_outcome"] for item in resolutions] == requests["outcomes"], "Post-window oracle rewrote original ACK/UNKNOWN")
    expected = expected_target(profile["operation"], resolutions)
    require(summary["target_after"] == expected, "DML full target digest differs")
    source = lifecycle.expected_source_digest()
    for phase in ("source_before", "source_after"):
        actual = summary[phase]
        require(actual["rows"] == 1000000 and actual["full_values_verified"] is True
                and actual["canonical_sha256"] == source, "DML source differs from independent million-row model")
    require(summary["source_before"] == summary["source_after"], "DML source/schema changed")
    return {"verified": True, "source_rows": 1000000, "source_canonical_sha256": source, "target": expected,
            "unknown_is_not_ack": True, "online_visibility_latency_measured": False}


def audit_resource_admission(directory, profile, requests):
    quota = read_json(directory / "quota-before.json")
    rows = [row for row in quota["raw_rows"] if row[0] == "Left"]
    require(len(rows) == 1 and len(rows[0]) == 4, "DML database quota receipt incomplete")
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]{1,3})?) (B|KB|MB|GB|TB|PB)", rows[0][1])
    require(match is not None, "DML database quota formatting invalid")
    lower = int(max(Decimal(0), Decimal(match[1]) - Decimal("0.001"))
                * 1024 ** ("B", "KB", "MB", "GB", "TB", "PB").index(match[2]))
    require(lower == quota["remaining_bytes_lower_bound"] >= requests["planned"]["target_rows_bound"] * 1024
            and int(rows[0][2]) == quota["remaining_replica_count"] >= 16, "DML database quota reserve was insufficient")
    samples = [json.loads(line) for line in (directory / "storage.jsonl").read_text().splitlines()]
    require(samples and len(samples) <= profile["max_requests"] + 20000, "DML disk observation missing/unbounded")
    for sample in samples:
        storage = sample["storage"]
        require(len(storage) == len(profile["storage_paths"])
                and [item["path"] for item in storage] == profile["storage_paths"]
                and all(type(item["usable_bytes"]) is int and item["usable_bytes"] >= profile["min_disk_free_bytes"]
                        for item in storage), "DML physical disk reserve failed")
    for phase in ("warmup", "measurement"):
        start, end = (read_json(directory / (phase + "-" + item + ".json")) for item in ("start", "end"))
        times = [sample["java_monotonic_ns"] for sample in samples if sample["phase"] == phase]
        require(times and times == sorted(times) and times[0] <= start["epoch_ns"] + 1500000000
                and times[-1] >= end["request_interval_end_ns"] - 1500000000
                and all(second - first <= 2500000000 for first, second in zip(times, times[1:])),
                "DML physical disk sampling has missing coverage")
    return {"quota_lower_bound_bytes": lower, "disk_reserve_bytes": profile["min_disk_free_bytes"],
            "disk_samples": len(samples), "verified": True}


def utc_anchor():
    before = time.monotonic_ns(); instant = time.time_ns(); after = time.monotonic_ns()
    return {"before_monotonic_ns": before, "utc_ns": instant, "after_monotonic_ns": after}


def validate_launch(launch, profile):
    require(launch["schema_version"] == 1 and launch["phase"] in ("CAPACITY", "AA", "AB", "DIAGNOSTIC")
            and launch["variant"] in ("A", "B"), "DML launch phase/variant invalid")
    require(launch["phase"] not in ("CAPACITY", "AA") or launch["variant"] == "A", "A-only launch contains B")
    require(re.fullmatch(r"[a-f0-9]{32}", launch["launch_token"]) and launch["boot_id"] == statistics.boot_id(),
            "DML launch token/boot invalid")
    require(type(launch["created_monotonic_ns"]) is int and launch["created_monotonic_ns"] >= 0,
            "DML launch clock missing")
    require(isinstance(launch["window_id"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", launch["window_id"])
            and type(launch["pair_id"]) is int and launch["pair_id"] >= 0, "DML window identity invalid")
    require(type(launch["max_clock_uncertainty_ns"]) is int and 0 < launch["max_clock_uncertainty_ns"] <= 10**9,
            "DML clock uncertainty bound missing")
    clocks.utc_anchor(launch["utc_anchor"]); statistics.validate_identity(launch["identity"])
    require(read_json(verify_reference(launch["workload"])) == profile, "DML launch workload changed")
    bindings = launch["bindings"]
    require(set(bindings) == {"runner", "java_helper", "process_lifecycle", "clock_adapter", "statistics", "jdbc_driver",
        "fe_artifact", "be_artifact", "environment", "configuration", "fixture", "client"}, "DML execution bindings incomplete")
    for item in bindings.values(): verify_reference(item)
    for key, path in (("runner", SOURCE), ("java_helper", JAVA_SOURCE), ("process_lifecycle", lifecycle.__file__),
                      ("clock_adapter", clocks.__file__), ("statistics", statistics.__file__)):
        require(bindings[key]["sha256"] == statistics.digest(path), "DML executed tool differs: " + key)
    require(Path(bindings["jdbc_driver"]["path"]).name == semantics.DRIVER_NAME, "DML JDBC driver changed")
    for key, field in (("fe_artifact", "fe_sha256"), ("be_artifact", "be_sha256"), ("environment", "environment_sha256"),
                       ("configuration", "configuration_sha256"), ("fixture", "fixture_sha256"), ("client", "client_sha256")):
        require(bindings[key]["sha256"] == launch["identity"][field], "DML environment identity does not bind " + key)
    if launch["phase"] == "AB":
        frozen, publication = (read_json(verify_reference(launch[key])) for key in ("freeze", "publication"))
        require(frozen["status"] == "FROZEN_ELIGIBLE" and frozen["identities"][launch["variant"]] == launch["identity"]
                and publication["freeze"] == launch["freeze"] and publication["boot_id"] == launch["boot_id"]
                and publication["published_monotonic_ns"] <= launch["created_monotonic_ns"], "DML A/B was not frozen before launch")
        cell = frozen["cell"]
        scheduled = plan(profile)["measurement"]
        require(cell["group"] == "G4" and cell["workload_sha256"] == business_binding(profile)["sha256"]
                and cell["rate"] == profile["rate_per_second"] and cell["concurrency"] == profile["concurrency"]
                and cell["warmup_seconds"] == profile["warmup_seconds"] and cell["duration_seconds"] == profile["duration_seconds"]
                and cell["connection_mode"] == "reuse" and cell["seed"] == 20260922
                and cell.get("license_state") == profile["license_state"]
                and cell["request_count"] == scheduled["requests"]
                and cell["arrival_schedule_sha256"] == scheduled["schedule_sha256"],
                "DML frozen A/B workload differs")
    else:
        require("freeze" not in launch and "publication" not in launch, "DML A-only/diagnostic launch claims A/B freeze")
    return launch


class DmlPerformance(lifecycle.Background):
    """Thin specialization of the existing owned launch/check/wait/reap lifecycle."""

    def __init__(self, api, plan, guard, target, cell, admin, whole_deadline, cpu_services, launch):
        frozen = plan["dml"]; profile = validate_config(frozen["config"]); validate_launch(launch, profile)
        require(set(cpu_services) == {"fe", "be"} and cpu_services["fe"]["pid"] != cpu_services["be"]["pid"]
                and all(api.same(pin) for pin in cpu_services.values()), "DML CPU service pins invalid")
        super().__init__(api, {**plan, "background": frozen}, guard, target, cell, admin, whole_deadline)
        require(all(any(all(owned.get(key) == pin.get(key) for key in ("pid", "start_ticks", "namespace", "exe", "command_sha256"))
                    for owned in self.config["cluster_pins"]) for pin in cpu_services.values()), "DML CPU pins not cluster members")
        require(launch["bindings"]["jdbc_driver"]["path"] in frozen["dependencies_sha256"]
                and frozen["dependencies_sha256"][launch["bindings"]["jdbc_driver"]["path"]] == launch["bindings"]["jdbc_driver"]["sha256"],
                "DML launched JDBC driver differs from fixed client dependency")
        self.token = launch["launch_token"]; self.launch = launch
        api.save(self.output / "p4-launch.json", launch); self.launch_ref = reference(self.output / "p4-launch.json")
        self.config.update(token=self.token, table="license_perf.dml_perf_" + self.token, launch=self.launch_ref,
                           cpu_services=cpu_services, clock_ticks_per_second=os.sysconf("SC_CLK_TCK"))
        api.save(self.config_path, self.config)

    def start(self):
        lifecycle.verify_frozen(self.api, self.frozen)
        classes = self.output / "classes"; classes.mkdir()
        jars = [Path(path) for path in sorted(self.frozen["dependencies_sha256"])]
        self.classpath = os.pathsep.join(map(str, [classes, *jars])); java = Path(self.frozen["java_home"]) / "bin/java"
        compile_deadline = min(self.whole_deadline, time.monotonic() + 120)
        try:
            self._launch([java.with_name("javac"), "-J-Xmx256m", "--release", "17", "-encoding", "UTF-8", "-cp", self.classpath,
                          "-d", classes, JAVA_SOURCE], "compile", compile_deadline)
            self._await(lambda: self.process.poll() is not None, compile_deadline)
            require(self.process.returncode == 0, "DML compilation failed")
        finally:
            lifecycle.reap_owned(self.api, self.process, self.pin, compile_deadline, self._process_event)
        lifecycle.verify_frozen(self.api, self.frozen)
        compiled = {str(path): self.api.sha(path) for path in classes.rglob("*.class")}
        require(str(classes / "LicenseDmlPerformance.class") in compiled, "DML compiled helper missing")
        self.api.save(self.output / "helper-identity.json", {"classes": compiled, "frozen": self.frozen})
        prepare_deadline = min(self.whole_deadline, time.monotonic() + self.profile["prepare_timeout_seconds"])
        self._launch([java, "-Xmx512m", "-cp", self.classpath, "LicenseDmlPerformance", self.config_path], "dml", prepare_deadline)
        self.work_pin = dict(self.pin)
        self._await(lambda: (self.output / "ready.json").exists(), prepare_deadline)
        ready = read_json(self.output / "ready.json"); self._identity_receipt(ready)
        require(ready["token"] == self.token and ready["connections"] == self.profile["concurrency"]
                and ready["source_rows_verified"] == 1000000, "DML preparation/readiness invalid")
        self.api.save(self.output / "controller-ready.json", {"observed_monotonic_ns": time.monotonic_ns(), "ready": ready})

    def coordinate(self):
        self.check()

    def release_warmup(self):
        self.check(); require((self.output / "ready.json").exists() and not (self.output / "clock-request.json").exists(),
                              "DML warmup is not ready or already released")
        nonce = uuid.uuid4().hex; before = time.monotonic_ns()
        self.api.save(self.output / "clock-request.json", {"token": self.token, "nonce": nonce})
        self._await(lambda: (self.output / "p4-helper-clock.json").exists(),
                    min(self.whole_deadline, time.monotonic() + self.profile["coordination_timeout_seconds"]))
        helper = read_json(self.output / "p4-helper-clock.json"); after = time.monotonic_ns(); self._identity_receipt(helper)
        bridge = {"schema_version": 1, "launch_token": self.token, "launch_sha256": self.launch_ref["sha256"],
                  "boot_id": self.launch["boot_id"], "nonce": nonce, "controller_before_ns": before,
                  "controller_after_ns": after, "helper_clock": reference(self.output / "p4-helper-clock.json")}
        clocks.clock_bridge(self.launch, self.launch_ref, bridge, helper)
        self.api.save(self.output / "p4-clock-bridge.json", bridge)
        self.api.save(self.output / "clock-ack.json", {"token": self.token, "nonce": nonce})

    def release_measurement(self):
        self.check(); require((self.output / "measurement-ready.json").exists()
                              and not (self.output / "measurement-release.json").exists(), "DML measurement not ready/already released")
        self._identity_receipt(read_json(self.output / "measurement-ready.json"))
        self.api.save(self.output / "measurement-release.json", {"token": self.token, "controller_monotonic_ns": time.monotonic_ns()})

    def allow_verification(self):
        self.check(); receipt = read_json(self.output / "verification-ready.json"); self._identity_receipt(receipt)
        require(receipt["workers_closed"] is True and not (self.output / "verify-release.json").exists(), "DML verification not quiescent/already released")
        self.api.save(self.output / "verify-release.json", {"token": self.token, "controller_monotonic_ns": time.monotonic_ns()})

    def finish(self):
        if self.finished: return read_json(self.output / "controller.json")
        self.finished = True; failures = []
        if not (self.output / "verification-ready.json").exists(): self.api.save(self.output / "stop.json", {"token": self.token})
        deadline = min(self.whole_deadline, time.monotonic() + self.profile["verify_timeout_seconds"] + self.profile["cleanup_timeout_seconds"])
        clean = False
        try:
            self._await(lambda: self.process.poll() is not None, deadline)
        except BaseException as error: failures.append(lifecycle.process_error(error, "dml_wait"))
        finally:
            try: clean = lifecycle.reap_owned(self.api, self.process, self.pin, deadline, self._process_event)
            except BaseException as error: failures.append(lifecycle.process_error(error, "dml_reap"))
        exit_code = self.process.returncode if self.process else None
        completion = {"schema_version": 1, "launch_token": self.token, "launch_sha256": self.launch_ref["sha256"],
            "boot_id": self.launch["boot_id"], "helper_pid": self.work_pin["pid"] if self.work_pin else None,
            "helper_start_ticks": self.work_pin["start_ticks"] if self.work_pin else None, "exit_code": exit_code,
            "completed_monotonic_ns": time.monotonic_ns(), "utc_anchor": utc_anchor(),
            "remaining_live_pids": [] if clean else [self.work_pin["pid"]] if self.work_pin else ["UNPROVEN_EXIT"]}
        if (self.output / "p4-clock-bridge.json").exists(): completion["bridge"] = reference(self.output / "p4-clock-bridge.json")
        self.api.save(self.output / "p4-completion.json", completion)
        summary = read_json(self.output / "summary.json") if (self.output / "summary.json").exists() else {}
        if summary:
            try: self._identity_receipt(summary)
            except BaseException as error: failures.append(lifecycle.process_error(error, "summary_identity")); summary = {}
        cleanup = summary.get("cleanup_confirmed") is True
        if not cleanup and clean and self.classpath:
            self.recovery_deadline = time.monotonic() + self.profile["cleanup_timeout_seconds"]
            try:
                java = Path(self.frozen["java_home"]) / "bin/java"
                self._launch([java, "-Xmx512m", "-cp", self.classpath, "LicenseDmlPerformance", self.config_path, "--cleanup-only"],
                             "recovery", self.recovery_deadline)
                self._await(lambda: self.process.poll() is not None, self.recovery_deadline)
                receipt = read_json(self.output / "cleanup.json")
                require(receipt["token"] == self.token and receipt["pid"] == self.pin["pid"]
                        and receipt["start_ticks"] == self.pin["start_ticks"] and receipt["namespace"] == self.pin["namespace"], "DML recovery identity changed")
                cleanup = receipt["cleanup_confirmed"] is True
            except BaseException as error: failures.append(lifecycle.process_error(error, "dml_owned_recovery"))
            finally:
                try: lifecycle.reap_owned(self.api, self.process, self.pin, self.recovery_deadline, self._process_event)
                except BaseException as error: failures.append(lifecycle.process_error(error, "dml_recovery_reap"))
        try: self.guard.check(); lifecycle.verify_frozen(self.api, self.frozen)
        except BaseException as error: failures.append(lifecycle.process_error(error, "final_inputs"))
        failures.extend(getattr(self, "process_evidence_errors", []))
        report = {"status": "RAW_WINDOW_COMPLETE" if clean and cleanup and not failures and exit_code == 0
                  and summary.get("status") == "RAW_WINDOW_COMPLETE" else "INVALID_WINDOW",
                  "summary": summary, "cleanup_confirmed": cleanup, "owned_child_exited": clean, "errors": failures,
                  "rss_peak_mib_sampled": self.peak, "resource_samples": self.samples,
                  "formal_performance_pass": False, "full_goal_complete": False}
        self.api.save(self.output / "controller.json", report); return report


def external_audit(binding, launch, launch_ref, lower, upper, kind, profile):
    """Require a separately implemented protocol/resource observer; never invent its observations."""
    result = read_json(verify_reference(binding))
    require(result["status"] == "VERIFIED" and result["kind"] == kind and result["launch_sha256"] == launch_ref["sha256"]
            and result["boot_id"] == launch["boot_id"], "DML external audit identity/status missing")
    require(result["coverage_start_monotonic_ns"] <= lower and result["coverage_end_monotonic_ns"] >= upper,
            "DML external observation does not enclose actual warmup and measurement")
    verify_reference(result["auditor"]); require(result["raw_artifacts"], "DML external observer lacks raw data")
    for item in result["raw_artifacts"]: verify_reference(item)
    if kind == "license_state":
        require(result["observed_state"] == ("ORIGINAL_A_NO_LICENSE" if launch["variant"] == "A" else profile["license_state"]),
                "DML actual license state differs from selected legal flow")
    else:
        require(kind == "resources" and result["resource_failures"] == [] and result["budget_verified"] is True,
                "DML resource failures cannot establish product capacity/performance")
    return result


def normalize(manifest):
    directory = Path(manifest["window_directory"]).resolve()
    def raw_files():
        return [reference(path) for path in sorted(directory.iterdir()) if path.is_file() and path.suffix in (".json", ".jsonl", ".tsv")]
    before = raw_files(); config = read_json(directory / "config.json")
    helper_identity = read_json(directory / "helper-identity.json"); frozen = helper_identity["frozen"]
    require(set(frozen["jdk_runtime"]) == {"bin/java", "bin/javac", "lib/modules", "release"}
            and str(JAVA_SOURCE) in frozen["source_sha256"] and str(SOURCE) in frozen["source_sha256"]
            and str(directory / "classes/LicenseDmlPerformance.class") in helper_identity["classes"],
            "DML actual compiler/runtime/source identity missing")
    lifecycle.verify_frozen(SimpleNamespace(sha=statistics.digest), frozen)
    for path, digest in helper_identity["classes"].items(): require(statistics.digest(path) == digest, "DML compiled helper changed")
    profile = validate_config(frozen["config"])
    require(all(config.get(key) == value for key, value in profile.items()), "DML runtime/frozen configuration differs")
    require(statistics.digest(frozen["input_path"]) == frozen["input_sha256"] and read_json(frozen["input_path"]) == profile,
            "DML frozen profile changed")
    launch_ref = manifest["launch"]; launch = read_json(verify_reference(launch_ref)); validate_launch(launch, profile)
    require(frozen["dependencies_sha256"].get(launch["bindings"]["jdbc_driver"]["path"])
            == launch["bindings"]["jdbc_driver"]["sha256"], "DML executed JDBC dependency differs from launch")
    require(launch_ref == config["launch"] and launch_ref == reference(directory / "p4-launch.json"), "DML helper launched another manifest")
    completion = read_json(verify_reference(manifest["completion"]))
    require(completion["launch_token"] == launch["launch_token"] and completion["launch_sha256"] == launch_ref["sha256"]
            and completion["boot_id"] == launch["boot_id"] and completion["exit_code"] == 0
            and completion["remaining_live_pids"] == [], "DML helper did not complete its owned launch")
    clocks.utc_anchor(completion["utc_anchor"])
    bridge = read_json(verify_reference(completion["bridge"])); helper = read_json(verify_reference(bridge["helper_clock"]))
    require(helper["helper_pid"] == completion["helper_pid"] and helper["helper_start_ticks"] == completion["helper_start_ticks"],
            "DML completed process differs from clock helper")
    original_mapping = clocks.clock_bridge(launch, launch_ref, bridge, helper)
    process = read_json(directory / "dml-process.json")
    require(process["pin"]["pid"] == helper["helper_pid"] and process["pin"]["start_ticks"] == helper["helper_start_ticks"]
            and process["pin"]["namespace"] == config["namespace"], "DML actual process lifetime missing")
    command = [str(Path(frozen["java_home"]) / "bin/java"), "-Xmx512m", "-cp",
               os.pathsep.join([str(directory / "classes"), *sorted(frozen["dependencies_sha256"])]),
               "LicenseDmlPerformance", str(directory / "config.json")]
    command_hash = hashlib.sha256(b"\0".join(os.fsencode(item) for item in command) + b"\0").hexdigest()
    require(process["pin"]["command_sha256"] == process["expected_launch"]["command_sha256"] == command_hash
            and process["pin"]["exe"] == str((Path(frozen["java_home"]) / "bin/java").resolve()), "DML executed command changed")
    waits = [item for item in read_json(directory / "process-lifecycle.json")
             if item.get("helper") == "dml" and item.get("reason") == "OWNED_PARENT_WAIT"]
    require(len(waits) == 1 and waits[0].get("pid") == helper["helper_pid"]
            and waits[0].get("exit_code") == 0 and waits[0].get("parent_wait_complete") is True,
            "DML unique actual parent wait missing or from another helper")
    wait = waits[0]
    require(type(wait.get("controller_monotonic_ns")) is int and type(completion["completed_monotonic_ns"]) is int
            and bridge["controller_after_ns"] <= wait["controller_monotonic_ns"] <= completion["completed_monotonic_ns"],
            "DML actual parent wait time missing or outside controller lifecycle")
    summary = read_json(directory / "summary.json"); control = read_json(directory / "controller.json")
    require(summary["status"] == control["status"] == "RAW_WINDOW_COMPLETE" and not control["errors"]
            and summary["errors"] == 0 and summary["automatic_write_replays"] == 0 and control["owned_child_exited"] is True,
            "DML invalid trial cannot qualify")
    owner, intent = (read_json(directory / name) for name in ("owner.json", "create-intent.json"))
    require(config["table"] == "license_perf.dml_perf_" + launch["launch_token"]
            and owner["token"] == intent["token"] == launch["launch_token"]
            and owner["table"] == intent["table"] == summary["table"] == config["table"]
            and owner["create_acknowledged"] is True and intent["absent_before_create"] is True
            and owner["configuration_sha256"] == statistics.digest(directory / "config.json"),
            "DML target creation ownership is unproven")
    tablets = owner["identity"]["tablet_ids"]
    require(len(tablets) == 16 and tablets == sorted(set(tablets))
            and all(type(item) is int and item > 0 for item in tablets)
            and re.fullmatch(r"[0-9a-f]{64}", owner["identity"]["schema_sha256"]), "DML target schema/tablet identity missing")
    expected_identity = {"token": launch["launch_token"], "pid": helper["helper_pid"],
                         "start_ticks": helper["helper_start_ticks"], "namespace": config["namespace"]}
    for name in ("ready.json", "warmup-start.json", "warmup-end.json", "measurement-ready.json", "measurement-start.json",
                 "measurement-end.json", "verification-ready.json", "verification-start.json", "lifecycle.json", "summary.json"):
        actual = read_json(directory / name)
        require(all(actual.get(key) == value for key, value in expected_identity.items()), "DML raw lifetime/launch identity changed: " + name)
    requests = audit_requests(directory, profile, summary); model = audit_models(directory, profile, summary, requests)
    admission = audit_resource_admission(directory, profile, requests)
    require(all(item["error_count"] == 0 for item in requests["phases"].values()), "DML warmup/measured errors retained")
    for index in range(profile["concurrency"]):
        session = read_json(directory / f"worker-{index}-session.json")
        expected = {**SESSION, "query_timeout": str(profile["timeout_seconds"]), "insert_timeout": str(profile["timeout_seconds"])}
        require(all(session.get(key) == value for key, value in expected.items()) and "8.0.33" in session["driver"]
                and session["jdk"].startswith("17.0.4"), "DML actual session/driver changed")
    ready, start, end, cleanup = (read_json(directory / name) for name in
        ("measurement-ready.json", "measurement-start.json", "measurement-end.json", "lifecycle.json"))
    warm_start, warm_end = ready["warmup_start_ns"], ready["warmup_end_ns"]
    require(warm_start == read_json(directory / "warmup-start.json")["epoch_ns"]
            and warm_end == read_json(directory / "warmup-end.json")["java_monotonic_ns"]
            and helper["jvm_sample_ns"] <= warm_start <= warm_end <= ready["ready_ns"] <= start["epoch_ns"]
            and warm_end - warm_start >= profile["warmup_seconds"] * 10**9, "DML actual warmup not complete")
    verification_ready = read_json(directory / "verification-ready.json")
    verification_start = read_json(directory / "verification-start.json")
    ordered = [end["java_monotonic_ns"], verification_ready["java_monotonic_ns"],
               verification_start["java_monotonic_ns"], cleanup["java_monotonic_ns"], cleanup["cleanup_end_ns"]]
    require(all(type(value) is int for value in ordered) and ordered == sorted(ordered)
            and verification_ready["workers_closed"] is True and cleanup["cleanup_confirmed"] is True
            and cleanup["workers_closed"] is True and summary["cleanup_confirmed"] is True and model["verified"] is True,
            "DML same-JVM measurement/verification/cleanup order or confirmation invalid")
    # This trusted helper publishes cleanup before it exits. Its actual parent wait is an
    # additional causal upper bound, not the unknown exact instant of process exit.
    causal_upper = wait["controller_monotonic_ns"] - cleanup["cleanup_end_ns"]
    low = original_mapping["offset_lower_ns"]; high = min(original_mapping["offset_upper_ns"], causal_upper)
    require(low <= high, "DML waited cleanup contradicts the original clock bridge")
    offset = (low + high) // 2
    mapping = {**original_mapping, "offset_upper_ns": high, "estimated_offset_ns": offset,
               "uncertainty_ns": max(offset - low, high - offset),
               "scope": "Original bounded bridge intersected with same-helper cleanup-before-parent-wait causality"}
    clock_audit = {"original_mapping": original_mapping, "effective_mapping": mapping,
        "original_uncertainty_limit_ns": launch["max_clock_uncertainty_ns"],
        "wait_constraint": {"offset_upper_ns": causal_upper, "parent_wait": wait,
            "process_lifecycle": reference(directory / "process-lifecycle.json"),
            "cleanup": reference(directory / "lifecycle.json"), "completion": manifest["completion"],
            "helper_pid": helper["helper_pid"], "helper_start_ticks": helper["helper_start_ticks"]},
        "same_jvm_end_verification_cleanup_ns": ordered,
        "raw_receipts_modified": False, "cpu_and_request_elapsed_values_modified": False}
    lower, upper = warm_start + mapping["offset_lower_ns"], end["request_interval_end_ns"] + mapping["offset_upper_ns"]
    require(lower >= launch["created_monotonic_ns"], "DML clock cannot prove launch before warmup")
    observed = [external_audit(manifest[key], launch, launch_ref, lower, upper, kind, profile)
                for key, kind in (("resources", "resources"), ("license_state", "license_state"))]
    for role in ("fe", "be"):
        deployed = observed[0]["services"][role]
        require(all(deployed[key] == config["cpu_services"][role][key] for key in ("pid", "start_ticks"))
                and deployed["artifact"] == launch["bindings"][role + "_artifact"],
                "DML resource observer did not bind the actually deployed service artifact")
        verify_reference(deployed["artifact"])
    # Bind physical service identities used by the same-JVM CPU snapshots to the launch.
    for name in ("warmup-start.json", "warmup-end.json", "measurement-start.json", "measurement-end.json"):
        value = read_json(directory / name)
        for role in ("fe", "be"):
            require(all(value["cpu"][role][key] == config["cpu_services"][role][key] for key in ("pid", "start_ticks"))
                    and value["cpu"][role]["start_ticks"] == launch["service_start_ticks"][role], "DML CPU is from another service lifetime")
    derived = requests["phases"]["measurement"]
    window = {"window_id": launch["window_id"], "pair_id": launch["pair_id"], "variant": launch["variant"],
        "boot_id": launch["boot_id"], "identity": launch["identity"], "workload_sha256": business_binding(profile)["sha256"],
        "arrival_schedule_sha256": derived["arrival_sha256"], "rate": profile["rate_per_second"],
        "warmup_seconds": profile["warmup_seconds"], "duration_seconds": profile["duration_seconds"],
        "warmup_start_monotonic_ns": warm_start + offset, "warmup_end_monotonic_ns": warm_end + offset,
        "start_monotonic_ns": start["epoch_ns"] + offset, "end_monotonic_ns": end["request_interval_end_ns"] + offset,
        "monotonic_clock_domain": "bounded_jvm_mapping", "monotonic_mapping": mapping,
        "monotonic_mapping_uncertainty_ns": mapping["uncertainty_ns"], "effective_duration_seconds": derived["effective_duration_seconds"],
        "scheduled_requests": derived["scheduled_requests"], "observed_requests": derived["observed_requests"],
        "successful_requests": derived["successful_requests"], "error_count": 0, "timeout_count": 0, "retry_count": 0,
        "oracle_verified": True, "cleanup_verified": True, "cpu_boundary_verified": True,
        "metrics": {key: derived[key] for key in statistics.METRICS}}
    dependencies = [launch["workload"], *launch["bindings"].values(), *[item["auditor"] for item in observed],
                    {"path": frozen["input_path"], "sha256": frozen["input_sha256"]}]
    for bindings in (helper_identity["classes"], frozen["source_sha256"], frozen["dependencies_sha256"]):
        dependencies.extend({"path": str(Path(path).resolve()), "sha256": digest} for path, digest in bindings.items())
    dependencies.extend({"path": str((Path(frozen["java_home"]) / path).resolve()), "sha256": digest}
                        for path, digest in frozen["jdk_runtime"].items())
    if launch["phase"] == "AB":
        publication = read_json(verify_reference(launch["publication"]))
        require(publication["published_monotonic_ns"] <= lower, "DML warmup predates published freeze")
        window.update(freeze_sha256=launch["freeze"]["sha256"], freeze_publication_sha256=launch["publication"]["sha256"])
        dependencies += [launch["freeze"], launch["publication"]]
    after = raw_files(); require(before == after, "DML raw evidence changed during independent audit")
    raw = {item["path"]: item for item in after}
    for item in (manifest["launch"], manifest["completion"], completion["bridge"], bridge["helper_clock"],
                 manifest["resources"], manifest["license_state"], *[item for audit in observed for item in audit["raw_artifacts"]]):
        verify_reference(item); raw[item["path"]] = item
    dependencies = list({item["path"]: item for item in dependencies}.values())
    for item in dependencies: verify_reference(item)
    status = ("VERIFIED" if profile["qualification"] == "formal" and launch["phase"] != "DIAGNOSTIC"
              else "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED")
    return {"status": status, "window": window, "auditor": reference(SOURCE), "raw_artifacts": list(raw.values()),
        "dependency_bindings": dependencies, "request_audit": requests["phases"], "full_model_audit": model,
        "resource_admission_audit": admission, "clock_causality_audit": clock_audit,
        "formal_shape_met": status == "VERIFIED" and derived["successful_requests"] >= 10000,
        "formal_performance_pass": False, "scope": "One actual G4 DML window; controller must establish capacity/A/A/A/B"}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("mode", choices=("plan", "normalize"))
    parser.add_argument("--input", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(); require(not args.output.exists(), "Never overwrite a DML evidence record")
    if args.mode == "normalize":
        require(Path(read_json(args.input)["window_directory"]).resolve() not in args.output.resolve().parents,
                "DML normalization must not mutate raw evidence")
    try: result = plan(read_json(args.input)) if args.mode == "plan" else normalize(read_json(args.input))
    except (ValueError, KeyError, TypeError, OSError) as error:
        result = {"status": "REJECTED", "error_class": type(error).__name__, "reason": str(error), "formal_performance_pass": False}
    with args.output.open("x") as output: json.dump(result, output, indent=2, allow_nan=False); output.write("\n")
    args.output.chmod(0o600)
    print(json.dumps({"status": result.get("status", "PLANNED_NOT_RUN"), "audit": reference(args.output)}))
    return 2 if result.get("status") == "REJECTED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
