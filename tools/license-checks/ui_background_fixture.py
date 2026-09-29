#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Explicit original-A UI background lifecycle; importing this module performs no work."""

import csv
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

SOURCE = Path(__file__).resolve()
JAVA_SOURCE = SOURCE.with_name("LicenseUiBackground.java")
FROZEN_REFERENCES = (SOURCE.with_name("LicenseJdbcBaseline.java"),
                     SOURCE.with_name("run_performance_baseline.py"),
                     SOURCE.parents[2] / "docs/license-performance-cases-20260922.json")
ACCOUNT_KEYS = {"username", "host", "password_env"}
BOUNDS = {"duration_seconds": (300, 300), "read_rate_per_second": (1, 1000),
          "write_batches_per_second": (1, 20), "write_batch_rows": (1, 1000),
          "read_workers": (1, 32), "write_workers": (1, 8), "timeout_seconds": (1, 30),
          "drain_seconds": (30, 120), "prepare_timeout_seconds": (120, 1800),
          "verify_timeout_seconds": (120, 1800), "visibility_timeout_seconds": (10, 120),
          "visibility_poll_millis": (100, 5000), "cleanup_timeout_seconds": (30, 120),
          "read_slo_millis": (1, 120000), "write_ack_slo_millis": (1, 120000),
          "visibility_slo_millis": (1, 120000)}


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_config(value):
    if isinstance(value, dict) and value.get("profile") == "current_allowed_business_v1":
        return validate_current_config(value)
    require(isinstance(value, dict) and set(value) == set(BOUNDS) | {
        "schema_version", "seed", "read_account", "write_account", "rate_basis"},
        "Background input has missing or extra fields")
    require(value["schema_version"] == 1 and type(value["seed"]) is int
            and 0 <= value["seed"] < 2 ** 63, "Background schema/seed is invalid")
    require(value["rate_basis"] == "explicit_functional_input_not_capacity_qualification",
            "This functional controller does not qualify a sustainable rate")
    for key, (lower, upper) in BOUNDS.items():
        require(type(value[key]) is int and lower <= value[key] <= upper,
                "Background resource/rate/SLO bound is invalid")
    require(value["duration_seconds"] * value["write_batches_per_second"] * value["write_batch_rows"] <= 500000,
            "Expected write rows exceed the bounded functional input")
    accounts = []
    for key in ("read_account", "write_account"):
        account = value[key]
        require(isinstance(account, dict) and set(account) == ACCOUNT_KEYS, "Background account must use references")
        require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", account["username"])
                and re.fullmatch(r"[A-Za-z0-9_.%:-]{1,128}", account["host"]), "Invalid background account identity")
        require(re.fullmatch(r"MASSDB_UI_[A-Z0-9_]+_PASSWORD", account["password_env"]), "Invalid background secret reference")
        accounts.append(account)
    require(accounts[0]["username"] != accounts[1]["username"]
            and accounts[0]["password_env"] != accounts[1]["password_env"], "Read/write identities must be distinct")
    return value


CURRENT_PROFILE = "current_allowed_business_v1"
CURRENT_BOUNDS = {key: bounds for key, bounds in BOUNDS.items()
                  if key not in {"read_rate_per_second", "write_batches_per_second", "visibility_timeout_seconds",
                                 "visibility_poll_millis", "visibility_slo_millis"}}
CURRENT_BOUNDS.update(duration_seconds=(1, 7200), write_batch_rows=(100, 100), read_workers=(8, 8), write_workers=(8, 8))
CURRENT_METADATA_SQL = ("SELECT 1", "SHOW TABLES FROM license_perf", "DESC license_perf.point_rows")


def validate_current_config(value):
    require(set(value) == set(CURRENT_BOUNDS) | {"schema_version", "profile", "group", "qualification", "seed",
            "read_account", "write_account", "rate_basis", "rate_per_second", "metadata_oracles"},
            "Current background input has missing or extra fields")
    require(value["schema_version"] == 1 and value["profile"] == CURRENT_PROFILE and value["seed"] == 20260922,
            "Current background schema/profile/seed changed")
    require(value["group"] in {"G5", "G6", "G7"} and value["qualification"] in {"formal", "diagnostic"},
            "Current background group/qualification invalid")
    require(value["rate_basis"] == "controller_frozen_input_not_capacity_qualification", "Current rate is not a frozen input")
    for key, (low, high) in CURRENT_BOUNDS.items():
        require(type(value[key]) is int and low <= value[key] <= high, "Current background bound invalid: " + key)
    require(value["qualification"] == "diagnostic" or value["duration_seconds"] >= (300 if value["group"] == "G7" else 600),
            "Formal current window is too short")
    rate = value["rate_per_second"]
    require(type(rate) in (int, float) and math.isfinite(rate) and 0 < rate <= 1000, "Current total rate invalid")
    require(rate * value["duration_seconds"] < 950000, "Current schedule can exceed the one-million arrival bound")
    # Reuse the existing account validator without changing its legacy input semantics.
    legacy = {key: bounds[0] for key, bounds in BOUNDS.items()}
    legacy.update(schema_version=1, seed=20260922, rate_basis="explicit_functional_input_not_capacity_qualification",
                  read_account=value["read_account"], write_account=value["write_account"])
    validate_config(legacy)
    oracles = value["metadata_oracles"]
    require(isinstance(oracles, list) and len(oracles) == 3, "Exactly three independent metadata oracles required")
    for oracle, sql in zip(oracles, CURRENT_METADATA_SQL):
        require(isinstance(oracle, dict) and set(oracle) == {"sql", "columns", "rows"} and oracle["sql"] == sql,
                "Current metadata SQL differs from frozen SELECT/SHOW/DESC")
        require(isinstance(oracle["columns"], list) and 1 <= len(oracle["columns"]) <= 64
                and all(isinstance(item, str) and 0 < len(item) <= 128 for item in oracle["columns"]),
                "Missing complete metadata columns")
        require(isinstance(oracle["rows"], list) and 0 < len(oracle["rows"]) <= 10000
                and all(isinstance(row, list) and len(row) == len(oracle["columns"])
                        and all(item is None or isinstance(item, str) and len(item) <= 1024 for item in row)
                        for row in oracle["rows"]), "Missing complete metadata row values")
    require(oracles[0]["columns"] == ["1"] and oracles[0]["rows"] == [["1"]], "SELECT 1 independent oracle differs")
    tables = oracles[1]["rows"]
    require(len(oracles[1]["columns"]) == 1 and ["point_rows"] in tables and ["${OWNED_TABLE}"] in tables
            and len({tuple(row) for row in tables}) == len(tables), "SHOW TABLES must cover source and exact owned target")
    require(len(oracles[2]["rows"]) == 4 and [row[0] for row in oracles[2]["rows"]] == ["id", "grp", "v", "payload"],
            "DESC must cover all four source columns")
    return value


def current_metadata_models(profile, table):
    result = []
    for index, oracle in enumerate(profile["metadata_oracles"]):
        rows = [[item.replace("${OWNED_TABLE}", table.split(".")[1]) if isinstance(item, str) else item
                 for item in row] for row in oracle["rows"]]
        if index == 1:
            rows.sort(key=lambda row: row[0])
        result.append([oracle["columns"], rows])
    return result


def freeze(api, path, cluster, resource, cells):
    path = api.owned(path)
    config = validate_config(api.read_json(path))
    require(resource["cell_timeout_seconds"] >= config["duration_seconds"] + 60,
            "Browser cell deadline must cover the full background window and bounded navigation")
    require(resource["whole_timeout_seconds"] >= cells * (config["duration_seconds"] + 60),
            "Whole deadline cannot cover every declared background cell")
    java_home = Path(cluster["java_home"]).resolve(strict=True)
    require(api.ROOT in java_home.parents, "Background JDK must belong to the checkout")
    release = (java_home / "release").read_text()
    require('JAVA_VERSION="17.0.4"' in release, "Background requires the actual JDK 17.0.4")
    package = Path(cluster["package"]).resolve(strict=True)
    require(api.ROOT in package.parents, "Background package must belong to the checkout")
    dependencies = sorted((package / "fe/lib").glob("*.jar"))
    require(dependencies, "Original background JDBC classpath is missing")
    return {"input_path": str(path), "input_sha256": api.sha(path), "config": config,
            "java_home": str(java_home), "jdk_runtime": {
                name: api.sha(java_home / name) for name in ("bin/java", "bin/javac", "lib/modules", "release")},
            "source_sha256": {str(item): api.sha(item) for item in (SOURCE, JAVA_SOURCE, *FROZEN_REFERENCES)},
            "dependencies_sha256": {str(path): api.sha(path) for path in dependencies},
            "connection_mode": "reuse_per_worker_no_replay",
            "point_mode": "metadata_text_statement" if config.get("profile") == CURRENT_PROFILE else "server_prepared",
            "schedule": "java.util.Random_poisson_StrictMath_log_frozen_before_SQL",
            "scope": ("Current allowed business background; independent controller release; no automatic qualification"
                      if config.get("profile") == CURRENT_PROFILE else
                      "300-second single-context functional coexistence; no formal qualification")}


def validate_probe(api, plan, explicit_path):
    frozen = plan.get("background")
    if frozen is None:
        require(explicit_path is None, "An existing plan cannot acquire a write workload at probe time")
        return None
    require(explicit_path is not None and api.owned(explicit_path) == Path(frozen["input_path"]),
            "Background probe needs the same explicit --background input used during planning")
    require(api.sha(explicit_path) == frozen["input_sha256"]
            and validate_config(api.read_json(explicit_path)) == frozen["config"], "Background input changed")
    verify_frozen(api, frozen)
    return frozen


def verify_frozen(api, frozen):
    for path, digest in frozen["source_sha256"].items():
        require(api.sha(path) == digest, "Background helper/frozen semantic reference changed")
    for relative, digest in frozen["jdk_runtime"].items():
        require(api.sha(Path(frozen["java_home"]) / relative) == digest, "Background JDK changed")
    for path, digest in frozen["dependencies_sha256"].items():
        require(api.sha(path) == digest, "Frozen background JDBC dependency changed")


def read_object(api, path):
    value = api.read_json(path)
    require(isinstance(value, dict), "Background receipt is not a JSON object")
    return value


def secret_environment(config, admin):
    environment = {key: os.environ[key] for key in ("PATH", "HOME", "LANG") if key in os.environ}
    for account in (config["read_account"], config["write_account"], admin):
        key = account["password_env"]
        require(key in os.environ, "Explicit background credential environment is missing")
        secret = os.environ[key]
        require(len(secret) <= 1024 and all(32 <= ord(char) < 127 for char in secret), "Invalid synthetic credential")
        environment[key] = secret
    return environment


def receipt_values(row, stream, offset, epoch, batch_rows, slo_millis):
    """Independent receipt arithmetic; never treat an unknown write as successful delivery."""
    require(set(row) == {"sequence", "scheduled_ns", "started_ns", "finished_ns", "outcome", "affected_rows",
                         "sql_state", "error_code", "e2e_ns"}, "Unexpected request receipt columns")
    values = {}
    for key in ("sequence", "scheduled_ns", "started_ns", "finished_ns", "affected_rows", "error_code", "e2e_ns"):
        require(re.fullmatch(r"-?[0-9]{1,20}", row[key]), "Invalid request receipt integer")
        values[key] = int(row[key])
    require(values["scheduled_ns"] == epoch + offset
            and values["finished_ns"] >= values["started_ns"]
            and values["e2e_ns"] == values["finished_ns"] - values["scheduled_ns"], "Request receipt timing mismatch")
    require(re.fullmatch(r"(?:NONE|[A-Za-z0-9]{1,5})", row["sql_state"]), "Unsafe SQL state")
    allowed = {"OK", "ERROR", "NOT_SENT"} if stream == "read" else {
        "ACK", "ACK_AFFECTED_MISMATCH", "UNKNOWN", "NOT_SENT", "ERROR"}
    require(row["outcome"] in allowed, "Unknown request outcome")
    successful = row["outcome"] == ("OK" if stream == "read" else "ACK")
    if successful:
        require(values["started_ns"] >= values["scheduled_ns"] and values["error_code"] == 0
                and row["sql_state"] == "NONE", "Success receipt contains an error or early dispatch")
        require(values["affected_rows"] == (batch_rows if stream == "write" else -1), "Affected-row receipt differs")
    return {**values, "successful": successful, "slo_met": successful
            and values["e2e_ns"] <= slo_millis * 1_000_000}


def expected_rows_digest(ids):
    result = hashlib.sha256()
    for identifier in ids:
        payload = hashlib.md5(str(identifier).encode("ascii"), usedforsecurity=False).hexdigest()
        result.update(f"{identifier}\t{identifier % 1024}\t{identifier % 100000}\t{payload}\n".encode("ascii"))
    return result.hexdigest()


@lru_cache(maxsize=1)
def expected_source_digest():
    # Invoked only by an explicit probe, outside the shared browser/background interval.
    return expected_rows_digest(range(1_000_000))


def audit_full_models(api, output, profile, summary):
    expected = expected_source_digest()
    for phase in ("source_before", "source_after"):
        actual = summary.get(phase, {})
        require(actual.get("rows") == 1_000_000 and actual.get("full_values_verified") is True
                and actual.get("canonical_sha256") == expected, "Full source model differs from the independent Python model")
    require(summary["source_before"] == summary["source_after"], "Source schema/data changed across the window")
    batches = api.read_json(output / "write-batch-resolution.json")
    require(isinstance(batches, list) and len(batches) == summary["planned_write_batches"], "Write resolution is incomplete")
    total = 0
    for index, batch in enumerate(batches):
        require(batch.get("sequence") == index and type(batch.get("rows")) is int
                and batch["rows"] in (0, profile["write_batch_rows"]), "Write resolution has a partial/foreign batch")
        require(batch.get("request_state") in ("ACK", "UNKNOWN", "NOT_SENT", "NO_COMPLETION_RECEIPT")
                and batch.get("observed_committed") is bool(batch["rows"])
                and batch.get("unknown_absence_is_rollback_proof") is False, "Write uncertainty classification changed")
        if batch["request_state"] == "ACK":
            require(batch["rows"] == profile["write_batch_rows"], "Acknowledged batch is not fully visible")
        elif batch["request_state"] == "NOT_SENT":
            require(batch["rows"] == 0, "An unsent batch appeared in the target")
        if summary.get("status") == "PASS":
            require(batch["request_state"] == "ACK", "Helper PASS hides an unknown or missing write")
        total += batch["rows"]
    ids = (1_000_000_000 + index * profile["write_batch_rows"] + offset
           for index, batch in enumerate(batches) for offset in range(batch["rows"]))
    target = summary.get("target_after", {})
    require(target.get("rows") == total and target.get("full_values_verified") is True
            and target.get("exact_id_domains_verified") is True
            and target.get("canonical_sha256") == expected_rows_digest(ids), "Full target differs from the independent Python model")
    return {"source_rows": 1_000_000, "source_canonical_sha256": expected,
            "target_rows": total, "target_canonical_sha256": target["canonical_sha256"],
            "independent_language_model": True, "exactly_once_inferred_from_row_count": False}


def audit_receipts(api, output, profile, summary):
    if profile.get("profile") == CURRENT_PROFILE:
        return audit_current_receipts(api, output, profile, summary)
    start = api.read_json(output / "window-start.json")
    end = api.read_json(output / "window-end.json")
    require(start.get("token") == end.get("token") == summary.get("token")
            and end.get("scheduled_window_complete") is True, "Missing complete background interval")
    require(all(start.get(key) == end.get(key) == summary.get(key) for key in ("pid", "start_ticks", "namespace")),
            "Background interval process identity differs")
    require(type(start.get("pid")) is int and start["pid"] > 1 and type(start.get("start_ticks")) is int
            and start["start_ticks"] > 0 and re.fullmatch(r"net:\[[0-9]+\]", start.get("namespace", "")),
            "Missing actual background process identity")
    epoch = start["epoch_java_monotonic_ns"]
    require(type(epoch) is int and epoch > 0, "Invalid actual background epoch")
    require(end["java_monotonic_ns"] >= epoch + profile["duration_seconds"] * 1_000_000_000,
            "Background interval is shorter than its frozen duration")
    result = {}
    write_receipts = None
    for stream in ("read", "write"):
        path = output / (stream + "-arrivals.tsv")
        require(api.sha(path) == summary[stream + "_schedule_sha256"], "Arrival schedule hash mismatch")
        arrivals = []
        with path.open(newline="") as source:
            expected = {"sequence", "offset_ns", "id"} if stream == "read" else {"sequence", "offset_ns", "first_id", "rows"}
            for row in csv.DictReader(source, delimiter="\t"):
                require(set(row) == expected and all(re.fullmatch(r"[0-9]{1,20}", value) for value in row.values()),
                        "Invalid frozen arrival row")
                require(int(row["sequence"]) == len(arrivals) and len(arrivals) < 1_000_000, "Arrival sequence mismatch")
                offset = int(row["offset_ns"])
                require(0 <= offset < profile["duration_seconds"] * 1_000_000_000
                        and (not arrivals or offset >= arrivals[-1]), "Arrival time is not a fixed ordered window")
                if stream == "read":
                    require(0 <= int(row["id"]) < 1_000_000, "Read key escaped the source model")
                else:
                    require(int(row["rows"]) == profile["write_batch_rows"]
                            and int(row["first_id"]) == 1_000_000_000 + len(arrivals) * profile["write_batch_rows"],
                            "Write ID domains overlap or differ from the frozen model")
                arrivals.append(offset)
        require(arrivals and len(arrivals) == summary["planned_reads" if stream == "read" else "planned_write_batches"],
                "Planned request count mismatch")
        seen = bytearray(len(arrivals))
        if stream == "write":
            write_receipts = [None] * len(arrivals)
        counters = {"planned": len(arrivals), "receipts": 0, "successful": 0, "within_slo": 0,
                    "unknown": 0, "not_sent": 0, "sent_during_window": 0, "completed_during_window": 0}
        for worker in range(profile[stream + "_workers"]):
            with (output / f"{stream}-{worker}.tsv").open(newline="") as source:
                for row in csv.DictReader(source, delimiter="\t"):
                    require(re.fullmatch(r"[0-9]{1,8}", row.get("sequence", "")), "Invalid completion sequence")
                    index = int(row["sequence"])
                    require(index < len(arrivals) and not seen[index] and index % profile[stream + "_workers"] == worker,
                            "Duplicate, replayed or foreign worker receipt")
                    seen[index] = 1
                    values = receipt_values(row, stream, arrivals[index], epoch, profile["write_batch_rows"],
                                            profile["read_slo_millis" if stream == "read" else "write_ack_slo_millis"])
                    counters["receipts"] += 1
                    counters["successful"] += values["successful"]
                    counters["within_slo"] += values["slo_met"]
                    counters["unknown"] += row["outcome"] == "UNKNOWN"
                    counters["not_sent"] += row["outcome"] == "NOT_SENT"
                    cutoff = epoch + profile["duration_seconds"] * 1_000_000_000
                    counters["sent_during_window"] += row["outcome"] != "NOT_SENT" and epoch <= values["started_ns"] < cutoff
                    counters["completed_during_window"] += values["successful"] and epoch <= values["finished_ns"] < cutoff
                    if stream == "write":
                        write_receipts[index] = {"finished_ns": values["finished_ns"], "outcome": row["outcome"]}
        require(all(seen), "Missing request completion receipts")
        if summary.get("status") == "PASS":
            require(counters["successful"] == counters["within_slo"] == len(arrivals)
                    and counters["sent_during_window"] > 0 and counters["completed_during_window"] > 0,
                    "Helper PASS conflicts with actual delivery/SLO receipts")
        result[stream] = counters
    visibility = bytearray(len(write_receipts))
    with (output / "visibility.tsv").open(newline="") as source:
        for row in csv.DictReader(source, delimiter="\t"):
            require(set(row) == {"sequence", "observed_ns", "ack_or_error_ns", "rows", "state"}
                    and all(re.fullmatch(r"[0-9]{1,20}", value) for key, value in row.items() if key != "state"),
                    "Invalid visibility receipt")
            index = int(row["sequence"])
            require(index < len(visibility) and not visibility[index], "Duplicate or foreign visibility receipt")
            visibility[index] = 1
            count, observed, ack = int(row["rows"]), int(row["observed_ns"]), int(row["ack_or_error_ns"])
            require(count in (0, profile["write_batch_rows"]) and ack == write_receipts[index]["finished_ns"]
                    and observed >= ack and row["state"] == ("FULL_MODEL_VISIBLE" if count else "NOT_VISIBLE_AT_CUTOFF"),
                    "Visibility differs from actual completion/batch receipt")
            if summary.get("status") == "PASS":
                require(count == profile["write_batch_rows"]
                        and observed - ack <= profile["visibility_slo_millis"] * 1_000_000,
                        "Helper PASS hides a visibility failure/SLO miss")
    require(all(visibility[index] or receipt["outcome"] not in ("ACK", "ACK_AFFECTED_MISMATCH", "UNKNOWN")
                for index, receipt in enumerate(write_receipts)), "Missing independent visibility observations")
    result["write"]["visibility_receipts"] = sum(visibility)
    return result


def current_arrivals(rate, seconds):
    """Independent Java Random double/Poisson model; StrictMath/libm rounding checked within 1 ns."""
    state = (20260922 ^ 0x5DEECE66D) & ((1 << 48) - 1)
    def bits(count):
        nonlocal state
        state = (state * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return state >> (48 - count)
    elapsed, arrivals = 0.0, []
    while True:
        uniform = ((bits(26) << 27) + bits(27)) / float(1 << 53)
        if uniform == 0:
            continue
        elapsed += -math.log(uniform) * 1_000_000_000 / rate
        if elapsed >= seconds * 1_000_000_000:
            return arrivals
        require(len(arrivals) < 1_000_000, "Current independent schedule exceeds bound")
        arrivals.append(int(elapsed))


def audit_current_receipts(api, output, profile, summary):
    validate_current_config(profile)
    config = api.read_json(output / "config.json")
    require(config["profile"] == CURRENT_PROFILE and summary.get("profile") == CURRENT_PROFILE
            and summary.get("metadata_preflight_verified") is True, "Current profile/preflight missing")
    require(all(config.get(key) == value for key, value in profile.items()), "Current frozen configuration changed")
    models = current_metadata_models(profile, config["table"])
    require(api.read_json(output / "metadata-oracles.json") == models, "Frozen metadata oracle changed")
    hashes = [hashlib.sha256(json.dumps(model, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
              for model in models]
    start, end = (api.read_json(output / name) for name in ("window-start.json", "window-end.json"))
    cpu_start, cpu_end = (api.read_json(output / name) for name in ("measurement-start.json", "measurement-end.json"))
    for item in (start, end, cpu_start, cpu_end):
        require(all(item.get(key) == summary.get(key) for key in ("token", "pid", "start_ticks", "namespace")),
                "Current boundary identity changed")
    epoch = start["epoch_java_monotonic_ns"]
    cutoff = epoch + profile["duration_seconds"] * 1_000_000_000
    require(type(epoch) is int and epoch > 0 and end["java_monotonic_ns"] >= cutoff
            and end.get("scheduled_window_complete") is True, "Current scheduled window incomplete")
    paths = {stream: output / (stream + "-arrivals.tsv") for stream in ("total", "read", "write")}
    for stream, file in paths.items():
        require(api.sha(file) == summary[stream + "_schedule_sha256"], "Current arrival digest changed")
    def rows(file):
        with file.open(newline="") as stream:
            return list(csv.DictReader(stream, delimiter="\t"))
    total = rows(paths["total"])
    expected = current_arrivals(profile["rate_per_second"], profile["duration_seconds"])
    require(len(total) == len(expected) == summary["generated_total_requests"], "Current Poisson generated count differs")
    for index, (row, offset) in enumerate(zip(total, expected)):
        require(set(row) == {"sequence", "offset_ns"} and int(row["sequence"]) == index
                and abs(int(row["offset_ns"]) - offset) <= 1, "Current Poisson schedule differs from independent model")
    count = len(total) // 2
    require(count > 0 and summary["tail_arrivals_not_scheduled"] == len(total) % 2
            and summary["scheduled_total_requests"] == count * 2
            and summary["planned_reads"] == summary["planned_write_batches"] == count,
            "Current 50/50 split or explicit odd-tail accounting differs")
    def quantile(samples, fraction):
        ordered = sorted(samples)
        if not ordered:
            return None
        position = (len(ordered) - 1) * fraction
        low = int(position)
        return ordered[low] + (ordered[min(low + 1, len(ordered) - 1)] - ordered[low]) * (position - low)

    all_latency, streams, last = [], {}, epoch
    for stream in ("read", "write"):
        arrivals = rows(paths[stream])
        require(len(arrivals) == count, "Current per-type schedule incomplete")
        for index, row in enumerate(arrivals):
            slot = index * 2 + (1 if stream == "read" else 0)
            require(int(row["sequence"]) == index and int(row["offset_ns"]) == int(total[slot]["offset_ns"]),
                    "Current alternating split changed")
            if stream == "read":
                require(set(row) == {"sequence", "offset_ns", "id"} and int(row["id"]) == index % 3,
                        "Current metadata round robin changed")
            else:
                require(set(row) == {"sequence", "offset_ns", "first_id", "rows"} and int(row["rows"]) == 100
                        and int(row["first_id"]) == 1_000_000_000 + index * 100, "Current write domains overlap")
        seen, latency, service, queue = bytearray(count), [], [], []
        counters = {"scheduled": count, "successful": 0, "unknown": 0, "not_sent": 0, "errors": 0}
        for worker in range(8):
            for row in rows(output / f"{stream}-{worker}.tsv"):
                row = dict(row)
                result_hash = row.pop("result_sha256", None)
                index = int(row["sequence"])
                require(0 <= index < count and not seen[index] and index % 8 == worker, "Current duplicate/foreign worker receipt")
                seen[index] = 1
                values = receipt_values(row, stream, int(arrivals[index]["offset_ns"]), epoch, 100,
                                        profile["read_slo_millis" if stream == "read" else "write_ack_slo_millis"])
                if values["successful"]:
                    require(result_hash == (hashes[index % 3] if stream == "read" else "NONE"),
                            "Current full metadata result hash differs from independent oracle")
                    latency.append(values["e2e_ns"] / 1e6)
                    service.append((values["finished_ns"] - values["started_ns"]) / 1e6)
                    queue.append((values["started_ns"] - values["scheduled_ns"]) / 1e6)
                else:
                    require(result_hash == "NONE", "Failed request cannot claim a successful result hash")
                counters["successful"] += values["successful"]
                counters["unknown"] += row["outcome"] == "UNKNOWN"
                counters["not_sent"] += row["outcome"] == "NOT_SENT"
                counters["errors"] += not values["successful"]
                last = max(last, values["finished_ns"])
        require(all(seen), "Current missing raw request completions")
        if summary.get("status") == "PASS":
            require(counters["successful"] == count, "Current PASS hides unknown/error/missing delivery")
        streams[stream] = {**counters, "successful_latency_ms": latency,
                           "p95_ms": quantile(latency, .95), "p99_ms": quantile(latency, .99),
                           "service_p95_ms": quantile(service, .95), "service_p99_ms": quantile(service, .99),
                           "queue_p95_ms": quantile(queue, .95), "queue_p99_ms": quantile(queue, .99),
                           "p99_sample_floor_met": counters["successful"] >= 10000}
        all_latency.extend(latency)
    require(cpu_end["epoch_java_monotonic_ns"] == epoch and cpu_end["last_request_end_java_ns"] == last
            and cpu_end["request_interval_end_java_ns"] == max(cutoff, last), "Actual request/measurement boundary mismatch")
    seconds = (max(cutoff, last) - epoch) / 1e9
    success = len(all_latency)
    for stream in streams.values():
        stream["success_qps"] = stream["successful"] / seconds
    cpu = {}
    for role in ("fe", "be"):
        first, final = cpu_start["cpu"][role], cpu_end["cpu"][role]
        pin = config["cpu_services"][role]
        require(first["pid"] == final["pid"] == pin["pid"]
                and first["start_ticks"] == final["start_ticks"] == pin["start_ticks"], "Current CPU service lifetime differs")
        require(first["sample_started_java_ns"] <= first["sample_ended_java_ns"] <= epoch
                and final["sample_ended_java_ns"] >= final["sample_started_java_ns"] >= max(cutoff, last),
                "CPU samples do not enclose the actual complete request interval")
        delta = final["cpu_seconds"] - first["cpu_seconds"]
        require(type(delta) in (int, float) and math.isfinite(delta) and delta >= 0, "Current CPU reset/nonfinite")
        cpu[role] = {"cpu_seconds": delta, "cpu_seconds_per_success": delta / success if success else None,
                     "leading_enclosure_ns": epoch - first["sample_ended_java_ns"],
                     "trailing_enclosure_ns": final["sample_started_java_ns"] - max(cutoff, last)}
    return {"status": "RAW_RECEIPTS_AUDITED", "streams": streams, "successful_requests": success,
            "generated_requests": len(total), "scheduled_requests": count * 2,
            "tail_arrivals_not_scheduled": len(total) % 2, "effective_duration_seconds": seconds,
            "drain_seconds": seconds - profile["duration_seconds"], "success_qps": success / seconds,
            "p95_ms": quantile(all_latency, .95), "p99_ms": quantile(all_latency, .99), "cpu": cpu,
            "eligible_window_shape": profile["qualification"] == "formal",
            "p99_sample_floor_met": success >= 10000, "formal_performance_pass": False,
            "visibility_policy": "post_window_full_model_not_online_visibility_latency",
            "schedule_rounding_tolerance_ns": 1}


EXIT_SETTLE_SECONDS = 0.25


class BackgroundProcessError(ValueError):
    """Fixed, credential-free process diagnostics; never copy child argv or environment."""

    def __init__(self, reason, stage, observation=None):
        super().__init__("Background process identity changed or unavailable: " + reason)
        self.reason, self.stage, self.observation = reason, stage, observation


def process_error(error, stage):
    result = {"stage": stage, "error_class": type(error).__name__}
    if isinstance(error, BackgroundProcessError):
        result.update(reason=error.reason, process_stage=error.stage, observation=error.observation)
    elif isinstance(error, ValueError):
        reasons = {"Background helper compilation failed": "COMPILE_NONZERO_EXIT",
                   "Background helper exceeded RSS budget": "RSS_BUDGET_EXCEEDED",
                   "Background helper escaped CPU affinity": "CPU_AFFINITY_CHANGED",
                   "Background deadline expired": "WHOLE_DEADLINE_EXPIRED",
                   "Background phase deadline expired": "PHASE_DEADLINE_EXPIRED",
                   "Background helper exited before its phase receipt": "EXIT_BEFORE_PHASE_RECEIPT"}
        if str(error) in reasons:
            result["reason"] = reasons[str(error)]
    return result


def process_observation(api, pid):
    """Bracket the identity read with the original process lifetime, including zombies."""
    result = {}
    def stat():
        fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
        return {"start_ticks": int(fields[19]), "state": fields[0]}
    try:
        result["before"] = stat()
        result["identity"] = api.proc(pid)
    except (OSError, ValueError) as error:
        result["read_error_class"] = type(error).__name__
    try:
        result["after"] = stat()
    except (OSError, ValueError) as error:
        result["after_error_class"] = type(error).__name__
    return result


STARTUP_PIN_SECONDS = 0.25


def acquire_launch_pin(api, process, expected, deadline, check, emit=None):
    """Bind the exact requested launch, never a transient empty or wrapper command.

    Two complete matching reads are required. /proc fields are not atomic, so this
    is observed identity evidence, not a claim of uninterrupted absence of exec.
    """
    end = min(deadline, time.monotonic() + STARTUP_PIN_SECONDS)
    first, observed, lifetime, attempts, consecutive = None, {}, None, 0, 0
    empty_command = hashlib.sha256(b"").hexdigest()

    def fail(reason):
        error = BackgroundProcessError(reason, "startup", {
            "expected": expected, "first_observation": first, "last_observation": observed,
            "attempts": attempts})
        try:
            raise error
        except BackgroundProcessError:
            if emit:
                emit(process_error(error, "startup"))
            raise

    while True:
        check()
        # Even an exit before the first usable identity must have a real parent wait.
        if process.poll() is not None:
            exit_code = process.wait(timeout=5)
            observed = {**observed, "exit_code": exit_code, "parent_wait_complete": True}
            fail("STARTUP_EXIT_BEFORE_IDENTITY")
        if time.monotonic() >= end:
            fail("STARTUP_IDENTITY_DEADLINE")
        observed = process_observation(api, process.pid)
        attempts += 1
        if first is None:
            first = observed
        for item in (observed.get("before"), observed.get("identity"), observed.get("after")):
            if item:
                if lifetime is None:
                    lifetime = item["start_ticks"]
                if item["start_ticks"] != lifetime:
                    fail("PROCESS_LIFETIME_CHANGED")
        identity = observed.get("identity")
        if identity:
            mismatches = [key for key in ("pid", "namespace", "exe", "command_sha256")
                          if identity[key] != expected[key]
                          and not (key == "command_sha256" and identity[key] == empty_command)]
            if mismatches:
                observed["mismatched_fields"] = mismatches
                fail("STARTUP_IDENTITY_MISMATCH")
        complete = (identity and observed.get("before") and observed.get("after")
                    and all(item["state"] not in ("Z", "X") for item in
                            (observed["before"], identity, observed["after"]))
                    and identity["command_sha256"] == expected["command_sha256"])
        consecutive = consecutive + 1 if complete else 0
        if time.monotonic() >= end:
            fail("STARTUP_IDENTITY_DEADLINE")
        if consecutive >= 2 and process.poll() is None:
            return {"pin": dict(identity), "event": {
                "stage": "startup", "reason": "EXPECTED_LAUNCH_IDENTITY_CONFIRMED",
                "expected": expected, "first_observation": first, "last_observation": observed,
                "attempts": attempts, "consecutive_complete_matches": consecutive}}
        time.sleep(min(0.001, max(0, end - time.monotonic())))


def owned_live(api, process, pin, stage, deadline=None, emit=None, force_exit_wait=False):
    """A missing /proc field is accepted only after an actual bounded Popen wait."""
    if process.poll() is not None:
        return False
    observed = process_observation(api, process.pid)
    def fail(reason):
        error = BackgroundProcessError(reason, stage, observed)
        try:
            raise error
        except BackgroundProcessError:
            if emit:
                emit(process_error(error, stage))
            raise
    if not pin or pin.get("pid") != process.pid or "start_ticks" not in pin:
        fail("MISSING_OWNED_PIN")
    for item in (observed.get("before"), observed.get("identity"), observed.get("after")):
        if item and item["start_ticks"] != pin["start_ticks"]:
            fail("PROCESS_LIFETIME_CHANGED")
    identity = observed.get("identity")
    empty_command = hashlib.sha256(b"").hexdigest()
    if identity:
        mismatches = [key for key in ("namespace", "exe", "command_sha256")
                      if identity[key] != pin[key]
                      and not (key == "command_sha256" and identity[key] == empty_command)]
        if mismatches:
            observed["mismatched_fields"] = mismatches
            fail("LIVE_IDENTITY_CHANGED")
        if (observed.get("before") and observed.get("after")
                and all(item["state"] not in ("Z", "X") for item in
                        (observed["before"], identity, observed["after"]))
                and identity["command_sha256"] != empty_command and not force_exit_wait):
            return process.poll() is None
    # Do not signal an incomplete identity, re-pin it, fabricate RSS=0, or infer exit 0.
    remaining = EXIT_SETTLE_SECONDS if deadline is None else min(EXIT_SETTLE_SECONDS, deadline - time.monotonic())
    if remaining <= 0:
        fail("EXIT_HANDSHAKE_DEADLINE")
    try:
        exit_code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        fail("IDENTITY_UNAVAILABLE_CHILD_STILL_LIVE")
    if process.poll() is None:
        fail("WAIT_WITHOUT_EXIT_RECEIPT")
    if emit:
        emit({"stage": stage, "reason": "OWNED_EXIT_AFTER_INCOMPLETE_PROC", "observation": observed,
              "exit_code": exit_code, "parent_wait_complete": True})
    return False


def reap_owned(api, process, pin, deadline=None, emit=None):
    if process is None:
        return True
    if owned_live(api, process, pin, "reap", deadline, emit):
        api.stop_owned([pin])
    exit_code = process.wait(timeout=5)
    require(process.poll() is not None, "Popen still reports a live background helper")
    if emit:
        emit({"stage": "reap", "reason": "OWNED_PARENT_WAIT", "pid": process.pid,
              "exit_code": exit_code, "parent_wait_complete": True})
    return True


class Background:
    """One fresh, owned write table per UI cell, including failure/recovery evidence."""

    def __init__(self, api, plan, guard, target, cell, admin, whole_deadline):
        self.api, self.plan, self.guard = api, plan, guard
        self.frozen = plan["background"]
        self.profile = self.frozen["config"]
        self.output = api.owned(Path(plan["output"]) / (cell["id"] + "-background"))
        self.output.mkdir(mode=0o700)
        self.config_path = self.output / "config.json"
        self.process, self.pin = None, None
        self.work_pin = None
        self.peak = 0
        self.whole_deadline = whole_deadline
        self.samples = 0
        self.last_sample = 0
        self.finished = False
        self.token = uuid.uuid4().hex
        self.environment = secret_environment(self.profile, admin)
        pins = list(guard.pins)
        if hasattr(guard, "multi"):
            pins = [api.proc(guard.multi.supervisor["pid"])]
            for record in guard.multi.nodes.values():
                pins.extend(api.proc(record[key]["pid"]) for key in ("keeper", "service"))
        require(pins and all(api.same(pin) for pin in pins), "Missing background cluster process bindings")
        self.config = {**self.profile, "output": str(self.output), "token": self.token,
                       "table": "license_perf.ui_bg_" + self.token,
                       "target": {key: target[key] for key in ("name", "host", "query_port")},
                       "oracle_account": {key: admin[key] for key in ACCOUNT_KEYS},
                       "cluster_pins": pins, "namespace": os.readlink("/proc/self/ns/net"),
                       "source_table": "license_perf.point_rows", "source_rows": 1000000,
                       "cell": cell["id"], "heap_mib": 512,
                       "background_input_sha256": self.frozen["input_sha256"]}
        api.save(self.config_path, self.config)
        self.classpath = None
        self.process_events = []

    def _process_event(self, event):
        primary_pending = sys.exc_info()[0] is not None
        events = getattr(self, "process_events", [])
        require(len(events) < 128, "Background process evidence exceeds bound")
        events.append({"helper": getattr(self, "process_name", "unknown"),
                       "controller_monotonic_ns": time.monotonic_ns(), **event})
        self.process_events = events
        try:
            self.api.save(self.output / "process-lifecycle.json", events)
        except BaseException as error:
            failures = getattr(self, "process_evidence_errors", [])
            failures.append({"stage": "process_lifecycle_save", "error_class": type(error).__name__})
            self.process_evidence_errors = failures
            if not primary_pending:
                raise

    def _launch(self, command, name, phase_deadline):
        self.guard.check()
        deadline = min(phase_deadline, getattr(self, "recovery_deadline", self.whole_deadline))
        require(time.monotonic() < deadline, "Background phase deadline expired")
        command = [str(item) for item in command]
        expected = {"namespace": os.readlink("/proc/self/ns/net"),
                    "exe": str(Path(command[0]).resolve(strict=True)),
                    "command_sha256": hashlib.sha256(b"\0".join(os.fsencode(item) for item in command)
                                                     + b"\0").hexdigest()}
        self.process_name = name
        require(time.monotonic() < deadline, "Background phase deadline expired")
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env=self.environment, start_new_session=True)
        # Register ownership before any fallible /proc read or evidence write.
        self.process, self.pin = process, None
        expected["pid"] = process.pid
        try:
            acquired = acquire_launch_pin(self.api, process, expected, deadline, self.guard.check,
                                          self._process_event)
            self.pin = acquired["pin"]
            self._process_event(acquired["event"])
            require(time.monotonic() < deadline, "Background phase deadline expired")
            self.api.save(self.output / (name + "-process.json"), {
                "pin": self.pin, "started_at_utc": self.api.utc(), "expected_launch": expected})
        except BaseException:
            # The original failure remains primary even when evidence persistence fails.
            if process.poll() is not None:
                code = process.wait(timeout=5)
                self._process_event({"stage": "startup_failure", "reason": "OWNED_PARENT_WAIT",
                                     "pid": process.pid, "exit_code": code, "parent_wait_complete": True})
            raise

    def check(self, phase_deadline=None):
        self.guard.check()
        deadline = getattr(self, "recovery_deadline", self.whole_deadline)
        if phase_deadline is not None:
            deadline = min(deadline, phase_deadline)
        require(time.monotonic() < deadline, "Background phase deadline expired" if phase_deadline is not None
                else "Background deadline expired")
        live = self.process is not None and owned_live(self.api, self.process, self.pin, "check", deadline,
                                                      self._process_event)
        pins = [self.pin] if live else []
        current_rss = self.api.rss_mib([self.api.proc(os.getpid())])
        sample = None
        if pins:
            process = Path("/proc") / str(self.pin["pid"])
            try:
                affinity = os.sched_getaffinity(self.pin["pid"])
                fields = (process / "stat").read_text().rsplit(")", 1)[1].split()
                status = (process / "status").read_text()
                io = {key: int(value) for key, value in re.findall(r"(?m)^(rchar|wchar|read_bytes|write_bytes): ([0-9]+)$",
                                                                   (process / "io").read_text())}
                rss = re.search(r"(?m)^VmRSS:\s+(\d+) kB$", status)
                require(int(fields[19]) == self.pin["start_ticks"], "Background resource lifetime changed")
                if not rss:
                    raise FileNotFoundError("Helper RSS unavailable")
            except (FileNotFoundError, ProcessLookupError):
                if owned_live(self.api, self.process, self.pin, "resource_read", deadline, self._process_event,
                              force_exit_wait=True):
                    raise BackgroundProcessError("LIVE_RESOURCE_EVIDENCE_MISSING", "resource_read") from None
                pins = []
            else:
                if owned_live(self.api, self.process, self.pin, "resource_after", deadline, self._process_event):
                    require(affinity <= set(self.plan["resources"]["cpus"]), "Background helper escaped CPU affinity")
                    current_rss += int(rss[1]) / 1024
                    sample = {"controller_monotonic_ns": time.monotonic_ns(), "pid": self.pin["pid"],
                              "cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                              "rss_bytes": int(rss[1]) * 1024, "io": io}
                else:
                    pins = []
            if not pins:
                self._process_event({"stage": "resource_read", "reason": "EXITED_PARTIAL_SAMPLE_DISCARDED",
                                     "pid": self.pin["pid"], "rss_bytes": None})
        self.peak = max(self.peak, current_rss)
        self.samples += 1
        require(current_rss <= self.plan["resources"]["rss_limit_mib"], "Background helper exceeded RSS budget")
        now = time.monotonic()
        if sample is not None and now - self.last_sample >= 0.2:
            self.last_sample = now
            with (self.output / "resources.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(sample, separators=(",", ":")) + "\n")
        return pins

    def _await(self, condition, deadline):
        while True:
            self.check(phase_deadline=deadline)
            require(time.monotonic() < min(deadline, getattr(self, "recovery_deadline", self.whole_deadline)),
                    "Background phase deadline expired")
            if condition():
                return
            require(self.process.poll() is None, "Background helper exited before its phase receipt")
            time.sleep(0.1)

    def start(self):
        verify_frozen(self.api, self.frozen)
        classes = self.output / "classes"
        classes.mkdir()
        jars = (sorted(Path(path) for path in self.frozen["dependencies_sha256"])
                if self.profile.get("profile") == CURRENT_PROFILE else sorted((self.guard.jar.parent).glob("*.jar")))
        require(jars, "Packaged JDBC dependencies are missing")
        inputs = {str(path): self.api.sha(path) for path in jars}
        require(inputs == self.frozen["dependencies_sha256"], "Actual packaged JDBC dependency set changed")
        self.classpath = os.pathsep.join(map(str, [classes, *jars]))
        java = Path(self.frozen["java_home"]) / "bin/java"
        compile_deadline = min(self.whole_deadline, time.monotonic() + 120)
        try:
            self._launch([java.with_name("javac"), "-J-Xmx256m", "--release", "17", "-encoding", "UTF-8",
                          "-cp", self.classpath, "-d", classes, JAVA_SOURCE], "compile", compile_deadline)
            self._await(lambda: self.process.poll() is not None, compile_deadline)
            require(self.process.returncode == 0, "Background helper compilation failed")
        except BaseException as error:
            self._process_event(process_error(error, "compile_wait"))
            raise
        finally:
            primary = sys.exc_info()[0] is not None
            try:
                reap_owned(self.api, self.process, self.pin, self.whole_deadline, self._process_event)
            except BaseException as error:
                self._process_event(process_error(error, "compile_reap"))
                if not primary:
                    raise
        require(all(self.api.sha(path) == digest for path, digest in inputs.items()), "Packaged dependencies changed")
        verify_frozen(self.api, self.frozen)
        compiled = {str(path): self.api.sha(path) for path in classes.rglob("*.class")}
        require(str(classes / "LicenseUiBackground.class") in compiled, "Expected background class is missing")
        self.api.save(self.output / "helper-identity.json", {"dependencies": inputs,
            "classes": compiled,
            "frozen": self.frozen})
        require(all(self.api.sha(path) == digest for path, digest in {**inputs, **compiled}.items()),
                "Runtime dependency/class identity changed before launch")
        prepare_deadline = min(self.whole_deadline, time.monotonic() + self.profile["prepare_timeout_seconds"])
        self._launch([java, "-Xmx512m", "-cp", self.classpath, "LicenseUiBackground", self.config_path],
                     "background", prepare_deadline)
        self.work_pin = dict(self.pin)
        self._await(lambda: (self.output / "ready.json").exists(), prepare_deadline)
        ready = self.api.read_json(self.output / "ready.json")
        self._identity_receipt(ready)
        require(ready.get("token") == self.token and ready.get("source_rows_verified") == 1000000
                and ready.get("empty_owned_target") is True, "Background readiness/oracle identity mismatch")
        self.api.save(self.output / "controller-ready.json", {"observed_monotonic_ns": time.monotonic_ns(),
                                                              "observed_at_utc": self.api.utc(), "ready": ready})

    def _identity_receipt(self, receipt):
        require(isinstance(receipt, dict) and self.work_pin is not None and receipt.get("pid") == self.work_pin["pid"]
                and receipt.get("start_ticks") == self.work_pin["start_ticks"]
                and receipt.get("namespace") == self.work_pin["namespace"], "Background receipt process identity mismatch")
        return True

    def browser_config(self):
        return {"directory": str(self.output), "token": self.token,
                "duration_seconds": self.profile["duration_seconds"]}

    def coordinate(self):
        self.check()
        ready = self.output / "browser-ready.json"
        release = self.output / "release.json"
        if ready.exists() and not release.exists():
            value = self.api.read_json(ready)
            require(value.get("token") == self.token, "Browser/background coordination identity mismatch")
            self.api.save(release, {"token": self.token, "controller_monotonic_ns": time.monotonic_ns(),
                                    "controller_at_utc": self.api.utc()})
        require(self.process.poll() is None or (self.output / "window-end.json").exists(),
                "Background exited while browser was active")

    def finish(self):
        if self.finished:
            return self.api.read_json(self.output / "controller.json")
        self.finished = True
        errors = list(getattr(self, "process_evidence_errors", []))
        def attempt(stage, operation, fallback=None):
            try:
                return operation()
            except BaseException as error:
                errors.append(process_error(error, stage))
                return fallback
        # Cancellation stops arrivals without pretending that the planned window completed.
        if not (self.output / "window-end.json").exists():
            attempt("stop_marker", lambda: self.api.save(self.output / "stop.json", {"token": self.token}))
        deadline = min(self.whole_deadline, time.monotonic() + self.profile["verify_timeout_seconds"]
                       + self.profile["drain_seconds"] + self.profile["cleanup_timeout_seconds"])
        try:
            while self.process and self.process.poll() is None and time.monotonic() < deadline:
                self.check()
                time.sleep(0.1)
        except BaseException as error:
            errors.append(process_error(error, "wait"))
        finally:
            clean = attempt("reap", lambda: reap_owned(self.api, self.process, self.pin, deadline,
                                                       self._process_event), False)
        summary_path = self.output / "summary.json"
        summary = attempt("summary_read", lambda: read_object(self.api, summary_path), {}) if summary_path.exists() else {}
        if summary:
            if not attempt("summary_identity", lambda: self._identity_receipt(summary), False):
                summary["cleanup_confirmed"], summary["status"] = False, "FAIL"
        attempt("final_cluster_identity", self.guard.check)
        attempt("final_frozen_inputs", lambda: verify_frozen(self.api, self.frozen))
        if not summary.get("cleanup_confirmed") and self.classpath and clean:
            # Exact owner receipt + cluster/tablet/schema pins are required by Java before DROP.
            try:
                self.guard.check()
                java = Path(self.frozen["java_home"]) / "bin/java"
                self.recovery_deadline = time.monotonic() + self.profile["cleanup_timeout_seconds"]
                self._launch([java, "-Xmx512m", "-cp", self.classpath, "LicenseUiBackground",
                              self.config_path, "--cleanup-only"], "recovery", self.recovery_deadline)
                self._await(lambda: self.process.poll() is not None, self.recovery_deadline)
            except BaseException as error:
                errors.append(process_error(error, "owned_recovery"))
            finally:
                clean = attempt("recovery_reap", lambda: reap_owned(self.api, self.process, self.pin,
                                                                   self.recovery_deadline, self._process_event), False) and clean
            recovery = self.output / "cleanup.json"
            if recovery.exists():
                receipt = attempt("cleanup_read", lambda: read_object(self.api, recovery), {})
                valid = receipt.get("token") == self.token and self.pin is not None \
                    and receipt.get("pid") == self.pin["pid"] and receipt.get("start_ticks") == self.pin["start_ticks"] \
                    and receipt.get("namespace") == self.pin["namespace"]
                if valid:
                    summary["recovery_cleanup"] = receipt
                else:
                    errors.append({"stage": "cleanup_identity", "error_class": "ValueError"})
        cleanup = bool(summary.get("cleanup_confirmed") or summary.get("recovery_cleanup", {}).get("cleanup_confirmed"))
        receipt_audit = None
        model_audit = None
        try:
            receipt_audit = audit_receipts(self.api, self.output, self.profile, summary)
            model_audit = audit_full_models(self.api, self.output, self.profile, summary)
        except BaseException as error:
            errors.append({"stage": "independent_receipt_audit", "error_class": type(error).__name__})
        browser_overlap = None
        if self.profile.get("profile") != CURRENT_PROFILE:
            browser_overlap = False
            try:
                browser = self.api.read_json(Path(self.plan["output"]) / self.config["cell"] / "browser.json")["background"]
                require(browser["token"] == self.token and browser["end_receipt"]["scheduled_window_complete"] is True,
                        "Browser/background interval identity mismatch")
                require(browser["browser_actions_started_unix_millis"] >= browser["start_receipt"]["unix_millis"]
                        and browser["browser_actions_started_unix_millis"] < browser["end_receipt"]["unix_millis"]
                        and browser["browser_context_held_until_unix_millis"] >= browser["end_receipt"]["unix_millis"],
                        "Browser did not span the background interval")
                browser_overlap = True
            except BaseException as error:
                errors.append({"stage": "browser_overlap", "error_class": type(error).__name__})
        errors.extend(item for item in getattr(self, "process_evidence_errors", []) if item not in errors)
        record = {"status": "PASS" if clean and cleanup and not errors and summary.get("status") == "PASS" else "FAIL",
                  "token": self.token, "table": self.config["table"], "owned_child_exited": clean,
                  "cleanup_confirmed": cleanup, "errors": errors, "rss_peak_mib_sampled": self.peak,
                  "resource_samples": self.samples, "summary": summary,
                  "receipt_audit": receipt_audit, "full_model_audit": model_audit, "browser_interval_overlap": browser_overlap,
                  "resource_scope": "helper CPU/RSS/IO sampled separately; per-process network not implemented",
                  "evidence_sha256": {path.name: self.api.sha(path) for path in self.output.iterdir()
                                      if path.is_file() and path.suffix in (".json", ".jsonl", ".tsv")},
                  "formal_performance_pass": False, "full_goal_complete": False}
        self.api.save(self.output / "controller.json", record)
        return record


class CurrentBackground(Background):
    """Standalone G5/G6/G7 participant. Its owner supplies capacity/A/A/A/B and UI coordination."""

    def __init__(self, api, plan, guard, target, cell, admin, whole_deadline, cpu_services):
        require(plan["background"]["config"].get("profile") == CURRENT_PROFILE, "Explicit current profile required")
        require(set(cpu_services) == {"fe", "be"} and cpu_services["fe"]["pid"] != cpu_services["be"]["pid"]
                and all(api.same(pin) for pin in cpu_services.values()), "Current CPU service pins invalid")
        super().__init__(api, plan, guard, target, cell, admin, whole_deadline)
        require(all(any(all(owned.get(key) == pin.get(key) for key in
                           ("pid", "start_ticks", "namespace", "exe", "command_sha256"))
                        for owned in self.config["cluster_pins"]) for pin in cpu_services.values()),
                "CPU services are not frozen cluster members")
        self.config.update(cpu_services=cpu_services, clock_ticks_per_second=os.sysconf("SC_CLK_TCK"))
        self.api.save(self.config_path, self.config)

    def coordinate(self):
        self.check()  # Intentionally no dependency on browser-ready.json.

    def release(self):
        self.check()
        require((self.output / "ready.json").exists() and not (self.output / "release.json").exists(),
                "Current background is not ready or was already released")
        self.api.save(self.output / "release.json", {"token": self.token,
            "controller_monotonic_ns": time.monotonic_ns(), "controller_at_utc": self.api.utc()})

    def allow_verification(self):
        self.check()
        require((self.output / "measurement-end.json").exists()
                and (self.output / "verification-ready.json").exists(), "Business window/worker quiescence is incomplete")
        require(not (self.output / "verify-release.json").exists(), "Verification already released")
        self.api.save(self.output / "verify-release.json", {"token": self.token,
            "controller_monotonic_ns": time.monotonic_ns(), "controller_at_utc": self.api.utc()})
