#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Plan or explicitly probe the frozen complex query and concurrent view event on owned original A."""

import argparse
import base64
import hashlib
from http.cookies import SimpleCookie
import http.client
import json
import math
import os
from pathlib import Path
import queue
import random
import re
import signal
import socket
import threading
import time
from types import SimpleNamespace
import uuid
import zipfile

import background_http_fixture as support
import complex_planning_oracle as oracle
from stream_load_fixture import ROOT, digest, owned, utc


SOURCE = Path(__file__).resolve()
JAVA = SOURCE.with_name("LicenseComplexPlanningFixture.java")
PERFORMANCE = ROOT / "docs/license-performance-cases-20260922.json"
SAVE = support.save
MAX_REQUESTS = 20000
MAX_RECEIPTS_BYTES = 128 * 1024 * 1024
MAX_PROFILE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_TOTAL = 256 * 1024 * 1024
MAX_PROFILES = 512
PROFILE_OVERLAP_LIMIT = 64
CREATE_VIEW = f"CREATE VIEW {oracle.VIEW} AS SELECT id, grp, v, payload FROM license_perf.point_rows"
SOURCE_INTEGRITY = ("SELECT COUNT(*) AS n,COUNT(DISTINCT id) AS distinct_ids,MIN(id) AS min_id,"
                    "MAX(id) AS max_id,SUM(id) AS sum_id,SUM(grp) AS sum_grp,SUM(v) AS sum_v,"
                    "SUM(IF(id IS NULL OR grp IS NULL OR v IS NULL OR payload IS NULL OR "
                    "grp<>id%1024 OR v<>id%100000 OR payload<>MD5(CAST(id AS STRING)),1,0)) AS bad_rows "
                    "FROM license_perf.point_rows")


def require(value, message):
    if not value:
        raise ValueError(message)


def json_read(path, maximum=MAX_RECEIPTS_BYTES):
    path = Path(path)
    require(path.stat().st_size <= maximum, "JSON evidence exceeds its declared bound")
    return json.loads(path.read_text(encoding="utf-8"))


def incomplete():
    return {"LP006_complete": False, "LP007_complete": False, "release_performance_pass": False,
            "full_goal_complete": False, "runtime_license_enforcement_proven": False,
            "remaining": ["All frozen connection/concurrency/rate/window and five-pair matrices",
                          "Original-A capacity and A/A detection precision; actual candidate B comparisons",
                          "FE/BE allocation/GC/RPC resource attribution and integrated license behavior"]}


def offsets(generator, rate, seconds, limit):
    elapsed, result = 0.0, []
    while seconds:
        elapsed += generator.expovariate(rate)
        if elapsed >= seconds:
            break
        require(len(result) < limit, "Arrival sequence exceeds the request bound; choose explicit inputs")
        value = int(elapsed * 1000000000)
        require(not result or value > result[-1], "Arrival offsets collide at nanosecond resolution")
        result.append(value)
    return result


def arrivals(rate, warmup, window, limit):
    require(type(rate) in (float, int) and math.isfinite(rate) and 0 < rate <= 100,
            "Declare a finite original-A arrival rate in (0,100]")
    require(type(warmup) is int and 0 <= warmup <= 180 and type(window) is int and 240 <= window <= 600,
            "Probe bounds require 0..180-second warmup and 240..600-second window")
    require(type(limit) is int and 1 <= limit <= MAX_REQUESTS, "Invalid request bound")
    generator = random.Random(20260922)
    pre = offsets(generator, rate, warmup, limit)
    measured = offsets(generator, rate, window, limit - len(pre))
    require(measured and any(value < 180000000000 for value in measured)
            and any(value > 180000000000 for value in measured), "Arrival sequence must span the dependency event")
    return {"schema_version": 1, "seed": 20260922, "rate_per_second": rate,
            "warmup_seconds": warmup, "window_seconds": window,
            "warmup_offsets_ns": pre, "measurement_offsets_ns": measured}


def make_plan(args):
    output, cluster = owned(args.output), owned(args.cluster_record)
    require(not output.exists(), "Use a new plan output directory")
    for value in (args.expected_fe_sha256, args.expected_be_sha256):
        require(re.fullmatch(r"[a-f0-9]{64}", value or ""), "Declare original FE and BE artifact SHA256")
    require(args.case_id in ("LP-006", "LP-007") and args.concurrency in (1, 8, 32), "Unsupported frozen workload")
    require(args.query_mode in ("text", "prepared") and args.connection_mode in ("reuse", "per_request"),
            "Explicit query and connection modes are required")
    for value in (args.reader_user, args.admin_user):
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value or ""), "Use simple isolated test account names")
    for value in (args.reader_password_env, args.admin_password_env):
        require(re.fullmatch(r"MASSDB_COMPLEX_[A-Z0-9_]+_PASSWORD", value or ""), "Use dedicated secret environment names")
    require(1 <= args.profile_every_n <= MAX_REQUESTS
            and args.rss_limit_mib == support.resources_module.LIMITS["combined_fixture_rss_bytes"] // (1024 * 1024)
            and 512 <= args.reserve_mib <= 16384 and args.cpu >= 0, "Invalid sampling/resource inputs")
    definition = oracle.verified_definition(json_read(oracle.CONTRACT))
    schedule = arrivals(args.rate, args.warmup_seconds, args.window_seconds, args.request_limit)
    count = len(schedule["warmup_offsets_ns"]) + len(schedule["measurement_offsets_ns"])
    require(count // args.profile_every_n + args.concurrency + PROFILE_OVERLAP_LIMIT + 16 <= MAX_PROFILES,
            "Declared periodic/initial/event profile sampling exceeds archive bound")
    require(JAVA.is_file(), "The same-JVM adapter source must exist before planning")
    sources = [SOURCE, JAVA, Path(oracle.__file__), Path(support.__file__), support.SQL_SOURCE,
               ROOT / "tools/license-checks/stream_load_fixture.py"]
    # Any helper resources imported by the support controller are frozen too.
    resources = SOURCE.with_name("background_http_resources.py")
    if resources.exists():
        sources.append(resources)
    value = {"schema_version": 1, "status": "PLANNED_NOT_RUN", "case_id": args.case_id,
             "created_at_utc": utc(), "output": str(output), "cluster_record": str(cluster),
             "cluster_record_sha256": digest(cluster), "expected_fe_sha256": args.expected_fe_sha256,
             "expected_be_sha256": args.expected_be_sha256, "jdk_runtime_version": args.jdk_runtime_version,
             "mode": args.query_mode, "connection_mode": args.connection_mode, "concurrency": args.concurrency,
             "reader_user": args.reader_user, "admin_user": args.admin_user,
             "reader_password_env": args.reader_password_env, "admin_password_env": args.admin_password_env,
             "request_limit": args.request_limit, "profile_every_n": args.profile_every_n,
             "profile_overlap_limit": PROFILE_OVERLAP_LIMIT,
             "cpu": args.cpu, "rss_limit_mib": args.rss_limit_mib, "reserve_mib": args.reserve_mib,
             "resource_limits": dict(support.resources_module.LIMITS),
             "resource_scope": "whole controller lifecycle and every helper; product services observed separately",
             "rss_limits_are_sampled": True, "may_miss_transient_peaks": True,
             "timeout_seconds": 30, "drain_seconds": 120, "cleanup_seconds": 60,
             "contract_sha256": digest(oracle.CONTRACT), "performance_sha256": digest(PERFORMANCE),
             "source_sha256": {str(path): digest(path) for path in sources},
             "scope": "One original-A functional window; no capacity, precision or license qualification",
             **incomplete()}
    output.mkdir(parents=True, mode=0o700)
    SAVE(output / "definition.json", definition)
    SAVE(output / "arrivals.json", schedule)
    value["definition_sha256"], value["arrival_sha256"] = digest(output / "definition.json"), digest(output / "arrivals.json")
    SAVE(output / "plan.json", value)
    return value


def pin(pid):
    path = Path("/proc") / str(pid)
    stat = (path / "stat").read_text().rsplit(") ", 1)[1].split()
    require(stat[0] not in ("Z", "X"), "A required process is terminal")
    return {"pid": pid, "start_ticks": int(stat[19]), "namespace": os.readlink(path / "ns/net"),
            "exe": str((path / "exe").resolve(strict=True)), "command_sha256": digest(path / "cmdline")}


def same(expected):
    try:
        return pin(expected["pid"]) == expected
    except (OSError, ValueError):
        return False


def source_integrity(sql):
    result = support.rows(sql.one(SOURCE_INTEGRITY))
    expected = {"n": 1000000, "distinct_ids": 1000000, "min_id": 0, "max_id": 999999,
                "sum_id": 499999500000, "sum_grp": 511370976, "sum_v": 49999500000, "bad_rows": 0}
    require(len(result) == 1 and set(result[0]) == set(expected), "Source integrity result shape differs")
    actual = {key: support.integer(value) for key, value in result[0].items()}
    require(actual == expected, "Complete million-row source differs from the original model")
    return actual


def view_definition(sql):
    result = sql.one("SHOW CREATE VIEW " + oracle.VIEW)
    values = support.rows(result)
    names = [column["name"] for column in result["columns"]]
    require(len(values) == 1 and len(names) >= 2 and isinstance(values[0].get(names[1]), str), "Missing view definition")
    return values[0][names[1]]


class JsonLines:
    def __init__(self, path, maximum):
        self.path, self.maximum, self.position, self.pending = Path(path), maximum, 0, b""

    def read(self, final=False):
        if not self.path.exists():
            require(not final, "Missing adapter receipt file")
            return []
        size = self.path.stat().st_size
        require(self.position <= size <= self.maximum, "Adapter receipt was truncated or exceeded its bound")
        with self.path.open("rb") as stream:
            stream.seek(self.position)
            raw = stream.read(min(1024 * 1024, size - self.position))
        self.position += len(raw)
        chunks = (self.pending + raw).split(b"\n")
        self.pending = chunks.pop()
        require(len(self.pending) <= 65536 and all(len(line) <= 65536 for line in chunks), "Oversized receipt line")
        if final and self.position == size:
            require(not self.pending, "Incomplete final adapter JSONL record")
        return [json.loads(line) for line in chunks]


def http_exchange(state, method, path, headers, maximum, seconds, on_headers=None):
    """Bound the entire headers/body exchange, including a peer sending one byte at a time."""
    deadline = time.monotonic() + seconds
    connection = http.client.HTTPConnection("127.0.0.1", state["http_port"], timeout=seconds)
    response = watchdog = None
    try:
        connection.connect()
        transport = connection.sock
        require(transport is not None, "Profile connection has no socket")
        def interrupt():
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        remaining = deadline - time.monotonic()
        require(remaining > 0, "Profile HTTP deadline expired during connect")
        watchdog = threading.Timer(remaining, interrupt)
        watchdog.daemon = True
        watchdog.start()
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        if on_headers:
            on_headers(response.getheaders())
        raw = bytearray()
        while True:
            require(time.monotonic() < deadline, "Profile HTTP absolute deadline expired")
            chunk = response.read1(min(65536, maximum + 1 - len(raw)))
            require(time.monotonic() < deadline, "Profile HTTP absolute deadline expired")
            if not chunk:
                break
            raw.extend(chunk)
            require(len(raw) <= maximum, "Profile HTTP body exceeds bound")
        return response.status, response.getheaders(), bytes(raw)
    finally:
        if watchdog:
            watchdog.cancel()
            watchdog.join(timeout=1)
        if response:
            response.close()
        connection.close()


def profile_http(state, username, password_env, query_id):
    require(re.fullmatch(oracle.QUERY_ID, query_id), "Invalid profile query ID")
    support.validate_live_identity(state)
    secret = os.environ[password_env]
    token = base64.b64encode((username + ":" + secret).encode()).decode()
    session = None
    def capture_cookie(headers):
        nonlocal session
        for key, value in headers:
            if key.lower() == "set-cookie":
                cookie = SimpleCookie()
                cookie.load(value)
                if "PALO_SESSION_ID" in cookie:
                    session = cookie["PALO_SESSION_ID"].value
    try:
        status, _, raw = http_exchange(state, "GET", "/api/profile/text?query_id=" + query_id,
                                       {"Authorization": "Basic " + token}, MAX_PROFILE_BYTES, 10, capture_cookie)
        require(status == 200, "Profile HTTP status is not 200")
        require(not secret or secret.encode() not in raw, "Profile unexpectedly contains the test credential")
        support.validate_live_identity(state)
        return raw.decode("utf-8")
    finally:
        if session is not None:
            support.validate_live_identity(state)
            status, _, body = http_exchange(state, "POST", "/rest/v1/logout",
                                            {"Cookie": "PALO_SESSION_ID=" + session}, 4096, 3)
            require(status == 200 and json.loads(body).get("code") == 0,
                    "Profile authentication session logout was not confirmed")


class Profiles:
    def __init__(self, state, plan, output, definition):
        self.state, self.plan, self.output, self.definition = state, plan, output, definition
        self.pending = queue.Queue(maxsize=MAX_PROFILES)
        self.seen, self.results, self.failures, self.total = set(), {}, [], 0
        self.stop = threading.Event()
        self.close_deadline = None
        self.thread = threading.Thread(target=self.work, name="complex-profile-collector", daemon=True)

    def add(self, record):
        if record.get("sample_profile") is not True or record.get("success") is not True:
            return
        identifier = record.get("query_id")
        require(isinstance(identifier, str) and re.fullmatch(oracle.QUERY_ID, identifier), "Sample has no target query ID")
        require(identifier not in self.seen and len(self.seen) < MAX_PROFILES, "Duplicate/excess sampled query ID")
        self.seen.add(identifier)
        self.pending.put_nowait(record)

    def work(self):
        while not self.stop.is_set() or not self.pending.empty():
            try:
                record = self.pending.get(timeout=0.2)
            except queue.Empty:
                continue
            query_id = record["query_id"]
            try:
                require(self.close_deadline is None or time.monotonic() < self.close_deadline,
                        "Profile cleanup drain deadline expired; receipt remains unverified")
                deadline = time.monotonic() + 30
                attempt = 0
                while True:
                    raw = profile_http(self.state, self.plan["admin_user"], self.plan["admin_password_env"], query_id)
                    encoded = raw.encode("utf-8")
                    require(self.total + len(encoded) <= MAX_PROFILE_TOTAL, "Combined profile archive exceeds bound")
                    self.total += len(encoded)
                    path = self.output / ("profile-" + query_id + "-" + str(attempt) + ".txt")
                    path.write_bytes(encoded)
                    attempt += 1
                    if raw.strip() == "query id " + query_id + " not found" or "   - Task State: RUNNING\n" in raw:
                        require(time.monotonic() < deadline and not self.stop.is_set(), "Profile remained incomplete")
                        self.stop.wait(0.2)
                        continue
                    cache = re.findall(r"(?m)^[ \t]*- Is Cached: (Yes|No)[ \t]*$", raw)
                    require(len(cache) == 1, "Missing or ambiguous cache evidence")
                    proof = oracle.verify_profile(raw, query_id, self.definition["query_sql"], cached=cache[0] == "Yes")
                    if self.plan["case_id"] == "LP-006":
                        require(proof["cached"] is False, "Cold workload unexpectedly used the SQL cache")
                    self.results[query_id] = {"path": path.name, "sha256": digest(path), "proof": proof,
                                              "request_id": record["request_id"]}
                    break
            except BaseException as error:
                self.failures.append({"query_id": query_id, "request_id": record.get("request_id"),
                                      "error_class": type(error).__name__})
            finally:
                self.pending.task_done()

    def close(self):
        if self.close_deadline is None:
            self.close_deadline = time.monotonic() + 15
        self.stop.set()
        self.thread.join(timeout=max(0, self.close_deadline - time.monotonic()) + 14)
        require(not self.thread.is_alive() and self.pending.empty(), "Profile collector did not drain/stop")
        require(not self.failures and len(self.results) == len(self.seen), "One or more selected profiles are missing")


def result_audit(output, definition, plan, profile_results):
    start = json_read(output / "measurement-start.json")
    schedule = json_read(output / "arrivals.json")
    require(isinstance(start.get("clock_domain"), str) and start["clock_domain"], "Missing actual JVM clock identity")
    require(type(start.get("warmup_start_ns")) is int and type(start.get("measurement_start_ns")) is int
            and start["measurement_start_ns"] >= start["warmup_start_ns"] + schedule["warmup_seconds"] * 1000000000,
            "Warmup and measurement epoch boundaries are inconsistent")
    event = json_read(output / "event.json") if plan["case_id"] == "LP-007" else None
    if event:
        require(event.get("ddl_success") is True and event.get("clock_domain") == start.get("clock_domain"),
                "No successful same-JVM dependency event")
        require(event["scheduled_ns"] == start["measurement_start_ns"] + 180000000000,
                "Dependency event was not scheduled at the frozen 180-second offset")
        require(event["started_ns"] >= event["scheduled_ns"], "DDL began before its declared event time")
        require(event.get("sql") == "ALTER VIEW " + oracle.VIEW
                + " AS SELECT id, grp, v + 1 AS v, payload FROM license_perf.point_rows"
                and event.get("commit_outcome") == "ACKNOWLEDGED" and event.get("ddl_attempted") is True
                and event.get("post_ddl_inspection_success") is True, "Unexpected or unconfirmed view mutation")
    records, identities, terminal = JsonLines(output / "requests.jsonl", MAX_RECEIPTS_BYTES), set(), {}
    counts, models, phases = {}, {}, {}
    overlaps = set()
    sampled, explained, arrival_indices, query_ids = {}, {}, {"warmup": set(), "measurement": set()}, set()
    while records.position < (output / "requests.jsonl").stat().st_size:
        for record in records.read(final=True):
            identifier = record["request_id"]
            require(type(identifier) is int and identifier >= 0 and identifier not in identities, "Duplicate/invalid request ID")
            identities.add(identifier)
            require(record.get("success") is True and record.get("clock_domain") == start.get("clock_domain"),
                    "Failed/incomplete request or foreign clock domain")
            require(record.get("phase") in ("warmup", "measurement"), "Unknown request phase")
            require(record.get("query_sha256_utf8") == definition["query_sha256_utf8"]
                    and record.get("query_id_same_connection") is True
                    and record.get("query_id_sql") == "SELECT last_query_id()",
                    "Target query/connection identity association differs from the fixed protocol")
            phase = record["phase"]
            index = record["arrival_index"]
            scheduled = schedule[phase + "_offsets_ns"]
            require(type(index) is int and 0 <= index < len(scheduled) and index not in arrival_indices[phase],
                    "Duplicate or missing declared arrival index")
            arrival_indices[phase].add(index)
            expected_time = start[phase + "_start_ns"] + scheduled[index]
            require(record.get("scheduled_ns") == expected_time, "Request was not bound to the frozen arrival sequence")
            required_sample = index == 0 or index % plan["profile_every_n"] == 0 \
                or (plan["case_id"] == "LP-007" and index == 1)
            require(not required_sample or record.get("sample_profile") is True,
                    "A mandatory first/periodic/EXPLAIN request lost its profile sample")
            boundaries = [record.get(name) for name in ("request_started_ns", "started_ns", "finished_ns", "request_finished_ns")]
            require(all(type(value) is int for value in boundaries) and boundaries == sorted(boundaries)
                    and boundaries[0] >= expected_time, "Request boundaries omit waiting or connection/fetch/close costs")
            query_id = record.get("query_id")
            require(isinstance(query_id, str) and re.fullmatch(oracle.QUERY_ID, query_id) and query_id not in query_ids,
                    "Missing or reused target query ID")
            query_ids.add(query_id)
            require(record.get("profile_overlap_cap_violation") is False,
                    "Event overlap sampling exceeded its predeclared bound")
            if record.get("event_overlap") is True:
                ordinal = record.get("event_overlap_ordinal")
                require(type(ordinal) is int and 1 <= ordinal <= PROFILE_OVERLAP_LIMIT and ordinal not in overlaps
                        and record.get("sample_profile") is True and record.get("sample_reason") == "event_overlap",
                        "Event overlap receipt lacks its unique bounded profile sample")
                overlaps.add(ordinal)
            proof = oracle.verify_request(record, definition, event)
            if event and record["finished_ns"] >= event["started_ns"] and record["started_ns"] <= event["commit_ack_ns"]:
                require(record.get("event_overlap") is True, "A real event-overlap request lost its required sample")
            counts[record["phase"]] = counts.get(record["phase"], 0) + 1
            models[proof["matched_model"]] = models.get(proof["matched_model"], 0) + 1
            phases[proof["phase"]] = phases.get(proof["phase"], 0) + 1
            terminal[identifier] = record
            if record.get("sample_profile"):
                profile = profile_results.get(record["query_id"])
                require(profile and profile["request_id"] == identifier, "Sampled query has no matching complete profile")
                key = proof["matched_model"] + ("_cached" if profile["proof"]["cached"] else "_cold")
                sampled[key] = sampled.get(key, 0) + 1
            if record.get("explain_file") is not None:
                name = f"explain-request-{identifier}.json"
                require(record["explain_file"] == name, "EXPLAIN path is outside the deterministic request artifact")
                explain = json_read(output / name, 2 * 1024 * 1024)
                require(explain.get("success") is True and explain.get("target_request_id") == identifier
                        and explain.get("target_query_id") == query_id and explain.get("phase") == phase
                        and explain.get("clock_domain") == start["clock_domain"]
                        and explain.get("after_target_query_id_capture") is True
                        and explain.get("sql") == "EXPLAIN PHYSICAL PLAN " + definition["query_sql"],
                        "EXPLAIN artifact is not linked to the same actual request")
                require(isinstance(explain.get("rows"), list) and explain["rows"]
                        and all(isinstance(row, str) for row in explain["rows"]), "Missing actual EXPLAIN rows")
                require(type(explain.get("started_ns")) is int and type(explain.get("finished_ns")) is int
                        and record["finished_ns"] <= explain["started_ns"] <= explain["finished_ns"]
                        <= record["request_finished_ns"], "EXPLAIN observer timing escaped the complete request boundary")
                if any(re.search(r"\bPhysicalSqlCache\b", row) for row in explain["rows"]):
                    explained[proof["matched_model"]] = explained.get(proof["matched_model"], 0) + 1
    require(counts.get("warmup", 0) == len(schedule["warmup_offsets_ns"])
            and counts.get("measurement", 0) == len(schedule["measurement_offsets_ns"]),
            "Missing scheduled requests; no successful subset may replace the declared arrivals")
    intents, sent = JsonLines(output / "request-starts.jsonl", MAX_RECEIPTS_BYTES), set()
    while intents.position < (output / "request-starts.jsonl").stat().st_size:
        for item in intents.read(final=True):
            require(item["request_id"] not in sent, "Duplicate execution intent")
            sent.add(item["request_id"])
            target = terminal.get(item["request_id"])
            require(target and all(item.get(key) == target.get(key) for key in
                    ("phase", "arrival_index", "scheduled_ns", "request_started_ns", "clock_domain")),
                    "Execution intent differs from its complete terminal receipt")
    require(sent == identities, "An execution intent lacks a complete terminal receipt")
    require(set(profile_results) == {value["query_id"] for value in terminal.values() if value.get("sample_profile")},
            "Archived profile set differs from selected target requests")
    needed = {"initial_cold"} if plan["case_id"] == "LP-006" else {
        "initial_cold", "initial_cached", "changed_cold", "changed_cached"}
    require(needed <= set(sampled), "Missing actual cold/cache/invalidation/rebuilt profile phases")
    if event:
        require(phases.get("started_after_commit_ack", 0) > 0, "No new request began after committed view mutation")
        require({"initial", "changed"} <= set(explained), "Missing actual initial/rebuilt PhysicalSqlCache EXPLAIN")
    require(overlaps == set(range(1, len(overlaps) + 1)), "An event overlap sample is missing")
    return {"requests_verified": len(identities), "phase_counts": counts, "model_counts": models,
            "ddl_relation_counts": phases, "profile_phases": sampled, "cache_explain_models": explained,
            "all_33_columns_per_request": True,
            "event_overlap_samples_verified": len(overlaps),
            "ddl_start_lateness_ns": event["started_ns"] - event["scheduled_ns"] if event else None,
            "performance_pass": False}


def setup_audit(output, identity, start, plan):
    records = []
    for worker in range(plan["concurrency"]):
        value = json_read(output / f"worker-setup-{worker}.json", 65536)
        require(value.get("worker") == worker and value.get("success") is True
                and value.get("clock_domain") == identity["clock_domain"]
                and value.get("connection_mode") == plan["connection_mode"], "Worker setup identity mismatch")
        begin, end = value.get("started_ns"), value.get("finished_ns")
        costs = [value.get(key) for key in ("connection_ns", "session_init_ns", "prepare_ns")]
        require(type(begin) is int and type(end) is int and begin <= end <= start["warmup_start_ns"]
                and all(type(cost) is int and cost >= 0 for cost in costs) and sum(costs) <= end - begin,
                "Worker connection setup costs or pre-window boundary are invalid")
        if plan["connection_mode"] == "per_request":
            require(costs == [0, 0, 0], "Per-request mode unexpectedly reused a worker connection")
        records.append(value)
    return records


def verify_sources(plan, output):
    required = {str(path) for path in (SOURCE, JAVA, Path(oracle.__file__), Path(support.__file__), support.SQL_SOURCE,
                SOURCE.with_name("background_http_resources.py"), ROOT / "tools/license-checks/stream_load_fixture.py")}
    require(set(plan["source_sha256"]) == required, "Missing or substituted helper source binding")
    for path, expected in plan["source_sha256"].items():
        require(digest(path) == expected, "Fixture source changed after planning")
    for path, expected in ((oracle.CONTRACT, plan["contract_sha256"]), (PERFORMANCE, plan["performance_sha256"]),
                           (plan["cluster_record"], plan["cluster_record_sha256"]),
                           (output / "arrivals.json", plan["arrival_sha256"]),
                           (output / "definition.json", plan["definition_sha256"])):
        require(digest(path) == expected, "Frozen fixture input changed")


def verify_compiled(output):
    record = json_read(output / "compiled.json")
    require(all(digest(path) == checksum for path, checksum in record["inputs"].items()),
            "Compiled source/dependency/JDK input changed")
    actual = {str(path.relative_to(output / "classes")): digest(path)
              for path in sorted((output / "classes").rglob("*.class"))}
    require(actual == record["classes"], "Compiled class set or bytes changed")


def compile_adapter(state, output, processes):
    classes = output / "classes"
    classes.mkdir()
    dependencies = []
    for prefix in ("mariadb-java-client", "jackson-core", "jackson-databind", "jackson-annotations"):
        found = list((Path(state["package"]) / "fe/lib").glob(prefix + "-*.jar"))
        require(len(found) == 1, "Ambiguous original JDBC/Jackson dependency")
        dependencies += found
    classpath = os.pathsep.join(map(str, [classes, *dependencies]))
    sources = [JAVA, support.SQL_SOURCE]
    java_home = Path(state["java_home"])
    runtime = [java_home / name for name in ("release", "bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so")]
    inputs = {str(path): digest(path) for path in [*sources, *dependencies, *runtime]}
    code, _ = processes.run([Path(state["java_home"]) / "bin/javac", "-J-Xmx256m", "--release", "17",
                             "-encoding", "UTF-8", "-cp", classpath, "-d", classes, *sources], "compile", 120)
    require(code == 0 and all(digest(path) == checksum for path, checksum in inputs.items()), "Adapter compile/input failure")
    compiled = {str(path.relative_to(classes)): digest(path) for path in sorted(classes.rglob("*.class"))}
    require("LicenseComplexPlanningFixture.class" in compiled and "LicenseFixtureSql.class" in compiled,
            "Compiled adapter or SQL helper is missing")
    SAVE(output / "compiled.json", {"inputs": inputs, "classes": compiled, "classpath": classpath})
    return classpath


def monitor(process, output, state, budget, plan, profiles, pins):
    receipts = JsonLines(output / "requests.jsonl", MAX_RECEIPTS_BYTES)
    peak = 0
    with (output / "adapter-resources.jsonl").open("x") as evidence:
        while process.poll() is None:
            budget.checkpoint()
            support.validate_live_identity(state)
            require(all(same(item) for item in pins if item["pid"] != process.pid),
                    "A pinned controller/service process was replaced")
            if not same(pins[-1]) and process.poll() is not None:
                break
            require(same(pins[-1]), "The adapter process identity changed")
            total = 0
            samples = []
            for item in pins:
                path = Path("/proc") / str(item["pid"])
                try:
                    stat = (path / "stat").read_text().rsplit(") ", 1)[1].split()
                    match = re.search(r"(?m)^VmRSS:\s+(\d+) kB$", (path / "status").read_text())
                    if item["pid"] == process.pid and (stat[0] in ("Z", "X") or match is None) and process.poll() is not None:
                        continue
                    require(match is not None, "Live process RSS observation missing")
                    rss = int(match[1])
                except FileNotFoundError:
                    if item["pid"] == process.pid and process.poll() is not None:
                        continue
                    raise
                samples.append({"pid": item["pid"], "rss_kib": rss, "user_ticks": int(stat[11]), "system_ticks": int(stat[12])})
                if item["pid"] in (os.getpid(), process.pid):
                    total += rss
                    try:
                        affinity = os.sched_getaffinity(item["pid"])
                    except ProcessLookupError:
                        if item["pid"] == process.pid and process.poll() is not None:
                            continue
                        raise
                    require(affinity == {plan["cpu"]}, "Helper CPU affinity changed")
            peak = max(peak, total)
            evidence.write(json.dumps({"utc": utc(), "controller_monotonic_ns": time.monotonic_ns(), "samples": samples}) + "\n")
            evidence.flush()
            require(total <= plan["rss_limit_mib"] * 1024, "Controller/adapter sampled RSS exceeded declared budget")
            for name in ("adapter.stdout", "adapter.stderr"):
                require((output / name).stat().st_size <= 2 * 1024 * 1024, "Adapter log exceeds bound")
            for record in receipts.read():
                profiles.add(record)
            require(not profiles.failures, "Selected profile collection failed")
            budget.pause(0.2)
        while receipts.path.exists() and receipts.position < receipts.path.stat().st_size:
            for record in receipts.read(final=True):
                profiles.add(record)
    require(process.returncode == 0, "Adapter exited unsuccessfully; partial receipts are retained")
    return {"sampled_auxiliary_peak_rss_kib": peak, "sampling_seconds": 0.2,
            "unsampled_transient_peaks_excluded": False, "namespace_network_or_allocation_attribution": "not_collected"}


def validate_resource_limits(plan):
    limits = support.resources_module.LIMITS
    require(type(plan.get("rss_limit_mib")) is int
            and plan["rss_limit_mib"] * 1024 * 1024 == limits["combined_fixture_rss_bytes"]
            and plan.get("resource_limits") == limits,
            "Plan must explicitly freeze the complete ResourceGuard budgets and total 2048 MiB RSS limit")


def audit_auxiliary_cleanup(budget, process_receipts, resource_receipt):
    require(budget.resource_failure is None, "Background helper output failure was observed")
    require(resource_receipt.get("complete") is True and resource_receipt.get("failure_count") == 0
            and resource_receipt.get("observer_thread_stopped") is True, "Resource lifecycle evidence is incomplete")
    outputs = list(resource_receipt.get("logs", []))
    for receipt in process_receipts:
        require(receipt.get("stopped") is True and not receipt.get("cleanup_error"), "Helper cleanup failed")
        if "output" in receipt:
            outputs.append(receipt["output"])
    for output in outputs:
        require(output.get("thread_stopped") is True and output.get("errors") == []
                and output.get("eof") == ["stderr", "stdout"], "Background output EOF/drainer cleanup is incomplete")
        counts = output.get("bytes")
        require(isinstance(counts, dict) and set(counts) == {"stdout", "stderr"}
                and all(type(value) is int and 0 <= value <= support.resources_module.LIMITS["output_bytes_per_stream"]
                        for value in counts.values()), "Background output byte accounting differs from its bound")
    return {"complete": True, "output_eof_and_threads_verified": True, "process_receipts": len(process_receipts)}


def finish_auxiliary_resources(resources, processes, budget):
    """Shutdown and resource evidence are independent; neither failure can skip the other."""
    result = {"process_cleanup": [], "resources": {}, "errors": []}
    try:
        result["process_cleanup"] = processes.stop_all()
    except BaseException as error:
        result["errors"].append({"step": "final_helper_shutdown", "error_class": type(error).__name__})
    try:
        result["resources"] = resources.stop()
    except BaseException as error:
        result["errors"].append({"step": "resource_guard_shutdown", "error_class": type(error).__name__})
    try:
        result["audit"] = audit_auxiliary_cleanup(budget, result["process_cleanup"], result["resources"])
    except BaseException as error:
        result["errors"].append({"step": "auxiliary_cleanup_audit", "error_class": type(error).__name__})
    result["complete"] = not result["errors"]
    return result


def probe(args):
    support.no_active_benchmark()
    plan_path = owned(args.plan)
    plan = json_read(plan_path)
    output = owned(plan["output"])
    require(plan_path == output / "plan.json" and not (output / "report.json").exists(), "Frozen plan may run only once")
    require(plan.get("schema_version") == 1 and plan.get("status") == "PLANNED_NOT_RUN"
            and plan.get("case_id") in ("LP-006", "LP-007")
            and type(plan.get("concurrency")) is int and plan["concurrency"] in (1, 8, 32)
            and plan.get("mode") in ("text", "prepared")
            and plan.get("connection_mode") in ("reuse", "per_request"), "Invalid frozen workload settings")
    validate_resource_limits(plan)
    bounds = {"cpu": (0, 1048576), "rss_limit_mib": (2048, 2048), "reserve_mib": (512, 16384),
              "profile_every_n": (1, MAX_REQUESTS), "request_limit": (1, MAX_REQUESTS),
              "timeout_seconds": (1, 30), "drain_seconds": (1, 120), "cleanup_seconds": (1, 60)}
    require(all(type(plan.get(key)) is int and lower <= plan[key] <= upper
                for key, (lower, upper) in bounds.items())
            and plan.get("profile_overlap_limit") == PROFILE_OVERLAP_LIMIT, "Invalid frozen resource/sampling bounds")
    for key in ("reader_user", "admin_user"):
        require(isinstance(plan.get(key), str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", plan[key]),
                "Invalid isolated test account")
    for key in ("reader_password_env", "admin_password_env"):
        require(isinstance(plan.get(key), str) and re.fullmatch(r"MASSDB_COMPLEX_[A-Z0-9_]+_PASSWORD", plan[key]),
                "Invalid isolated credential environment name")
    verify_sources(plan, output)
    definition = oracle.verified_definition(json_read(oracle.CONTRACT))
    require(json_read(output / "definition.json") == definition, "Saved definition differs from independent oracle")
    schedule = json_read(output / "arrivals.json")
    require(schedule == arrivals(schedule["rate_per_second"], schedule["warmup_seconds"], schedule["window_seconds"],
                                  plan["request_limit"]), "Frozen arrivals are not the complete independent sequence")
    count = len(schedule["warmup_offsets_ns"]) + len(schedule["measurement_offsets_ns"])
    require(count // plan["profile_every_n"] + plan["concurrency"] + PROFILE_OVERLAP_LIMIT + 16 <= MAX_PROFILES,
            "Frozen profile sampling exceeds archive bound")
    for key in ("reader_password_env", "admin_password_env"):
        require(plan[key] in os.environ and len(os.environ[plan[key]]) <= 1024, "Explicit bounded test credential is required")
    state = support.cluster_identity(SimpleNamespace(**plan))
    with zipfile.ZipFile(Path(state["package"]) / "fe/lib/doris-fe.jar") as artifact:
        require(not any(name.startswith("org/apache/doris/massdb/license/") for name in artifact.namelist()),
                "Original-A fixture cannot use the candidate license-core artifact")
    require(plan["cpu"] in os.sched_getaffinity(0), "Declared fixture CPU unavailable")
    os.sched_setaffinity(0, {plan["cpu"]})
    available = int(re.search(r"(?m)^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text())[1])
    require(available >= (plan["rss_limit_mib"] + plan["reserve_mib"]) * 1024, "Insufficient declared memory headroom")
    budget = support.Budget(schedule["warmup_seconds"] + schedule["window_seconds"] + 600)
    resources = support.resources_module.ResourceGuard(output, state)
    budget.resources = resources
    processes = support.Processes(budget, output, state["namespace"], resources=resources)
    report = {"status": "RUNNING", "started_at_utc": utc(), "plan_sha256": digest(plan_path), **incomplete()}
    SAVE(output / "report.json", report)
    lock = Path(state["installation"]) / "complex-view-owner.lock"
    token, lock_acquired, created, sql, profiles, process = uuid.uuid4().hex, False, False, None, None, None
    previous = {sig: signal.signal(sig, lambda _s, _f: setattr(budget, "cancelled", True))
                for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        resources.start()
        with lock.open("x") as stream:
            stream.write(token + "\n")
        lock_acquired = True
        verify_sources(plan, output)
        classpath = compile_adapter(state, output, processes)
        verify_sources(plan, output)
        sql = support.Sql(SimpleNamespace(user=plan["admin_user"], password_env=plan["admin_password_env"]),
                          state, output, processes, classpath)
        grants = support.rows(sql.one("SHOW GRANTS"))
        require(len(grants) == 1 and re.search(r"(?i)\badmin_priv\b", grants[0].get("GlobalPrivs", "")),
                "The independent DDL identity lacks actual global ADMIN")
        report["source_before"] = source_integrity(sql)
        report["source_create_before"] = sql.one("SHOW CREATE TABLE license_perf.point_rows")
        tables = support.rows(sql.one("SHOW TABLES FROM license_perf"))
        require(not any("license_complex_view" in row.values() for row in tables), "Refuse to adopt an existing fixed-name view")
        report["create_attempted"] = True
        sql.one(CREATE_VIEW)
        created = True
        initial = view_definition(sql)
        owner = {"schema_version": 1, "view": oracle.VIEW, "view_owner_token": token, "namespace": state["namespace"],
                 "cluster_record_sha256": plan["cluster_record_sha256"], "create_success": True,
                 "initial_show_create_view_sha256": hashlib.sha256(initial.encode()).hexdigest(), "create_sql": CREATE_VIEW}
        SAVE(output / "view-owner.json", owner)
        (output / "view-initial.txt").write_text(initial, encoding="utf-8")
        report["cold_explain_all"] = sql.one("EXPLAIN ALL PLAN " + definition["query_sql"])
        pins = [pin(os.getpid()), pin(state["verified_identity"]["supervisor_pid"])]
        pins += [pin(item["pid"]) for item in state["verified_identity"]["services"].values()]
        config = {key: plan[key] for key in ("case_id", "mode", "connection_mode", "concurrency", "reader_user",
                  "admin_user", "reader_password_env", "admin_password_env", "request_limit", "profile_every_n", "profile_overlap_limit",
                  "timeout_seconds", "drain_seconds", "cleanup_seconds")}
        config.update(namespace=state["namespace"], host_namespace=state["host_namespace"], service_pins=pins,
                      query_port=state["query_port"], output_directory=str(output),
                      definition_file=str(output / "definition.json"), definition_sha256=plan["definition_sha256"],
                      arrival_file=str(output / "arrivals.json"), arrival_sha256=plan["arrival_sha256"],
                      owner_record_file=str(output / "view-owner.json"), controller_owner_record_sha256=digest(output / "view-owner.json"),
                      view_owner_token=token, expected_initial_show_create_view_sha256=owner["initial_show_create_view_sha256"],
                      stop_file=str(output / "stop"))
        SAVE(output / "adapter-config.json", config)
        verify_sources(plan, output)
        verify_compiled(output)
        profiles = Profiles(state, plan, output, definition)
        profiles.thread.start()
        process = processes.start([Path(state["java_home"]) / "bin/java", "-Xmx512m", "-XX:+UseG1GC", "-cp",
                                   classpath, "LicenseComplexPlanningFixture", output / "adapter-config.json"], "adapter", background=True)
        pins.append(pin(process.pid))
        SAVE(output / "live-pins.json", pins)
        report["resource_observation"] = monitor(process, output, state, budget, plan, profiles, pins)
        profiles.close()
        budget.checkpoint()
        report["profiles"] = profiles.results
        report["oracle"] = result_audit(output, definition, plan, profiles.results)
        budget.checkpoint()
        report["adapter_summary"] = json_read(output / "summary.json")
        report["adapter_cleanup"] = json_read(output / "cleanup.json")
        identity = json_read(output / "identity.json")
        ready = json_read(output / "ready.json")
        start = json_read(output / "measurement-start.json")
        require(identity.get("pid") == process.pid and identity.get("start_ticks") == pins[-1]["start_ticks"]
                and identity.get("namespace") == state["namespace"] and identity.get("case_id") == plan["case_id"]
                and identity.get("java_runtime_version") == plan["jdk_runtime_version"]
                and identity.get("definition_sha256") == plan["definition_sha256"]
                and identity.get("arrival_sha256") == plan["arrival_sha256"]
                and identity.get("controller_owner_record_sha256") == digest(output / "view-owner.json")
                and identity.get("view_owner_token") == token
                and all(identity.get(key) == plan[key] for key in
                        ("mode", "connection_mode", "concurrency", "profile_every_n", "profile_overlap_limit")),
                "Actual adapter identity differs from its frozen process/configuration")
        require(ready.get("pid") == process.pid and ready.get("namespace") == state["namespace"]
                and ready.get("clock_domain") == identity.get("clock_domain") == start.get("clock_domain"),
                "Ready/epoch/adapter records belong to different JVM identities")
        summary, cleanup = report["adapter_summary"], report["adapter_cleanup"]
        report["worker_connection_setup"] = setup_audit(output, identity, start, plan)
        require(summary.get("clock_domain") == cleanup.get("clock_domain") == identity["clock_domain"],
                "Summary or cleanup belongs to a different JVM clock domain")
        require(summary.get("success") is True and summary.get("cleanup_success") is True
                and summary.get("event_commit_unknown") is False and summary.get("uncompleted_intents") == 0,
                "Adapter summary contains an error or unknown submission")
        require(cleanup.get("success") is True and cleanup.get("reader_threads_terminated") is True
                and cleanup.get("event_thread_terminated") is True and cleanup.get("cleanup_threads_terminated") is True
                and cleanup.get("deadline_exceeded") is False
                and cleanup.get("remaining_connection_handles") == 0
                and cleanup.get("initial_definition_matches") is True,
                "Adapter connections, threads or view restoration were not confirmed")
        require(summary.get("completed_receipts") == report["oracle"]["requests_verified"]
                and summary.get("request_intents") == report["oracle"]["requests_verified"],
                "Adapter summary counts differ from complete raw receipts")
        require(summary.get("profile_overlap_cap_violation") is False
                and summary.get("profile_overlap_limit") == PROFILE_OVERLAP_LIMIT
                and summary.get("profile_overlap_requests") == summary.get("profile_overlap_samples")
                == report["oracle"]["event_overlap_samples_verified"], "Event overlap sampling summary differs from receipts")
        report["source_after"] = source_integrity(sql)
        report["source_create_after"] = sql.one("SHOW CREATE TABLE license_perf.point_rows")
        require(support.rows(report["source_create_after"]) == support.rows(report["source_create_before"]),
                "Source table definition changed during the probe")
        require(view_definition(sql) == initial, "Adapter did not restore the original view definition")
        verify_sources(plan, output)
        verify_compiled(output)
        budget.checkpoint()
        report["status"] = "FUNCTIONAL_WINDOW_PASS"
    except BaseException as error:
        report["status"], report["failure_class"] = "FAIL", type(error).__name__
    finally:
        urgent = budget.abort_requested()
        budget.begin_cleanup()
        errors = []
        def attempt(name, action):
            try:
                return action()
            except BaseException as error:
                errors.append({"step": name, "error_class": type(error).__name__})
                return None
        if process and process.poll() is None:
            attempt("adapter_stop_marker", lambda: (output / "stop").touch(exist_ok=False))
            if not urgent:
                attempt("adapter_graceful_stop", lambda: process.wait(timeout=plan["cleanup_seconds"] + 5))
        report["process_cleanup"] = attempt("initial_helper_shutdown", processes.stop_all) or []
        if profiles:
            attempt("profile_collector_stop", profiles.close)
            report["profiles"], report["profile_failures"] = profiles.results, profiles.failures
        if created and sql:
            attempt("drop_owned_view", lambda: sql.one("DROP VIEW " + oracle.VIEW))
            def absent():
                values = support.rows(sql.one("SHOW TABLES FROM license_perf"))
                require(not any("license_complex_view" in row.values() for row in values), "Owned view remains")
            attempt("owned_view_absent", absent)
        elif report.get("create_attempted"):
            errors.append({"step": "uncertain_view_creation", "error_class": "UnknownCommit"})
        # Keep the observer through SQL/profile/audit cleanup and stop all newly created SQL helpers first.
        final_resources = finish_auxiliary_resources(resources, processes, budget)
        report["process_cleanup"] = final_resources["process_cleanup"]
        report["resources"] = final_resources["resources"]
        report["auxiliary_cleanup"] = final_resources.get("audit")
        errors.extend(final_resources["errors"])
        if lock_acquired:
            def release():
                require(lock.read_text() == token + "\n", "Ownership lock changed")
                lock.unlink()
            attempt("release_owned_lock", release)
        if any(not item.get("stopped") or item.get("cleanup_error") for item in report["process_cleanup"]):
            errors.append({"step": "helper_processes", "error_class": "IncompleteProcessCleanup"})
        report["cleanup_errors"] = errors
        if errors:
            report["status"] = "FAIL"
        report["finished_at_utc"] = utc()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        SAVE(output / "report.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "probe"), default="plan")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cluster-record", type=Path)
    parser.add_argument("--expected-fe-sha256")
    parser.add_argument("--expected-be-sha256")
    parser.add_argument("--jdk-runtime-version", default="17.0.4+8")
    parser.add_argument("--case-id", choices=("LP-006", "LP-007"), default="LP-007")
    parser.add_argument("--query-mode", choices=("text", "prepared"), default="text")
    parser.add_argument("--connection-mode", choices=("reuse", "per_request"), default="reuse")
    parser.add_argument("--concurrency", type=int, choices=(1, 8, 32), default=8)
    parser.add_argument("--rate", type=float)
    parser.add_argument("--warmup-seconds", type=int, default=180)
    parser.add_argument("--window-seconds", type=int, default=600)
    parser.add_argument("--request-limit", type=int, default=MAX_REQUESTS)
    parser.add_argument("--profile-every-n", type=int, default=10)
    parser.add_argument("--reader-user", default="root")
    parser.add_argument("--admin-user", default="root")
    parser.add_argument("--reader-password-env", default="MASSDB_COMPLEX_READER_PASSWORD")
    parser.add_argument("--admin-password-env", default="MASSDB_COMPLEX_ADMIN_PASSWORD")
    parser.add_argument("--cpu", type=int, default=5)
    parser.add_argument("--rss-limit-mib", type=int, default=2048)
    parser.add_argument("--reserve-mib", type=int, default=2048)
    args = parser.parse_args(argv)
    try:
        require(args.plan if args.mode == "probe" else args.output and args.cluster_record and args.rate is not None,
                "Provide a frozen plan or explicit new plan inputs")
        result = probe(args) if args.mode == "probe" else make_plan(args)
        print(json.dumps({"status": result["status"], **incomplete()}))
        return 0 if result["status"] in ("PLANNED_NOT_RUN", "FUNCTIONAL_WINDOW_PASS") else 2
    except Exception as error:
        print(json.dumps({"status": "FAIL", "error_class": type(error).__name__, **incomplete()}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
