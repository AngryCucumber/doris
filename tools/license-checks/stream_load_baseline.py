#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""One complete, non-replayed LP012 original-A offered-rate window; default is plan only."""

import argparse
import asyncio
import base64
from collections import deque
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import threading
import time
from types import SimpleNamespace
from urllib.parse import unquote, urlsplit
import uuid
import zipfile

import background_http_fixture as support
import resource_observer as observer
import stream_load_fixture as fixture
import p4_statistics as p4


ROOT = fixture.ROOT
SOURCE = Path(__file__).resolve()
PERFORMANCE = ROOT / "docs/license-performance-cases-20260922.json"
ROWS, WIDTH, SEED = 10000000, 128, 20260922
NANO = 1000000000
MIB = 1024 * 1024
LIMITS = {"header_bytes": 16384, "response_bytes": 65536, "receipt_archive_bytes": 64 * MIB,
          "metrics_archive_bytes": 64 * MIB, "queue_capacity_model": "unexpired_frozen_arrivals_per_worker_v1",
          "request_seconds_from_arrival": 60, "drain_seconds": 65, "visibility_seconds": 180,
          "server_timeout_seconds": 60,
          "warmup_seconds": 180, "metrics_interval_seconds": 5, "metrics_endpoint_seconds": 2,
          "minimum_free_disk_bytes": ROWS * WIDTH + 512 * MIB, "max_sql_calls": 64}
MISSING_METRICS = ["FE total allocated bytes", "individual GC pause distribution",
                   "existing RPC count/bytes with their original metric definitions",
                   "per-process network attribution"]
require = support.require
save = support.save
digest = fixture.digest
owned = fixture.owned


def read_json(path, maximum=2 * MIB):
    with Path(path).open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "JSON evidence exceeds its declared bound")
    return json.loads(raw, object_pairs_hook=unique_object)


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, "Duplicate JSON object key")
        result[key] = value
    return result


def schedule(batch_rows, concurrency, window_seconds):
    require(type(batch_rows) is int and batch_rows in (1000, 10000), "Unsupported LP012 batch size")
    require(type(concurrency) is int and concurrency in (1, 8, 32), "Unsupported LP012 concurrency")
    require(type(window_seconds) is int and 600 <= window_seconds <= 3600,
            "A full measured window must last 600..3600 seconds")
    count = ROWS // batch_rows
    warmup_count = count * LIMITS["warmup_seconds"] // window_seconds
    phases = {}
    for phase, size in (("warmup", warmup_count), ("measurement", count)):
        phases[phase] = [{"index": index, "worker": index % concurrency,
                          "offset_ns": index * window_seconds * NANO // count,
                          "first_id": index * batch_rows, "rows": batch_rows}
                         for index in range(size)]
    return {"schema_version": 1, "seed": SEED, "arrival": "deterministic constant-rate batch spacing",
            "window_seconds": window_seconds, "warmup_seconds": LIMITS["warmup_seconds"],
            "rate_rows_numerator": ROWS, "rate_rows_denominator_seconds": window_seconds,
            "rate_bytes_numerator": ROWS * WIDTH, "rows_replayed_in_measurement": 0,
            "warmup_input": "prefix of the same immutable input, separate empty warmup table",
            "measurement": phases["measurement"], "warmup": phases["warmup"]}


def model_record(identifier):
    # Independent input reconstruction; deliberately do not call the fixture generator's record().
    fields = f"{identifier},{identifier % 1024},{identifier % 100000},"
    suffix = hashlib.md5(str(identifier).encode("ascii"), usedforsecurity=False).hexdigest()
    padding = hashlib.sha256(b"20260922").hexdigest() * 2
    return (fields + suffix + padding[:WIDTH - len(fields) - 33] + "\n").encode("ascii")


def pending_capacities(arrivals, concurrency, deadline_ns):
    require(type(concurrency) is int and concurrency > 0 and type(deadline_ns) is int and deadline_ns > 0,
            "Invalid pending-reference model bounds")
    windows, capacities = [deque() for _ in range(concurrency)], [1] * concurrency
    for item in arrivals:
        worker, offset = item["worker"], item["offset_ns"]
        require(type(worker) is int and 0 <= worker < concurrency and type(offset) is int and offset >= 0,
                "Invalid pending-reference arrival")
        window = windows[worker]
        require(not window or offset >= window[-1], "Pending-reference arrivals must be ordered per worker")
        # Equality is expired: the HTTP executor also requires completion strictly before the deadline.
        while window and window[0] + deadline_ns <= offset:
            window.popleft()
        window.append(offset)
        capacities[worker] = max(capacities[worker], len(window))
    return capacities


def queue_model(arrivals, concurrency):
    deadline_ns = LIMITS["request_seconds_from_arrival"] * NANO
    return {"schema_version": 1, "model": LIMITS["queue_capacity_model"],
            "deadline_ns": deadline_ns, "expiration": "scheduled_ns + deadline_ns <= observed_ns",
            "capacities": {phase: pending_capacities(arrivals[phase], concurrency, deadline_ns)
                           for phase in ("warmup", "measurement")},
            "capacity_basis": "Maximum arrivals per worker in (t - deadline_ns, t]; references only",
            "active_request_limit": concurrency, "body_read_policy": "Only an active unexpired request reads its batch"}


def unsent_result(item, phase, epoch, status, observed_ns):
    return {**item, "phase": phase, "status": status, "scheduled_monotonic_ns": epoch + item["offset_ns"],
            "decision_monotonic_ns": observed_ns, "server_transaction_state": "NOT_SUBMITTED_TO_BE",
            "server_transaction_termination_not_proven": False}


def expire_pending(queue, results, phase, epoch, observed_ns):
    retained = []
    for _ in range(queue.qsize()):
        item = queue.get_nowait()
        try:
            if epoch + item["offset_ns"] + LIMITS["request_seconds_from_arrival"] * NANO <= observed_ns:
                results[item["index"]] = unsent_result(item, phase, epoch, "DEADLINE_EXPIRED_NOT_SENT", observed_ns)
            else:
                retained.append(item)
        finally:
            queue.task_done()
    # This synchronous operation never yields between removing and restoring live references.
    for item in retained:
        queue.put_nowait(item)


def input_binding(path):
    path = owned(path)
    require(path.is_file() and path.stat().st_size == ROWS * WIDTH, "Require the complete 10M x 128-byte input")
    manifest_path = path.with_suffix(path.suffix + ".json")
    value = read_json(manifest_path)
    require(value.get("case_id") == "LP-012" and value.get("rows") == ROWS and value.get("seed") == SEED
            and value.get("row_bytes_including_lf") == WIDTH and value.get("input_bytes") == ROWS * WIDTH
            and value.get("columns") == ["id", "grp", "v", "payload"] and value.get("id_start") == 0
            and owned(value.get("input_path", "")) == path
            and re.fullmatch(r"[a-f0-9]{64}", value.get("input_sha256", "")), "Invalid complete LP012 input manifest")
    return {"path": str(path), "manifest": str(manifest_path), "manifest_sha256": digest(manifest_path),
            "sha256": value["input_sha256"], "bytes": ROWS * WIDTH, "rows": ROWS,
            "content_checked_at_plan_time": False}


def frozen_files(cluster, expected_fe, expected_be, runtime, variant="A", current=False):
    state = read_json(cluster)
    installation = owned(state["installation"])
    package = Path(state["package"]).resolve(strict=True)
    require(ROOT in package.parents, "Original distribution must belong to this checkout")
    if current:
        require(os.path.samefile(installation / "fe/lib/doris-fe.jar", package / "fe/lib/doris-fe.jar"),
                "Current G4 must bind the installed FE JAR slot, including its package symlink")
    java_home = Path(state["java_home"]).resolve(strict=True)
    release = dict(re.findall(r'^([A-Z_]+)="([^"]*)"$', (java_home / "release").read_text(), re.M))
    support.validate_jdk_release(release, runtime)
    require(state["namespace"] != state["host_namespace"], "Require a private recorded namespace")
    sources = [SOURCE, Path(support.__file__), Path(support.resources_module.__file__), Path(observer.__file__),
               Path(fixture.__file__), support.SQL_SOURCE, PERFORMANCE]
    jars = sorted((package / "fe/lib").glob("*.jar"))
    require(jars, "Original package has no FE jars")
    paths = sources + jars + [package / "be/lib/doris_be", java_home / "release",
                             java_home / "bin/java", java_home / "bin/javac",
                             java_home / "lib/modules", java_home / "lib/server/libjvm.so",
                             installation / "fe/conf/fe.conf", installation / "be/conf/be.conf"]
    files = {str(path.resolve()): digest(path) for path in paths}
    require(state["fe_jar_sha256"] == expected_fe == files[str((package / "fe/lib/doris-fe.jar").resolve())]
            and state["be_binary_sha256"] == expected_be == files[str((package / "be/lib/doris_be").resolve())],
            "Explicit original distribution digests differ")
    with zipfile.ZipFile(package / "fe/lib/doris-fe.jar") as archive:
        licensed = any(name.startswith("org/apache/doris/massdb/license/") for name in archive.namelist())
        require(variant in ("A", "B") and licensed == (variant == "B"),
                "Original-A/candidate-B license-core artifact policy mismatch")
    pins = {}
    for component in ("fe", "be"):
        pid = int((installation / component / "bin" / (component + ".pid")).read_text())
        pins[component] = support.resources_module.process_identity(pid)
    pins["supervisor"] = support.resources_module.process_identity(int(state["supervisor_pid"]))
    require(all(pin["namespace"] == state["namespace"] for pin in pins.values()), "Original service namespace mismatch")
    require(pins["fe"]["executable"] == str((java_home / "bin/java").resolve())
            and pins["be"]["executable"] == str((package / "be/lib/doris_be").resolve()),
            "Live original executables differ from the frozen package and JDK")
    return {"files": files, "package": str(package), "java_home": str(java_home),
            "jar_paths": [str(path.resolve()) for path in jars], "pins": pins,
            "namespace": state["namespace"], "jdk_release": release}


def make_plan(args):
    require(args.output is not None and args.cluster_record is not None and args.input is not None,
            "Plan requires output, cluster record, and an existing complete input")
    for value in (args.expected_fe_sha256, args.expected_be_sha256):
        require(re.fullmatch(r"[a-f0-9]{64}", value or ""), "Declare both original artifact SHA256 values")
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", args.user or ""), "Select a simple isolated test account")
    require(re.fullmatch(r"MASSDB_STREAM_[A-Z0-9_]+_PASSWORD", args.password_env or ""),
            "Use a dedicated Stream Load password environment variable")
    require(type(args.cpu) is int and args.cpu >= 0, "Declare a CPU for the client")
    output, cluster = owned(args.output), owned(args.cluster_record)
    require(not output.exists(), "A plan requires a new evidence directory")
    arrivals = schedule(args.batch_rows, args.concurrency, args.window_seconds)
    value = {"schema_version": 1, "case_id": "LP-012", "status": "PLANNED_NOT_RUN", "output": str(output),
             "cluster_record": str(cluster), "cluster_record_sha256": digest(cluster), "input": input_binding(args.input),
             "expected_fe_sha256": args.expected_fe_sha256, "expected_be_sha256": args.expected_be_sha256,
             "jdk_runtime_version": args.jdk_runtime_version, "cpu": args.cpu, "concurrency": args.concurrency,
             "batch_rows": args.batch_rows, "window_seconds": args.window_seconds, "user": args.user,
             "password_env": args.password_env, "limits": dict(LIMITS),
             "queue_model": queue_model(arrivals, args.concurrency),
             "resource_limits": dict(support.resources_module.LIMITS), "missing_metrics": MISSING_METRICS,
             "bindings": frozen_files(cluster, args.expected_fe_sha256, args.expected_be_sha256, args.jdk_runtime_version),
             "created_at_utc": fixture.utc(), "LP012_complete": False, "release_performance_pass": False,
             "full_contract_retained": {"rows": ROWS, "concurrency": [1, 8, 32], "batch_rows": [1000, 10000],
                                        "minimum_AA_pairs": 5, "minimum_AB_pairs": 5,
                                        "minimum_completed_operations_for_P99_per_window": 10000}}
    output.mkdir(parents=True, mode=0o700)
    save(output / "arrivals.json", arrivals)
    value["arrivals_sha256"] = digest(output / "arrivals.json")
    save(output / "plan.json", value)
    return value


def verify_frozen(plan):
    require(digest(owned(plan["cluster_record"])) == plan["cluster_record_sha256"], "Cluster record changed")
    current = plan.get("profile") == "current-g4"
    require((g4_input_binding(plan["input"]["path"]) if current else input_binding(plan["input"]["path"]))
            == plan["input"], "Input manifest or size changed")
    actual = frozen_files(owned(plan["cluster_record"]), plan["expected_fe_sha256"],
                          plan["expected_be_sha256"], plan["jdk_runtime_version"],
                          plan["context"]["variant"] if current else "A", current=current)
    require(actual == plan["bindings"], "Frozen sources, configurations, JDK, package inventory or original pins changed")
    if current:
        for item in plan["current_bindings"].values():
            p4.verify_reference(item)


def prepare_batches(plan, output, budget):
    directory = output / "batches"
    directory.mkdir()
    checksum, entries = hashlib.sha256(), []
    count, size = ROWS // plan["batch_rows"], plan["batch_rows"] * WIDTH
    require(shutil.disk_usage(output).free >= LIMITS["minimum_free_disk_bytes"], "Insufficient bounded evidence disk space")
    with owned(plan["input"]["path"]).open("rb") as stream:
        for index in range(count):
            budget.checkpoint()
            data = stream.read(size)
            require(len(data) == size, "Complete fixture was truncated")
            for offset in range(plan["batch_rows"]):
                start = offset * WIDTH
                require(data[start:start + WIDTH] == model_record(index * plan["batch_rows"] + offset),
                        "Fixture contents differ from the independent complete model")
            checksum.update(data)
            path = directory / f"batch-{index:05d}.csv"
            with path.open("xb") as target:
                require(target.write(data) == size, "Incomplete prepared batch write")
            entries.append({"index": index, "path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
                            "bytes": size, "rows": plan["batch_rows"], "first_id": index * plan["batch_rows"]})
        require(stream.read(1) == b"", "Unexpected trailing fixture bytes")
    require(checksum.hexdigest() == plan["input"]["sha256"], "Complete fixture digest changed")
    save(output / "batches.json", {"rows": ROWS, "source_sha256": checksum.hexdigest(), "batches": entries,
                                   "every_input_byte_checked_against_independent_model": True,
                                   "preparation_inside_timed_window": False})
    return entries


def compile_sql(plan, state, output, processes):
    classes = output / "classes"
    classes.mkdir()
    jars = []
    for prefix in ("mariadb-java-client", "jackson-core", "jackson-databind", "jackson-annotations"):
        matches = [path for path in plan["bindings"]["jar_paths"] if Path(path).name.startswith(prefix + "-")]
        require(len(matches) == 1, "Ambiguous original SQL helper dependency")
        jars.extend(matches)
    classpath = os.pathsep.join([str(classes), *jars])
    code, _ = processes.run([Path(state["java_home"]) / "bin/javac", "-J-Xmx256m", "--release", "17",
                             "-encoding", "UTF-8", "-cp", classpath, "-d", classes, support.SQL_SOURCE], "compile-sql", 90)
    require(code == 0, "Original-JDK SQL helper compilation failed")
    value = {str(path): digest(path) for path in sorted(classes.rglob("*.class"))}
    require(str(classes / "LicenseFixtureSql.class") in value, "SQL helper class missing")
    save(output / "compiled-helper.json", {"classes": value, "classpath": classpath,
                                          "jdk": plan["bindings"]["java_home"], "dependencies": jars})
    return classpath, value


class OracleSql(support.Sql):
    def __init__(self, plan, state, output, processes, classpath, classes):
        super().__init__(SimpleNamespace(user=plan["user"], password_env=plan["password_env"]),
                         state, output, processes, classpath)
        self.plan, self.classes = plan, classes
        self.dependencies = [path for path in classpath.split(os.pathsep) if path.endswith(".jar")]

    def execute(self, statements, continue_on_error=False):
        maximum = LIMITS["max_sql_calls"] + (10 if self.processes.budget.cleanup else 0)
        require(self.sequence < maximum, "SQL observation count exceeded its frozen bound")
        for path, checksum in self.classes.items():
            require(digest(path) == checksum, "Compiled SQL helper changed")
        for path in self.dependencies:
            require(digest(path) == self.plan["bindings"]["files"][path], "Original helper classpath changed")
        for name in ("java", "javac"):
            path = str((Path(self.state["java_home"]) / "bin" / name).resolve())
            require(digest(path) == self.plan["bindings"]["files"][path], "Bound JDK executable changed")
        return super().execute(statements, continue_on_error)


class Archive:
    def __init__(self, output, maximum=LIMITS["receipt_archive_bytes"]):
        self.output, self.maximum, self.used = output, maximum, 0

    def write(self, name, data):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name), "Invalid evidence basename")
        require(self.used + len(data) <= self.maximum, "HTTP evidence archive byte bound exceeded")
        self.used += len(data)  # Reserve before writing, including a failed or partial write.
        with (self.output / name).open("xb") as stream:
            require(stream.write(data) == len(data), "Partial HTTP evidence write")
        return {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class Metrics:
    def __init__(self, output, state, be_port, resources):
        self.state, self.resources = state, resources
        self.output, self.phase = output, "setup"
        self.event, self.thread, self.stream = threading.Event(), None, None
        self.bytes, self.samples, self.errors, self.skipped = 0, 0, [], 0
        self.terminal_interrupted_samples = 0
        self.pins = {name: {"pid": value["pid"], "start_ticks": int(value["start_ticks"]),
                           "http_port": state["http_port"] if name == "fe" else be_port}
                     for name, value in state["verified_identity"]["services"].items()}

    def start(self):
        self.stream = (self.output / "existing-metrics.jsonl").open("xb")
        def run():
            due = time.monotonic()
            try:
                while not self.event.is_set():
                    if self.event.wait(max(0, due - time.monotonic())):
                        break
                    support.validate_live_identity(self.state)
                    value = observer.collect_sample(self.state, self.pins, LIMITS["metrics_endpoint_seconds"], self)
                    value["phase"] = self.phase
                    support.validate_live_identity(self.state)
                    raw = (json.dumps(value, separators=(",", ":")) + "\n").encode()
                    require(self.bytes + len(raw) <= LIMITS["metrics_archive_bytes"], "Metric archive bound exceeded")
                    self.bytes += len(raw)
                    require(self.stream.write(raw) == len(raw), "Partial metrics write")
                    self.stream.flush()
                    self.samples += 1
                    terminal = self.event.is_set() and value["errors"] and all(
                        item.get("type") == "InterruptedBeforeScrape" for item in value["errors"])
                    if terminal:
                        self.terminal_interrupted_samples += 1
                    require(not value["errors"] or terminal, "Existing metrics/proc observation failed")
                    due += LIMITS["metrics_interval_seconds"]
                    if time.monotonic() > due:
                        missed = int((time.monotonic() - due) // LIMITS["metrics_interval_seconds"]) + 1
                        self.skipped += missed
                        due += missed * LIMITS["metrics_interval_seconds"]
            except BaseException as error:
                self.errors.append(type(error).__name__)
                self.resources.fail("lp012_existing_metrics", type(error).__name__)
        self.thread = threading.Thread(target=run, name="lp012-existing-metrics", daemon=True)
        self.thread.start()

    def boundary(self, label):
        support.validate_live_identity(self.state)
        before = time.monotonic_ns()
        processes = {name: support.resources_module.sample_process(pin)
                     for name, pin in self.resources.state["lp012_pins"].items() if name in ("fe", "be")}
        value = {"label": label, "started_monotonic_ns": before, "finished_monotonic_ns": time.monotonic_ns(),
                 "processes": processes, "atomic_across_processes": False,
                 "namespace_network": support.resources_module.network_values(
                     support.resources_module.bounded_read("/proc/net/dev"))}
        support.validate_live_identity(self.state)
        save(self.output / (label + "-boundary.json"), value)
        return value

    def stop(self):
        self.event.set()
        if self.thread:
            self.thread.join(timeout=6)
        stopped = not self.thread or not self.thread.is_alive()
        if self.stream and stopped:
            self.stream.close()
        return {"samples": self.samples, "errors": self.errors, "skipped_slots": self.skipped,
                "thread_stopped": stopped, "evidence_bytes_reserved": self.bytes,
                "terminal_interrupted_samples": self.terminal_interrupted_samples,
                "complete": stopped and self.samples > self.terminal_interrupted_samples and not self.errors and self.skipped == 0,
                "missing_metrics": MISSING_METRICS,
                "GC_time_is_cumulative_collection_time_not_pause_histogram": True,
                "network_scope": "whole private namespace, including clients and observers; RX+TX not summed",
                "observer_cost_included_in_service_measurement": True}


class LateIo(ValueError):
    def __init__(self, result):
        super().__init__("I/O completed after the absolute request deadline")
        self.result = result


class LateBody(ValueError):
    def __init__(self, body):
        super().__init__("Complete response body arrived after the request deadline")
        self.body = body


class ResponseInterrupted(asyncio.CancelledError):
    def __init__(self, response):
        super().__init__("Cancellation during close after a complete HTTP response")
        self.response = response


async def wait_io(awaitable, deadline, budget, clock=time.monotonic, on_result=None):
    task = asyncio.ensure_future(awaitable)
    delivered = False
    try:
        while True:
            budget.checkpoint()
            remaining = deadline - clock()
            require(remaining > 0, "Absolute HTTP request deadline expired")
            done, _ = await asyncio.wait((task,), timeout=min(.2, remaining))
            if done:
                result = task.result()
                if on_result:
                    on_result(result)
                    delivered = True
                budget.checkpoint()
                if clock() >= deadline:
                    raise LateIo(result)
                return result
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        # A connection can finish at the same instant the caller is cancelled. Keep its writer
        # before propagating any deadline, resource or cancellation error to the owner.
        if on_result and not delivered and task.done() and not task.cancelled() and task.exception() is None:
            on_result(task.result())


async def read_headers(reader, deadline, budget):
    line = await wait_io(reader.readline(), deadline, budget)
    require(re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9][0-9](?: [^\r\n]*)?\r\n", line), "Malformed HTTP status line")
    status, size, fields = int(line.split()[1]), len(line), {}
    while True:
        line = await wait_io(reader.readline(), deadline, budget)
        size += len(line)
        require(size <= LIMITS["header_bytes"] and line.endswith(b"\r\n"), "Malformed or oversized HTTP headers")
        if line == b"\r\n":
            return status, fields
        key, separator, raw = line[:-2].partition(b":")
        require(separator and re.fullmatch(rb"[A-Za-z0-9_-]+", key), "Invalid HTTP header name")
        key = key.decode("ascii").lower()
        value = raw.strip().decode("latin1")
        if key == "vary":
            # The original FE sends three Vary field lines. Vary is a list, unlike the
            # framing, routing and authentication fields below; preserve its combined value.
            names = [name.strip() for name in value.split(",") if name.strip()]
            require(all(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) for name in names)
                    and ("*" not in names or names == ["*"]), "Invalid Vary field list")
            prior = fields.get(key, "")
            fields[key] = "*" if value == "*" or prior == "*" else ", ".join(part for part in (prior, ", ".join(names)) if part)
        else:
            # Keep unknown repeated fields fail-closed too; this exception is only for Vary.
            require(key not in fields, "Ambiguous duplicate HTTP header")
            fields[key] = value


async def read_body(reader, headers, deadline, budget):
    require(not ("content-length" in headers and "transfer-encoding" in headers), "Ambiguous HTTP body framing")
    result = bytearray()
    async def take(size):
        require(0 <= size <= LIMITS["response_bytes"] - len(result), "HTTP body exceeds its byte bound")
        result.extend(await wait_io(reader.readexactly(size), deadline, budget))
    if "transfer-encoding" in headers:
        require(headers["transfer-encoding"].lower() == "chunked", "Unsupported HTTP transfer encoding")
        while True:
            line = await wait_io(reader.readline(), deadline, budget)
            require(len(line) <= 128 and re.fullmatch(rb"[0-9A-Fa-f]+\r\n", line), "Invalid chunk length")
            count = int(line.strip(), 16)
            if not count:
                # No trailers are expected from the existing Stream Load endpoint.
                require(await wait_io(reader.readline(), deadline, budget) == b"\r\n", "Unexpected HTTP trailer")
                break
            await take(count)
            require(await wait_io(reader.readexactly(2), deadline, budget) == b"\r\n", "Invalid chunk delimiter")
    elif "content-length" in headers:
        require(re.fullmatch(r"[0-9]+", headers["content-length"]), "Invalid content length")
        size = int(headers["content-length"])
        try:
            await take(size)
        except LateIo as error:
            if isinstance(error.result, bytes) and len(error.result) == size:
                raise LateBody(error.result) from None
            raise
    else:
        while True:
            data = await wait_io(reader.read(min(4096, LIMITS["response_bytes"] + 1 - len(result))), deadline, budget)
            if not data:
                break
            result.extend(data)
            require(len(result) <= LIMITS["response_bytes"], "HTTP body exceeds its byte bound")
    return bytes(result)


async def close_transport(writer, trace, budget):
    task = asyncio.create_task(writer.wait_closed())
    cancelled = None
    try:
        writer.close()
        await asyncio.wait_for(asyncio.shield(task), timeout=1)
        trace["local_transport_closed"] = True
    except BaseException as error:
        trace["close_error_class"] = type(error).__name__
        if isinstance(error, asyncio.CancelledError):
            cancelled = error
        try:
            writer.transport.abort()
            trace["transport_abort_requested"] = True
            await asyncio.wait_for(asyncio.shield(task), timeout=1)
            trace["local_transport_closed"] = True
        except BaseException as abort_error:
            trace["abort_close_error_class"] = type(abort_error).__name__
            budget.resource_failure = ("lp012_http_transport", "unconfirmed_close")
            if isinstance(abort_error, asyncio.CancelledError):
                cancelled = abort_error
    finally:
        if not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout=.2)
            except BaseException as error:
                trace["close_task_error_class"] = type(error).__name__
                if isinstance(error, asyncio.CancelledError):
                    cancelled = error
        trace["close_task_terminated"] = task.done()
    if cancelled is not None:
        raise cancelled


def redirect_port(location, path, plan, state, be_port):
    target = urlsplit(location)
    require(target.scheme == "http" and target.hostname == "127.0.0.1" and target.port == be_port
            and target.path == path and not target.query and not target.fragment,
            "FE redirect left the exact owned BE endpoint")
    secret = os.environ[plan["password_env"]]
    require((target.username is None or unquote(target.username) == plan["user"])
            and (target.password is None or unquote(target.password) == secret), "FE redirect changed the account")
    return target.port


async def exchange(port, path, token, label, data, send_body, deadline, budget, state, trace):
    support.validate_live_identity(state)
    writer, completed = None, None
    def keep_connection(result):
        nonlocal writer
        writer = result[1]
        trace["connected"] = True
    trace.update(started_monotonic_ns=time.monotonic_ns(), port=port, connected=False,
                 request_headers_write_attempted=False,
                 request_headers_handed_to_writer=False, request_body_bytes_handed_to_writer=0,
                 request_body_bytes_sent=0, interim_statuses=[], local_transport_closed=False)
    try:
        reader, writer = await wait_io(asyncio.open_connection("127.0.0.1", port,
                                                              limit=LIMITS["header_bytes"]), deadline, budget,
                                       on_result=keep_connection)
        trace["connected"] = True
        headers = (f"PUT {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Basic {token}\r\n"
                   f"Content-Length: {len(data)}\r\nExpect: 100-continue\r\nConnection: close\r\n"
                   "format: csv\r\ncolumn_separator: ,\r\ncolumns: id,grp,v,payload\r\n"
                   f"timeout: {LIMITS['server_timeout_seconds']}\r\n"
                   f"strict_mode: true\r\nmax_filter_ratio: 0\r\nlabel: {label}\r\n\r\n")
        trace["request_headers_write_attempted"] = True
        writer.write(headers.encode("ascii"))
        trace["request_headers_handed_to_writer"] = True
        await wait_io(writer.drain(), deadline, budget)
        interim, sent = [], 0
        while True:
            status, fields = await read_headers(reader, deadline, budget)
            trace["http_status"] = status
            if status >= 200:
                break
            require(status == 100 and len(interim) < 2, "Unexpected interim HTTP response")
            interim.append(status)
            trace["interim_statuses"] = list(interim)
            # Original-A archived FE receipts start with 307; its action reads only headers.
            # An unexpected FE 100 is a protocol mismatch, never an unbounded wait for body dispatch.
            require(send_body, "Original FE unexpectedly requested the request body before its redirect")
            if send_body and not sent:
                for index in range(0, len(data), 65536):
                    chunk = data[index:index + 65536]
                    writer.write(chunk)
                    trace["request_body_bytes_handed_to_writer"] += len(chunk)
                    await wait_io(writer.drain(), deadline, budget)
                    sent += len(chunk)
                    trace["request_body_bytes_sent"] = sent
        try:
            body = await read_body(reader, fields, deadline, budget)
        except LateBody as error:
            body = error.body
            trace["complete_body_after_deadline"] = True
        trace.update(response_body_bytes=len(body), response_body_sha256=hashlib.sha256(body).hexdigest())
        support.validate_live_identity(state)
        completed = status, fields, body, trace
        return completed
    except BaseException as error:
        trace["error_class"] = type(error).__name__
        raise
    finally:
        try:
            if writer:
                try:
                    await close_transport(writer, trace, budget)
                except asyncio.CancelledError:
                    if completed is not None:
                        raise ResponseInterrupted(completed) from None
                    raise
            else:
                trace["local_transport_closed"] = True
        finally:
            trace["finished_monotonic_ns"] = time.monotonic_ns()


def validate_receipt(value, label, batch_rows):
    require(isinstance(value, dict) and value.get("Status") == "Success" and value.get("Label") == label,
            "Stream Load did not acknowledge the exact label with Success")
    for key, expected in (("NumberTotalRows", batch_rows), ("NumberLoadedRows", batch_rows),
                          ("NumberFilteredRows", 0), ("NumberUnselectedRows", 0)):
        require(type(value.get(key)) is int and value[key] == expected, "Stream Load receipt row counts differ")
    require(type(value.get("TxnId")) is int and value["TxnId"] > 0, "Stream Load transaction ID missing")
    return value["TxnId"]


def read_batch(batch):
    maximum = batch["bytes"]
    require(type(maximum) is int and 0 < maximum <= 10000 * WIDTH, "Prepared batch has an invalid byte bound")
    with Path(batch["path"]).open("rb") as stream:
        if "offset" in batch:
            require(type(batch["offset"]) is int and batch["offset"] >= 0
                    and batch["offset"] + maximum <= os.fstat(stream.fileno()).st_size,
                    "Prepared input slice is outside the single source file")
            data = os.pread(stream.fileno(), maximum, batch["offset"])
        else:
            data = stream.read(maximum + 1)
    require(len(data) == maximum and hashlib.sha256(data).hexdigest() == batch["sha256"],
            "Prepared batch changed before upload")
    return data


def server_transaction_state(value):
    # A local deadline, socket close or DROP receipt cannot manufacture a terminal server state.
    if value.get("acknowledged_commit_retained") is True and type(value.get("txn_id")) is int and value["txn_id"] > 0:
        return "ACKNOWLEDGED_SUCCESS"
    if any(hop.get("component") == "be" and (hop.get("request_headers_write_attempted") is True
           or hop.get("request_headers_handed_to_writer") is True
           or hop.get("request_body_bytes_handed_to_writer", 0) > 0) for hop in value.get("hops", [])):
        return "TERMINATION_NOT_PROVEN"
    return "NOT_SUBMITTED_TO_BE"


def transaction_evidence(requests):
    counts = {name: 0 for name in ("NOT_SUBMITTED_TO_BE", "ACKNOWLEDGED_SUCCESS", "TERMINATION_NOT_PROVEN")}
    for value in requests:
        state = server_transaction_state(value)
        value["server_transaction_state"] = state
        value["server_transaction_termination_not_proven"] = state == "TERMINATION_NOT_PROVEN"
        counts[state] += 1
    return {"counts": counts, "server_timeout_seconds_requested": LIMITS["server_timeout_seconds"],
            "success_basis": "Previously validated original Success response with exact label/row counts and positive TxnId",
            "unknown_basis": "BE header write attempted without a validated Success acknowledgement",
            "server_transaction_termination_not_proven": counts["TERMINATION_NOT_PROVEN"] > 0,
            "timeout_elapsed_or_local_cleanup_proves_server_termination": False}


async def upload(plan, state, be_port, database, table, phase, item, batch, epoch, budget, archive, results):
    label = f"{database}_{phase}_w00_c{item['worker']:02d}_b{item['index']:05d}"
    path = f"/api/{database}/{table}/_stream_load"
    deadline_ns = epoch + item["offset_ns"] + LIMITS["request_seconds_from_arrival"] * NANO
    deadline = deadline_ns / NANO
    value = {**item, "phase": phase, "label": label, "status": "STARTED",
             "scheduled_monotonic_ns": epoch + item["offset_ns"], "started_monotonic_ns": time.monotonic_ns(),
             "batch_sha256": batch["sha256"], "hops": [],
             "server_timeout_seconds_requested": LIMITS["server_timeout_seconds"]}
    # Publish the intent before any await; cancellation must retain an unknown submission, not pretend it was unsent.
    results[item["index"]] = value
    try:
        require(time.monotonic() < deadline, "Queued request missed its absolute deadline")
        data = read_batch(batch)
        token = base64.b64encode((plan["user"] + ":" + os.environ[plan["password_env"]]).encode()).decode()
        hop = {"component": "fe"}
        value["hops"].append(hop)
        status, headers, _, hop = await exchange(state["http_port"], path, token, label, data, False,
                                                 deadline, budget, state, hop)
        require(status == 307 and "location" in headers, "Expected actual FE Stream Load redirect")
        port = redirect_port(headers["location"], path, plan, state, be_port)
        hop = {"component": "be"}
        value["hops"].append(hop)
        status, _, body, hop = await exchange(port, path, token, label, data, True, deadline, budget, state, hop)
        secret = os.environ[plan["password_env"]]
        require(not secret or secret.encode() not in body, "Refuse to archive echoed credentials")
        value["original_be_response"] = archive.write(f"{phase}-{item['index']:05d}-be.json", body)
        require(status == 200 and hop["request_body_bytes_sent"] == len(data), "BE response was incomplete")
        receipt = json.loads(body, object_pairs_hook=unique_object)
        value["txn_id"] = validate_receipt(receipt, label, item["rows"])
        value["acknowledged_commit_retained"] = True
        value["status"] = ("ACK_SUCCESS" if all(hop.get("local_transport_closed") is True
                           and not hop.get("close_error_class") for hop in value["hops"])
                           else "ACK_WITH_TRANSPORT_CLEANUP_FAILURE")
    except BaseException as error:
        if isinstance(error, ResponseInterrupted) and value["hops"] and value["hops"][-1]["component"] == "be":
            status, _, body, _ = error.response
            try:
                secret = os.environ[plan["password_env"]]
                require(status == 200 and (not secret or secret.encode() not in body), "Interrupted response invalid")
                receipt = json.loads(body, object_pairs_hook=unique_object)
                value["txn_id"] = validate_receipt(receipt, label, item["rows"])
                value["acknowledged_commit_retained"] = True
                value["original_be_response"] = archive.write(f"{phase}-{item['index']:05d}-be.json", body)
            except BaseException as evidence_error:
                value["interrupted_response_evidence_error"] = type(evidence_error).__name__
        value["status"] = "ACK_WITH_EVIDENCE_FAILURE" if value.get("txn_id") else "FAILED_OR_COMMIT_UNKNOWN"
        if value.get("txn_id") and isinstance(error, asyncio.CancelledError):
            value["status"] = "ACK_CANCELLED_AFTER_RESPONSE"
        value["error_class"] = type(error).__name__
        if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
            raise
    finally:
        value["finished_monotonic_ns"] = time.monotonic_ns()
        value["latency_ns_including_queue"] = value["finished_monotonic_ns"] - value["scheduled_monotonic_ns"]
        value["deadline_exceeded"] = value["finished_monotonic_ns"] >= deadline_ns
        if value["status"] == "ACK_SUCCESS" and value["finished_monotonic_ns"] >= deadline_ns:
            value["status"] = "ACK_LATE"
            value["deadline_exceeded"] = True
            value["acknowledged_commit_retained"] = True
        value["server_transaction_state"] = server_transaction_state(value)
        value["server_transaction_termination_not_proven"] = value["server_transaction_state"] == "TERMINATION_NOT_PROVEN"
    return value


async def run_phase(plan, state, be_port, database, phase, arrivals, batches, budget, archive, metrics, output):
    current = plan.get("profile") == "current-g4"
    seconds = plan.get("warmup_seconds", LIMITS["warmup_seconds"]) if phase == "warmup" else plan["window_seconds"]
    table = phase + "_rows"
    metrics.phase = phase
    boundary = None if current else metrics.boundary(phase + "-start")
    epoch = 0 if current else time.monotonic_ns() + NANO
    end_boundary, interval_end = None, None
    capacities = pending_capacities(arrivals, plan["concurrency"], LIMITS["request_seconds_from_arrival"] * NANO)
    require(capacities == plan["queue_model"]["capacities"][phase], "Frozen pending-reference capacities changed")
    result, queues = {}, [asyncio.Queue(maxsize=capacity) for capacity in capacities]
    pending_peaks = [0] * plan["concurrency"]
    # Keep the live intent records reachable by cleanup even if publishing a phase archive fails.
    if not isinstance(getattr(budget, "stream_load_request_results", None), dict):
        budget.stream_load_request_results = {}
    budget.stream_load_request_results[phase] = result
    stopping = asyncio.Event()
    async def worker(number):
        while not stopping.is_set():
            item = await queues[number].get()
            try:
                if item is None:
                    return
                now = time.monotonic_ns()
                if epoch + item["offset_ns"] + LIMITS["request_seconds_from_arrival"] * NANO <= now:
                    result[item["index"]] = unsent_result(item, phase, epoch, "DEADLINE_EXPIRED_NOT_SENT", now)
                else:
                    result[item["index"]] = await upload(plan, state, be_port, database, table, phase, item,
                                                         batches[item["index"]], epoch, budget, archive, result)
            finally:
                queues[number].task_done()
    workers = [asyncio.create_task(worker(number), name=f"lp012-upload-{number}")
               for number in range(plan["concurrency"])]
    if current:
        boundary = metrics.boundary(phase + "-start")
        epoch = time.monotonic_ns()
    phase_error = None
    try:
        for item in arrivals:
            while time.monotonic_ns() < epoch + item["offset_ns"]:
                budget.checkpoint()
                await asyncio.sleep(min(.05, max(0, (epoch + item["offset_ns"] - time.monotonic_ns()) / NANO)))
            budget.checkpoint()
            require(all(not task.done() for task in workers), "An upload worker exited early")
            now = time.monotonic_ns()
            queue = queues[item["worker"]]
            expire_pending(queue, result, phase, epoch, now)
            if epoch + item["offset_ns"] + LIMITS["request_seconds_from_arrival"] * NANO <= now:
                result[item["index"]] = unsent_result(item, phase, epoch, "DEADLINE_EXPIRED_NOT_SENT", now)
                continue
            try:
                queue.put_nowait(item)
                pending_peaks[item["worker"]] = max(pending_peaks[item["worker"]], queue.qsize())
            except asyncio.QueueFull:
                result[item["index"]] = unsent_result(item, phase, epoch, "QUEUE_FULL_NOT_SENT", now)
        while time.monotonic_ns() < epoch + seconds * NANO:
            budget.checkpoint()
            await asyncio.sleep(.05)
        metrics.phase = phase + "_drain"
        deadline = (epoch + seconds * NANO) / NANO + LIMITS["drain_seconds"]
        await wait_io(asyncio.gather(*(queue.join() for queue in queues)), deadline, budget)
        if current:
            interval_end = max([epoch + seconds * NANO,
                                *[row.get("finished_monotonic_ns", 0) for row in result.values()]])
            end_boundary = metrics.boundary(phase + "-end")
    except BaseException as error:
        phase_error = type(error).__name__
    finally:
        stopping.set()
        for task in workers:
            task.cancel()
        done, pending = await asyncio.wait(workers, timeout=5)
        if pending:
            phase_error = phase_error or "UploadWorkerCleanupTimeout"
            budget.resource_failure = ("lp012_workers", "cleanup_timeout")
            for task in pending:
                task.cancel()
            more, pending = await asyncio.wait(pending, timeout=3)
            done.update(more)
        outcomes = [task.exception() for task in done if not task.cancelled()]
        if any(isinstance(item, BaseException) and not isinstance(item, asyncio.CancelledError) for item in outcomes):
            phase_error = phase_error or "UploadWorkerException"
        for item in arrivals:
            result.setdefault(item["index"], {**item, "phase": phase, "status": "CANCELLED_OR_NOT_SENT",
                                              "scheduled_monotonic_ns": epoch + item["offset_ns"]})
        receipt = {"phase": phase, "epoch_monotonic_ns": epoch, "offered_window_seconds": seconds,
                   "finished_monotonic_ns": time.monotonic_ns(), "error_class": phase_error,
                   "start_boundary": boundary, "workers_terminated": all(task.done() for task in workers),
                   "pending_reference_capacities": capacities, "pending_reference_peaks": pending_peaks,
                   "request_count": len(arrivals), "arrival_sha256": hashlib.sha256(
                       json.dumps(arrivals, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        if current:
            receipt.update(interval_end_monotonic_ns=interval_end, end_boundary=end_boundary,
                           cpu_boundary_before_worker_cleanup=end_boundary is not None)
        rows = [result[index] for index in range(len(arrivals))]
        receipt["server_transactions"] = transaction_evidence(rows)
        raw = b"".join((json.dumps(value, separators=(",", ":")) + "\n").encode() for value in rows)
        receipt["requests"] = archive.write(phase + "-requests.jsonl", raw)
        save(output / (phase + "-window.json"), receipt)
    if not current:
        receipt["end_boundary"] = metrics.boundary(phase + "-end")
    save(output / (phase + "-window.json"), receipt)
    if current:
        save(output / (phase + "-statistics.json"), g4_latency_summary(rows, epoch, seconds))
    require(phase_error is None and all(row["status"] == "ACK_SUCCESS" for row in rows),
            "Window contains a dropped, failed, unknown or incomplete request")
    return receipt, rows


def group_visibility_sql(database, table, row_count, batch_rows):
    require(re.fullmatch(r"lp012w_[a-f0-9]{24}", database) and table in ("warmup_rows", "measurement_rows"),
            "Oracle target is outside the newly owned database")
    padding = hashlib.sha256(b"20260922").hexdigest() * 2
    size = "128 - LENGTH(CAST(id AS STRING)) - LENGTH(CAST(grp AS STRING)) - LENGTH(CAST(v AS STRING)) - 36"
    payload = f"CONCAT(MD5(CAST(id AS STRING)), SUBSTRING('{padding}', 1, {size}))"
    bad = (f"id IS NULL OR grp IS NULL OR v IS NULL OR payload IS NULL "
           f"OR id < 0 OR id >= {row_count} OR grp != id % 1024 OR v != id % 100000 "
           f"OR payload != {payload} OR LENGTH(payload) != 32 + ({size})")
    return (f"SELECT CAST(FLOOR(id / {batch_rows}) AS BIGINT) AS batch_index, COUNT(*) AS n, "
            f"COUNT(DISTINCT id) AS d, SUM(IF({bad}, 1, 0)) AS bad FROM {database}.{table} "
            "GROUP BY batch_index ORDER BY batch_index")


def audit_visibility(values, count, batch_rows):
    require(len(values) <= count, "Unexpected batch groups or rows outside the complete model")
    seen, complete = set(), []
    for value in values:
        require(set(value) == {"batch_index", "n", "d", "bad"}, "Unexpected visibility columns")
        require(all(isinstance(item, str) and re.fullmatch(r"-?[0-9]+", item) for item in value.values()),
                "Visibility helper returned a non-integral or non-string counter")
        number, rows, distinct, bad = (int(value[key]) for key in ("batch_index", "n", "d", "bad"))
        require(0 <= number < count and number not in seen and bad == 0 and rows == distinct
                and 0 < rows <= batch_rows, "Visible batch has duplicate, corrupt or out-of-range contents")
        seen.add(number)
        if rows == batch_rows:
            complete.append(number)
    return sorted(complete)


def visibility(sql, database, phase, requests, batch_rows, budget, output):
    count = len(requests)
    deadline = min(budget.deadline, time.monotonic() + LIMITS["visibility_seconds"])
    observed, observations = {}, []
    while True:
        budget.checkpoint()
        require(time.monotonic() < deadline, "Independent visibility deadline expired")
        start = time.monotonic_ns()
        original_deadline = budget.deadline
        try:
            budget.deadline = min(original_deadline, deadline)
            result = sql.one(group_visibility_sql(database, phase + "_rows", count * batch_rows, batch_rows))
        finally:
            budget.deadline = original_deadline
        finish = time.monotonic_ns()
        complete = audit_visibility(support.rows(result), count, batch_rows)
        for index in complete:
            observed.setdefault(index, finish)
        observations.append({"started_monotonic_ns": start, "finished_monotonic_ns": finish,
                             "sql_sequence": sql.sequence, "complete_batches": len(complete)})
        if len(complete) == count:
            break
        budget.pause(min(10, max(0, deadline - time.monotonic())))
    values = [{"index": row["index"], "label": row["label"], "txn_id": row["txn_id"],
               "ack_monotonic_ns": row["finished_monotonic_ns"],
               "observed_visible_upper_bound_monotonic_ns": observed[row["index"]],
               "actual_commit_time_known": False} for row in requests]
    result = {"rows": count * batch_rows, "complete_batches": count, "observations": observations,
              "checks": "Every batch has exactly the complete distinct ID domain and zero incorrect column values",
              "visibility_observation": "Post-window SQL full scan; times are upper bounds, not commit latency samples",
              "batches": values, "every_row_and_column_checked": True}
    save(output / (phase + "-visibility.json"), result)
    return result


def latency_summary(requests, epoch, seconds):
    good = [value for value in requests if value["status"] == "ACK_SUCCESS"]
    latency = sorted(value["latency_ns_including_queue"] / 1000000 for value in good)
    def percentile(percent):
        return latency[max(0, (len(latency) * percent + 99) // 100 - 1)] if latency else None
    before_end = sum(value["finished_monotonic_ns"] <= epoch + seconds * NANO for value in good)
    return {"scheduled_batches": len(requests), "ack_success_batches": len(good),
            "completed_within_offered_window": before_end, "ack_success_per_offered_second": before_end / seconds,
            "drain_completions": len(good) - before_end, "p50_ms_including_queue": percentile(50),
            "p95_ms_including_queue": percentile(95),
            "p99_ms_including_queue": percentile(99) if len(good) >= 10000 else None,
            "P99_sample_floor_met": len(good) >= 10000, "P99_operations_are_batches_not_rows": True,
            "capacity_proven": False, "AA_precision_proven": False, "performance_pass": False}


def database_id(sql, database):
    values = [row for row in support.rows(sql.one("SHOW PROC '/dbs'")) if row.get("DbName") == database]
    require(len(values) == 1 and re.fullmatch(r"[1-9][0-9]*", values[0].get("DbId", "")),
            "Cannot bind the acknowledged database to its actual ID")
    return values[0]["DbId"]


def table_inventory(sql, db_id):
    require(re.fullmatch(r"[1-9][0-9]*", db_id), "Invalid bound database ID")
    result = {}
    for row in support.rows(sql.one(f"SHOW PROC '/dbs/{db_id}'")):
        name, identity = row.get("TableName"), row.get("TableId", "")
        require(isinstance(name, str) and name not in result and re.fullmatch(r"[1-9][0-9]*", identity),
                "Ambiguous actual table identity")
        result[name] = identity
    return result


def table_identity(sql, database, name, table_id):
    schema = support.rows(sql.one(f"SHOW CREATE TABLE {database}.{name}"))
    require(len(schema) == 1 and any("DUPLICATE KEY" in value for value in schema[0].values()),
            "Unexpected owned table definition")
    tablets = [row.get("TabletId", "") for row in support.rows(sql.one(f"SHOW TABLETS FROM {database}.{name}"))]
    require(len(tablets) == 16 and len(set(tablets)) == 16
            and all(re.fullmatch(r"[1-9][0-9]*", item) for item in tablets), "Unexpected table tablet identities")
    return {"table_id": table_id, "show_create": schema, "tablet_ids": sorted(tablets, key=int)}


def verify_owner(sql, owner):
    require(isinstance(owner, dict) and owner.get("create_acknowledged") is True, "No acknowledged database identity")
    require(database_id(sql, owner["database"]) == owner["db_id"], "Database name refers to a replacement")
    tables = table_inventory(sql, owner["db_id"])
    require(tables == {name: value["table_id"] for name, value in owner["tables"].items()},
            "Owned database contains a replaced, missing or unowned table")
    for name, expected in owner["tables"].items():
        require(table_identity(sql, owner["database"], name, tables[name]) == expected,
                "Owned table definition or tablet identity changed")
    return True


def cleanup(sql, created, database, owner, metrics, processes, resources, budget):
    # No evidence failure or resource violation may bypass local actor shutdown.
    budget.begin_cleanup()
    result = {"errors": [], "database_owned": created, "database_absent": False,
              "manual_cleanup_required": not created and database is not None,
              "local_cleanup_scope": "Owned database absence and local helpers/observers; server transaction evidence is separate"}
    requests = getattr(budget, "stream_load_request_results", {})
    requests = requests if isinstance(requests, dict) else {}
    result["server_transactions"] = {phase: transaction_evidence(values.values()) for phase, values in requests.items()}
    result["server_transaction_termination_not_proven"] = any(
        value["server_transaction_termination_not_proven"] for value in result["server_transactions"].values())
    def attempt(name, action):
        try:
            return action()
        except BaseException as error:
            result["errors"].append({"step": name, "error_class": type(error).__name__})
            return None
    if sql and created:
        verified = attempt("verify_database_and_table_ownership", lambda: verify_owner(sql, owner))
        if verified is True:
            attempt("drop_owned_database", lambda: sql.one("DROP DATABASE " + database))
        def absent():
            values = support.rows(sql.one("SHOW DATABASES"))
            require(not any(database in value.values() for value in values), "Owned database remains")
            result["database_absent"] = True
        attempt("confirm_database_absent", absent)
        result["manual_cleanup_required"] = not result["database_absent"]
    if metrics:
        result["existing_metrics"] = attempt("stop_existing_metrics", metrics.stop)
    result["processes"] = attempt("stop_owned_helpers", processes.stop_all) or []
    result["resources"] = attempt("stop_resource_guard", resources.stop) or {}
    if budget.resource_failure or not result["resources"].get("complete"):
        result["errors"].append({"step": "resource_evidence", "error_class": "IncompleteResourceLifecycle"})
    if metrics and not (result.get("existing_metrics") or {}).get("complete"):
        result["errors"].append({"step": "metric_evidence", "error_class": "IncompleteMetrics"})
    for value in result["processes"]:
        if not value.get("stopped") or value.get("cleanup_error"):
            result["errors"].append({"step": "owned_helper", "error_class": "IncompleteCleanup"})
    if result["manual_cleanup_required"]:
        result["errors"].append({"step": "database_owner", "error_class": "ManualResidual"})
    if result["server_transaction_termination_not_proven"]:
        result["errors"].append({"step": "server_transaction_termination", "error_class": "NotProven"})
    return result


def probe(args):
    support.no_active_benchmark()
    path = owned(args.plan)
    plan = read_json(path, 8 * MIB)
    current = plan.get("profile") == "current-g4"
    require(current == (getattr(args, "profile", "legacy-lp012") == "current-g4"), "Explicit probe profile differs from its plan")
    output = owned(plan["output"])
    require(path == output / "plan.json" and not (output / "report.json").exists(), "Frozen plan may execute only once")
    require(plan.get("schema_version") == 1 and plan.get("case_id") == "LP-012"
            and plan.get("status") == "PLANNED_NOT_RUN" and plan.get("limits") == LIMITS
            and plan.get("resource_limits") == support.resources_module.LIMITS, "Invalid or changed plan bounds")
    if current:
        require(plan["boot_id"] == p4.boot_id(), "G4 plan belongs to another monotonic boot")
        offsets = {phase: [x[0] for x in struct.iter_unpack(">q", (output / (phase + "-arrivals.bin")).read_bytes())]
                   for phase in ("warmup", "measurement")}
        arrivals = g4_schedule(plan["context"], offsets)
        require(plan["business_binding"] == g4_business_binding(plan["context"], plan["input"]), "G4 business model changed")
        g4_freeze(plan["context"], hashlib.sha256(support.canonical(arrivals["measurement"])).hexdigest())
    else:
        arrivals = schedule(plan["batch_rows"], plan["concurrency"], plan["window_seconds"])
    require(digest(output / "arrivals.json") == plan["arrivals_sha256"]
            and read_json(output / "arrivals.json", 32 * MIB) == arrivals, "Frozen complete arrivals changed")
    require(plan.get("queue_model") == queue_model(arrivals, plan["concurrency"]),
            "Frozen pending-reference model changed")
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", plan["user"])
            and re.fullmatch(r"MASSDB_STREAM_[A-Z0-9_]+_PASSWORD", plan["password_env"]), "Invalid isolated credentials")
    require(plan["password_env"] in os.environ and len(os.environ[plan["password_env"]]) <= 1024,
            "Explicit bounded test password environment value is required")
    verify_frozen(plan)
    state = support.cluster_identity(SimpleNamespace(**plan))
    state["lp012_pins"] = plan["bindings"]["pins"]
    _, be_port = fixture.validate_cluster(plan["cluster_record"])
    require(type(plan["cpu"]) is int and plan["cpu"] in os.sched_getaffinity(0), "Declared client CPU unavailable")
    os.sched_setaffinity(0, {plan["cpu"]})
    available = int(re.search(r"(?m)^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text())[1])
    require(available >= 2560 * 1024, "Require 2048 MiB sampled fixture budget plus 512 MiB available reserve")
    (output / "probe-claim").touch(exist_ok=False)
    budget = support.Budget(plan["window_seconds"] + 2400 + (plan["warmup_seconds"]
                            + 2 * plan["context"]["barrier_timeout_seconds"] if current else 0))
    resources = support.resources_module.ResourceGuard(output, state)
    budget.resources = resources
    processes = support.Processes(budget, output, state["namespace"], resources)
    metrics, sql, created, database, owner, locked = None, None, False, None, None, False
    lock = Path(state["installation"]) / "lp012-window-owner.lock"
    token = uuid.uuid4().hex
    report = {"schema_version": 1, "case_id": "LP-012", "status": "RUNNING", "plan_sha256": digest(path),
              "started_at_utc": fixture.utc(), "LP012_complete": False, "release_performance_pass": False,
              "AA_precision_proven": False, "missing_metrics": MISSING_METRICS,
              "scope": "One non-replayed complete original-A window; all required matrices and pairs remain required"}
    if current:
        report.update(profile="current-g4", context=plan["context"], missing_metrics=[],
                      actual_client_affinity=sorted(os.sched_getaffinity(0)),
                      scope="One current G4 window; capacity, independent pairs and performance remain external")
    previous = {sig: signal.signal(sig, lambda _sig, _frame: setattr(budget, "cancelled", True))
                for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        save(output / "report.json", report)
        resources.start()
        with lock.open("x") as stream:
            stream.write(token + "\n")
        locked = True
        metrics = (G4BoundaryMetrics if current else Metrics)(output, state, be_port, resources)
        metrics.start()
        batches = (prepare_g4_batches if current else prepare_batches)(plan, output, budget)
        classpath, compiled = compile_sql(plan, state, output, processes)
        verify_frozen(plan)
        sql = OracleSql(plan, state, output, processes, classpath, compiled)
        if current:
            g4_observe_license(plan, sql, output, "setup", "VALID")
        grants = support.rows(sql.one("SHOW GRANTS"))
        require(len(grants) == 1 and re.search(r"(?i)\badmin_priv\b", grants[0].get("GlobalPrivs", "")),
                "Fixture account must have actual ADMIN for owned setup and cleanup")
        proposed = "lp012w_" + uuid.uuid4().hex[:24]
        require(not any(proposed in row.values() for row in support.rows(sql.one("SHOW DATABASES"))),
                "Refuse to adopt an existing database")
        database = proposed
        save(output / "create-intent.json", {"database": database, "namespace": state["namespace"],
                                             "owner_token": token, "absence_confirmed": True})
        sql.one("CREATE DATABASE " + database)
        created = True
        owner = {"database": database, "owner_token": token, "create_acknowledged": True,
                 "namespace": state["namespace"], "db_id": database_id(sql, database), "tables": {}}
        save(output / "database-owner.json", owner)
        for table in ("warmup_rows", "measurement_rows"):
            sql.one(f"CREATE TABLE {database}.{table} (id BIGINT NOT NULL, grp INT NOT NULL, v BIGINT NOT NULL, "
                    "payload VARCHAR(128) NOT NULL) DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 16 "
                    'PROPERTIES ("replication_num"="1")')
            tables = table_inventory(sql, owner["db_id"])
            require(table in tables, "Acknowledged table has no actual identity")
            owner["tables"][table] = table_identity(sql, database, table, tables[table])
            save(output / "database-owner.json", owner)
            require(support.rows(sql.one(f"SELECT COUNT(*) AS n FROM {database}.{table}")) == [{"n": "0"}],
                    "Target is not independently confirmed empty")
        require(verify_owner(sql, owner), "Initial owned database identity differs")
        if current:
            state_ack = g4_barrier(plan, output, "state", budget)
            g4_observer_launch(plan, state_ack)
            before_license = g4_observe_license(plan, sql, output, "before", plan["context"]["license_state"])
            verify_frozen(plan)
        archive = Archive(output, maximum=128 * MIB if current else LIMITS["receipt_archive_bytes"])
        phase_results = {}
        for phase in ("warmup", "measurement"):
            window, requests = asyncio.run(run_phase(plan, state, be_port, database, phase, arrivals[phase],
                                                      batches, budget, archive, metrics, output))
            phase_results[phase] = requests
            report[phase] = {"window": window, "statistics": (g4_latency_summary if current else latency_summary)(
                requests, window["epoch_monotonic_ns"], window["offered_window_seconds"])}
            if not current:
                metrics.phase = phase + "_visibility"
                report[phase]["visibility"] = visibility(sql, database, phase, requests, plan["batch_rows"], budget, output)
        if current:
            after_license = g4_observe_license(plan, sql, output, "after", plan["context"]["license_state"])
            g4_stable_license(plan, before_license, after_license)
            oracle_ack = g4_barrier(plan, output, "oracle", budget)
            g4_observe_license(plan, sql, output, "restored", "VALID")
            for phase in ("warmup", "measurement"):
                metrics.phase = phase + "_visibility"
                report[phase]["visibility"] = g4_visibility(sql, database, phase, phase_results[phase], plan["batch_rows"], budget, output)
            report["observer"] = g4_observer_evidence(plan, state_ack, oracle_ack, report["warmup"]["window"], report["measurement"]["window"])
            report["measured_unique_rows"] = len(arrivals["measurement"]) * plan["batch_rows"]
        else:
            report["measured_10000000_row_input_executed_once"] = True
        report["content_oracle_complete"] = True
        metrics.phase = "final_audit"
        verify_frozen(plan)
        require(verify_owner(sql, owner), "Final owned database identity differs")
        support.validate_live_identity(state)
        budget.checkpoint()
        report["status"] = "CURRENT_G4_RAW_WINDOW_COMPLETE" if current else "FUNCTIONAL_WINDOW_COMPLETE_PERFORMANCE_INCONCLUSIVE"
        report["precision_status"] = "inconclusive_release_blocked"
        report["precision_reasons"] = ["One window is not independent A/A and A/B pairs"] if current else [
            "One window is not five independent A/A pairs", "Required resource metrics missing"]
        if not report["measurement"]["statistics"]["P99_sample_floor_met"]:
            report["precision_reasons"].append("Fewer than 10000 completed batch operations; P99 withheld, no implicit replay")
    except BaseException as error:
        report["status"], report["failure_class"] = "FAIL", type(error).__name__
        if current and isinstance(error, ValueError):
            report["failure_reason"] = str(error)
    finally:
        if metrics:
            metrics.phase = "cleanup"
        report["cleanup"] = cleanup(sql, created, database, owner, metrics, processes, resources, budget)
        if locked:
            try:
                require(lock.read_text() == token + "\n", "Ownership lock changed")
                lock.unlink()
            except BaseException as error:
                report["cleanup"]["errors"].append({"step": "owner_lock", "error_class": type(error).__name__})
        if report["cleanup"]["errors"]:
            report["status"] = "FAIL"
        report["finished_at_utc"] = fixture.utc()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        save(output / "report.json", report)
    if current:
        try:
            audit = g4_audit_window(output)
            save(output / "g4-audit.json", audit)
            save(output / "g4-window.json", {**audit["window"], "evidence": p4.reference(output / "g4-audit.json")})
        except (OSError, ValueError, KeyError, TypeError) as error:
            save(output / "g4-audit.json", {"status": "INCOMPLETE_OR_FAILED", "failure_class": type(error).__name__,
                                           "reason": str(error) if isinstance(error, ValueError) else None,
                                           "formal_performance_pass": False})
            report["status"] = "FAIL"
            save(output / "report.json", report)
    return report


G4_MAX_REQUESTS = 100000
G4_GENERATOR = ROOT / "tools/license-checks/LicenseJdbcBaseline.java"


def g4_business_binding(context, input_value):
    value = {"schema": "current_g4_stream_v1", "seed": SEED, "batch_rows": context["batch_rows"],
             "concurrency": context["concurrency"], "connection_mode": "stream_load_two_hop_close",
             "arrival": "java_random_strictmath_poisson_v1", "input_sha256": input_value["sha256"],
             "row_width": WIDTH, "model": "id, id%1024, id%100000, MD5(id)+SHA256(seed) padding",
             "target": "fresh DUPLICATE KEY(id), 16 buckets, replication=1; separate warmup/measurement tables",
             "request_deadline_from_arrival_seconds": LIMITS["request_seconds_from_arrival"],
             "server_timeout_seconds": LIMITS["server_timeout_seconds"], "retries": 0}
    return {"payload": value, "sha256": hashlib.sha256(support.canonical(value)).hexdigest()}


def g4_validate_context(value):
    require(value.get("group") == "G4" and value.get("seed") == SEED, "Explicit current G4 / seed required")
    require(value.get("phase") in ("DIAGNOSTIC", "AA", "AB") and value.get("variant") in ("A", "B"),
            "Explicit execution phase and variant required")
    require(value["phase"] != "AA" or value["variant"] == "A", "A/A cannot run candidate B")
    require(value.get("license_state") in ("VALID", "EXPIRED"), "Declare the legal-write comparison state")
    require(type(value.get("concurrency")) is int and value["concurrency"] in (1, 8), "Current G4 concurrency is 1/8")
    require(type(value.get("batch_rows")) is int and value["batch_rows"] in (1000, 10000), "Current G4 batch is 1000/10000")
    require(value.get("connection_mode") == "stream_load_two_hop_close", "Freeze actual two-hop connection mode")
    require(type(value.get("rate")) in (int, float) and math.isfinite(value["rate"]) and 0 < value["rate"] <= 100000,
            "Rate must be positive finite batches per second")
    for key in ("warmup_seconds", "duration_seconds"):
        require(type(value.get(key)) is int and 0 < value[key] <= 14400, "Invalid bounded G4 duration")
    require(value["rate"] * max(value["warmup_seconds"], value["duration_seconds"]) <= G4_MAX_REQUESTS,
            "Expected arrivals exceed the bounded G4 request budget")
    if value["phase"] != "DIAGNOSTIC":
        require(value["warmup_seconds"] >= 180 and value["duration_seconds"] >= 600,
                "Formal G4 needs 180s warmup and 600s measurement, extended for samples")
    require(type(value.get("barrier_timeout_seconds")) is int and 1 <= value["barrier_timeout_seconds"] <= 3600,
            "External state barriers need an explicit bounded timeout")
    require(isinstance(value.get("window_id"), str) and re.fullmatch(r"G4-[A-Za-z0-9_.-]+", value["window_id"])
            and isinstance(value.get("cell_id"), str) and value["cell_id"].startswith("G4-"), "Missing G4 cell/window")
    require(type(value.get("pair_id")) is int and value["pair_id"] >= 0, "Missing independent pair")
    p4.validate_identity(value["identity"])
    allowed = {"group", "seed", "phase", "variant", "license_state", "concurrency", "batch_rows", "rate",
               "connection_mode", "warmup_seconds", "duration_seconds", "barrier_timeout_seconds", "window_id",
               "cell_id", "pair_id", "identity", "identity_bindings", "business_workload_sha256", "freeze"}
    require(set(value) <= allowed, "Unknown context fields; credentials belong only in password_env")
    if value["phase"] != "DIAGNOSTIC":
        require(set(value.get("identity_bindings", {})) == {"environment", "configuration", "fixture", "client"},
                "Formal G4 requires actual immutable identity snapshots")
    for key, item in value.get("identity_bindings", {}).items():
        require(key in ("environment", "configuration", "fixture", "client"), "Unknown identity snapshot")
        p4.verify_reference(item)
        require(item["sha256"] == value["identity"][key + "_sha256"], "Identity snapshot digest mismatch")


def g4_input_binding(path):
    path = owned(path)
    manifest = path.with_suffix(path.suffix + ".json")
    value = read_json(manifest)
    count = value.get("rows")
    require(type(count) is int and 0 < count <= 10**10 and value.get("case_id") == "LP-012"
            and value.get("seed") == SEED and value.get("row_bytes_including_lf") == WIDTH
            and value.get("columns") == ["id", "grp", "v", "payload"] and value.get("id_start") == 0
            and owned(value.get("input_path", "")) == path and value.get("input_bytes") == count * WIDTH
            and path.stat().st_size == count * WIDTH and re.fullmatch(r"[a-f0-9]{64}", value.get("input_sha256", "")),
            "Invalid single-file G4 input manifest or size")
    return {"path": str(path), "manifest": str(manifest), "manifest_sha256": digest(manifest),
            "sha256": value["input_sha256"], "bytes": count * WIDTH, "rows": count,
            "content_checked_at_plan_time": False}


def generate_g4_input(path, rows):
    require(type(rows) is int and 0 < rows <= G4_MAX_REQUESTS * 10000, "Explicit bounded G4 input row count required")
    path = owned(path)
    require(not path.exists() and not path.with_suffix(path.suffix + ".json").exists(), "Never overwrite existing input/evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    require(shutil.disk_usage(path.parent).free >= rows * WIDTH + 512 * MIB,
            "Insufficient disk for the single input and evidence reserve; no reduced-input substitute")
    fixture.generate(SimpleNamespace(output=path, rows=rows))
    return {"status": "INPUT_GENERATED", "input": g4_input_binding(path), "LP012_complete": False,
            "release_performance_pass": False}


def g4_schedule(context, offsets):
    g4_validate_context(context)
    phases = {}
    for phase, seconds in (("warmup", context["warmup_seconds"]), ("measurement", context["duration_seconds"])):
        values = offsets[phase]
        require(0 < len(values) <= G4_MAX_REQUESTS and all(type(x) is int and 0 <= x < seconds * NANO for x in values)
                and values == sorted(set(values)), "Empty/oversized/invalid generated arrival sequence")
        phases[phase] = [{"index": i, "worker": i % context["concurrency"], "offset_ns": offset,
                          "first_id": i * context["batch_rows"], "rows": context["batch_rows"]}
                         for i, offset in enumerate(values)]
    require(context["phase"] == "DIAGNOSTIC" or len(phases["measurement"]) >= 10000,
            "Formal sample shortage: extend duration and provide enough unique input before launch")
    return {"schema_version": 2, "seed": SEED, "arrival": "java_random_strictmath_poisson_v1",
            "rate_batches_per_second": context["rate"], "window_seconds": context["duration_seconds"],
            "warmup_seconds": context["warmup_seconds"], "rows_replayed_in_measurement": 0, **phases}


def g4_generate_schedule(context, output, java_home):
    classes = output / "schedule-classes"
    classes.mkdir()
    subprocess.run([str(java_home / "bin/javac"), "-J-Xmx256m", "--release", "17", "-d", str(classes), str(G4_GENERATOR)],
                   check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    values = {}
    for phase, seconds, seed in (("warmup", context["warmup_seconds"], SEED ^ 0x5DEECE66D),
                                 ("measurement", context["duration_seconds"], SEED)):
        target = output / (phase + "-arrivals.bin")
        subprocess.run([str(java_home / "bin/java"), "-Xmx256m", "-cp", str(classes), "LicenseJdbcBaseline",
                        "--schedule-only", str(context["rate"]), str(seconds), str(seed), str(target)],
                       check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        require(target.stat().st_size <= G4_MAX_REQUESTS * 8, "Arrival vector exceeds current bounded window")
        values[phase] = [x[0] for x in struct.iter_unpack(">q", target.read_bytes())]
        require(target.with_name(target.name + ".sha256").read_text().strip() == digest(target), "Generator vector hash differs")
    return g4_schedule(context, values)


def g4_freeze(context, arrival_hash):
    if context["phase"] != "AB":
        require("freeze" not in context, "Only formal AB consumes a published freeze")
        return {}
    path = owned(context["freeze"])
    reference = p4.reference(path)
    frozen = read_json(path, 32 * MIB)
    publication_ref = p4.reference(path.with_suffix(path.suffix + ".published.json"))
    publication = read_json(publication_ref["path"])
    require(frozen["status"] == "FROZEN_ELIGIBLE" and frozen["boot_id"] == p4.boot_id()
            and frozen["identities"][context["variant"]] == context["identity"], "Published freeze identity mismatch")
    require(publication["freeze"] == reference and publication["boot_id"] == p4.boot_id()
            and publication["published_monotonic_ns"] <= time.monotonic_ns(), "Freeze not published before launch")
    cell = frozen["cell"]
    for key in ("rate", "concurrency", "connection_mode", "warmup_seconds", "duration_seconds", "seed", "license_state", "batch_rows"):
        require(cell[key] == context[key], "Current G4 differs from freeze: " + key)
    require(cell["id"] == context["cell_id"] and cell["workload_sha256"] == context["business_workload_sha256"]
            and cell["arrival_schedule_sha256"] == arrival_hash, "Frozen G4 cell/business/arrivals mismatch")
    return {"freeze": reference, "publication": publication_ref}


def make_g4_plan(args):
    require(args.context and args.output and args.cluster_record and args.input, "Current G4 requires context/output/cluster/input")
    context = read_json(owned(args.context))
    g4_validate_context(context)
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", args.user or "")
            and re.fullmatch(r"MASSDB_STREAM_[A-Z0-9_]+_PASSWORD", args.password_env or ""), "Explicit isolated account required")
    require(type(args.cpu) is int and args.cpu >= 0, "Explicit client CPU required")
    inputs = g4_input_binding(args.input)
    business = g4_business_binding(context, inputs)
    require(context["business_workload_sha256"] == business["sha256"], "Compute actual G4 business hash before planning")
    identity = context["identity"]
    bindings = frozen_files(owned(args.cluster_record), identity["fe_sha256"], identity["be_sha256"],
                            args.jdk_runtime_version, context["variant"], current=True)
    current_bindings = {"context": p4.reference(args.context), "generator": p4.reference(G4_GENERATOR),
                        "statistics": p4.reference(p4.__file__),
                        "current_contract": p4.reference(ROOT / "docs/license-p0-contract-20260922.md"),
                        **context.get("identity_bindings", {})}
    output = owned(args.output)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    arrivals = g4_generate_schedule(context, output, Path(bindings["java_home"]))
    require(inputs["rows"] >= max(len(arrivals[x]) for x in ("warmup", "measurement")) * context["batch_rows"],
            "Input too small for unique requests; no replay or formal sample waiver")
    save(output / "arrivals.json", arrivals)
    phase_hash = hashlib.sha256(support.canonical(arrivals["measurement"])).hexdigest()
    for item in current_bindings.values():
        p4.verify_reference(item)
    current_bindings.update(g4_freeze(context, phase_hash))
    plan = {"schema_version": 1, "profile": "current-g4", "case_id": "LP-012", "status": "PLANNED_NOT_RUN",
            "output": str(output), "cluster_record": str(owned(args.cluster_record)), "cluster_record_sha256": digest(args.cluster_record),
            "context": context, "business_binding": business, "input": inputs, "bindings": bindings,
            "current_bindings": current_bindings, "expected_fe_sha256": identity["fe_sha256"], "expected_be_sha256": identity["be_sha256"],
            "jdk_runtime_version": args.jdk_runtime_version, "user": args.user, "password_env": args.password_env,
            "cpu": args.cpu, "concurrency": context["concurrency"], "batch_rows": context["batch_rows"],
            "window_seconds": context["duration_seconds"], "warmup_seconds": context["warmup_seconds"],
            "limits": dict(LIMITS), "resource_limits": dict(support.resources_module.LIMITS),
            "queue_model": queue_model(arrivals, context["concurrency"]), "arrivals_sha256": digest(output / "arrivals.json"),
            "created_at_utc": fixture.utc(), "boot_id": p4.boot_id(), "created_monotonic_ns": time.monotonic_ns(),
            "launch_token": uuid.uuid4().hex, "LP012_complete": False, "release_performance_pass": False}
    save(output / "plan.json", plan)
    return plan


def prepare_g4_batches(plan, output, budget):
    """One immutable source, no second 12.8GB batch copy. Every byte is independently model-checked."""
    arrivals = read_json(output / "arrivals.json", 32 * MIB)
    count = max(len(arrivals[x]) for x in ("warmup", "measurement"))
    size, total = plan["batch_rows"] * WIDTH, plan["input"]["rows"]
    require(total >= count * plan["batch_rows"], "Not enough distinct source rows")
    require(shutil.disk_usage(output).free >= 512 * MIB, "Require bounded evidence reserve; source is never copied")
    checksum, entries = hashlib.sha256(), []
    path = owned(plan["input"]["path"])
    with path.open("rb") as stream:
        for first in range(0, total, plan["batch_rows"]):
            budget.checkpoint()
            row_count = min(plan["batch_rows"], total - first)
            data = stream.read(row_count * WIDTH)
            require(len(data) == row_count * WIDTH, "Truncated G4 source")
            for offset in range(row_count):
                require(data[offset * WIDTH:(offset + 1) * WIDTH] == model_record(first + offset), "G4 source row model mismatch")
            checksum.update(data)
            if first // plan["batch_rows"] < count:
                require(len(data) == size, "Active batch is not complete")
                entries.append({"index": first // plan["batch_rows"], "path": str(path), "offset": first * WIDTH,
                                "bytes": size, "rows": row_count, "first_id": first,
                                "sha256": hashlib.sha256(data).hexdigest()})
        require(stream.read(1) == b"", "Trailing G4 input bytes")
    require(checksum.hexdigest() == plan["input"]["sha256"], "Whole G4 input hash mismatch")
    save(output / "batches.json", {"rows": total, "source_sha256": checksum.hexdigest(), "batches": entries,
                                   "every_input_byte_checked_against_independent_model": True,
                                   "preparation_inside_timed_window": False, "copied_input_bytes": 0,
                                   "active_body_maximum_bytes_per_worker": size})
    return entries


class G4BoundaryMetrics(Metrics):
    """Only synchronous boundaries here; the root schedules the existing observer once."""
    def start(self):
        pass

    def stop(self):
        return {"complete": True, "thread_stopped": True, "scope": "Boundary sampler only; external observer audited separately"}


def g4_barrier(plan, output, stage, budget):
    path = output / ("g4-" + stage + "-ready.json")
    require(not path.exists(), "State barrier cannot be reused")
    ready = {"stage": stage, "launch_token": plan["launch_token"], "plan_sha256": digest(output / "plan.json"),
             "boot_id": p4.boot_id(), "nonce": uuid.uuid4().hex, "created_monotonic_ns": time.monotonic_ns(),
             "requested_state": plan["context"]["license_state"] if stage == "state" else "VALID_FOR_ORACLE"}
    save(path, ready)
    acknowledgement = output / ("g4-" + stage + "-ack.json")
    deadline = time.monotonic() + plan["context"]["barrier_timeout_seconds"]
    while not acknowledgement.exists():
        budget.checkpoint()
        require(time.monotonic() < deadline, "External G4 barrier expired")
        budget.pause(.05)
    ack = read_json(acknowledgement)
    require(set(ack) <= set(ready) | {"acknowledged_monotonic_ns", "observer_launch", "observer_summary", "observer_samples"}
            and all(ack.get(key) == value for key, value in ready.items()), "Stale/mismatched external barrier acknowledgement")
    require(type(ack.get("acknowledged_monotonic_ns")) is int and ready["created_monotonic_ns"]
            <= ack["acknowledged_monotonic_ns"] <= time.monotonic_ns() < int(deadline * NANO), "Expired/future barrier receipt")
    save(output / ("g4-" + stage + "-accepted.json"), {"ready": p4.reference(path), "ack": p4.reference(acknowledgement),
                                                    "accepted_monotonic_ns": time.monotonic_ns()})
    return ack


def g4_license_values(result):
    values = {}
    for row in support.rows(result):
        require(set(row) == {"Key", "Value"} and row["Key"] not in values, "Invalid SHOW LICENSE result")
        values[row["Key"]] = row["Value"]
    require(values.get("administrator") == "true" and values.get("recovery_ready") == "true", "License administrator/readiness missing")
    return values


def g4_check_license(values, target):
    require(values.get("status") in (("VALID", "EXPIRING") if target == "VALID" else ("EXPIRED",)),
            "Actual license state does not permit the declared G4 comparison")
    require(values.get("pending") == "null" and values.get("active") not in (None, "null"), "Pending/missing certificate cannot prove a stable G4 state")
    now, expiry = int(values["trusted_utc"]), int(values["expires_at"])
    require((now < expiry) if target == "VALID" else (now >= expiry), "License time/state mismatch")


def g4_observe_license(plan, sql, output, stage, target):
    started = time.monotonic_ns()
    if plan["context"]["variant"] == "A":
        value = {"status": "ORIGINAL_A_NO_LICENSE", "target_comparison_state": plan["context"]["license_state"]}
    else:
        result = sql.one("SHOW LICENSE")
        value = g4_license_values(result)
        g4_check_license(value, target)
    receipt = {"started_monotonic_ns": started, "finished_monotonic_ns": time.monotonic_ns(),
               "values": value, "sql_sequence": sql.sequence if plan["context"]["variant"] == "B" else None}
    save(output / ("g4-license-" + stage + ".json"), receipt)
    return receipt


def g4_stable_license(plan, before, after):
    if plan["context"]["variant"] == "A":
        require(before["values"] == after["values"] and before["values"]["status"] == "ORIGINAL_A_NO_LICENSE", "A license evidence changed")
        return
    for observation in (before, after):
        g4_check_license(observation["values"], plan["context"]["license_state"])
    for key in ("active", "pending", "expires_at", "applied_version", "highest_sequence", "clock_epoch"):
        require(before["values"][key] == after["values"][key], "License/clock/version changed inside G4 window")
    require(int(after["values"]["trusted_utc"]) >= int(before["values"]["trusted_utc"]), "Trusted clock decreased")


def g4_observer_launch(plan, acknowledgement):
    item = acknowledgement.get("observer_launch")
    if item is None:
        require(plan["context"]["phase"] == "DIAGNOSTIC", "Formal G4 requires a running external observer snapshot")
        return None
    value = read_json(p4.verify_reference(item))
    require(value["status"] == "RUNNING" and value["namespace"] == plan["bindings"]["namespace"], "Wrong observer launch")
    require(value["source_sha256"]["tools/license-checks/resource_observer.py"]
            == plan["bindings"]["files"][str(Path(observer.__file__).resolve())], "Observer implementation differs from plan")
    for name in ("fe", "be"):
        pin = plan["bindings"]["pins"][name]
        require(value["services"][name]["pid"] == pin["pid"]
                and value["services"][name]["start_ticks"] == pin["start_ticks"], "Observer target lifecycle differs")
    require(value["started_monotonic_ns"] <= acknowledgement["acknowledged_monotonic_ns"], "Observer was not started before acknowledgement")
    return value


def g4_observer_evidence(plan, state_ack, oracle_ack, warm, measured):
    launch = g4_observer_launch(plan, state_ack)
    if launch is None:
        return {"status": "DIAGNOSTIC_NO_OBSERVER", "formal_qualified": False}
    refs = {key: oracle_ack[key] for key in ("observer_summary", "observer_samples")}
    summary = read_json(p4.verify_reference(refs["observer_summary"]))
    samples_path = p4.verify_reference(refs["observer_samples"])
    require(summary["status"] in ("COMPLETED", "INTERRUPTED") and summary["samples_with_errors"] == 0
            and summary["skipped_schedule_slots"] == 0 and summary["samples_sha256"] == refs["observer_samples"]["sha256"],
            "Observer did not finish with complete clean samples")
    for key in ("namespace", "services", "started_monotonic_ns", "source_sha256", "observer_cpu_affinity", "interval_seconds"):
        require(summary[key] == launch[key], "Observer changed after launch: " + key)
    require(samples_path.stat().st_size <= 128 * MIB, "Observer evidence exceeded bound")
    first, last, count, previous = None, None, 0, None
    with samples_path.open() as stream:
        for line in stream:
            value = json.loads(line, object_pairs_hook=unique_object)
            start, end = value["started_monotonic_ns"], value["finished_monotonic_ns"]
            require(value["sample_index"] == count and start <= end and not value["errors"], "Invalid observer sample")
            if previous is not None:
                require(previous <= start and start - previous <= (summary["interval_seconds"] + 2 * summary["http_timeout_seconds"] + 1) * NANO,
                        "Observer coverage gap")
            for name in ("fe", "be"):
                actual, expected = value["processes"][name], summary["services"][name]
                require(actual["pid"] == expected["pid"] and actual["start_ticks"] == expected["start_ticks"]
                        and isinstance(actual.get("metrics"), dict) and actual["metrics"], "Observer target/metrics missing")
            first = start if first is None else first
            last, previous, count = end, start, count + 1
    require(count == summary["samples"] and first is not None and first <= warm["epoch_monotonic_ns"]
            and last >= measured["interval_end_monotonic_ns"] and summary["finished_monotonic_ns"] >= last,
            "Observer does not cover actual warmup through final completion")
    return {"status": "VERIFIED", "formal_qualified": True, "launch": state_ack["observer_launch"],
            **refs, "samples": count, "scope": "Existing CPU/RSS/GC/IO/namespace metrics; no allocation/network-attribution claim"}


def g4_latency_summary(requests, epoch, seconds):
    good = [row for row in requests if row["status"] == "ACK_SUCCESS"]
    last = max([epoch + seconds * NANO, *[row.get("finished_monotonic_ns", row.get("decision_monotonic_ns", epoch)) for row in requests]])
    def percentile(values, fraction):
        values = sorted(values)
        if not values:
            return None
        position = (len(values) - 1) * fraction
        low, high = math.floor(position), math.ceil(position)
        return values[low] + (values[high] - values[low]) * (position - low)
    latency = [(row["finished_monotonic_ns"] - row["scheduled_monotonic_ns"]) / 1e6 for row in good]
    queue = [(row["started_monotonic_ns"] - row["scheduled_monotonic_ns"]) / 1e6 for row in good]
    service = [(row["finished_monotonic_ns"] - row["started_monotonic_ns"]) / 1e6 for row in good]
    errors = {}
    for row in requests:
        if row["status"] != "ACK_SUCCESS":
            key = row["status"] + "/" + row.get("error_class", "NONE")
            errors[key] = errors.get(key, 0) + 1
    duration = (last - epoch) / NANO
    return {"scheduled_requests": len(requests), "observed_requests": len(requests), "successful_requests": len(good),
            "error_count": len(requests) - len(good), "errors": errors,
            "timeout_count": sum(row.get("deadline_exceeded") is True or row["status"] == "DEADLINE_EXPIRED_NOT_SENT"
                                 or row.get("error_class") in ("TimeoutError", "LateIo", "LateBody") for row in requests),
            "retry_count": 0, "effective_duration_seconds": duration, "drain_seconds": duration - seconds,
            "success_qps": len(good) / duration, "p95_ms": percentile(latency, .95), "p99_ms": percentile(latency, .99),
            "client_queue_p99_ms": percentile(queue, .99), "service_p99_ms": percentile(service, .99),
            "P99_sample_floor_met": len(good) >= 10000, "operation_unit": "acknowledged batch, not rows",
            "request_deadline_from_arrival_seconds": LIMITS["request_seconds_from_arrival"], "performance_pass": False}


def g4_visibility(sql, database, phase, requests, batch_rows, budget, output):
    """Bound each SQL result to 10000 groups, preserving full-table cardinality and every column model."""
    count, observations, sequences = len(requests), [], []
    deadline = min(budget.deadline, time.monotonic() + LIMITS["visibility_seconds"])
    observed = {}
    for first in range(0, count, 10000):
        stop = min(count, first + 10000)
        query = group_visibility_sql(database, phase + "_rows", count * batch_rows, batch_rows).replace(
            "ORDER BY batch_index", f"HAVING batch_index >= {first} AND batch_index < {stop} ORDER BY batch_index")
        while True:
            budget.checkpoint()
            require(time.monotonic() < deadline, "G4 full visibility deadline expired")
            original = budget.deadline
            start = time.monotonic_ns()
            try:
                budget.deadline = min(original, deadline)
                result = sql.one(query)
            finally:
                budget.deadline = original
            finish = time.monotonic_ns()
            complete = audit_visibility(support.rows(result), count, batch_rows)
            require(all(first <= i < stop for i in complete), "Visibility page returned another ID interval")
            observations.append({"started_monotonic_ns": start, "finished_monotonic_ns": finish,
                                 "sql_sequence": sql.sequence, "first_batch": first, "stop_batch": stop})
            for index in complete:
                observed.setdefault(index, finish)
            if complete == list(range(first, stop)):
                sequences.append(sql.sequence)
                break
            budget.pause(min(2, max(0, deadline - time.monotonic())))
    query = f"SELECT COUNT(*) AS n, COUNT(DISTINCT id) AS d FROM {database}.{phase}_rows"
    total = count * batch_rows
    require(support.rows(sql.one(query)) == [{"n": str(total), "d": str(total)}], "Unexpected extra/duplicate rows outside visibility pages")
    receipt = {"rows": total, "complete_batches": count, "observations": observations,
               "final_page_sql_sequences": sequences, "cardinality_sql_sequence": sql.sequence,
               "every_row_and_column_checked": True, "actual_commit_time_known": False,
               "batches": [{"index": row["index"], "label": row["label"], "txn_id": row["txn_id"],
                            "ack_monotonic_ns": row["finished_monotonic_ns"],
                            "observed_visible_upper_bound_monotonic_ns": observed[row["index"]]} for row in requests]}
    save(output / (phase + "-visibility.json"), receipt)
    return receipt


def g4_sql_receipt(output, sequence, expected):
    value = read_json(output / ("sql-%04d.result.json" % sequence), 16 * MIB)
    require(value.get("success") is True and not value.get("connection_error"), "Original SQL result failed")
    statements = value["statements"]
    require(statements and statements[-1]["sql"] == expected and statements[-1]["success"] is True,
            "Original oracle SQL differs from expected full model")
    return statements[-1]


def g4_raw_bindings(output):
    return [p4.reference(path) for path in sorted(output.rglob("*")) if path.is_file()
            and path.name not in ("g4-audit.json", "g4-window.json")]


def g4_audit_window(output):
    output = Path(output)
    original_bindings = g4_raw_bindings(output)
    plan, report = read_json(output / "plan.json", 8 * MIB), read_json(output / "report.json", 64 * MIB)
    require(plan.get("profile") == "current-g4" and plan["boot_id"] == p4.boot_id(), "Not a same-boot current G4 window")
    context = plan["context"]
    g4_validate_context(context)
    require(report["status"] == "CURRENT_G4_RAW_WINDOW_COMPLETE" and report["plan_sha256"] == digest(output / "plan.json")
            and not report["cleanup"]["errors"] and report["cleanup"]["database_absent"] is True
            and not report["cleanup"]["server_transaction_termination_not_proven"], "Incomplete current G4 operation/cleanup")
    require(report["actual_client_affinity"] == [plan["cpu"]], "Actual client CPU differs from frozen plan")
    dependencies = [{"path": name, "sha256": value} for name, value in plan["bindings"]["files"].items()]
    dependencies += list(plan["current_bindings"].values())
    dependencies += [{"path": plan["input"]["path"], "sha256": plan["input"]["sha256"]},
                     {"path": plan["input"]["manifest"], "sha256": plan["input"]["manifest_sha256"]}]
    for item in dependencies:
        p4.verify_reference(item)
    require(g4_business_binding(context, plan["input"]) == plan["business_binding"]
            and context["business_workload_sha256"] == plan["business_binding"]["sha256"], "G4 business hash changed")
    offsets = {phase: [x[0] for x in struct.iter_unpack(">q", (output / (phase + "-arrivals.bin")).read_bytes())]
               for phase in ("warmup", "measurement")}
    arrivals = g4_schedule(context, offsets)
    require(read_json(output / "arrivals.json", 32 * MIB) == arrivals
            and digest(output / "arrivals.json") == plan["arrivals_sha256"], "Actual G4 arrivals changed")
    batches = read_json(output / "batches.json", 32 * MIB)
    require(batches["source_sha256"] == plan["input"]["sha256"] and batches["copied_input_bytes"] == 0
            and batches["every_input_byte_checked_against_independent_model"] is True, "Missing full input preparation")
    entries = batches["batches"]
    require(len(entries) == max(len(arrivals[phase]) for phase in ("warmup", "measurement")), "Missing prepared ranges")
    for index, entry in enumerate(entries):
        require(entry["index"] == index and entry["offset"] == index * context["batch_rows"] * WIDTH
                and entry["first_id"] == index * context["batch_rows"] and entry["rows"] == context["batch_rows"]
                and entry["bytes"] == context["batch_rows"] * WIDTH and entry["path"] == plan["input"]["path"],
                "Prepared source offsets overlap or differ from unique input")
        read_batch(entry)  # Recheck every actually consumed slice against its preparation digest.
    labels, transactions, phase_summaries = set(), set(), {}
    owner = read_json(output / "database-owner.json")
    for phase in ("warmup", "measurement"):
        actual = report[phase]
        window = read_json(output / (phase + "-window.json"))
        require(actual["window"] == window and window["error_class"] is None and window["workers_terminated"] is True,
                "Phase worker lifecycle changed")
        expected_seconds = context["warmup_seconds"] if phase == "warmup" else context["duration_seconds"]
        require(window["offered_window_seconds"] == expected_seconds
                and window["arrival_sha256"] == hashlib.sha256(support.canonical(arrivals[phase])).hexdigest(),
                "Phase duration/arrival digest changed")
        ref = window["requests"]
        path = output / ref["path"]
        require(path.parent == output and digest(path) == ref["sha256"] and path.stat().st_size == ref["bytes"], "Raw request artifact mismatch")
        requests = [json.loads(line, object_pairs_hook=unique_object) for line in path.read_text().splitlines()]
        require(len(requests) == window["request_count"] == len(arrivals[phase]), "Dropped or extra G4 request")
        epoch = window["epoch_monotonic_ns"]
        for index, row in enumerate(requests):
            item = arrivals[phase][index]
            require(all(row.get(key) == value for key, value in item.items()) and row["phase"] == phase
                    and row["status"] == "ACK_SUCCESS", "G4 request schedule/status mismatch")
            require(row["batch_sha256"] == entries[index]["sha256"] and row["scheduled_monotonic_ns"] == epoch + item["offset_ns"]
                    <= row["started_monotonic_ns"] <= row["finished_monotonic_ns"]
                    < row["scheduled_monotonic_ns"] + LIMITS["request_seconds_from_arrival"] * NANO
                    and row["latency_ns_including_queue"] == row["finished_monotonic_ns"] - row["scheduled_monotonic_ns"],
                    "G4 data/timestamp/deadline mismatch")
            label = f"{owner['database']}_{phase}_w00_c{item['worker']:02d}_b{index:05d}"
            require(row["label"] == label and label not in labels and row["txn_id"] not in transactions,
                    "Duplicate/mismatched label or transaction")
            labels.add(label)
            transactions.add(row["txn_id"])
            body = row["original_be_response"]
            body_path = output / body["path"]
            require(body_path.parent == output and digest(body_path) == body["sha256"]
                    and body_path.stat().st_size == body["bytes"], "Original BE response changed")
            require(validate_receipt(read_json(body_path), label, item["rows"]) == row["txn_id"]
                    and server_transaction_state(row) == "ACKNOWLEDGED_SUCCESS", "Unproven transaction")
            require([hop["component"] for hop in row["hops"]] == ["fe", "be"]
                    and [hop["http_status"] for hop in row["hops"]] == [307, 200]
                    and row["hops"][1]["request_body_bytes_sent"] == item["rows"] * WIDTH
                    and all(hop.get("local_transport_closed") is True and not hop.get("close_error_class") for hop in row["hops"]),
                    "Actual two-hop transport/cleanup differs")
        summary = g4_latency_summary(requests, epoch, window["offered_window_seconds"])
        require(summary == actual["statistics"] == read_json(output / (phase + "-statistics.json"))
                and summary["error_count"] == summary["timeout_count"] == 0,
                "Raw G4 statistics differ")
        end = max([epoch + expected_seconds * NANO, *[row["finished_monotonic_ns"] for row in requests]])
        require(window["interval_end_monotonic_ns"] == end and window["cpu_boundary_before_worker_cleanup"] is True,
                "CPU interval excludes drain or includes cleanup")
        first, final = window["start_boundary"], window["end_boundary"]
        require(first["started_monotonic_ns"] <= first["finished_monotonic_ns"] <= epoch <= end
                <= final["started_monotonic_ns"] <= final["finished_monotonic_ns"], "CPU boundary order mismatch")
        for name in ("fe", "be"):
            before, after = first["processes"][name], final["processes"][name]
            require(before["start_ticks"] == after["start_ticks"] == plan["bindings"]["pins"][name]["start_ticks"], "CPU process changed")
            differences = [after[key] - before[key] for key in ("user_cpu_ticks", "system_cpu_ticks")]
            require(all(value >= 0 for value in differences), "CPU counters decreased")
            ticks = sum(differences)
            summary[name + "_cpu_seconds_per_success"] = ticks / os.sysconf("SC_CLK_TCK") / len(requests)
        visibility_value = read_json(output / (phase + "-visibility.json"), 32 * MIB)
        require(visibility_value == actual["visibility"] and visibility_value["rows"] == len(requests) * context["batch_rows"], "Visibility receipt changed")
        for first_batch, sequence in zip(range(0, len(requests), 10000), visibility_value["final_page_sql_sequences"]):
            stop_batch = min(len(requests), first_batch + 10000)
            query = group_visibility_sql(owner["database"], phase + "_rows", len(requests) * context["batch_rows"], context["batch_rows"]).replace(
                "ORDER BY batch_index", f"HAVING batch_index >= {first_batch} AND batch_index < {stop_batch} ORDER BY batch_index")
            complete = audit_visibility(support.rows(g4_sql_receipt(output, sequence, query)), len(requests), context["batch_rows"])
            require(complete == list(range(first_batch, stop_batch)), "Incomplete independent full-content visibility")
        require(len(visibility_value["final_page_sql_sequences"]) == math.ceil(len(requests) / 10000), "Missing visibility pages")
        require(len(visibility_value["batches"]) == len(requests), "Missing per-transaction visibility association")
        for row, visible in zip(requests, visibility_value["batches"]):
            require(all(visible.get(key) == row[key] for key in ("index", "label", "txn_id"))
                    and visible["ack_monotonic_ns"] == row["finished_monotonic_ns"]
                    <= visible["observed_visible_upper_bound_monotonic_ns"]
                    and any(item["first_batch"] <= row["index"] < item["stop_batch"]
                            and item["finished_monotonic_ns"] == visible["observed_visible_upper_bound_monotonic_ns"]
                            for item in visibility_value["observations"]), "Visibility does not identify the acknowledged transaction")
        query = f"SELECT COUNT(*) AS n, COUNT(DISTINCT id) AS d FROM {owner['database']}.{phase}_rows"
        total = str(len(requests) * context["batch_rows"])
        require(support.rows(g4_sql_receipt(output, visibility_value["cardinality_sql_sequence"], query)) == [{"n": total, "d": total}], "Wrong final cardinality")
        phase_summaries[phase] = summary
    before, after, restored = [read_json(output / ("g4-license-" + name + ".json")) for name in ("before", "after", "restored")]
    g4_stable_license(plan, before, after)
    warm, measured = report["warmup"]["window"], report["measurement"]["window"]
    require(before["finished_monotonic_ns"] <= warm["epoch_monotonic_ns"]
            <= warm["interval_end_monotonic_ns"] <= measured["epoch_monotonic_ns"]
            <= measured["interval_end_monotonic_ns"] <= after["started_monotonic_ns"]
            <= restored["started_monotonic_ns"], "License/warmup/measurement/restore ordering changed")
    for stage, observation in (("before", before), ("after", after), ("restored", restored)):
        if context["variant"] == "B":
            require(g4_license_values(g4_sql_receipt(output, observation["sql_sequence"], "SHOW LICENSE")) == observation["values"], "License declaration differs from actual SQL")
            g4_check_license(observation["values"], "VALID" if stage == "restored" else context["license_state"])
    acks = {stage: read_json(output / ("g4-" + stage + "-ack.json")) for stage in ("state", "oracle")}
    for stage, ack in acks.items():
        accepted = read_json(output / ("g4-" + stage + "-accepted.json"))
        ready = read_json(p4.verify_reference(accepted["ready"]))
        require(p4.verify_reference(accepted["ack"]) == (output / ("g4-" + stage + "-ack.json")).resolve()
                and all(ack.get(key) == value for key, value in ready.items())
                and ready["plan_sha256"] == digest(output / "plan.json") and ready["launch_token"] == plan["launch_token"]
                and ready["created_monotonic_ns"] <= ack["acknowledged_monotonic_ns"] <= accepted["accepted_monotonic_ns"]
                < ready["created_monotonic_ns"] + context["barrier_timeout_seconds"] * NANO, "State barrier evidence changed")
        require((accepted["accepted_monotonic_ns"] <= before["started_monotonic_ns"]) if stage == "state" else
                (after["finished_monotonic_ns"] <= ready["created_monotonic_ns"]
                 <= accepted["accepted_monotonic_ns"] <= restored["started_monotonic_ns"]), "State acknowledgement has wrong execution ordering")
    for phase in ("warmup", "measurement"):
        observations = report[phase]["visibility"]["observations"]
        require(observations and all(item["started_monotonic_ns"] >= restored["finished_monotonic_ns"]
                                    and item["finished_monotonic_ns"] >= item["started_monotonic_ns"] for item in observations),
                "Visibility oracle ran before restoration")
    observer_evidence = g4_observer_evidence(plan, acks["state"], acks["oracle"], warm, measured)
    require(observer_evidence == report["observer"], "Observer receipt differs")
    for key in ("launch", "observer_summary", "observer_samples"):
        if key in observer_evidence:
            dependencies.append(observer_evidence[key])
    summary = phase_summaries["measurement"]
    window = {"window_id": context["window_id"], "pair_id": context["pair_id"], "variant": context["variant"],
              "boot_id": plan["boot_id"], "identity": context["identity"], "workload_sha256": context["business_workload_sha256"],
              "arrival_schedule_sha256": measured["arrival_sha256"], "rate": context["rate"],
              "warmup_seconds": context["warmup_seconds"], "duration_seconds": context["duration_seconds"],
              "warmup_start_monotonic_ns": warm["epoch_monotonic_ns"], "warmup_end_monotonic_ns": warm["interval_end_monotonic_ns"],
              "start_monotonic_ns": measured["epoch_monotonic_ns"], "end_monotonic_ns": measured["interval_end_monotonic_ns"],
              "monotonic_clock_domain": "controller_monotonic_exact", "monotonic_mapping_uncertainty_ns": 0,
              "effective_duration_seconds": summary["effective_duration_seconds"], "scheduled_requests": summary["scheduled_requests"],
              "observed_requests": summary["observed_requests"], "successful_requests": summary["successful_requests"],
              "error_count": 0, "timeout_count": 0, "retry_count": 0, "oracle_verified": True, "cleanup_verified": True,
              "cpu_boundary_verified": True, "metrics": {key: summary[key] for key in p4.METRICS}}
    freeze = g4_freeze(context, measured["arrival_sha256"])
    if freeze:
        require(all(plan["current_bindings"][key] == ref for key, ref in freeze.items()), "AB freeze changed after actual plan")
        require(read_json(freeze["publication"]["path"])["published_monotonic_ns"] <= plan["created_monotonic_ns"]
                <= warm["epoch_monotonic_ns"], "AB measured before freeze publication")
        window.update(freeze_sha256=freeze["freeze"]["sha256"], freeze_publication_sha256=freeze["publication"]["sha256"])
    require(original_bindings == g4_raw_bindings(output), "G4 evidence changed during audit")
    return {"status": "DIAGNOSTIC_VERIFIED" if context["phase"] == "DIAGNOSTIC" else "VERIFIED", "window": window,
            "auditor": p4.reference(SOURCE), "raw_artifacts": original_bindings, "dependency_bindings": dependencies,
            "observer": observer_evidence, "formal_performance_pass": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "probe", "generate-input"), default="plan")
    parser.add_argument("--profile", choices=("legacy-lp012", "current-g4"), default="legacy-lp012")
    parser.add_argument("--context", type=Path, help="Explicit current G4 single-window context; no inline certificate")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cluster-record", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--rows", type=int, help="Explicit current-G4 input generation count, outside all measured windows")
    parser.add_argument("--expected-fe-sha256")
    parser.add_argument("--expected-be-sha256")
    parser.add_argument("--jdk-runtime-version", default="17.0.4+8")
    parser.add_argument("--concurrency", type=int, choices=(1, 8, 32), default=1)
    parser.add_argument("--batch-rows", type=int, choices=(1000, 10000), default=1000)
    parser.add_argument("--window-seconds", type=int, default=600)
    parser.add_argument("--cpu", type=int, default=5)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_STREAM_ADMIN_PASSWORD")
    args = parser.parse_args(argv)
    require(args.mode != "probe" or args.plan is not None, "Explicit probe requires a frozen plan")
    if args.mode == "generate-input":
        require(args.profile == "current-g4" and args.input is not None, "Input generation requires explicit current-G4 profile and path")
        result = generate_g4_input(args.input, args.rows)
    else:
        result = probe(args) if args.mode == "probe" else make_g4_plan(args) if args.profile == "current-g4" else make_plan(args)
    print(json.dumps({"status": result["status"], "LP012_complete": False, "release_performance_pass": False}), flush=True)
    return 1 if result["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
