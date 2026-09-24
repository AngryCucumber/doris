#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""LP026 sampled process budgets and bounded helper output; no database or network requests."""

import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
LIMITS = {"interval_seconds": 1.0, "controller_rss_bytes": 512 * MIB, "helper_rss_bytes": 768 * MIB,
          "combined_fixture_rss_bytes": 2048 * MIB, "controller_threads": 32, "helper_threads": 128,
          "output_bytes_per_stream": 2 * MIB, "resource_evidence_bytes": 64 * MIB,
          "registered_processes": 4096, "controller_thread_samples": 64}
IO_KEYS = ("rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes", "cancelled_write_bytes")


class ProcessObservationUnavailable(ValueError):
    """A proc field can disappear during exit; this alone is never proof of exit."""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded_read(path, limit=65536):
    with Path(path).open("rb") as stream:
        value = stream.read(limit + 1)
    require(len(value) <= limit, "Proc input exceeded its fixed bound")
    return value


def stat_values(raw):
    fields = raw.decode("utf-8", "replace").rsplit(")", 1)[1].split()
    require(len(fields) >= 22, "Incomplete process stat")
    return {"state": fields[0], "start_ticks": int(fields[19]), "user_cpu_ticks": int(fields[11]),
            "system_cpu_ticks": int(fields[12]), "threads": int(fields[17]),
            "rss_bytes": max(0, int(fields[21])) * os.sysconf("SC_PAGE_SIZE")}


def io_values(raw):
    fields = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition(":")
        if separator and key in IO_KEYS:
            require(key not in fields, "Duplicate process IO counter")
            fields[key] = int(value.strip())
    require(set(fields) == set(IO_KEYS), "Incomplete process IO counters")
    require(all(value >= 0 for key, value in fields.items() if key != "cancelled_write_bytes"),
            "Negative process IO counter")
    return fields


def network_values(raw):
    interfaces = {}
    for line in raw.decode("ascii").splitlines():
        name, separator, value = line.partition(":")
        if not separator:
            continue
        values = [int(part) for part in value.split()]
        require(len(values) == 16 and min(values) >= 0, "Malformed namespace network counters")
        name = name.strip()
        require(name and len(name) <= 32 and name not in interfaces, "Ambiguous namespace interface")
        interfaces[name] = {"rx_bytes": values[0], "rx_packets": values[1], "tx_bytes": values[8],
                            "tx_packets": values[9], "loopback": name == "lo"}
    require(interfaces, "No namespace network counters")
    return {"scope": "whole_private_namespace_including_FE_BE_helpers_controller",
            "process_attribution": False, "rx_plus_tx_summed": False, "interfaces": interfaces}


def process_identity(pid):
    directory = Path("/proc") / str(pid)
    before = stat_values(bounded_read(directory / "stat"))
    command = bounded_read(directory / "cmdline", 256 * 1024)
    if not command or before["state"] == "Z":
        raise ProcessObservationUnavailable("empty_command_or_zombie")
    result = {"pid": pid, "start_ticks": before["start_ticks"],
              "executable": os.readlink(directory / "exe"), "namespace": os.readlink(directory / "ns/net"),
              "command_sha256": hashlib.sha256(command).hexdigest(), "command_bytes": len(command),
              "raw_command_archived": False}
    require(stat_values(bounded_read(directory / "stat"))["start_ticks"] == result["start_ticks"],
            "Process identity changed during capture")
    return result


def sample_process(pin, include_threads=False):
    current = process_identity(pin["pid"])
    require(current == pin, "Pinned process identity changed")
    directory = Path("/proc") / str(pin["pid"])
    stat = stat_values(bounded_read(directory / "stat"))
    memory = {}
    for line in bounded_read(directory / "status").decode("ascii").splitlines():
        key, separator, value = line.partition(":")
        if separator and key in ("VmRSS", "VmHWM", "VmSwap"):
            parts = value.split()
            require(len(parts) == 2 and parts[1] == "kB", "Unexpected memory counter unit")
            memory[key + "_bytes"] = int(parts[0]) * 1024
    if set(memory) != {"VmRSS_bytes", "VmHWM_bytes", "VmSwap_bytes"}:
        raise ProcessObservationUnavailable("incomplete_memory_counters")
    result = {**stat, **memory, "io": io_values(bounded_read(directory / "io")),
              "sample_monotonic_ns": time.monotonic_ns()}
    if include_threads:
        tasks = sorted((directory / "task").iterdir(), key=lambda path: int(path.name))
        require(len(tasks) <= LIMITS["controller_thread_samples"], "Controller thread inventory exceeded its bound")
        thread_rows = []
        for task in tasks:
            try:
                row = stat_values(bounded_read(task / "stat"))
                # Thread RSS refers to shared process memory and must never be summed.
                thread_rows.append({key: row[key] for key in ("start_ticks", "user_cpu_ticks", "system_cpu_ticks")}
                                   | {"tid": int(task.name)})
            except FileNotFoundError:
                thread_rows.append({"tid": int(task.name), "exited_during_sample": True})
        result["thread_cpu"] = thread_rows
        result["thread_rss_attribution"] = "shared_process_memory_not_summed"
        result["known_python_thread_roles"] = [{"tid": thread.native_id, "role": thread.name}
                                               for thread in threading.enumerate()
                                               if thread.name == "MainThread" or thread.name.startswith("lp026-")]
    require(process_identity(pin["pid"]) == pin, "Process changed while collecting resource sample")
    return result


def exceeded(role, sample):
    if role not in ("controller", "helper"):
        return []
    reasons = []
    # HWM is separately useful for peaks occurring between samples; it is still not a hard RSS limit.
    if max(sample["rss_bytes"], sample["VmRSS_bytes"], sample["VmHWM_bytes"]) > LIMITS[role + "_rss_bytes"]:
        reasons.append(role + "_rss_budget")
    if sample["threads"] > LIMITS[role + "_threads"]:
        reasons.append(role + "_thread_budget")
    return reasons


class ResourceGuard:
    """Sample owned actors, fail closed, and preserve partial telemetry without impeding cleanup."""

    def __init__(self, output, state):
        output = Path(output).resolve()
        require(ROOT / ".build-records" in output.parents, "Resource evidence must be checkout-owned")
        self.output, self.state = output, state
        self.lock, self.write_lock = threading.RLock(), threading.Lock()
        self.failed, self.stopping = threading.Event(), threading.Event()
        self.actors, self.failures, self.logs = {}, [], []
        self.helper_processes = {}
        self.failure_count = self.evidence_bytes = self.samples = 0
        self.cleanup = False
        self.thread = None
        self.stream = None
        self.network_first = self.network_last = None

    def fail(self, scope, kind):
        with self.lock:
            self.failure_count += 1
            if len(self.failures) < 32:
                self.failures.append({"scope": scope, "kind": kind, "monotonic_ns": time.monotonic_ns(),
                                      "during_cleanup": self.cleanup})
        self.failed.set()

    def write(self, value):
        try:
            raw = (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
            with self.write_lock:
                require(self.evidence_bytes + len(raw) <= LIMITS["resource_evidence_bytes"],
                        "Resource evidence byte bound exceeded")
                require(self.stream is not None, "Resource evidence stream unavailable")
                # Reserve before write: partial writes/errors must not allow later retries beyond the bound.
                self.evidence_bytes += len(raw)
                require(self.stream.write(raw) == len(raw), "Incomplete resource evidence write")
                self.stream.flush()
        except Exception as error:
            self.fail("resource_evidence", type(error).__name__)

    def register(self, name, pid, role, expected=None):
        require(role in ("controller", "helper", "service", "supervisor"), "Invalid resource actor role")
        with self.lock:
            require(len(self.actors) < LIMITS["registered_processes"] and name not in self.actors,
                    "Resource actor registry bound or name collision")
            actor = {"name": name, "role": role, "pid": pid, "pin": None, "active": True,
                     "samples": 0, "first": None, "last": None, "peak_rss_bytes": 0,
                     "capture_errors": 0, "exit_code": None, "phase_registered": "cleanup" if self.cleanup else "work"}
            self.actors[name] = actor
        try:
            pin = process_identity(pid)
            require(pin["namespace"] == self.state["namespace"], "Resource actor belongs to foreign namespace")
            if expected:
                require(str(pin["start_ticks"]) == str(expected["start_ticks"]), "Resource actor start ticks differ")
                if expected.get("executable"):
                    require(pin["executable"] == expected["executable"], "Resource actor executable differs")
            actor["pin"] = pin
            self.write({"type": "registration", "actor": name, "role": role, "identity": pin})
            self.sample_actor(actor)
        except Exception as error:
            actor["capture_errors"] += 1
            self.fail(name, "registration_" + type(error).__name__)
        return actor

    def register_child(self, process, record, command):
        self.helper_processes[record["name"]] = process
        actor = self.register(record["name"], process.pid, "helper", record)
        # Only the command digest is stored; environment and arbitrary JVM properties never enter evidence.
        actor["launch_command_sha256"] = hashlib.sha256(
            b"\0".join(os.fsencode(str(arg)) for arg in command) + b"\0").hexdigest()
        if actor["pin"] and actor["pin"]["command_sha256"] != actor["launch_command_sha256"]:
            self.fail(record["name"], "launch_command_identity_mismatch")
        return actor

    def retire_child(self, record, exit_code):
        with self.lock:
            actor = self.actors.get(record["name"])
            if actor:
                actor["active"] = False
                actor["exit_code"] = exit_code
                actor["retired_monotonic_ns"] = time.monotonic_ns()
        if actor:
            self.write({"type": "retired", "actor": record["name"], "exit_code": exit_code,
                        "samples": actor["samples"], "last_sample_precedes_exit": True})

    def sample_actor(self, actor):
        pin = actor["pin"]
        if pin is None:
            return None
        try:
            sample = sample_process(pin, actor["role"] == "controller")
        except (FileNotFoundError, ProcessLookupError, ProcessObservationUnavailable) as error:
            process = self.helper_processes.get(actor["name"]) if actor["role"] == "helper" else None
            if process is None:
                raise
            # /proc disappearance, an empty cmdline and zombie/missing RSS fields do not prove exit.
            # Only this exact owned Popen's wait result permits an explicitly missing final sample.
            try:
                exit_code = process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                raise error
            require(type(exit_code) is int, "Missing owned child exit receipt")
            missing = {"reason": str(error) if isinstance(error, ProcessObservationUnavailable)
                       else type(error).__name__, "exit_code": exit_code,
                       "monotonic_ns": time.monotonic_ns(), "final_RSS_not_observed": True}
            with self.lock:
                actor["unavailable_exit_samples"] = actor.get("unavailable_exit_samples", 0) + 1
                actor["last_unavailable_exit_sample"] = missing
            self.write({"type": "sample_unavailable_after_confirmed_exit", "actor": actor["name"],
                        "pid": pin["pid"], "start_ticks": pin["start_ticks"], **missing})
            return None
        with self.lock:
            actor["samples"] += 1
            if actor["first"] is None or sample["sample_monotonic_ns"] < actor["first"]["sample_monotonic_ns"]:
                actor["first"] = sample
            if actor["last"] is None or sample["sample_monotonic_ns"] > actor["last"]["sample_monotonic_ns"]:
                actor["last"] = sample
            actor["peak_rss_bytes"] = max(actor["peak_rss_bytes"], sample["rss_bytes"], sample["VmRSS_bytes"],
                                           sample["VmHWM_bytes"])
        for reason in exceeded(actor["role"], sample):
            self.fail(actor["name"], reason)
        self.write({"type": "process_sample", "actor": actor["name"], "role": actor["role"],
                    "pid": pin["pid"], "start_ticks": pin["start_ticks"], "sample": sample})
        return sample

    def sample(self):
        with self.lock:
            actors = [actor for actor in self.actors.values() if actor["active"]]
        total = 0
        for actor in actors:
            try:
                value = self.sample_actor(actor)
                if value and actor["role"] in ("controller", "helper"):
                    total += max(value["rss_bytes"], value["VmRSS_bytes"])
            except Exception as error:
                actor["capture_errors"] += 1
                self.fail(actor["name"], "sample_" + type(error).__name__)
        if total > LIMITS["combined_fixture_rss_bytes"]:
            self.fail("fixture_processes", "combined_sampled_rss_budget")
        try:
            require(os.readlink("/proc/self/ns/net") == self.state["namespace"], "Namespace identity changed")
            network = network_values(bounded_read("/proc/net/dev"))
            self.network_first = self.network_first or network
            self.network_last = network
            self.write({"type": "namespace_network", "monotonic_ns": time.monotonic_ns(), "counters": network,
                        "combined_fixture_sampled_rss_bytes": total, "samples_simultaneous": False})
        except Exception as error:
            self.fail("namespace_network", type(error).__name__)
        self.samples += 1

    def start(self):
        require(self.thread is None, "Resource guard already started")
        try:
            self.stream = (self.output / "resources.jsonl").open("xb")
        except Exception as error:
            self.fail("resource_evidence", type(error).__name__)
        identity = self.state["verified_identity"]
        self.register("controller_including_ES_and_observer_threads", os.getpid(), "controller")
        for name, pin in identity["services"].items():
            self.register("original_" + name, pin["pid"], "service", pin)
        self.register("namespace_supervisor", identity["supervisor_pid"], "supervisor",
                      {"start_ticks": identity["supervisor_start_ticks"]})
        def observe():
            while not self.stopping.is_set():
                try:
                    self.sample()
                except Exception as error:
                    self.fail("observer", type(error).__name__)
                self.stopping.wait(LIMITS["interval_seconds"])
        self.thread = threading.Thread(target=observe, name="lp026-resources", daemon=True)
        self.thread.start()
        self.check()

    def check(self):
        if self.failed.is_set() and not self.cleanup:
            raise ValueError("LP026 resource budget/identity/evidence failed; inspect partial resource evidence")

    def begin_cleanup(self):
        self.cleanup = True

    def attach_output(self, process, name):
        capture = BoundedOutput(process, self.output, name, self.fail)
        self.logs.append(capture)
        capture.start()
        return capture

    def stop(self):
        self.stopping.set()
        if self.thread:
            try:
                self.thread.join(timeout=3)
            except Exception as error:
                self.fail("observer_join", type(error).__name__)
        running = bool(self.thread and self.thread.is_alive())
        if running:
            self.fail("observer", "thread_did_not_stop")
        else:
            try:
                self.sample()
            except Exception as error:
                self.fail("final_resource_sample", type(error).__name__)
        for capture in self.logs:
            try:
                capture.stop()
            except Exception as error:
                self.fail("background_output_stop", type(error).__name__)
        if any(actor["active"] and actor["role"] == "helper" for actor in self.actors.values()):
            self.fail("helpers", "unretired_helper_remains")
        if not running and self.stream:
            try:
                self.stream.close()
            except Exception as error:
                self.fail("resource_evidence_close", type(error).__name__)
        log_summaries = []
        for capture in self.logs:
            try:
                log_summaries.append(capture.summary())
            except Exception as error:
                self.fail("background_output_summary", type(error).__name__)
                log_summaries.append({"summary_error": type(error).__name__})
        return {"limits": dict(LIMITS), "sampled_limits_only": True, "may_miss_transient_peaks": True,
                "heap_is_not_rss": True, "process_cpu_ticks_per_second": os.sysconf("SC_CLK_TCK"),
                "cpu_io_scope": "per_process_cumulative_observed_counters_excludes_descendants",
                "thread_cpu_scope": "controller_threads_only_shared_RSS_not_summed",
                "service_resources_counted_as_helper_cost": False, "samples": self.samples,
                "sum_of_RSS_may_double_count_shared_pages": True,
                "evidence_bytes_reserved": self.evidence_bytes, "failures": list(self.failures),
                "failure_count": self.failure_count, "observer_thread_stopped": not running,
                "actors": list(self.actors.values()), "network_first": self.network_first,
                "network_last": self.network_last, "logs": log_summaries,
                "complete": not self.failed.is_set() and not running,
                "performance_pass": False}


class BoundedOutput:
    """Drain background stdout/stderr through bounded files, never direct unbounded redirection."""

    def __init__(self, process, output, name, failure):
        self.process, self.output, self.name, self.failure = process, Path(output), name, failure
        self.stopping = threading.Event()
        self.thread = None
        self.streams = {}
        self.bytes = {"stdout": 0, "stderr": 0}
        self.hashes = {name: hashlib.sha256() for name in self.bytes}
        self.errors = []
        self.eof = set()
        self.stop_completed = False

    def start(self):
        try:
            for name in self.bytes:
                self.streams[name] = (self.output / (self.name + "." + name)).open("xb")
        except Exception:
            for stream in self.streams.values():
                stream.close()
            raise
        self.thread = threading.Thread(target=self.run, name="lp026-broker-output", daemon=True)
        self.thread.start()

    def accept(self, name, chunk):
        require(self.bytes[name] + len(chunk) <= LIMITS["output_bytes_per_stream"], "Background output byte bound exceeded")
        require(self.streams[name].write(chunk) == len(chunk), "Incomplete background output write")
        self.streams[name].flush()
        self.hashes[name].update(chunk)
        self.bytes[name] += len(chunk)

    def run(self):
        try:
            with selectors.DefaultSelector() as selected:
                for name in self.bytes:
                    stream = getattr(self.process, name)
                    os.set_blocking(stream.fileno(), False)
                    selected.register(stream, selectors.EVENT_READ, name)
                while selected.get_map() and not self.stopping.is_set():
                    for key, _ in selected.select(0.2):
                        try:
                            chunk = os.read(key.fileobj.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            self.eof.add(key.data)
                            selected.unregister(key.fileobj)
                        else:
                            self.accept(key.data, chunk)
        except Exception as error:
            self.errors.append(type(error).__name__)
            self.failure(self.name + "_output", type(error).__name__)
        finally:
            for stream in (*self.streams.values(), self.process.stdout, self.process.stderr):
                try:
                    stream.close()
                except Exception as error:
                    self.failure(self.name + "_output_close", type(error).__name__)

    def stop(self):
        if self.stop_completed:
            return
        # Reaped children should deliver EOF first; then the bounded fallback ends the drain loop.
        if self.thread:
            self.thread.join(timeout=1)
            if self.thread.is_alive():
                self.stopping.set()
                self.thread.join(timeout=1)
            if self.thread.is_alive():
                self.failure(self.name + "_output", "thread_did_not_stop")
        if self.eof != set(self.bytes):
            self.failure(self.name + "_output", "incomplete_EOF_capture")
        self.stop_completed = True

    def summary(self):
        return {"name": self.name, "bytes": dict(self.bytes), "sha256": {key: value.hexdigest() for key, value in self.hashes.items()},
                "errors": list(self.errors), "eof": sorted(self.eof),
                "byte_limit_per_stream": LIMITS["output_bytes_per_stream"],
                "thread_stopped": not self.thread or not self.thread.is_alive()}
