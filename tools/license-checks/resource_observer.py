#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Bounded, read-only /proc and allowlisted /metrics sampling for an owned private FE/BE cluster."""

import argparse
from collections import Counter
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import shutil
import stat
import threading
import time

from stream_load_fixture import ROOT, digest, owned, save, utc, validate_cluster


MAX_BODY_BYTES = 2 * 1024 * 1024
# Explicit P4-only extension: 7200 warmup + 86400 measurement + 2*3600 drain
# + 480 runner allowance + 720 observer preparation/finalization seconds.
# The historical observer mode remains bounded to 14400 seconds.
P4_MAX_DURATION_SECONDS = 102000
P4_MAX_SAMPLE_BYTES = 8 * 1024 * 1024
P4_MAX_LOG_BYTES = 8 * 1024**3
IO_FIELDS = ("rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes", "cancelled_write_bytes")
STATUS_FIELDS = ("VmRSS", "VmHWM", "VmSwap")
NET_FIELDS = ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped")
THRIFT_METHODS = frozenset("""
getDbNames getTableNames describeTables showVariables reportExecStatus finishTask report fetchResource forward
listTableStatus listTableMetadataNameIds listTablePrivilegeStatus listSchemaPrivilegeStatus listUserPrivilegeStatus
loadTxnBegin loadTxnPreCommit loadTxn2PC loadTxnCommit loadTxnRollback beginTxn commitTxn rollbackTxn getBinlog
getSnapshot restoreSnapshot lockBinlog waitingTxnStatus streamLoadPut streamLoadMultiTablePut snapshotLoaderReport
getAliveSessions ping syncCloudVersion initExternalCtlMeta fetchSchemaTableData acquireToken checkToken
confirmUnusedRemoteFiles checkAuth getQueryStats getTabletReplicaInfos addPlsqlStoredProcedure dropPlsqlStoredProcedure
addPlsqlPackage dropPlsqlPackage getMasterToken getBinlogLag updateStatsCache updatePlanStatsCache getAutoIncrementRange
createPartition replacePartition getMeta getBackendMeta getColumnInfo invalidateStatsCache showProcessList
reportCommitTxnResult showUser syncQueryColumns fetchSplitBatch updatePartitionStatsCache fetchRunningQueries
fetchRoutineLoadJob fetchLoadJob getEncryptionKeys getTableTDEInfo getOlapTableMeta
""".split())
GC_LIMITS = {"files": 11, "open_files": 12, "batch_bytes": 1024 * 1024, "line_bytes": 65536,
             "event_line_bytes": 4096, "total_read_bytes": 256 * 1024 * 1024,
             "archive_bytes": 64 * 1024 * 1024, "events": 100000, "batch_seconds": .25,
             "finish_seconds": 1.0, "directory_entries": 4096}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def validate_rpc_selection(value):
    if (not isinstance(value, dict) or set(value) != {"schema_version", "be_hostnames", "thrift_methods"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1):
        raise ValueError("Unexpected RPC selection schema")
    for name, allowed in (("be_hostnames", {"127.0.0.1"}), ("thrift_methods", THRIFT_METHODS)):
        values = value[name]
        if (not isinstance(values, list) or not values or any(type(item) is not str for item in values)
                or values != sorted(set(values)) or not set(values) <= allowed):
            raise ValueError("RPC selection is outside the explicit original single-node allowlist")
    return value


def load_rpc_selection(path):
    path = owned(path)
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("RPC selection exceeds bound")
    return validate_rpc_selection(json.loads(raw, object_pairs_hook=unique_object)), {
        "path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def rpc_allowlist(selection):
    validate_rpc_selection(selection)
    values = {}
    for host in selection["be_hostnames"]:
        for suffix, unit, semantics in (
                ("total", "attempts", "fragment prepare/execute attempts before proxy/send; excludes phase2 and other RPCs"),
                ("size", "bytes", "protobuf request serialized size at attempt; not sent or wire bytes")):
            values[("doris_fe_query_rpc_" + suffix, (("be", host),))] = {
                "unit": unit, "counter_semantics": semantics, "monotonic_expected": True}
    for method in selection["thrift_methods"]:
        for suffix, unit, semantics, monotonic in (
                ("total", "handler_invocations", "FE FrontendService handler entry, including throwing handlers", True),
                ("latency_ms", "milliseconds", "sum of handler wall-clock end-minus-start; not a latency distribution", False)):
            values[("doris_fe_thrift_rpc_" + suffix, (("method", method),))] = {
                "unit": unit, "counter_semantics": semantics, "monotonic_expected": monotonic}
    return values


def parse_rpc_metrics(body, selection):
    started = time.monotonic_ns()
    allowed, found, ignored = rpc_allowlist(selection), {}, 0
    names = {key[0] for key in allowed}
    pattern = re.compile(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([+-]?\d+)\s*$')
    for line in body.decode("utf-8", errors="strict").splitlines():
        prefix = re.match(r"([a-zA-Z_:][a-zA-Z0-9_:]*)", line)
        if not prefix or prefix[1] not in names:
            continue
        match = pattern.fullmatch(line)
        if not match:
            raise ValueError("Malformed selected RPC metric")
        labels = parse_labels(match[2] or "")
        key = (match[1], tuple(sorted(labels.items())))
        if key not in allowed:
            ignored += 1
            continue
        if key in found:
            raise ValueError("Duplicate selected RPC series")
        value = int(match[3])
        if value < 0 and allowed[key]["monotonic_expected"]:
            raise ValueError("Negative RPC counter")
        found[key] = value
    return {"schema_version": 1, "scope": "fe_fragment_attempts_and_frontend_thrift_handlers",
            "all_rpc_coverage": False, "wire_bytes": False, "ignored_rpc_series": ignored,
            "parse_elapsed_nanos": time.monotonic_ns() - started,
            "series": [{"name": key[0], "labels": dict(key[1]), **details,
                        "presence": "present" if key in found else "not_created_or_unavailable",
                        "value": found.get(key)} for key, details in sorted(allowed.items())]}


class RpcTracker:
    """Differences over observed scrape intervals; never invent lazy-series zero baselines."""
    def __init__(self):
        self.previous, self.seen = {}, set()
        self.samples, self.intervals, self.invalid, self.missing, self.unavailable = 0, 0, 0, set(), 0
        self.parse_elapsed_nanos = 0

    def update(self, sample):
        extension = sample.get("processes", {}).get("fe", {}).get("metrics", {}).get("extensions", {}).get("scoped_rpc")
        self.samples += 1
        if extension is None:
            self.previous.clear()
            self.unavailable += 1
            return
        current = {}
        self.parse_elapsed_nanos += extension["parse_elapsed_nanos"]
        for row in extension["series"]:
            key = (row["name"], tuple(sorted(row["labels"].items())))
            row.update({"delta": None, "delta_scope": "observed_scrape_interval", "delta_reason": "no_start_baseline"})
            value = row["value"]
            if value is None:
                self.missing.add(key)
                row["delta_reason"] = "series_absent"
                if key in self.seen:
                    row["presence"] = "lost_after_observed"
                    sample["errors"].append({"scope": "fe_rpc", "type": "RpcSeriesLost"})
                    self.invalid += 1
                continue
            self.seen.add(key)
            prior = self.previous.get(key)
            if value < 0 or prior is not None and value < prior[0]:
                row["delta_reason"] = "counter_or_wall_clock_discontinuity"
                sample["errors"].append({"scope": "fe_rpc", "type": "RpcCounterDiscontinuity"})
                self.invalid += 1
                continue
            elif prior is not None:
                row.update({"delta": value - prior[0], "delta_reason": None,
                            "from_scrape": prior[1], "to_scrape": extension["scrape_monotonic_ns"]})
                self.intervals += 1
            current[key] = (value, extension["scrape_monotonic_ns"])
        self.previous = current

    def summary(self):
        return {"samples_seen": self.samples, "valid_series_intervals": self.intervals,
                "invalid_intervals": self.invalid, "keys_absent_in_any_sample": len(self.missing),
                "unavailable_samples": self.unavailable,
                "rpc_parse_elapsed_nanos": self.parse_elapsed_nanos,
                "scoped_rpc_delta_complete": self.samples > 1 and self.intervals > 0
                and not self.missing and not self.invalid and not self.unavailable,
                "all_rpc_coverage": False, "wire_bytes": False}


class IdentityChanged(RuntimeError):
    pass


def bounded_file(path, maximum):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Local identity input exceeds bound")
    return data


def gc_binding(state, pin):
    check_identity(pin, state["namespace"])
    proc = Path("/proc") / str(pin["pid"])
    command = bounded_file(proc / "cmdline", 65536)
    args = command.rstrip(b"\0").decode("utf-8", errors="strict").split("\0")
    options = [value for value in args if value.startswith("-Xlog:")]
    if len(options) != 1:
        raise ValueError("Require one original GC log configuration")
    match = re.fullmatch(r'-Xlog:gc\*,classhisto\*=trace:(?:file=)?([^:]+):time,uptime:filecount=10,filesize=50M', options[0])
    if not match:
        raise ValueError("Unsupported original GC log configuration")
    path = Path(match[1])
    installation = owned(state["installation"])
    if (not path.is_absolute() or path.resolve() != path or path.parent != installation / "fe/log"
            or not re.fullmatch(r"fe\.gc\.log\.\d{8}-\d{6}", path.name)):
        raise ValueError("GC log is outside the exact owned FE log family")
    executable = os.readlink(proc / "exe")
    expected = str((Path(state["java_home"]) / "bin/java").resolve())
    if executable != expected:
        raise IdentityChanged("GC owner executable changed")
    check_identity(pin, state["namespace"])
    if bounded_file(proc / "cmdline", 65536) != command:
        raise IdentityChanged("GC owner command changed")
    return {"path": str(path), "pid": pin["pid"], "start_ticks": pin["start_ticks"],
            "namespace": state["namespace"], "executable": executable,
            "cmdline_sha256": hashlib.sha256(command).hexdigest(), "log_option": options[0],
            "filecount": 10, "filesize_bytes": 50 * 1024 * 1024,
            "all_jvm_gc_pauses_proven": False}


def parse_gc_pause(line):
    """Parse complete top-level durations, without retaining arbitrary histogram/log text."""
    text = line.decode("utf-8", errors="strict").rstrip("\n")
    match = re.fullmatch(r'\[([^]\r\n]+)\]\[([0-9]+(?:\.[0-9]+)?)s\] GC\((\d+)\) Pause (.+) ([0-9]+(?:\.[0-9]+)?)ms', text)
    if not match:
        if re.search(r'\] GC\(\d+\) Pause ', text) and re.search(r'(?:ms|NaN|Inf)\s*$', text):
            raise ValueError("Malformed completed GC Pause event")
        return None
    if len(line) > GC_LIMITS["event_line_bytes"] or not re.fullmatch(
            r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d{4}', match[1]):
        raise ValueError("Unexpected GC timestamp or event line length")
    category = match[4].split(" ", 1)[0]
    if category not in {"Young", "Full", "Remark", "Cleanup"}:
        raise ValueError("Unsupported completed GC Pause category")
    try:
        datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S.%f%z")
        uptime = Decimal(match[2]) * 1000000000
        duration = Decimal(match[5]) * 1000000
        if uptime != uptime.to_integral_value() or duration != duration.to_integral_value():
            raise ValueError("Unsupported GC timestamp precision")
    except InvalidOperation as error:
        raise ValueError("Invalid GC event numbers") from error
    if duration < 0 or duration > uptime or uptime > 2 ** 63 - 1:
        raise ValueError("GC duration exceeds uptime")
    return {"wall_time_raw": match[1], "uptime_raw_seconds": match[2], "duration_raw_ms": match[5],
            "end_uptime_ns": int(uptime), "start_uptime_ns": int(uptime - duration),
            "duration_ns": int(duration), "gc_id": int(match[3]), "category": category.lower(),
            "window_assignment": "unmapped", "window_mapping_complete": False,
            "reason": "No independently bounded JVM-uptime to workload-monotonic mapping",
            "raw_line_sha256": hashlib.sha256(line).hexdigest()}


class GcPauseReader:
    """Bounded append/rename cursor; observed retained bytes are not proof of lossless JVM logging."""
    def __init__(self, binding, output):
        self.binding, self.output = binding, owned(output)
        self.path = Path(binding["path"])
        if self.path.resolve() != self.path or owned(self.path) != self.path:
            raise ValueError("GC source path must be canonical and owned")
        self.files, self.dirfd, self.stream = {}, None, None
        self.read_bytes, self.archive_bytes, self.events, self.ignored_lines = 0, 0, 0, 0
        self.confirmed_events = 0
        self.batches, self.elapsed_nanos = 0, 0
        self.last_uptime, self.closed, self.failed = None, False, False
        self.next_generation = 0
        self.gaps, self.errors = [], []
        self.output.mkdir(parents=True, exist_ok=True)
        self.event_path = self.output / "gc-pauses.jsonl"
        try:
            self._identity()
            self.dirfd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.parent_identity = self._key(os.fstat(self.dirfd))
            self._scan(initial=True)
            self.stream = self.event_path.open("xb")
            self._identity()
        except BaseException as error:
            error.gc_initialization_cleanup_errors = self._close()
            raise

    @staticmethod
    def _key(value):
        return value.st_dev, value.st_ino

    def _identity(self):
        check_identity(self.binding, self.binding["namespace"])
        proc = Path("/proc") / str(self.binding["pid"])
        if (os.readlink(proc / "exe") != self.binding["executable"]
                or hashlib.sha256(bounded_file(proc / "cmdline", 65536)).hexdigest() != self.binding["cmdline_sha256"]):
            raise IdentityChanged("GC process executable or command changed")

    def _scan(self, initial=False):
        if self._key(self.path.parent.stat()) != self.parent_identity:
            raise ValueError("GC source directory replaced")
        names, count = [], 0
        pattern = re.compile(re.escape(self.path.name) + r'(?:\.[0-9])?$')
        # scandir(fd) shares that open file description's directory position. Open a fresh
        # description each time; dup(self.dirfd) would retain the same stale cursor too.
        scanfd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.dirfd)
        try:
            with os.scandir(scanfd) as directory:
                for item in directory:
                    count += 1
                    if count > GC_LIMITS["directory_entries"]:
                        raise ValueError("GC directory scan bound exceeded")
                    if pattern.fullmatch(item.name):
                        names.append(item.name)
        finally:
            os.close(scanfd)
        if len(names) > GC_LIMITS["files"] or self.path.name not in names:
            raise ValueError("GC current file absent or family bound exceeded")
        # Free fully consumed unlinked generations; retain pending bytes as a gap instead of forgetting them.
        for key, value in list(self.files.items()):
            state = os.fstat(value["fd"])
            if not state.st_nlink and state.st_size == value["offset"]:
                if value["pending"]:
                    raise ValueError("Unlinked GC generation has an incomplete line")
                os.close(value["fd"])
                del self.files[key]
        for name in sorted(names):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.dirfd)
            retained = False
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("GC input is not a regular file")
                key = self._key(info)
                if key in self.files:
                    continue
                if len(self.files) >= GC_LIMITS["open_files"]:
                    raise ValueError("GC open generation bound exceeded")
                offset, pending, line_offset = 0, b"", 0
                if initial:
                    offset = info.st_size
                    tail = os.pread(fd, min(offset, GC_LIMITS["line_bytes"] + 1), max(0, offset - GC_LIMITS["line_bytes"] - 1))
                    self.read_bytes += len(tail)
                    if tail and not tail.endswith(b"\n"):
                        pending = tail.rsplit(b"\n", 1)[-1]
                        if len(pending) > GC_LIMITS["line_bytes"]:
                            raise ValueError("Initial GC partial line exceeds bound")
                    line_offset = offset - len(pending)
                elif name != self.path.name:
                    self.gaps.append("unseen_rotated_generation")
                self.files[key] = {"fd": fd, "offset": offset, "line_offset": line_offset,
                                   "baseline_offset": offset, "committed_offset": line_offset,
                                   "pending": pending, "generation": self.next_generation,
                                   "initial_partial": bool(pending), "last_uptime": None}
                self.next_generation += 1
                retained = True
            finally:
                if not retained:
                    os.close(fd)

    def _write_event(self, event):
        if self.events >= GC_LIMITS["events"]:
            raise ValueError("GC event count bound exceeded")
        event["seq"] = self.events
        raw = (json.dumps(event, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if self.archive_bytes + len(raw) > GC_LIMITS["archive_bytes"]:
            raise ValueError("GC event archive bound exceeded")
        self.archive_bytes += len(raw)
        if self.stream.write(raw) != len(raw):
            raise OSError("Partial GC event archive write")
        self.events += 1

    def read_batch(self, stop, deadline=None, targets=None):
        if self.closed or self.failed:
            raise ValueError("GC cursor is closed or failed")
        started = time.monotonic_ns()
        batch_index = self.batches
        self.batches += 1
        deadline = min(deadline or float("inf"), time.monotonic() + GC_LIMITS["batch_seconds"])
        before_events, consumed, segments = self.events, 0, []
        try:
            self._identity()
            if targets is None:
                self._scan()
                targets = {key: os.fstat(value["fd"]).st_size for key, value in self.files.items()}
            for key, end in targets.items():
                value = self.files[key]
                if end < value["offset"] or os.fstat(value["fd"]).st_size < end:
                    raise ValueError("GC generation truncated")
                begin, chunk_hash = value["offset"], hashlib.sha256()
                while value["offset"] < end:
                    if stop.event.is_set():
                        raise InterruptedError("GC read cancelled")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("GC read deadline")
                    size = min(65536, end - value["offset"], GC_LIMITS["batch_bytes"] - consumed)
                    if size <= 0 or self.read_bytes + size > GC_LIMITS["total_read_bytes"]:
                        raise ValueError("GC read byte bound exceeded")
                    chunk = os.pread(value["fd"], size, value["offset"])
                    if not chunk:
                        raise ValueError("GC source ended before frozen prefix")
                    consumed += len(chunk)
                    self.read_bytes += len(chunk)
                    chunk_hash.update(chunk)
                    value["offset"] += len(chunk)
                    value["pending"] += chunk
                    while b"\n" in value["pending"]:
                        line, value["pending"] = value["pending"].split(b"\n", 1)
                        line += b"\n"
                        if len(line) > GC_LIMITS["line_bytes"]:
                            raise ValueError("GC line exceeds bound")
                        event = parse_gc_pause(line)
                        if event is None:
                            self.ignored_lines += 1
                        else:
                            # Multiple generations may be discovered together; do not invent a global ordering.
                            if value["last_uptime"] is not None and event["end_uptime_ns"] < value["last_uptime"]:
                                raise ValueError("GC uptime decreased within a file generation")
                            value["last_uptime"] = event["end_uptime_ns"]
                            event.update({"source_device": key[0], "source_inode": key[1],
                                          "generation": value["generation"], "pid": self.binding["pid"],
                                          "start_ticks": self.binding["start_ticks"],
                                          "line_start_offset": value["line_offset"],
                                          "line_end_offset": value["line_offset"] + len(line),
                                          "initial_partial": value["initial_partial"]})
                            event["read_batch_index"] = batch_index
                            self._write_event(event)
                        value["line_offset"] += len(line)
                        value["initial_partial"] = False
                    if len(value["pending"]) > GC_LIMITS["line_bytes"]:
                        raise ValueError("GC pending line exceeds bound")
                segments.append({"device": key[0], "inode": key[1], "generation": value["generation"],
                                 "start_offset": begin, "end_offset": value["offset"],
                                 "frozen_size": end, "read_sha256": chunk_hash.hexdigest(),
                                 "pending_bytes": len(value["pending"])})
            self._identity()
            if time.monotonic() >= deadline:
                raise TimeoutError("GC processing deadline")
            self.stream.flush()
            if time.monotonic() >= deadline:
                raise TimeoutError("GC evidence flush deadline")
            for value in self.files.values():
                value["committed_offset"] = value["line_offset"]
            self.confirmed_events = self.events
            return {"schema_version": 1, "batch_index": batch_index, "segments": segments, "read_bytes": consumed,
                    "first_event_seq": before_events if self.events > before_events else None,
                    "last_event_seq": self.events - 1 if self.events > before_events else None,
                    "elapsed_nanos": time.monotonic_ns() - started,
                    "detected_gaps": list(self.gaps), "all_jvm_gc_pauses_proven": False,
                    "window_mapping_complete": False}
        except BaseException as error:
            self.failed = True
            self.errors.append(type(error).__name__)
            raise
        finally:
            self.elapsed_nanos += time.monotonic_ns() - started

    def _close(self):
        errors = []
        for value in self.files.values():
            try:
                os.close(value["fd"])
            except BaseException as error:
                errors.append(type(error).__name__)
        self.files.clear()
        if self.dirfd is not None:
            try:
                os.close(self.dirfd)
            except BaseException as error:
                errors.append(type(error).__name__)
            self.dirfd = None
        if self.stream is not None:
            try:
                self.stream.close()
            except BaseException as error:
                errors.append(type(error).__name__)
            self.stream = None
        self.closed = True
        return errors

    def finish(self):
        if self.closed:
            raise ValueError("GC reader already closed")
        started = time.monotonic_ns()
        deadline = time.monotonic() + GC_LIMITS["finish_seconds"]
        terminal = None
        try:
            if not self.failed:
                self._scan()
                targets = {key: os.fstat(value["fd"]).st_size for key, value in self.files.items()}
                terminal = self.read_batch(StopSignals(), deadline, targets)
        except BaseException as error:
            self.errors.append(type(error).__name__)
        pending = sum(len(value["pending"]) for value in self.files.values())
        final_cursors = [{"device": key[0], "inode": key[1], "generation": value["generation"],
                          "read_offset": value["offset"], "line_offset": value["line_offset"],
                          "baseline_offset": value["baseline_offset"],
                          "event_archive_confirmed_offset": value["committed_offset"],
                          "unconfirmed_read_range": [value["committed_offset"], value["offset"]]
                          if value["offset"] != value["committed_offset"] else None,
                          "pending_bytes": len(value["pending"]),
                          "pending_sha256": hashlib.sha256(value["pending"]).hexdigest()}
                         for key, value in self.files.items()]
        cleanup_errors = self._close()
        result = {"schema_version": 1, "binding": self.binding, "events": self.events,
                  "events_flushed_confirmed": self.confirmed_events,
                  "read_bytes": self.read_bytes, "archive_bytes_reserved": self.archive_bytes,
                  "batches": self.batches, "gc_read_parse_archive_elapsed_nanos": self.elapsed_nanos,
                  "ignored_lines": self.ignored_lines, "pending_bytes": pending,
                  "tail_complete": pending == 0, "errors": self.errors, "cleanup_errors": cleanup_errors,
                  "files_closed": not cleanup_errors, "terminal_prefix": terminal, "detected_gaps": self.gaps,
                  "final_cursors": final_cursors,
                  "observed_retained_prefix_continuity": not self.errors and not self.gaps and not pending,
                  "all_jvm_gc_pauses_proven": False, "window_mapping_complete": False}
        try:
            with self.event_path.open("rb") as stream:
                size = os.fstat(stream.fileno()).st_size
                if size > self.archive_bytes or size > GC_LIMITS["archive_bytes"]:
                    raise ValueError("GC event archive grew beyond owned writes")
                checksum, read, last = hashlib.sha256(), 0, b""
                while read < size:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("GC final evidence digest deadline")
                    chunk = stream.read(min(65536, size - read))
                    if not chunk:
                        raise ValueError("GC event archive changed while hashing")
                    read += len(chunk)
                    checksum.update(chunk)
                    last = chunk[-1:]
                if os.fstat(stream.fileno()).st_size != size:
                    raise ValueError("GC event archive changed while hashing")
                result.update({"events_sha256": checksum.hexdigest(), "event_archive_actual_bytes": size,
                               "event_archive_valid_eof": not size or last == b"\n"})
                if size != self.archive_bytes or size and last != b"\n":
                    result["cleanup_errors"].append("GcArchiveIncomplete")
        except (OSError, ValueError) as error:
            result["cleanup_errors"].append(type(error).__name__)
        result["finish_elapsed_nanos"] = time.monotonic_ns() - started
        return result


def metric_allowlist(component):
    result = {}

    def add(name, labels, unit, meaning):
        result[(name, tuple(sorted(labels.items())))] = {"unit": unit, "meaning": meaning}

    prefix, generation = ("", "Generation") if component == "fe" else ("doris_be_", "generation")
    for age in ("Young", "Old"):
        for suffix, kind, unit in (("Count", "count", "collections"), ("Time", "time", "milliseconds")):
            add(prefix + "jvm_gc", {"name": f"G1 {age} {generation} {suffix}", "type": kind}, unit,
                ("FE JVM" if component == "fe" else "BE embedded JVM; excludes native C++ memory")
                + "; cumulative collection count/time, not a pause histogram")
    if component == "fe":
        for name, kinds in {"jvm_heap_size_bytes": ("used", "committed", "max"),
                            "jvm_non_heap_size_bytes": ("used", "committed")}.items():
            for kind in kinds:
                add(name, {"type": kind}, "bytes", "FE JVM memory gauge")
    else:
        for suffix in ("allocated_bytes", "tcache_bytes", "active_bytes", "mapped_bytes", "resident_bytes",
                       "retained_bytes", "metadata_bytes", "pactive_num", "pdirty_num", "pmuzzy_num",
                       "dirty_purged_num", "muzzy_purged_num"):
            add("doris_be_memory_jemalloc_" + suffix, {}, "bytes" if suffix.endswith("bytes") else "pages_or_count",
                "Existing BE native jemalloc metric; distinct from embedded JVM GC")
    return result


def parse_stat(text, ticks, page_size):
    fields = text.rsplit(")", 1)[1].split()
    if len(fields) < 22:
        raise ValueError("Short proc stat")
    return {"start_ticks": int(fields[19]), "user_cpu_ticks": int(fields[11]), "system_cpu_ticks": int(fields[12]),
            "cpu_seconds": (int(fields[11]) + int(fields[12])) / ticks,
            "rss_bytes": int(fields[21]) * page_size, "virtual_bytes": int(fields[20]),
            "threads": int(fields[17])}


def parse_io(text):
    values = {}
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in IO_FIELDS:
            if name in values:
                raise ValueError("Duplicate proc IO field")
            values[name] = int(value.strip())
    if set(values) != set(IO_FIELDS):
        raise ValueError("Missing proc IO fields")
    if any(value < 0 for name, value in values.items() if name != "cancelled_write_bytes"):
        raise ValueError("Negative proc IO counter")
    return values


def parse_status(text):
    values = {}
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in STATUS_FIELDS:
            match = re.fullmatch(r"\s*(\d+)\s+kB\s*", value)
            if not match or name in values:
                raise ValueError("Unexpected proc status memory field")
            values[name + "_bytes"] = int(match.group(1)) * 1024
    if len(values) != len(STATUS_FIELDS):
        raise ValueError("Missing proc status memory fields")
    return values


def parse_netdev(text):
    result = {}
    for line in text.splitlines():
        name, separator, raw = line.partition(":")
        if not separator:
            continue
        name = name.strip()
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,32}", name):
            raise ValueError("Unexpected namespace interface name")
        fields = raw.split()
        if len(fields) != 16 or name in result:
            raise ValueError("Malformed network counters")
        counters = [int(value) for value in fields]
        if any(value < 0 for value in counters):
            raise ValueError("Negative network counter")
        result[name] = {**dict(zip(NET_FIELDS, counters[:4] + counters[8:12])), "loopback": name == "lo"}
    if not result:
        raise ValueError("No namespace network interfaces")
    # Do not add RX to TX: loopback packets appear once in each direction.
    return {"scope": "whole current network namespace, including observer and all clients/services",
            "process_attribution": False, "rx_plus_tx_total_computed": False, "interfaces": result}


def parse_labels(text):
    labels, position = {}, 0
    pattern = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*("(?:[^"\\]|\\["\\n])*")\s*(?:,|$)')
    while position < len(text):
        match = pattern.match(text, position)
        if not match or match.group(1) in labels:
            raise ValueError("Malformed metric labels")
        labels[match.group(1)] = json.loads(match.group(2))
        position = match.end()
    return labels


def parse_metrics(body, component, *, rpc_selection=None):
    allowed = metric_allowlist(component)
    names = {key[0] for key in allowed}
    found, ignored = {}, 0
    pattern = re.compile(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+\d+)?\s*$')
    for line in body.decode("utf-8", errors="strict").splitlines():
        if not line or line.startswith("#"):
            continue
        prefix = re.match(r"([a-zA-Z_:][a-zA-Z0-9_:]*)", line)
        if not prefix or prefix.group(1) not in names:
            ignored += 1
            continue
        match = pattern.fullmatch(line)
        if not match:
            raise ValueError("Malformed selected metric")
        labels = parse_labels(match.group(2) or "")
        key = (match.group(1), tuple(sorted(labels.items())))
        if key not in allowed:
            ignored += 1
            continue  # Never archive unselected labels, even on an allowed metric name.
        if key in found:
            raise ValueError("Duplicate selected metric")
        raw = match.group(3)
        value = int(raw) if re.fullmatch(r"[+-]?\d+", raw) else float(raw)
        if not math.isfinite(value) or value < 0:
            raise ValueError("Nonfinite or unsupported negative metric")
        found[key] = {"name": key[0], "labels": dict(key[1]), "value": value, **allowed[key]}
    if set(found) != set(allowed):
        raise ValueError("Missing selected metric series")
    result = {"series": [found[key] for key in sorted(found)], "ignored_series_count": ignored}
    if rpc_selection is not None and component == "fe":
        result["extensions"] = {"scoped_rpc": parse_rpc_metrics(body, rpc_selection)}
    return result


def fetch_metrics(port, component, timeout, *, rpc_selection=None):
    started = time.monotonic_ns()
    deadline = time.monotonic() + timeout
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", "/metrics", headers={"Accept": "text/plain", "Connection": "close"})
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Metrics deadline")
        socket = connection.sock
        socket.settimeout(remaining)
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Metrics HTTP status is not 200")
        chunks, received = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Metrics deadline")
            # Retain the socket after Connection:close detaches it from HTTPConnection.
            # read1 performs at most one underlying read, so a slow trickle cannot extend the absolute deadline.
            socket.settimeout(remaining)
            chunk = response.read1(min(65536, MAX_BODY_BYTES + 1 - received))
            if not chunk:
                break
            received += len(chunk)
            if received > MAX_BODY_BYTES:
                raise ValueError("Metrics response exceeds byte limit")
            chunks.append(chunk)
            if response.isclosed():
                break
        body = b"".join(chunks)
        data = (parse_metrics(body, component) if rpc_selection is None
                else parse_metrics(body, component, rpc_selection=rpc_selection))
        if rpc_selection is not None and component == "fe":
            data["extensions"]["scoped_rpc"]["scrape_monotonic_ns"] = {
                "started": started, "finished": time.monotonic_ns()}
        return {**data, "http_status": 200, "response_bytes": received,
                "elapsed_nanos": time.monotonic_ns() - started,
                "transport": "direct HTTPConnection to owned loopback; no proxy or redirects"}
    finally:
        connection.close()


def process_stat(pid):
    return parse_stat((Path("/proc") / str(pid) / "stat").read_text(), os.sysconf("SC_CLK_TCK"),
                      os.sysconf("SC_PAGE_SIZE"))


def check_identity(pin, namespace):
    if os.readlink(f"/proc/{pin['pid']}/ns/net") != namespace:
        raise IdentityChanged("Service namespace changed")
    current = process_stat(pin["pid"])
    if current["start_ticks"] != pin["start_ticks"]:
        raise IdentityChanged("Service PID was reused or restarted")
    return current


def freeze_cluster(path):
    state, be_port = validate_cluster(path)
    installation = owned(state["installation"])
    config = (installation / "fe/conf/fe.conf").read_text()
    ports = re.findall(r"(?m)^\s*http_port\s*=\s*(\d+)\s*(?:#.*)?$", config)
    if len(ports) != 1 or int(ports[0]) != state["http_port"]:
        raise ValueError("FE HTTP port differs from its single explicit owned configuration")
    pins = {}
    for component, port in (("fe", int(ports[0])), ("be", be_port)):
        pid = int((installation / component / "bin" / (component + ".pid")).read_text().strip())
        pins[component] = {"pid": pid, "start_ticks": process_stat(pid)["start_ticks"], "http_port": port}
    return state, pins


def collect_sample(state, pins, timeout, stop, *, rpc_selection=None, gc_reader=None):
    result = {"started_at_utc": utc(), "started_monotonic_ns": time.monotonic_ns(), "errors": [], "processes": {}}
    if rpc_selection is not None or gc_reader is not None:
        result["http_metrics_calls"] = {"attempted": {}, "returned_parsed": {},
                                        "scope": "observer calls, independent of valid target attribution"}
    try:
        if os.readlink("/proc/self/ns/net") != state["namespace"]:
            raise IdentityChanged("Observer namespace changed")
        # Verify both services before touching either endpoint.
        before = {name: check_identity(pin, state["namespace"]) for name, pin in pins.items()}
        result["namespace_network"] = parse_netdev(Path("/proc/net/dev").read_text())
        for name, pin in pins.items():
            directory = Path("/proc") / str(pin["pid"])
            item = {"pid": pin["pid"], **before[name], "io": parse_io((directory / "io").read_text()),
                    "memory_status": parse_status((directory / "status").read_text())}
            result["processes"][name] = item
            if stop.event.is_set():
                result["errors"].append({"scope": name + "_metrics", "type": "InterruptedBeforeScrape"})
                continue
            request_started = time.monotonic_ns()
            if rpc_selection is not None or gc_reader is not None:
                item["metrics_call_attempted"] = True
                result["http_metrics_calls"]["attempted"][name] = 1
            try:
                item["metrics"] = (fetch_metrics(pin["http_port"], name, timeout) if rpc_selection is None
                                   else fetch_metrics(pin["http_port"], name, timeout, rpc_selection=rpc_selection))
                if rpc_selection is not None or gc_reader is not None:
                    result["http_metrics_calls"]["returned_parsed"][name] = 1
            except (OSError, ValueError, http.client.HTTPException) as error:
                result["errors"].append({"scope": name + "_metrics", "type": type(error).__name__,
                                         "elapsed_nanos": time.monotonic_ns() - request_started})
        for pin in pins.values():
            check_identity(pin, state["namespace"])
        if gc_reader is not None:
            try:
                result["extensions"] = {"gc_cursor_receipt": gc_reader.read_batch(stop)}
            except IdentityChanged:
                raise
            except (OSError, ValueError) as error:
                result["errors"].append({"scope": "gc_log", "type": type(error).__name__})
                result["fatal_extension_error"] = True
    except (IdentityChanged, FileNotFoundError, ProcessLookupError):
        result["processes"] = {}  # Discard possible cross-lifetime attribution.
        result["errors"].append({"scope": "identity", "type": "IdentityChanged"})
        result["fatal_identity_error"] = True
    except (OSError, ValueError, IndexError) as error:
        result["errors"].append({"scope": "proc", "type": type(error).__name__})
    result["finished_monotonic_ns"] = time.monotonic_ns()
    result["finished_at_utc"] = utc()
    result["elapsed_nanos"] = result["finished_monotonic_ns"] - result["started_monotonic_ns"]
    return result


class StopSignals:
    def __init__(self):
        self.event = threading.Event()
        self.signal_number = None
        self.previous = {}

    def __enter__(self):
        def received(number, frame):
            self.signal_number = number
            self.event.set()
        for number in (signal.SIGINT, signal.SIGTERM):
            self.previous[number] = signal.signal(number, received)
        return self

    def __exit__(self, *args):
        for number, previous in self.previous.items():
            signal.signal(number, previous)


class ObserverBudgetExceeded(ValueError):
    """An explicit long-window resource bound stopped collection before another sample."""


def validate_window_limits(duration, interval, long_limits=None):
    maximum = 14400 if long_limits is None else P4_MAX_DURATION_SECONDS
    if not 0 < duration <= maximum or not 1 <= interval <= 60:
        raise ValueError("Require duration in (0,%d] and interval in [1,60] seconds" % maximum)
    if long_limits is None:
        return None
    if not isinstance(long_limits, dict) or set(long_limits) != {"max_samples", "max_log_bytes", "min_free_disk_bytes"}:
        raise ValueError("P4 long windows require explicit sample/log/disk budgets")
    if any(type(value) is not int or value <= 0 for value in long_limits.values()):
        raise ValueError("P4 budgets must be positive integers")
    expected = math.floor(duration / interval) + 1
    if not expected <= long_limits["max_samples"] <= P4_MAX_DURATION_SECONDS + 1:
        raise ValueError("P4 sample budget cannot cover the full declared schedule")
    if not P4_MAX_SAMPLE_BYTES <= long_limits["max_log_bytes"] <= P4_MAX_LOG_BYTES:
        raise ValueError("P4 sample log byte budget lies outside explicit bounds")
    if long_limits["min_free_disk_bytes"] < 1024**2:
        raise ValueError("P4 final-receipt disk reserve must be at least one MiB")
    return {**long_limits, "maximum_sample_bytes": P4_MAX_SAMPLE_BYTES, "maximum_scheduled_samples": expected}


def observe(output, duration, interval, collector, stop, metadata, clock=time.monotonic,
            long_limits=None, disk_free=None):
    limits = validate_window_limits(duration, interval, long_limits)
    disk_free = disk_free or (lambda: shutil.disk_usage(output).free)
    started, index, skipped, failures = clock(), 0, 0, 0
    deadline, samples, error_types = started + duration, 0, Counter()
    before = resource.getrusage(resource.RUSAGE_SELF)
    report = {**metadata, "started_at_utc": utc(), "started_monotonic_ns": int(started * 1e9),
              "duration_seconds": duration, "interval_seconds": interval,
              "status": "RUNNING", "statistical_precision_proven": False, "performance_pass_proven": False}
    if limits is not None:
        report["p4_long_window_limits"] = limits
    bytes_written = 0
    save(output / "summary.json", report)
    try:
        if limits is not None and disk_free() < limits["max_log_bytes"] + limits["min_free_disk_bytes"]:
            raise ObserverBudgetExceeded("P4 declared log allocation and final-receipt reserve unavailable")
        with (output / "samples.jsonl").open("x", encoding="utf-8") as stream:
            while started + index * interval <= deadline:
                scheduled = started + index * interval
                if stop.event.wait(max(0, scheduled - clock())):
                    break
                if limits is not None:
                    # Leave room for a full bounded record before calling the collector.
                    # Never collect/then silently omit a sample to keep a green window.
                    if samples >= limits["max_samples"]:
                        raise ObserverBudgetExceeded("P4 actual sample count exceeds frozen budget")
                    if bytes_written + P4_MAX_SAMPLE_BYTES > limits["max_log_bytes"]:
                        raise ObserverBudgetExceeded("P4 raw log has no space for another full bounded sample")
                    if disk_free() < P4_MAX_SAMPLE_BYTES + limits["min_free_disk_bytes"]:
                        raise ObserverBudgetExceeded("P4 disk reserve reached before next sample")
                sample = collector()
                sample["sample_index"] = samples
                sample["scheduled_offset_seconds"] = index * interval
                sample["schedule_lag_seconds"] = max(0, clock() - scheduled - sample.get("elapsed_nanos", 0) / 1e9)
                encoded = json.dumps(sample, ensure_ascii=False, allow_nan=False) + "\n"
                encoded_bytes = len(encoded.encode("utf-8")) if limits is not None else 0
                if limits is not None and encoded_bytes > P4_MAX_SAMPLE_BYTES:
                    report["unarchived_oversized_samples"] = 1
                    raise ObserverBudgetExceeded("P4 collector produced an oversized raw record; window invalid")
                stream.write(encoded)
                stream.flush()
                bytes_written += encoded_bytes
                samples += 1
                failures += bool(sample["errors"])
                error_types.update(item["type"] for item in sample["errors"])
                if sample.get("fatal_identity_error"):
                    report["status"] = "FAILED_IDENTITY_CHANGED"
                    break
                if sample.get("fatal_extension_error"):
                    report["status"] = "FAILED_EXTENSION"
                    break
                index += 1
                while started + index * interval < min(clock(), deadline + 0.000001):
                    index += 1
                    skipped += 1
            if report["status"] == "RUNNING":
                report["status"] = "INTERRUPTED" if stop.event.is_set() else "COMPLETED_WITH_ERRORS" if failures else "COMPLETED"
    except Exception as error:
        report["status"] = "FAILED_RESOURCE_BOUND" if isinstance(error, ObserverBudgetExceeded) else "FAILED"
        report["failure_type"] = type(error).__name__
        raise
    finally:
        after = resource.getrusage(resource.RUSAGE_SELF)
        finished = clock()
        report.update({"finished_at_utc": utc(), "finished_monotonic_ns": int(finished * 1e9),
                       "elapsed_seconds": finished - started, "samples": samples,
                       "samples_with_errors": failures, "error_types": dict(error_types),
                       "skipped_schedule_slots": skipped, "signal_number": stop.signal_number,
                       "observer_cpu_seconds": after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
                       "observer_peak_rss_bytes": after.ru_maxrss * 1024})
        if limits is not None:
            report["raw_sample_bytes_written"] = bytes_written
        if (output / "samples.jsonl").exists():
            report["samples_sha256"] = digest(output / "samples.jsonl")
        save(output / "summary.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=float, required=True)
    parser.add_argument("--interval-seconds", type=float, default=5)
    parser.add_argument("--http-timeout-seconds", type=float, default=2)
    parser.add_argument("--rpc-selection", type=Path,
                        help="Opt in to exact original FE RPC hostname/method selection from an owned JSON file")
    parser.add_argument("--gc-pauses", action="store_true", help="Opt in to existing original FE GC log event reads")
    parser.add_argument("--p4-long-window", action="store_true", help="Explicit bounded P4 collection up to 102000 seconds; default remains 14400")
    parser.add_argument("--max-samples", type=int)
    parser.add_argument("--max-log-bytes", type=int)
    parser.add_argument("--min-free-disk-bytes", type=int)
    args = parser.parse_args()
    if not 0.05 <= args.http_timeout_seconds <= 5:
        parser.error("HTTP timeout must be in [0.05,5] seconds")
    budgets = {"max_samples": args.max_samples, "max_log_bytes": args.max_log_bytes,
               "min_free_disk_bytes": args.min_free_disk_bytes}
    if not args.p4_long_window and any(value is not None for value in budgets.values()):
        parser.error("Long-window budgets require explicit --p4-long-window")
    long_limits = budgets if args.p4_long_window else None
    try:
        validate_window_limits(args.duration_seconds, args.interval_seconds, long_limits)
    except ValueError as error:
        parser.error(str(error))
    state, pins = freeze_cluster(args.cluster_record)
    selection, selection_receipt = (load_rpc_selection(args.rpc_selection) if args.rpc_selection else (None, None))
    binding = gc_binding(state, pins["fe"]) if args.gc_pauses else None
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    metadata = {"schema_version": 1, "evidence_scope": "read-only resource time series; no statistical pass claim",
                "cluster_record_sha256": digest(args.cluster_record), "namespace": state["namespace"], "services": pins,
                "http_timeout_seconds": args.http_timeout_seconds, "http_body_limit_bytes": MAX_BODY_BYTES,
                "observer_cpu_affinity": sorted(os.sched_getaffinity(0)),
                "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"), "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
                "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in
                                  [Path(__file__), ROOT / "tools/license-checks/stream_load_fixture.py"]},
                "selected_metrics": {name: [{"name": key[0], "labels": dict(key[1]), **details}
                                              for key, details in metric_allowlist(name).items()] for name in pins},
                "monitoring_overhead": "Includes HTTP, parsing, /proc reads and output writes. Formal A/A and A/B require the same schedule.",
                "network_boundary": "Namespace totals, not FE/BE attribution; RX/TX remain separate to avoid loopback double counting.",
                "gc_boundary": "FE JVM and BE embedded JVM cumulative GC time/count only; not native BE GC or pause histograms."}
    enabled = selection is not None or binding is not None
    if enabled:
        metadata.update({"schema_version": 2, "extensions_enabled": {"scoped_rpc": selection is not None,
                                                                    "gc_pause_events": binding is not None},
                         "rpc_selection": selection, "rpc_selection_receipt": selection_receipt,
                         "gc_binding": binding, "gc_limits": GC_LIMITS if binding else None,
                         "gc_max_open_descriptors": 16 if binding else 0,
                         "all_rpc_coverage": False, "allocation_total_coverage": False,
                         "process_network_attribution": False, "full_service_overhead_precision_proven": False,
                         "unresolved_requirements": ["FE total allocated bytes", "all RPC request/response/wire bytes",
                                                     "per-process network attribution", "complete window GC pause mapping"]})
    reader, tracker, report, primary_error = None, RpcTracker() if selection else None, None, None
    http_calls, http_completed = Counter(), Counter()
    lifecycle_usage = resource.getrusage(resource.RUSAGE_SELF) if enabled else None
    with StopSignals() as stop:
        try:
            if binding:
                reader = GcPauseReader(binding, output)
            def collect():
                if selection_receipt:
                    fresh, receipt = load_rpc_selection(args.rpc_selection)
                    if receipt != selection_receipt or fresh != selection:
                        raise ValueError("Frozen RPC selection changed")
                if not enabled:
                    return collect_sample(state, pins, args.http_timeout_seconds, stop)
                value = collect_sample(state, pins, args.http_timeout_seconds, stop,
                                       rpc_selection=selection, gc_reader=reader)
                http_calls.update(value["http_metrics_calls"]["attempted"])
                http_completed.update(value["http_metrics_calls"]["returned_parsed"])
                if tracker:
                    tracker.update(value)
                return value
            report = observe(output, args.duration_seconds, args.interval_seconds, collect, stop, metadata,
                             long_limits=long_limits)
        except BaseException as error:
            primary_error = error
        finally:
            if enabled:
                extensions, final_errors = {}, []
                if reader:
                    try:
                        extensions["gc_pause_events"] = reader.finish()
                        result = extensions["gc_pause_events"]
                        if (result["errors"] or result["cleanup_errors"] or result["detected_gaps"]
                                or not result["tail_complete"]):
                            final_errors.append("GcCoverageOrCleanupIncomplete")
                    except BaseException as error:
                        final_errors.append(type(error).__name__)
                if tracker:
                    extensions["scoped_rpc"] = tracker.summary()
                if selection_receipt:
                    try:
                        fresh, receipt = load_rpc_selection(args.rpc_selection)
                        if fresh != selection or receipt != selection_receipt:
                            raise ValueError("Frozen RPC selection changed at stop")
                    except (OSError, ValueError) as error:
                        final_errors.append(type(error).__name__)
                try:
                    if any(digest(ROOT / path) != expected for path, expected in metadata["source_sha256"].items()):
                        raise ValueError("Observer source binding changed")
                except (OSError, ValueError) as error:
                    final_errors.append(type(error).__name__)
                if report is None:
                    try:
                        report = json.loads(bounded_file(output / "summary.json", 2 * 1024 * 1024),
                                            object_pairs_hook=unique_object)
                    except (OSError, ValueError):
                        report = {**metadata, "status": "FAILED", "failure_type": type(primary_error).__name__}
                if primary_error and hasattr(primary_error, "gc_initialization_cleanup_errors"):
                    report["gc_initialization_cleanup_errors"] = primary_error.gc_initialization_cleanup_errors
                after = resource.getrusage(resource.RUSAGE_SELF)
                report["observer_lifecycle_cpu_seconds_including_prepare_finish"] = (
                    after.ru_utime + after.ru_stime - lifecycle_usage.ru_utime - lifecycle_usage.ru_stime)
                report.update({"extension_summary": extensions, "extension_final_errors": final_errors})
                report["http_metrics_calls"] = {"attempted": dict(http_calls), "returned_parsed": dict(http_completed),
                                                "scope": "collector calls, not proof of transmitted packets"}
                if final_errors and report["status"] == "COMPLETED":
                    report["status"] = "COMPLETED_WITH_ERRORS"
                try:
                    save(output / "summary.json", report)
                except BaseException as error:
                    primary_error = primary_error or error
    if primary_error:
        raise primary_error
    print(json.dumps({key: report[key] for key in ["status", "samples", "samples_with_errors", "elapsed_seconds",
                                                "observer_cpu_seconds", "statistical_precision_proven"]}, indent=2))
    return 0 if report["status"] == "COMPLETED" else 128 + report["signal_number"] if report["signal_number"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
