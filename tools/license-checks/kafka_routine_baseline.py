#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""A complete original-A LP013 offered-rate window; default plan never contacts a service."""

import argparse
import base64
import csv
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import time
import uuid
import zipfile

import background_http_fixture as support
import kafka_routine_fixture as small
import stream_load_fixture as fixture

ROOT = fixture.ROOT
SOURCE = Path(__file__).resolve()
HELPER = SOURCE.with_name("LicenseKafkaBaseline.java")
ROWS, WARM_ROWS, WIDTH, NANO = 10000000, 3000000, 128, 1000000000
TOTAL = ROWS + WARM_ROWS
PHASES = {"warmup": (WARM_ROWS, ROWS, 180), "measurement": (ROWS, 0, 600)}
LIMITS = {"main_seconds": 3600, "visibility_seconds": 300, "drain_seconds": 120,
          "barrier_seconds": 600, "request_seconds_from_arrival": 60, "cleanup_seconds": 180,
          "consumer_seconds": 900, "sql_oracle_range_rows": 250000,
          "minimum_free_disk_bytes": 16 * 1024 ** 3, "broker_heap_mib": 512,
          "producer_heap_mib": 512, "disk_offset_index_bytes": TOTAL * 8,
          "maximum_evidence_bytes": 8 * 1024 ** 3, "poll_interval_seconds": 5}
require = support.require
digest = fixture.digest
owned = fixture.owned
save = fixture.save


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, "Duplicate JSON object key")
        result[key] = value
    return result


def read_json(path, limit=4 * 1024 * 1024):
    with Path(path).open("rb") as stream:
        value = stream.read(limit + 1)
    require(len(value) <= limit, "JSON receipt exceeds its bound")
    return json.loads(value, object_pairs_hook=unique_object)


def object_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class CapturedProcesses(support.Processes):
    """Retain bounded stdout AND stderr, including the first unsuccessful Java/SQL invocation."""

    def run(self, command, name, timeout=75):
        process = self.start(command, name, background=True)
        primary = None
        try:
            deadline = min(self.budget.deadline, time.monotonic() + timeout)
            while process.poll() is None:
                self.budget.checkpoint()
                require(time.monotonic() < deadline, "Owned helper exceeded its fixed deadline")
                self.budget.pause(min(.05, max(0, deadline - time.monotonic())))
        except BaseException as error:
            primary = error
            raise
        finally:
            errors = []
            try:
                self.stop(process)
            except BaseException as error:
                errors.append(error)
            try:
                if process.pid in self.outputs:
                    self.outputs[process.pid].stop()
            except BaseException as error:
                errors.append(error)
            if errors:
                record = next((record for child, record in self.children if child is process), None)
                if record is not None:
                    record["initial_cleanup_errors"] = [type(error).__name__ for error in errors]
                self.budget.resource_failure = (name, "helper_cleanup_error")
                if primary is None:
                    raise errors[0]
        raw = (self.output / (name + ".stdout")).read_bytes()
        return process.returncode, raw


def model_record(identifier):
    # Deliberately reconstruct independently of the preparation generator's fixture.record().
    prefix = f"{identifier},{identifier % 1024},{identifier % 100000},"
    md5 = hashlib.md5(str(identifier).encode("ascii"), usedforsecurity=False).hexdigest()
    padding = hashlib.sha256(b"20260922").hexdigest() * 2
    return (prefix + md5 + padding[:WIDTH - len(prefix) - 33] + "\n").encode("ascii")


def schedule(workers, batch_rows):
    require(type(workers) is int and workers in (1, 8, 32), "Producer workers must be 1, 8 or 32")
    require(type(batch_rows) is int and batch_rows in (1000, 10000), "Batch rows must be 1000 or 10000")
    return {phase: [{"batch_index": index, "worker": index % workers,
                     "offset_ns": index * seconds * NANO // (rows // batch_rows), "rows": batch_rows}
                    for index in range(rows // batch_rows)]
            for phase, (rows, _, seconds) in PHASES.items()}


def plan(args):
    require(args.consumer_tasks in (1, 8), "One eight-partition job supports requested consumers 1 or 8")
    schedule_value = schedule(args.producer_workers, args.batch_rows)
    return {"schema_version": 1, "case_id": "LP-013", "status": "PLANNED", "mode": args.mode,
            "LP013_complete": False, "release_performance_pass": False,
            "scope": "One original-A full-input offered-rate window; no AA qualification or candidate claim",
            "definition_clarification": {
                "concurrency_axis": "producer_client_workers", "concurrency_values": [1, 8, 32],
                "consumer_axis": "separately requested and observed; capped by partitions and FE configuration",
                "consumer_source": "fe/fe-core/src/main/java/org/apache/doris/load/routineload/KafkaRoutineLoadJob.java:calculateCurrentConcurrentTaskNum",
                "consumer_formula": "min(partition_count, desired_concurrent_number, max_routine_load_task_concurrent_num)",
                "batch_axis": "offered producer rows per batch, not Routine Load max_batch_rows",
                "canonical_file_modified": False},
            "rows": ROWS, "warmup_rows": WARM_ROWS, "total_physical_rows": TOTAL,
            "warmup_id_interval": [ROWS, TOTAL], "measurement_id_interval": [0, ROWS],
            "row_bytes_including_lf": WIDTH, "kafka_value_bytes": WIDTH - 1, "partitions": 8,
            "warmup_seconds": 180, "window_seconds": 600, "seed": small.SEED,
            "offered_rows_per_second": {"numerator": ROWS, "denominator": 600},
            "producer_workers": args.producer_workers, "batch_rows": args.batch_rows,
            "client_cpu": args.cpu,
            "routine_desired_tasks": args.consumer_tasks,
            "arrival": "Fixed integer-nanosecond batch arrivals, preassigned round-robin to persistent clients",
            "schedule_sha256": object_sha(schedule_value),
            "warmup_barrier": "Same clients/JVM/topic/job/table; all 3M ACKs, actual physical offsets, committed offsets and independent SQL visibility before measurement; barrier gap excluded",
            "latency_unit": "producer batch send/ACK request, never individual rows",
            "measurement_batch_samples": ROWS // args.batch_rows,
            "p99_sample_floor_met": ROWS // args.batch_rows >= 10000,
            "p99_qualified": False, "pair_count": 0,
            "broker": {"version": small.VERSION, "archive_sha512": small.ARCHIVE_SHA512,
                       "partitions": 8, "replication_factor": 1, "broker_port": args.broker_port,
                       "controller_port": args.controller_port, "loopback_private_namespace_only": True},
            "limits": LIMITS, "java_runtime": small.JAVA_RUNTIME,
            "observer_overhead": "Per-row ACK evidence plus periodic SQL/task and /proc sampling; separate IO/CPU actors",
            "missing_formal_evidence": ["five or more AA/AB pairs and confidence precision",
                                        "FE total allocated bytes", "individual GC pauses", "RPC count/bytes",
                                        "VALID/EXPIRED/renewal candidate behavior", "per-process network attribution"],
            "frozen_sources": {str(path): digest(path) for path in
                               (SOURCE, HELPER, Path(small.__file__), Path(fixture.__file__),
                                Path(support.__file__), Path(support.resources_module.__file__), small.SQL_HELPER,
                                ROOT / "docs/license-performance-cases-20260922.json",
                                ROOT / "fe/fe-core/src/main/java/org/apache/doris/load/routineload/KafkaRoutineLoadJob.java")},
            "created_at_utc": fixture.utc()}


def prepare(args, output, report):
    require(args.archive is not None, "Preparation needs the already recovered official archive; no downloads")
    require(shutil.disk_usage(output).free >= LIMITS["minimum_free_disk_bytes"], "Insufficient fixed disk budget")
    archive = owned(args.archive)
    distribution = small.extract_archive(archive, output)
    bindings = {}
    for phase, (rows, base, _) in PHASES.items():
        path = output / (phase + ".csv")
        with path.open("xb", buffering=1024 * 1024) as stream:
            for index in range(rows):
                stream.write(fixture.record(base + small.identifier_at(index, rows)))
        bindings[phase] = {"path": str(path), "sha256": digest(path), "rows": rows,
                           "bytes": rows * WIDTH, "id_base": base}
    report.update(status="PREPARED_NOT_PROBED", distribution=str(distribution), archive_path=str(archive),
                  archive_sha256=digest(archive), archive_sha512_actual=small.sha512(archive),
                  distribution_files=small.prepared_inventory(output), inputs=bindings,
                  archive_pgp_signature_verified=False)
    save(output / "prepared.json", report)


def validate_prepared(path):
    path = owned(path)
    manifest = read_json(path / "prepared.json")
    require(manifest.get("status") == "PREPARED_NOT_PROBED" and manifest.get("rows") == ROWS
            and manifest.get("warmup_rows") == WARM_ROWS and manifest.get("seed") == small.SEED
            and manifest.get("archive_sha512_actual") == small.ARCHIVE_SHA512,
            "Prepared full-input manifest differs from the fixed LP013 definition")
    archive = owned(manifest["archive_path"])
    official = small.archive_inventory(archive)
    require(digest(archive) == manifest["archive_sha256"] and small.prepared_inventory(path) == official
            and manifest["distribution_files"] == official, "Distribution differs from the actual pinned Apache archive")
    for phase, (rows, base, _) in PHASES.items():
        item = manifest["inputs"][phase]
        source = owned(item["path"])
        require(source == path / (phase + ".csv") and source.stat().st_size == rows * WIDTH
                and item["rows"] == rows and item["id_base"] == base and item["bytes"] == rows * WIDTH
                and digest(source) == item["sha256"], "Prepared phase input changed")
        with source.open("rb", buffering=1024 * 1024) as stream:
            for index in range(rows):
                require(stream.read(WIDTH) == model_record(base + small.identifier_at(index, rows)),
                        "Full prepared input differs from the independent deterministic model")
            require(stream.read(1) == b"", "Unexpected trailing input")
    return path, manifest


class Bitmap:
    def __init__(self, size):
        self.size, self.count = size, 0
        self.bits = bytearray((size + 7) // 8)

    def add(self, value):
        require(type(value) is int and 0 <= value < self.size, "Out-of-domain bitmap entry")
        byte, bit = value // 8, 1 << (value % 8)
        require(not self.bits[byte] & bit, "Duplicate ID/index/physical offset")
        self.bits[byte] |= bit
        self.count += 1


def csv_records(path, maximum_rows):
    require(Path(path).stat().st_size <= maximum_rows * 320 + 256, "CSV evidence exceeds its row/byte bound")
    csv.field_size_limit(256)
    with Path(path).open(newline="") as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames is not None and len(set(reader.fieldnames)) == len(reader.fieldnames),
                "Invalid CSV header")
        for index, row in enumerate(reader):
            require(index < maximum_rows and None not in row and all(value is not None for value in row.values()),
                    "Excess or malformed CSV records")
            yield row


def verify_physical(output, workers, batch_rows, epochs, rows=ROWS, warm_rows=WARM_ROWS, checkpoint=lambda: None):
    """Full independent bytes and offset oracle, with 104MB on-disk index and <10MB bitmaps at full scale."""
    total, per_partition = rows + warm_rows, (rows + warm_rows) // 8
    require(rows > 0 and warm_rows > 0 and rows % 8 == warm_rows % 8 == 0, "Unbalanced oracle domains")
    indices = {"warmup": Bitmap(warm_rows), "measurement": Bitmap(rows)}
    offsets, ids = Bitmap(total), Bitmap(total)
    in_window_acks = 0
    index_path = output / "offset-id-index.bin"
    with index_path.open("x+b") as file:
        file.truncate(total * 8)
        with mmap.mmap(file.fileno(), total * 8) as index:
            for worker in range(workers):
                for row in csv_records(output / f"acks-{worker}.csv", total):
                    phase = row["phase"]
                    require(phase in indices, "Unknown ACK phase")
                    count, base = (warm_rows, rows) if phase == "warmup" else (rows, 0)
                    position, identifier, partition, offset = (int(row[key]) for key in ("index", "id", "partition", "offset"))
                    require(0 <= position < count and identifier == base + small.identifier_at(position, count)
                            and int(row["worker"]) == worker == (position // batch_rows) % workers
                            and int(row["batch_index"]) == position // batch_rows and partition == identifier % 8,
                            "ACK input order, ID, batch, worker or partition mismatch")
                    low, high = (0, warm_rows // 8) if phase == "warmup" else (warm_rows // 8, per_partition)
                    require(low <= offset < high, "ACK crossed the warmup/measurement physical barrier")
                    scheduled = epochs[phase] + (position // batch_rows) * PHASES[phase][2] * NANO // (count // batch_rows)
                    require(scheduled <= int(row["sent_ns"]) <= int(row["ack_ns"])
                            <= scheduled + 60 * NANO, "ACK is outside its offered batch timing boundary")
                    require(row["value_sha256"] == hashlib.sha256(model_record(identifier)[:-1]).hexdigest(),
                            "ACK payload digest differs from the independent byte model")
                    indices[phase].add(position)
                    if phase == "measurement" and int(row["ack_ns"]) < epochs[phase] + 600 * NANO:
                        in_window_acks += 1
                    slot = partition * per_partition + offset
                    offsets.add(slot)
                    struct.pack_into(">Q", index, slot * 8, identifier + 1)
                    if offsets.count % 10000 == 0:
                        checkpoint()
            require(offsets.count == total and indices["warmup"].count == warm_rows
                    and indices["measurement"].count == rows, "Incomplete producer coverage")
            next_offsets = [0] * 8
            for row in csv_records(output / "consumer-records.csv", total):
                partition, offset = int(row["partition"]), int(row["offset"])
                require(0 <= partition < 8 and offset == next_offsets[partition] and offset < per_partition,
                        "Independent consumer skipped/repeated a physical offset")
                key, value = (base64.b64decode(row[field], validate=True) for field in ("key_base64", "value_base64"))
                require(re.fullmatch(rb"0|[1-9][0-9]{0,7}", key) is not None, "Noncanonical Kafka key")
                identifier = int(key)
                require(identifier % 8 == partition and value == model_record(identifier)[:-1]
                        and struct.unpack_from(">Q", index, (partition * per_partition + offset) * 8)[0] == identifier + 1,
                        "Actual consumed ID/value differs from independent model or acknowledged physical offset")
                ids.add(identifier)
                next_offsets[partition] += 1
                if ids.count % 10000 == 0:
                    checkpoint()
            require(ids.count == total and next_offsets == [per_partition] * 8, "Incomplete independent consumer coverage")
            index.flush()
    return {"producer_rows": offsets.count, "consumer_rows": ids.count, "measurement_rows": rows,
            "warmup_rows": warm_rows, "complete_ids_and_bytes": True, "contiguous_offsets": True,
            "measurement_acks_inside_window": in_window_acks,
            "measurement_acks_in_drain": rows - in_window_acks,
            "ack_rows_per_second_inside_window": in_window_acks / 600,
            "disk_index_bytes": total * 8, "disk_index_sha256": digest(index_path),
            "ack_files": {f"acks-{worker}.csv": digest(output / f"acks-{worker}.csv") for worker in range(workers)},
            "consumer_sha256": digest(output / "consumer-records.csv")}


def audit_batches(output, report, start, warmup):
    epochs = {"warmup": warmup["warmup_start_ns"], "measurement": start["measurement_start_ns"]}
    expected = schedule(report["producer_workers"], report["batch_rows"])
    require(start["clock_domain"] == warmup["clock_domain"]
            and start["warmup_start_ns"] == epochs["warmup"]
            and start["measurement_end_ns"] == epochs["measurement"] + 600 * NANO
            and epochs["warmup"] + 180 * NANO <= warmup["completed_ns"]
            <= start["barrier_received_ns"] <= epochs["measurement"],
            "Phase epochs or same-JVM clock domain mismatch")
    seen = {phase: Bitmap(len(values)) for phase, values in expected.items()}
    latencies, service, delays = [], [], []
    warmup_last_finished = epochs["warmup"]
    for worker in range(report["producer_workers"]):
        path = output / f"batches-{worker}.jsonl"
        require(path.stat().st_size <= 16 * 1024 * 1024, "Batch receipts exceed bound")
        previous = {phase: 0 for phase in PHASES}
        with path.open() as stream:
            for line in stream:
                require(len(line) <= 4096, "Batch receipt exceeds line bound")
                value = json.loads(line, object_pairs_hook=unique_object)
                phase, index = value["phase"], value["batch_index"]
                require(phase in expected and type(index) is int and 0 <= index < len(expected[phase]), "Unknown batch")
                item = expected[phase][index]
                require(value["success"] is True and value["clock_domain"] == start["clock_domain"]
                        and value["owner_token"] == report["owner_token"]
                        and value["configuration_sha256"] == report["configuration_sha256"]
                        and value["worker"] == worker == item["worker"]
                        and value["scheduled_ns"] == epochs[phase] + item["offset_ns"]
                        and value["rows"] == value["sent_rows"] == value["acknowledged_rows"] == item["rows"]
                        and previous[phase] <= value["started_ns"]
                        and value["scheduled_ns"] <= value["started_ns"] <= value["finished_ns"]
                        <= value["scheduled_ns"] + 60 * NANO, "Failed, overlapping or mistimed offered batch")
                seen[phase].add(index)
                previous[phase] = value["finished_ns"]
                if phase == "warmup":
                    warmup_last_finished = max(warmup_last_finished, value["finished_ns"])
                if phase == "measurement":
                    latencies.append(value["finished_ns"] - value["scheduled_ns"])
                    service.append(value["finished_ns"] - value["started_ns"])
                    delays.append(value["started_ns"] - value["scheduled_ns"])
    require(all(seen[phase].count == len(expected[phase]) for phase in PHASES), "Missing offered batch terminal receipt")
    require(warmup_last_finished <= warmup["completed_ns"], "Warmup barrier precedes the last completed producer batch")
    latencies.sort()
    service.sort()
    delays.sort()
    samples = len(latencies)
    percentile = lambda values, p: values[(len(values) * p + 99) // 100 - 1]
    return epochs, {"unit": "producer_batch", "latency_boundary": "scheduled_to_finished_including_queue",
                    "samples": samples, "p99_sample_floor_met": samples >= 10000,
                    "p95_ns": percentile(latencies, 95), "p99_ns": percentile(latencies, 99) if samples >= 10000 else None,
                    "service_p95_ns": percentile(service, 95),
                    "service_p99_ns": percentile(service, 99) if samples >= 10000 else None,
                    "dispatch_delay_p95_ns": percentile(delays, 95), "max_dispatch_delay_ns": max(delays),
                    "qualified": False, "offered_rows_per_second": ROWS / 600,
                    "warmup_barrier_gap_ns": epochs["measurement"] - epochs["warmup"] - 180 * NANO}


def modulo_sum(end, modulus):
    cycles, tail = divmod(end, modulus)
    return cycles * modulus * (modulus - 1) // 2 + tail * (tail - 1) // 2


def range_expected(low, high):
    return {"n": high - low, "distinct_ids": high - low, "min_id": low, "max_id": high - 1,
            "sum_id": (high * (high - 1) - low * (low - 1)) // 2,
            "sum_grp": modulo_sum(high, 1024) - modulo_sum(low, 1024),
            "sum_v": modulo_sum(high, 100000) - modulo_sum(low, 100000), "bad_rows": 0}


def visibility(sql, name, low, high, checkpoint):
    padding = hashlib.sha256(b"20260922").hexdigest() * 2
    prefix_length = "LENGTH(CONCAT(CAST(id AS STRING),',',CAST(id % 1024 AS STRING),',',CAST(id % 100000 AS STRING),','))"
    payload = f"CONCAT(MD5(CAST(id AS STRING)),SUBSTRING('{padding}',1,95-({prefix_length})))"
    results = []
    for begin in range(low, high, LIMITS["sql_oracle_range_rows"]):
        checkpoint()
        end = min(high, begin + LIMITS["sql_oracle_range_rows"])
        statement = (f"SELECT COUNT(*) AS n,COUNT(DISTINCT id) AS distinct_ids,MIN(id) AS min_id,MAX(id) AS max_id,"
                     f"SUM(id) AS sum_id,SUM(grp) AS sum_grp,SUM(v) AS sum_v,"
                     f"SUM(IF(grp!=id%1024 OR v!=id%100000 OR payload!={payload},1,0)) AS bad_rows "
                     f"FROM license_perf.{name} WHERE id>={begin} AND id<{end}")
        value = sql.one(statement)
        wanted = range_expected(begin, end)
        require(len(value["rows"]) == 1 and {key: int(value["rows"][0][key]) for key in wanted} == wanted,
                "Independent bounded-range SQL oracle failed")
        results.append({"low": begin, "high": end, "expected": wanted, "actual": value["rows"][0]})
    count = sql.one(f"SELECT COUNT(*) AS n FROM license_perf.{name}")
    require(len(count["rows"]) == 1 and int(count["rows"][0]["n"]) == high - low,
            "SQL table contains excess, duplicate or out-of-phase rows")
    return {"complete": True, "ranges": results, "total_count": count["rows"][0]}


def checked_receipt(output, name, binding):
    value = read_json(output / name)
    require(value.get("owner_token") == binding["owner_token"]
            and value.get("configuration_sha256") == binding["configuration_sha256"]
            and value.get("java_runtime") == small.JAVA_RUNTIME and value.get("kafka_client_version") == small.VERSION,
            "Helper receipt belongs to different inputs/owner/JDK/Kafka")
    return value


def table_identity(sql, name):
    databases = [row for row in sql.one("SHOW PROC '/dbs'")["rows"] if row.get("DbName") == "license_perf"]
    require(len(databases) == 1 and re.fullmatch(r"[1-9][0-9]*", databases[0].get("DbId", "")), "Ambiguous database ID")
    db_id = databases[0]["DbId"]
    tables = [row for row in sql.one(f"SHOW PROC '/dbs/{db_id}'")["rows"] if row.get("TableName") == name]
    require(len(tables) == 1 and re.fullmatch(r"[1-9][0-9]*", tables[0].get("TableId", "")), "Ambiguous actual table ID")
    schema = sql.one(f"SHOW CREATE TABLE license_perf.{name}")["rows"]
    require(len(schema) == 1 and any("DUPLICATE KEY" in str(value) for value in schema[0].values()), "Unexpected table definition")
    tablets = [row.get("TabletId", "") for row in sql.one(f"SHOW TABLETS FROM license_perf.{name}")["rows"]]
    require(len(tablets) == len(set(tablets)) == 8 and all(re.fullmatch(r"[1-9][0-9]*", value) for value in tablets),
            "Unexpected actual eight-tablet ownership")
    return {"db_id": db_id, "table_id": tables[0]["TableId"], "show_create_sha256": object_sha(schema),
            "tablet_ids": sorted(tablets, key=int)}


def job_identity(row, name, table, broker_port):
    """SHOW's actual field is Id; its TableName resolves the job's stored tableId (RoutineLoadJob.getShowInfo)."""
    require(re.fullmatch(r"[1-9][0-9]*", row.get("Id", "")) and row.get("Name") == name
            and row.get("DbName") == "license_perf" and row.get("TableName") == name
            and row.get("IsMultiTable") == "false" and row.get("DataSourceType") == "KAFKA",
            "Routine job is not the acknowledged single-table Kafka owner")
    source = json.loads(row["DataSourceProperties"], object_pairs_hook=unique_object)
    require(source.get("topic") == name and source.get("brokerList") == f"127.0.0.1:{broker_port}",
            "Routine job source refers to another owned topic/broker")
    return {"job_id": row["Id"], "name": name, "db_id": table["db_id"], "table_id": table["table_id"],
            "create_time": row["CreateTime"], "topic": source["topic"], "broker_list": source["brokerList"]}


def verify_table_owner(sql, name, owner):
    require(owner is not None and table_identity(sql, name) == owner, "Database/table/tablet identity changed; refuse mutation")


def verify_job_owner(sql, name, owner, table, broker_port):
    require(owner is not None, "No successful CREATE acknowledgement and actual job ID; do not adopt by name")
    verify_table_owner(sql, name, table)
    rows = sql.one(f"SHOW ALL ROUTINE LOAD FOR license_perf.{name}")["rows"]
    require(len(rows) == 1 and job_identity(rows[0], name, table, broker_port) == owner,
            "Job name refers to a replacement; refuse STOP")
    return rows[0]


def probe(args, output, report):
    support.no_active_benchmark()
    require(args.password_env in os.environ and len(os.environ[args.password_env]) <= 1024,
            "Dedicated bounded password variable must explicitly exist (empty is permitted)")
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", args.user) is not None
            and re.fullmatch(r"MASSDB_KAFKA_[A-Z0-9_]+_PASSWORD", args.password_env) is not None,
            "Use a simple owned test account and dedicated password variable")
    prepared, manifest = validate_prepared(args.prepared)
    state = support.cluster_identity(args)
    require(args.cpu in os.sched_getaffinity(0), "Declared client CPU is not available")
    os.sched_setaffinity(0, {args.cpu})
    available = int(re.search(r"(?m)^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text())[1])
    require(available >= 2560 * 1024, "Require 2GiB sampled fixture budget plus 512MiB available reserve")
    java_home = Path(state["java_home"])
    java = java_home / "bin/java"
    with zipfile.ZipFile(Path(state["package"]) / "fe/lib/doris-fe.jar") as archive:
        require(not any(name.startswith("org/apache/doris/massdb/license/") for name in archive.namelist()),
                "Original-A execution requires the original FE without candidate license implementation")
    require(shutil.disk_usage(output).free >= LIMITS["minimum_free_disk_bytes"], "Insufficient evidence/broker disk budget")
    for port in (args.broker_port, args.controller_port):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", port))
    name, token = "lp013_" + uuid.uuid4().hex[:16], uuid.uuid4().hex
    classes = output / "classes"
    classes.mkdir()
    classpath, dependencies = small.classpath_for(state, prepared, classes)
    jars = sorted((prepared / small.PACKAGE / "libs").glob("*.jar"))
    paths = [*dependencies, java, java_home / "bin/javac", java_home / "release", java_home / "lib/modules",
             java_home / "lib/server/libjvm.so", Path(state["package"]) / "fe/lib/doris-fe.jar",
             Path(state["package"]) / "be/lib/doris_be", owned(args.cluster_record), prepared / "prepared.json",
             output / "plan.json", output / "schedule.json", Path(small.lifecycle.__file__),
             *(Path(value["path"]) for value in manifest["inputs"].values()), *jars]
    frozen = {**report["frozen_sources"], **{str(path): digest(path) for path in paths}}
    report.update(status="RUNNING", namespace=state["namespace"], verified_identity=state["verified_identity"],
                  owner_token=token, name=name, frozen_inputs=frozen, client_cpu_affinity=sorted(os.sched_getaffinity(0)),
                  cleanup={"sql": [], "processes": []})
    save(output / "report.json", report)
    budget = support.Budget(LIMITS["main_seconds"])
    guard = support.resources_module.ResourceGuard(output, state)
    budget.resources = guard
    processes = CapturedProcesses(budget, output, state["namespace"], guard)
    original, sql, producer, broker = None, None, None, None
    table_attempted, table_created, table_owner, job_attempted, job_owner = False, False, None, False, None
    previous_signals = {}
    lock, locked = Path(state["installation"]) / "lp013-baseline-owner.lock", False
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous_signals[signum] = signal.signal(signum, lambda *_: setattr(budget, "cancelled", True))
    last_disk_check = [0.0]
    def checkpoint():
        budget.checkpoint()
        support.validate_live_identity(state)
        if broker is not None:
            require(broker.poll() is None, "Owned broker exited unexpectedly")
        if time.monotonic() - last_disk_check[0] >= 5:
            paths = list(output.rglob("*"))
            require(len(paths) <= 4096 and not any(path.is_symlink() for path in paths), "Output file/ownership bound exceeded")
            # Kafka may rotate/delete its own segment files during sampling; retry at the next checkpoint.
            try:
                size = sum(path.stat().st_size for path in paths if path.is_file())
            except FileNotFoundError:
                size = 0
            require(size <= LIMITS["maximum_evidence_bytes"] and shutil.disk_usage(output).free >= 256 * 1024 ** 2,
                    "Output evidence/broker disk budget exceeded")
            last_disk_check[0] = time.monotonic()
    try:
        with lock.open("x") as stream:
            stream.write(token + "\n")
        locked = True
        guard.start()
        code, _ = processes.run([java_home / "bin/javac", "-J-Xmx256m", "--release", "8", "-proc:none", "-encoding", "UTF-8",
                                 "-cp", classpath, "-d", classes, HELPER, small.SQL_HELPER], "compile", 120)
        require(code == 0, "Real original dependency compilation failed")
        report["compiled_classes"] = {str(path): digest(path) for path in classes.rglob("*.class")}
        config_path = small.broker_config(output, args)
        logging = output / "log4j.properties"
        logging.write_text("log4j.rootLogger=WARN,stderr\nlog4j.appender.stderr=org.apache.log4j.ConsoleAppender\n"
                           "log4j.appender.stderr.Target=System.err\nlog4j.appender.stderr.layout=org.apache.log4j.PatternLayout\n"
                           "log4j.appender.stderr.layout.ConversionPattern=%d %-5p %c - %m%n\n")
        broker_command = [java, "-Xms512m", "-Xmx512m", "-XX:+UseG1GC", "-Djava.awt.headless=true",
                          "-Dlog4j.configuration=" + logging.as_uri(), "-cp", os.pathsep.join(map(str, jars))]
        cluster_id = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")
        code, _ = processes.run([*broker_command, "kafka.tools.StorageTool", "format", "-t", cluster_id, "-c", config_path],
                                "storage-format", 90)
        require(code == 0, "Owned KRaft storage formatting failed")
        broker = processes.start([*broker_command, "kafka.Kafka", config_path], "broker", background=True)
        config = {"checkout": str(ROOT), "output": str(output), "namespace": state["namespace"],
                  "host_namespace": state["host_namespace"], "bootstrap": "127.0.0.1:" + str(args.broker_port),
                  "topic": name, "owner_token": token, "workers": args.producer_workers, "batch_rows": args.batch_rows,
                  **{phase + "_input": value["path"] for phase, value in manifest["inputs"].items()},
                  "frozen_inputs_sha256": object_sha(frozen), "schedule_sha256": report["schedule_sha256"]}
        config["configuration_sha256"] = object_sha(config)
        helper_config = output / "kafka-config.json"
        save(helper_config, config)
        report["configuration_sha256"] = config["configuration_sha256"]
        runtime_files = [config_path, logging, helper_config]
        report["runtime_inputs"] = {str(path): digest(path) for path in runtime_files}
        def command(mode):
            return [java, "-Xmx512m", "-cp", classpath, "LicenseKafkaBaseline", mode, helper_config]
        code, _ = processes.run(command("init"), "kafka-init", 120)
        require(code == 0, "Actual eight-partition topic initialization failed")
        initial = checked_receipt(output, "kafka-init.json", config)
        require(initial["begin_offsets"] == initial["end_offsets_exclusive"] == small.expected_offsets(0), "Topic was not empty")
        sql = support.Sql(args, state, output, processes, classpath)
        grants = sql.one("SHOW GRANTS")["rows"]
        require(len(grants) == 1 and re.search(r"(?i)\badmin_priv\b", grants[0].get("GlobalPrivs", "")),
                "Require actual ADMIN to enumerate and own the complete setup/cleanup namespace")
        sql.one("CREATE DATABASE IF NOT EXISTS license_perf")
        existing = sql.one(f"SHOW TABLES FROM license_perf LIKE '{name}'")
        require(existing["rows"] == [], "Generated table name is not absent; do not adopt it")
        existing_job = sql.execute(["USE license_perf", "SHOW ALL ROUTINE LOAD"])[1]
        require(not any(row.get("Name") == name for row in existing_job["rows"]), "Generated job name is not absent; do not adopt it")
        save(output / "create-intent.json", {"owner_token": token, "name": name, "namespace": state["namespace"],
                                             "table_and_job_absence_confirmed": True,
                                             "cluster_record_sha256": digest(args.cluster_record)})
        table_attempted = True
        sql.one(f"CREATE TABLE license_perf.{name} (id BIGINT NOT NULL,grp INT NOT NULL,v BIGINT NOT NULL,payload VARCHAR(128) NOT NULL) "
                "DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 8 PROPERTIES ('replication_num'='1')")
        table_created = True
        table_owner = table_identity(sql, name)
        save(output / "sql-owner.json", {"owner_token": token, "name": name, "create_success": True,
                                         "table": table_owner, "namespace": state["namespace"]})
        job_attempted = True
        sql.one(small.routine_sql(name, name, args))
        verify_table_owner(sql, name, table_owner)
        actual_jobs = sql.one(f"SHOW ROUTINE LOAD FOR license_perf.{name}")["rows"]
        require(len(actual_jobs) == 1, "Acknowledged new job has no unique actual ID")
        job_owner = job_identity(actual_jobs[0], name, table_owner, args.broker_port)
        save(output / "job-owner.json", {"owner_token": token, "create_acknowledged": True, "job": job_owner})
        producer = processes.start(command("produce"), "kafka-produce", background=True)
        polls = []
        def poll(wanted):
            checkpoint()
            result = sql.execute(["USE license_perf", f"SHOW ROUTINE LOAD FOR license_perf.{name}",
                                  f"SHOW ROUTINE LOAD TASK WHERE JobName='{name}'"])
            require(len(result[1]["rows"]) == 1, "Missing or ambiguous Routine Load job")
            require(job_identity(result[1]["rows"][0], name, table_owner, args.broker_port) == job_owner,
                    "Routine Load job identity changed during polling")
            derived = small.routine_progress(result[1]["rows"][0], wanted)
            require(0 <= derived["current_tasks"] <= min(8, args.consumer_tasks), "Observed consumer tasks exceed requested partition bound")
            polls.append({"at_utc": fixture.utc(), "controller_monotonic_ns": time.monotonic_ns(),
                          "wanted_rows": wanted, "raw": result[1]["rows"][0], "derived": derived, "tasks": result[2]})
            require(len(polls) <= 720, "Routine observation count bound exceeded")
            save(output / "routine-progress.json", polls)
            return derived["complete"]
        warm_deadline = time.monotonic() + 420
        while not (output / "warmup-complete.json").exists():
            checkpoint()
            require(producer.poll() is None, "Producer exited during warmup; retain partial evidence")
            require(time.monotonic() < warm_deadline, "Warmup production exceeded fixed window plus drain")
            poll(WARM_ROWS)
            budget.pause(LIMITS["poll_interval_seconds"])
        warm = checked_receipt(output, "warmup-complete.json", config)
        warm_start = checked_receipt(output, "warmup-start.json", config)
        require(warm["acknowledged_rows"] == WARM_ROWS and warm["end_offsets_exclusive"] == small.expected_offsets(WARM_ROWS),
                "Warmup barrier has incomplete physical rows/offsets")
        require(warm_start["clock_domain"] == warm["clock_domain"]
                and warm_start["warmup_start_ns"] == warm["warmup_start_ns"]
                and warm_start["warmup_end_ns"] == warm["warmup_start_ns"] + 180 * NANO
                and warm["completed_ns"] >= warm_start["warmup_end_ns"], "Warmup timing receipt mismatch")
        visibility_deadline = time.monotonic() + LIMITS["visibility_seconds"]
        while not poll(WARM_ROWS):
            require(time.monotonic() < visibility_deadline, "Warmup Routine Load visibility timed out")
            budget.pause(LIMITS["poll_interval_seconds"])
        report["warmup_sql_oracle"] = visibility(sql, name, ROWS, TOTAL, checkpoint)
        verify_table_owner(sql, name, table_owner)
        go = {"owner_token": token, "configuration_sha256": config["configuration_sha256"],
              "clock_domain": warm["clock_domain"], "warmup_visible": True,
              "warmup_sql_oracle_sha256": object_sha(report["warmup_sql_oracle"])}
        temporary = output / "measurement-go.tmp"
        save(temporary, go)
        temporary.rename(output / "measurement-go.json")
        measured_deadline = time.monotonic() + 780
        while producer.poll() is None:
            checkpoint()
            require(time.monotonic() < measured_deadline, "Measurement exceeded 600-second window plus drain")
            poll(TOTAL)
            budget.pause(LIMITS["poll_interval_seconds"])
        require(producer.returncode == 0, "Producer failed; no replay or completion claim")
        processes.stop(producer)
        produced = checked_receipt(output, "kafka-produce.json", config)
        require(produced.get("success") is True and produced.get("workers_terminated") is True
                and produced.get("unknown_or_partial") is False and produced.get("warmup_rows") == WARM_ROWS
                and produced.get("measurement_rows") == ROWS and produced.get("end_offsets_exclusive") == small.expected_offsets(TOTAL),
                "Incomplete producer terminal receipt")
        metrics = produced["actual_client_metrics"]
        require(len(metrics) == args.producer_workers and {value["worker"] for value in metrics} == set(range(args.producer_workers))
                and sum(value["record-send-total"] for value in metrics) == TOTAL
                and all(value["record-error-total"] == value["record-retry-total"] == 0 for value in metrics),
                "Producer errors/retries or incomplete actual client metrics")
        start = checked_receipt(output, "measurement-start.json", config)
        require(produced["clock_domain"] == start["clock_domain"]
                and produced["warmup_start_ns"] == start["warmup_start_ns"]
                and produced["measurement_start_ns"] == start["measurement_start_ns"]
                and produced["finished_ns"] >= start["measurement_end_ns"], "Producer terminal clock/window mismatch")
        epochs, report["batch_latency"] = audit_batches(output, report, start, warm)
        report["producer"] = produced
        visibility_deadline = time.monotonic() + LIMITS["visibility_seconds"]
        while not poll(TOTAL):
            require(time.monotonic() < visibility_deadline, "Full Routine Load visibility timed out")
            budget.pause(LIMITS["poll_interval_seconds"])
        report["full_sql_oracle"] = visibility(sql, name, 0, TOTAL, checkpoint)
        verify_job_owner(sql, name, job_owner, table_owner, args.broker_port)
        code, _ = processes.run(command("verify"), "kafka-verify", 930)
        require(code == 0, "Independent actual Kafka consumer failed")
        consumed = checked_receipt(output, "kafka-verify.json", config)
        require(consumed["records"] == TOTAL and consumed["begin_offsets"] == small.expected_offsets(0)
                and consumed["end_offsets_exclusive"] == small.expected_offsets(TOTAL), "Consumer offset snapshot mismatch")
        report["physical_oracle"] = verify_physical(output, args.producer_workers, args.batch_rows, epochs, checkpoint=checkpoint)
        checkpoint()
        require(all(digest(Path(path)) == value for path, value in frozen.items()), "Frozen execution input changed")
        require(small.prepared_inventory(prepared) == manifest["distribution_files"], "Official broker distribution changed")
        require(all(digest(Path(path)) == value for path, value in report["runtime_inputs"].items()), "Runtime configuration changed")
        require({str(path): digest(path) for path in classes.rglob("*.class")} == report["compiled_classes"], "Executed classes changed")
        report["status"] = "FULL_INPUT_WINDOW_COMPLETE_NOT_QUALIFIED"
    except BaseException as error:
        original = error
        report.update(status="FAILED", error={"class": type(error).__name__, "message": str(error)})
    finally:
        budget.begin_cleanup()
        # Stop the sender first so no new rows race job/table cleanup. Keep the original FE/BE running.
        if producer is not None:
            try:
                (output / "stop").touch(exist_ok=True)
                processes.stop(producer)
            except BaseException as error:
                report["cleanup"]["sender_error"] = type(error).__name__
        if sql is not None:
            if job_attempted:
                try:
                    verify_job_owner(sql, name, job_owner, table_owner, args.broker_port)
                    result = sql.execute([f"STOP ROUTINE LOAD FOR license_perf.{name}", f"SHOW ALL ROUTINE LOAD FOR license_perf.{name}"],
                                         continue_on_error=True)
                    clean = result[0]["success"] is True and len(result[1]["rows"]) == 1 and all(
                        row["State"] == "STOPPED" and int(row["CurrentTaskNum"]) == 0
                        and job_identity(row, name, table_owner, args.broker_port) == job_owner for row in result[1]["rows"])
                    report["cleanup"]["sql"].append({"operation": "stop_owned_job", "clean": clean, "result": result})
                except BaseException as error:
                    report["cleanup"]["sql"].append({"operation": "stop_owned_job", "clean": False,
                                                     "commit_state": "UNKNOWN_OR_IDENTITY_UNVERIFIED_NO_ADOPTION",
                                                     "error": type(error).__name__})
            if table_created:
                try:
                    require(not job_attempted or (job_owner is not None and report["cleanup"]["sql"][-1]["clean"]),
                            "Unstopped/unknown job may retain a table reference; preserve manual residual")
                    verify_table_owner(sql, name, table_owner)
                    sql.one(f"DROP TABLE license_perf.{name}")
                    absent = sql.one(f"SHOW TABLES FROM license_perf LIKE '{name}'")
                    require(absent["rows"] == [], "Owned table remains after DROP")
                    report["cleanup"]["sql"].append({"operation": "drop_owned_table", "clean": True, "absence": absent})
                except BaseException as error:
                    report["cleanup"]["sql"].append({"operation": "drop_owned_table", "clean": False, "error": type(error).__name__})
            elif table_attempted:
                report["cleanup"]["sql"].append({"operation": "create_table", "clean": False,
                                                 "commit_state": "UNKNOWN_NO_CREATE_ACK_NO_ADOPTION"})
        report["cleanup"]["processes"] = processes.stop_all()
        for record in report["cleanup"]["processes"]:
            try:
                record["remaining_live_group_pids"] = small.lifecycle.live_group_members(record["pid"])
            except BaseException as error:
                record.update(remaining_live_group_pids=None, group_audit_error=type(error).__name__)
        report["resources"] = guard.stop()
        if locked:
            try:
                require(not lock.is_symlink() and lock.read_text() == token + "\n", "Owner lock changed; refuse removal")
                lock.unlink()
                report["cleanup"]["owner_lock_removed"] = True
            except BaseException as error:
                report["cleanup"]["owner_lock_removed"] = False
                report["cleanup"]["owner_lock_error"] = type(error).__name__
        clean = (all(value.get("clean") is True for value in report["cleanup"]["sql"])
                 and all(value.get("stopped") is True and value["remaining_live_group_pids"] == []
                         for value in report["cleanup"]["processes"])
                 and "sender_error" not in report["cleanup"] and report["resources"].get("complete") is True
                 and (not locked or report["cleanup"].get("owner_lock_removed") is True))
        report["cleanup"]["complete"] = clean
        if not clean or budget.cancelled:
            report["status"] = "FAILED"
        report["finished_at_utc"] = fixture.utc()
        try:
            save(output / "report.json", report)
        finally:
            for signum, previous in previous_signals.items():
                signal.signal(signum, previous)
    require(original is None and report["status"] == "FULL_INPUT_WINDOW_COMPLETE_NOT_QUALIFIED",
            "Full Kafka window failed; retain its original and partial cleanup evidence")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "prepare", "probe"), default="plan")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--cluster-record", type=Path)
    parser.add_argument("--expected-fe-sha256")
    parser.add_argument("--expected-be-sha256")
    parser.add_argument("--jdk-runtime-version", default=small.JAVA_RUNTIME, choices=(small.JAVA_RUNTIME,))
    parser.add_argument("--producer-workers", type=int, choices=(1, 8, 32), default=1)
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--consumer-tasks", type=int, choices=(1, 8), default=8)
    parser.add_argument("--batch-rows", type=int, choices=(1000, 10000), default=1000)
    parser.add_argument("--broker-port", type=int, default=39092)
    parser.add_argument("--controller-port", type=int, default=39093)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_KAFKA_BASELINE_PASSWORD")
    args = parser.parse_args()
    require(args.cpu >= 0, "Select an explicit nonnegative client CPU")
    require(all(1024 <= port <= 65535 for port in (args.broker_port, args.controller_port))
            and args.broker_port != args.controller_port, "Require distinct unprivileged loopback ports")
    require(args.mode != "probe" or (args.prepared and args.cluster_record), "Probe requires prepared input and original cluster")
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    report = plan(args)
    save(output / "plan.json", report)
    save(output / "schedule.json", schedule(args.producer_workers, args.batch_rows))
    try:
        if args.mode == "prepare":
            prepare(args, output, report)
        elif args.mode == "probe":
            probe(args, output, report)
    except BaseException as error:
        report.update(status="FAILED")
        report.setdefault("error", {"class": type(error).__name__, "message": str(error)})
        raise
    finally:
        save(output / "report.json", report)
    print(json.dumps({"status": report["status"], "output": str(output), "LP013_complete": False,
                      "release_performance_pass": False}), flush=True)


if __name__ == "__main__":
    main()
