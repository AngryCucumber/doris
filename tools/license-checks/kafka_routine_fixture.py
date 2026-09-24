#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Plan, prepare or probe a real, privately owned LP013 Kafka prerequisite; never a performance pass."""

import argparse
import base64
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import subprocess
import tarfile
import time
import urllib.request
import uuid

import calibrate_read_capacity as lifecycle
import stream_load_fixture as fixture


ROOT = fixture.ROOT
VERSION = "3.9.2"
PACKAGE = "kafka_2.13-" + VERSION
ARCHIVE_URL = "https://archive.apache.org/dist/kafka/" + VERSION + "/" + PACKAGE + ".tgz"
# Apache's release checksum, read from ARCHIVE_URL + '.sha512'; hexadecimal groups joined verbatim.
ARCHIVE_SHA512 = ("01186a5086b5ae753811ee71808a797baec1303d4e0d4b1c0acf42c489654a7b"
                  "8988136f8469d0b66f0be439f8e3e9b816171ea0b0d7a36462b07aa2d3ef0023")
PARTITIONS = 8
ROWS = (10000, 100000)
SEED = 20260922
JAVA_RUNTIME = "17.0.4+8"
HELPER = ROOT / "tools/license-checks/LicenseKafkaFixture.java"
SQL_HELPER = ROOT / "tools/license-checks/LicenseFixtureSql.java"


def sha512(path):
    result = hashlib.sha512()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def order_parameters(rows):
    # A permutation, not independent random draws: each ID must occur exactly once.
    multiplier = (SEED * 2 + 1) % rows
    while math.gcd(multiplier, rows) != 1:
        multiplier = (multiplier + 2) % rows
    return multiplier, SEED % rows


def identifier_at(index, rows):
    multiplier, shift = order_parameters(rows)
    return (index * multiplier + shift) % rows


def expected_offsets(rows):
    return {str(partition): (rows + PARTITIONS - 1 - partition) // PARTITIONS
            for partition in range(PARTITIONS)}


def plan(args):
    return {"schema_version": 1, "case_id": "LP-013", "status": "PLANNED", "mode": args.mode,
            "performance_policy_sha256": fixture.digest(ROOT / "docs/license-performance-cases-20260922.json"),
            "scope": "Real Kafka to BE Routine Load functional prerequisite only",
            "LP013_complete": False, "release_performance_pass": False,
            "version": VERSION, "archive_url": ARCHIVE_URL, "archive_sha512": ARCHIVE_SHA512,
            "checksum_source": ARCHIVE_URL + ".sha512", "java_runtime_required": JAVA_RUNTIME,
            "broker": {"mode": "single combined KRaft controller/broker", "partitions": PARTITIONS,
                       "replication_factor": 1, "listener": "private netns loopback only",
                       "broker_port": args.broker_port, "controller_port": args.controller_port,
                       "heap_mib": 512, "provisional_total_memory_budget_mib": [1024, 2048]},
            "rows": args.rows, "row_bytes_including_lf": fixture.ROW_BYTES, "seed": SEED,
            "kafka_value_bytes": fixture.ROW_BYTES - 1,
            "id_order": {"method": "affine permutation", "parameters": order_parameters(args.rows)},
            "producer_workers": args.producer_workers, "producer_batch_rows": args.batch_rows,
            "routine_desired_tasks": args.consumer_tasks,
            "concurrency_note": "Producer workers and observed consumer tasks are separate; one 8-partition job cannot have 32 active partition consumers",
            "batch_note": "Producer row batches are not Routine Load max_batch_rows (minimum 200000)",
            "input_bytes": args.rows * fixture.ROW_BYTES, "expected_end_offsets_exclusive": expected_offsets(args.rows),
            "full_contract_retained": {"rows": 10000000, "concurrency": [1, 8, 32],
                                       "batch_rows": [1000, 10000], "warmup_seconds": 180,
                                       "window_seconds": 600, "minimum_pairs": 5,
                                       "qps_cpu_precision_percent": 1, "p95_p99_precision_percent": 2},
            "not_measured": ["VALID/EXPIRED transition and renewal", "paired A/B performance", "fixed offered-rate sustained windows",
                             "capacity or latency precision", "formal concurrency dimension interpretation"],
            "producer_settings": {"acks": "all", "enable.idempotence": True,
                                  "max.in.flight.requests.per.connection": 1, "compression.type": "none",
                                  "delivery.timeout.ms": 30000, "request.timeout.ms": 10000,
                                  "max.block.ms": 10000},
            "ack_scope": "Replication factor 1 acknowledges the single leader; not a replicated durability test",
            "lifecycle_bounds_seconds": {"main_work": 1200, "individual_sql_helper": 90,
                                         "cleanup_sql_helpers_maximum_total": 270, "owned_group_term_then_kill": 10},
            "created_at_utc": fixture.utc(), "validation_note": "Separate tool tests do not establish real Kafka reachability"}


def archive_members(source):
    members = source.getmembers()
    if len(members) > 20000 or sum(item.size for item in members) > 1024 ** 3:
        raise ValueError("Kafka archive exceeds the bounded extraction budget")
    for member in members:
        parts = Path(member.name).parts
        if (not parts or parts[0] != PACKAGE or any(part in ("..", ".") for part in parts)
                or Path(member.name).is_absolute() or not (member.isfile() or member.isdir())):
            raise ValueError("Kafka archive contains an unsafe path or special entry")
    return members


def extract_archive(archive, output):
    if sha512(archive) != ARCHIVE_SHA512:
        raise ValueError("Kafka archive differs from the pinned official SHA-512")
    with tarfile.open(archive, "r:gz") as source:
        members = archive_members(source)
        # Only regular files/directories survived the preceding validation; no links or devices.
        source.extractall(output, members=members)
    return output / PACKAGE


def archive_inventory(archive):
    """Bind executable files to the pinned release, independently of the editable preparation manifest."""
    if sha512(archive) != ARCHIVE_SHA512:
        raise ValueError("Kafka archive differs from the pinned official SHA-512")
    result = {}
    with tarfile.open(archive, "r:gz") as source:
        for member in archive_members(source):
            if not member.isfile():
                continue
            checksum = hashlib.sha256()
            with source.extractfile(member) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    checksum.update(chunk)
            result[str(Path(member.name))] = checksum.hexdigest()
    if not result:
        raise ValueError("Empty Kafka archive distribution")
    return result


def download_archive(output):
    path = output / (PACKAGE + ".tgz")
    deadline = time.monotonic() + 300
    with urllib.request.urlopen(ARCHIVE_URL, timeout=20) as response, path.open("xb") as stream:
        if response.url != ARCHIVE_URL:
            raise ValueError("Unexpected Kafka archive redirect")
        count = 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("Kafka download exceeded five minutes")
            block = response.read(1024 * 1024)
            if not block:
                break
            count += len(block)
            if count > 160 * 1024 ** 2:
                raise ValueError("Kafka archive exceeds the download bound")
            stream.write(block)
    return path


def prepared_inventory(directory):
    paths = sorted((directory / PACKAGE).rglob("*"))
    result = {}
    for path in paths:
        if path.is_symlink():
            raise ValueError("Prepared distribution must not contain symlinks")
        if path.is_file():
            result[str(path.relative_to(directory))] = fixture.digest(path)
    if not result:
        raise ValueError("Empty Kafka distribution")
    return result


def prepare(args, output, report):
    archive = download_archive(output) if args.download else fixture.owned(args.archive)
    distribution = extract_archive(archive, output)
    source = output / "rows.csv"
    with source.open("xb") as stream:
        for index in range(args.rows):
            stream.write(fixture.record(identifier_at(index, args.rows)))
    report.update(status="PREPARED_NOT_PROBED", archive_path=str(archive), archive_sha256=fixture.digest(archive),
                  archive_sha512_actual=sha512(archive), archive_sha512_verified=True,
                  archive_pgp_signature_verified=False, distribution=str(distribution),
                  distribution_files=prepared_inventory(output), input_path=str(source),
                  input_sha256=fixture.digest(source), expected_rows=fixture.expected(args.rows),
                  generator_sha256=fixture.digest(Path(__file__)))
    fixture.save(output / "prepared.json", report)


def validate_prepared(path, args):
    path = fixture.owned(path)
    report = json.loads((path / "prepared.json").read_text())
    if (report.get("status") != "PREPARED_NOT_PROBED" or report.get("version") != VERSION
            or report.get("archive_sha512_actual") != ARCHIVE_SHA512
            or report.get("rows") != args.rows or report.get("seed") != SEED
            or report.get("row_bytes_including_lf") != fixture.ROW_BYTES
            or report.get("expected_rows") != fixture.expected(args.rows)
            or report.get("expected_end_offsets_exclusive") != expected_offsets(args.rows)):
        raise ValueError("Prepared manifest differs from the declared fixture")
    source = path / "rows.csv"
    if source.stat().st_size != args.rows * fixture.ROW_BYTES or fixture.digest(source) != report["input_sha256"]:
        raise ValueError("Prepared input changed")
    archive = fixture.owned(report["archive_path"])
    official_files = archive_inventory(archive)
    if fixture.digest(archive) != report.get("archive_sha256"):
        raise ValueError("Prepared archive SHA-256 provenance changed")
    if prepared_inventory(path) != official_files or report["distribution_files"] != official_files:
        raise ValueError("Prepared broker distribution differs from the pinned official archive")
    # Verify the complete saved sequence, not only a self-reported hash in the manifest.
    with source.open("rb") as stream:
        for index in range(args.rows):
            if stream.read(fixture.ROW_BYTES) != fixture.record(identifier_at(index, args.rows)):
                raise ValueError("Prepared data does not match the fixed-seed complete ID permutation")
    return path, report


def cluster_identity(path):
    state, _ = fixture.validate_cluster(path)
    installation = fixture.owned(state["installation"])
    config = (installation / "fe/conf/fe.conf").read_text()
    ports = re.findall(r"(?m)^query_port\s*=\s*(\d+)\s*$", config)
    if len(ports) != 1 or int(ports[0]) != state["query_port"]:
        raise ValueError("Cluster record query_port does not match the owned FE configuration")
    ticks = {}
    for service in ("fe", "be"):
        pid = int((installation / service / "bin" / (service + ".pid")).read_text())
        ticks[service] = {"pid": pid, "start_ticks": int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])}
    return state, ticks


class OwnedProcesses:
    """All children use private sessions; retain receipts even when their leader already exited."""

    def __init__(self, output, checkpoint):
        self.output, self.checkpoint = output, checkpoint
        self.children, self.receipts = [], []
        self.deadline = time.monotonic() + 1200

    def start(self, command, name, env=None):
        self.checkpoint()
        with (self.output / (name + ".stdout")).open("w") as stdout, \
                (self.output / (name + ".stderr")).open("w") as stderr:
            process = subprocess.Popen(list(map(str, command)), stdin=subprocess.DEVNULL, stdout=stdout,
                                       stderr=stderr, start_new_session=True, env=env)
        self.children.append((name, process))
        fixture.save(self.output / "owned-processes.json", {"children": [{"name": n, "process_group": p.pid}
                                                                        for n, p in self.children],
                                                           "namespace": os.readlink("/proc/self/ns/net")})
        return process

    def run(self, command, name, timeout, env=None, cleanup=False):
        # Cleanup commands must run even after a deferred cancellation, but remain time-bounded.
        saved = self.checkpoint
        if cleanup:
            self.checkpoint = lambda: None
        else:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                raise TimeoutError("Kafka fixture exceeded its twenty-minute main-work watchdog")
        process = None
        original = None
        try:
            process = self.start(command, name, env)
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                self.checkpoint()
                if time.monotonic() >= deadline:
                    raise TimeoutError(name + " exceeded its declared watchdog")
                time.sleep(.05)
            if process.returncode:
                raise RuntimeError(name + " failed; see its archived output")
        except BaseException as error:
            original = error
            raise
        finally:
            self.checkpoint = saved
            if process is not None:
                receipt = self.stop(name, process, original)
                if original is None and not receipt["clean"]:
                    raise RuntimeError(name + " left owned processes or could not persist cleanup evidence")

    def stop(self, name, process, original=None):
        receipt = {"name": name, "process_group": process.pid, "at_utc": fixture.utc(),
                   "original_error": None if original is None else type(original).__name__ + ": " + str(original),
                   "clean": False}
        try:
            receipt["cleanup"] = lifecycle.terminate_client(process)
            receipt["exit_code"] = process.poll()
            receipt["clean"] = receipt["cleanup"]["remaining_live_pids"] == []
        except BaseException as error:
            receipt["cleanup_error"] = type(error).__name__ + ": " + str(error)
        self.receipts.append(receipt)
        try:
            fixture.save(self.output / (name + ".cleanup.json"), receipt)
        except BaseException as error:
            receipt.update(clean=False, receipt_error=type(error).__name__ + ": " + str(error))
        return receipt

    def stop_all(self):
        completed = {receipt["process_group"] for receipt in self.receipts if receipt["clean"]}
        for name, process in reversed(self.children):
            if process.pid not in completed:
                self.stop(name, process)
        return self.receipts


class ProbeSql:
    def __init__(self, args, state, java, classpath, processes):
        self.args, self.state, self.java = args, state, java
        self.classpath, self.processes, self.sequence = classpath, processes, 0

    def execute(self, statements, cleanup=False):
        self.sequence += 1
        name = "sql-%03d" % self.sequence
        config = self.processes.output / (name + ".json")
        fixture.save(config, {"query_port": self.state["query_port"], "user": self.args.user,
                              "password_env": self.args.password_env, "sql": statements,
                              "continue_on_error": cleanup})
        self.processes.run([self.java, "-cp", self.classpath, "LicenseFixtureSql", config], name, 90, cleanup=cleanup)
        value = json.loads((self.processes.output / (name + ".stdout")).read_text())
        if value.get("connection_error") or len(value.get("statements", [])) != len(statements):
            raise ValueError("Incomplete SQL execution")
        if not cleanup and value.get("success") is not True:
            raise ValueError("SQL statement failed; see the archived structured result")
        return value["statements"]


def classpath_for(state, prepared, classes):
    dependencies = []
    for directory, name in [(Path(state["package"]) / "fe/lib", name) for name in
                            ("mariadb-java-client", "jackson-core", "jackson-databind", "jackson-annotations")] + [
                                (prepared / PACKAGE / "libs", "kafka-clients"),
                                (prepared / PACKAGE / "libs", "slf4j-api")]:
        paths = list(directory.glob(name + "-*.jar"))
        if len(paths) != 1:
            raise ValueError("Expected exactly one dependency: " + name)
        dependencies.append(paths[0])
    return os.pathsep.join(map(str, [classes, *dependencies])), dependencies


def routine_sql(name, topic, args):
    return (f"CREATE ROUTINE LOAD license_perf.{name} ON {name} COLUMNS TERMINATED BY ',', "
            "COLUMNS(id,grp,v,payload) PROPERTIES ("
            f"'desired_concurrent_number'='{args.consumer_tasks}', 'max_batch_interval'='5', "
            "'max_batch_rows'='200000', 'max_batch_size'='104857600', 'max_error_number'='0', "
            "'max_filter_ratio'='0', 'strict_mode'='true', 'timezone'='UTC') FROM KAFKA ("
            f"'kafka_broker_list'='127.0.0.1:{args.broker_port}', 'kafka_topic'='{topic}', "
            "'kafka_partitions'='0,1,2,3,4,5,6,7', 'kafka_offsets'='0,0,0,0,0,0,0,0')")


def broker_config(output, args):
    values = {"process.roles": "broker,controller", "node.id": "1", "controller.quorum.voters":
              f"1@127.0.0.1:{args.controller_port}", "listeners":
              f"PLAINTEXT://127.0.0.1:{args.broker_port},CONTROLLER://127.0.0.1:{args.controller_port}",
              "advertised.listeners": f"PLAINTEXT://127.0.0.1:{args.broker_port}",
              "listener.security.protocol.map": "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT",
              "controller.listener.names": "CONTROLLER", "inter.broker.listener.name": "PLAINTEXT",
              "log.dirs": str(output / "broker-data"), "num.partitions": "8",
              "offsets.topic.replication.factor": "1", "transaction.state.log.replication.factor": "1",
              "transaction.state.log.min.isr": "1", "default.replication.factor": "1", "min.insync.replicas": "1",
              "auto.create.topics.enable": "false", "num.network.threads": "2", "num.io.threads": "2",
              "log.retention.hours": "24", "log.segment.bytes": "134217728", "group.initial.rebalance.delay.ms": "0"}
    path = output / "server.properties"
    path.write_text("".join(key + "=" + value + "\n" for key, value in values.items()))
    return path


def verify_kafka(output, rows, workers=1, batch_rows=1000):
    """Recompute acknowledgements and the independent real-consumer capture; no helper success flag suffices."""
    acknowledged, indices = {}, set()
    offsets = {partition: set() for partition in range(PARTITIONS)}
    with (output / "producer-acks.csv").open() as stream:
        for row in csv.DictReader(stream):
            index, identifier, partition, offset = (int(row[key]) for key in ("index", "id", "partition", "offset"))
            expected = fixture.record(identifier).rstrip(b"\n")
            if (not 0 <= index < rows or index in indices or identifier != identifier_at(index, rows)
                    or int(row["worker"]) != (index % batch_rows) % workers
                    or partition != identifier % PARTITIONS or offset < 0 or (partition, offset) in acknowledged
                    or row["value_sha256"] != hashlib.sha256(expected).hexdigest()):
                raise ValueError("Invalid, missing, duplicate or corrupt producer acknowledgement")
            indices.add(index)
            offsets[partition].add(offset)
            acknowledged[(partition, offset)] = (str(identifier).encode(), expected)
    if len(indices) != rows or any(offsets[p] != set(range(expected_offsets(rows)[str(p)])) for p in offsets):
        raise ValueError("Producer acknowledgements do not cover every row and contiguous partition offset")
    consumed, ids = set(), set()
    with (output / "consumer-records.csv").open() as stream:
        for row in csv.DictReader(stream):
            key = (int(row["partition"]), int(row["offset"]))
            value = (base64.b64decode(row["key_base64"], validate=True),
                     base64.b64decode(row["value_base64"], validate=True))
            if key in consumed or acknowledged.get(key) != value:
                raise ValueError("Real Kafka consumer capture differs from acknowledged data")
            identifier = int(value[0])
            if identifier in ids:
                raise ValueError("Duplicate ID in real Kafka consumer capture")
            ids.add(identifier)
            consumed.add(key)
    if len(consumed) != rows or ids != set(range(rows)):
        raise ValueError("Real Kafka consumer capture has missing rows")
    receipt = json.loads((output / "kafka-verify.json").read_text())
    if (receipt.get("begin_offsets") != {str(p): 0 for p in range(PARTITIONS)}
            or receipt.get("end_offsets_exclusive") != expected_offsets(rows) or receipt.get("records") != rows):
        raise ValueError("Broker offset snapshot differs from the complete data oracle")
    return {"acknowledged_rows": len(indices), "independently_consumed_rows": len(consumed),
            "complete_ids": True, "contiguous_partition_offsets": True,
            "producer_acks_sha256": fixture.digest(output / "producer-acks.csv"),
            "consumer_records_sha256": fixture.digest(output / "consumer-records.csv")}


def routine_progress(row, rows):
    statistic, progress = json.loads(row["Statistic"]), json.loads(row["Progress"])
    if row["State"] not in ("RUNNING", "NEED_SCHEDULE"):
        raise ValueError("Routine Load entered " + row["State"] + ": " + row.get("ReasonOfStateChanged", ""))
    if int(statistic["errorRows"]) or int(statistic["unselectedRows"]) or int(statistic["loadedRows"]) > rows:
        raise ValueError("Routine Load filtered, skipped or loaded excess rows")
    complete = (int(statistic["loadedRows"]) == rows and int(statistic["committedTaskNum"]) > 0
                and set(progress) == set(expected_offsets(rows))
                and all(str(progress[p]) == str(end - 1) for p, end in expected_offsets(rows).items()))
    # SHOW reports last committed offset, whereas Kafka's end offset is exclusive.
    return {"complete": complete, "statistic": statistic, "last_committed_offsets": progress,
            "current_tasks": int(row["CurrentTaskNum"])}


def probe(args, output, report):
    prepared, prepared_report = validate_prepared(args.prepared, args)
    state, identity = cluster_identity(args.cluster_record)  # Before any SQL/network operation.
    java_home = fixture.owned(state["java_home"])
    release = (java_home / "release").read_text()
    if ('IMPLEMENTOR_VERSION="Temurin-' + JAVA_RUNTIME + '"' not in release
            or 'IMPLEMENTOR="Eclipse Adoptium"' not in release or 'JAVA_VERSION="17.0.4"' not in release):
        raise ValueError("Fixture requires the recorded Temurin 17.0.4+8 JDK")
    java = java_home / "bin/java"
    for port in (args.broker_port, args.controller_port):
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", port))
    name = "lp013_" + uuid.uuid4().hex[:16]
    classes = output / "classes"
    classes.mkdir()
    classpath, dependencies = classpath_for(state, prepared, classes)
    inputs = [Path(__file__), HELPER, SQL_HELPER, Path(fixture.__file__), Path(lifecycle.__file__),
              java, java_home / "bin/javac", java_home / "release", *dependencies,
              prepared / "prepared.json", prepared / "rows.csv"]
    frozen = {str(path): fixture.digest(path) for path in inputs}
    report.update(status="RUNNING", namespace=state["namespace"], services=identity, name=name,
                  frozen_inputs=frozen, prepared_manifest_sha256=fixture.digest(prepared / "prepared.json"),
                  distribution_revalidated_against_pinned_archive=True,
                  cleanup={"sql": [], "processes": []})
    fixture.save(output / "report.json", report)
    sql, broker, original = None, None, None
    table_attempted, job_attempted = False, False
    with lifecycle.interrupt_handlers() as checkpoint:
        processes = OwnedProcesses(output, checkpoint)
        try:
            processes.run([java_home / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-cp",
                           classpath, "-d", classes, HELPER, SQL_HELPER], "compile", 60)
            compiled = {str(path): fixture.digest(path) for path in classes.rglob("*.class")}
            report["compiled_classes"] = compiled
            config = broker_config(output, args)
            environment = {key: value for key, value in os.environ.items() if not key.startswith(("KAFKA_", "JMX_"))
                           and key not in ("CLASSPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS")}
            environment.update(JAVA_HOME=str(java_home), KAFKA_HEAP_OPTS="-Xms512m -Xmx512m",
                               LOG_DIR=str(output / "broker-logs"), KAFKA_OPTS="",
                               KAFKA_JMX_OPTS="-Dcom.sun.management.jmxremote=false",
                               KAFKA_JVM_PERFORMANCE_OPTS="-server -XX:+UseG1GC -Djava.awt.headless=true")
            cluster_id = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")
            bin_path = prepared / PACKAGE / "bin"
            processes.run([bin_path / "kafka-storage.sh", "format", "-t", cluster_id, "-c", config],
                          "storage-format", 60, environment)
            broker = processes.start([bin_path / "kafka-server-start.sh", config], "broker", environment)
            report["broker_process_group"] = broker.pid
            report["broker_config_sha256"] = fixture.digest(config)
            helper_config = output / "kafka-helper.json"
            fixture.save(helper_config, {"bootstrap": "127.0.0.1:" + str(args.broker_port), "topic": name,
                                        "input": str(prepared / "rows.csv"), "output": str(output), "rows": args.rows,
                                        "workers": args.producer_workers, "batch_rows": args.batch_rows,
                                        "java_runtime": JAVA_RUNTIME, "timeout_seconds": 600})
            # AdminClient has a bounded 60s readiness/create deadline; no detached retry loop.
            def kafka(mode, timeout):
                if broker.poll() is not None:
                    raise RuntimeError("Owned Kafka broker exited")
                processes.run([java, "-Xmx256m", "-cp", classpath, "LicenseKafkaFixture", mode, helper_config],
                              "kafka-" + mode, timeout)
                return json.loads((output / ("kafka-" + mode + ".json")).read_text())
            initial = kafka("init", 90)
            if (initial.get("partitions") != PARTITIONS or initial.get("replication_factor") != 1
                    or initial.get("end_offsets_exclusive") != {str(p): 0 for p in range(PARTITIONS)}):
                raise ValueError("New Kafka topic is not the declared empty eight-partition fixture")
            sql = ProbeSql(args, state, java, classpath, processes)
            sql.execute(["CREATE DATABASE IF NOT EXISTS license_perf"])
            table_attempted = True
            sql.execute([f"CREATE TABLE license_perf.{name} (id BIGINT NOT NULL, grp INT NOT NULL, v BIGINT NOT NULL, "
                         "payload VARCHAR(128) NOT NULL) DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 8 "
                         "PROPERTIES ('replication_num'='1')"])
            ddl = routine_sql(name, name, args)
            (output / "routine-load.sql").write_text(ddl + ";\n")
            job_attempted = True
            sql.execute([ddl])
            report["producer"] = kafka("produce", 650)
            if report["producer"].get("acknowledged_rows") != args.rows:
                raise ValueError("Producer did not acknowledge every input row")
            kafka("verify", 180)
            report["kafka_oracle"] = verify_kafka(output, args.rows, args.producer_workers, args.batch_rows)
            polls, deadline = [], time.monotonic() + 300
            while True:
                checkpoint()
                if broker.poll() is not None:
                    raise RuntimeError("Owned Kafka broker exited during Routine Load")
                observations = sql.execute(["USE license_perf", f"SHOW ROUTINE LOAD FOR license_perf.{name}",
                                            f"SHOW ROUTINE LOAD TASK WHERE JobName='{name}'"])
                rows = observations[1]["rows"]
                if len(rows) != 1:
                    raise ValueError("Routine Load job missing or ambiguous")
                status = routine_progress(rows[0], args.rows)
                polls.append({"at_utc": fixture.utc(), "raw": rows[0], "derived": status,
                              "tasks_with_be_assignment": observations[2]})
                fixture.save(output / "routine-progress.json", polls)
                if status["complete"]:
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError("Routine Load did not commit the complete partition offsets in five minutes")
                time.sleep(1)
            report["routine_tasks"] = observations[2]
            report["visibility"] = fixture.assert_visibility(sql, name, fixture.expected(args.rows))
            _, final_identity = cluster_identity(args.cluster_record)
            if final_identity != identity:
                raise ValueError("FE/BE identity changed during the fixture")
            if any(fixture.digest(Path(path)) != digest for path, digest in frozen.items()) \
                    or {str(path): fixture.digest(path) for path in classes.rglob("*.class")} != compiled:
                raise ValueError("Fixture input or executed bytecode changed")
            if prepared_inventory(prepared) != prepared_report["distribution_files"]:
                raise ValueError("Broker distribution changed during the probe")
            report["status"] = "FUNCTIONAL_SUBSET_COMPLETE"
        except BaseException as error:
            original = error
            report.update(status="FAILED", error={"class": type(error).__name__, "message": str(error)})
        finally:
            # Attempt each cleanup independently, even if CREATE returned an ambiguous transport error.
            if sql is not None:
                cleanup_commands = []
                if job_attempted:
                    cleanup_commands.extend([f"STOP ROUTINE LOAD FOR license_perf.{name}",
                                             f"SHOW ALL ROUTINE LOAD FOR license_perf.{name}"])
                if table_attempted:
                    cleanup_commands.append(f"DROP TABLE IF EXISTS license_perf.{name}")
                for command in cleanup_commands:
                    try:
                        result = sql.execute([command], cleanup=True)[0]
                        clean = result.get("success") is True
                        if command.startswith("SHOW ALL"):
                            clean = clean and bool(result.get("rows")) and all(row["State"] == "STOPPED" for row in result["rows"])
                        report["cleanup"]["sql"].append({"sql": command, "clean": clean, "result": result})
                    except BaseException as error:
                        report["cleanup"]["sql"].append({"sql": command, "clean": False,
                                                       "error": type(error).__name__ + ": " + str(error)})
            report["cleanup"]["processes"] = processes.stop_all()
            report["cleanup"]["complete"] = (all(item["clean"] for item in report["cleanup"]["sql"])
                                                and all(item["clean"] for item in report["cleanup"]["processes"]))
            if not report["cleanup"]["complete"]:
                report["status"] = "FAILED"
            try:
                checkpoint()
            except lifecycle.CalibrationInterrupted as error:
                report.update(status="FAILED", interrupted_signal=error.number)
                original = original or error
            report["finished_at_utc"] = fixture.utc()
            fixture.save(output / "report.json", report)
    if original is not None or report["status"] != "FUNCTIONAL_SUBSET_COMPLETE":
        raise RuntimeError("Kafka fixture failed; inspect report.json and cleanup receipts") from original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "prepare", "probe"), default="plan")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", type=int, choices=ROWS, default=10000)
    parser.add_argument("--producer-workers", type=int, choices=(1, 8, 32), default=1)
    parser.add_argument("--consumer-tasks", type=int, choices=(1, 8), default=8)
    parser.add_argument("--batch-rows", type=int, choices=(1000, 10000), default=1000)
    parser.add_argument("--broker-port", type=int, default=39092)
    parser.add_argument("--controller-port", type=int, default=39093)
    archive = parser.add_mutually_exclusive_group()
    archive.add_argument("--archive", type=Path)
    archive.add_argument("--download", action="store_true")
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--cluster-record", type=Path)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_FIXTURE_PASSWORD")
    args = parser.parse_args()
    if args.mode == "prepare" and not (args.archive or args.download):
        parser.error("prepare requires --archive or the explicit --download option")
    if args.mode == "probe" and (not args.prepared or not args.cluster_record):
        parser.error("probe requires --prepared and --cluster-record")
    if not all(1024 <= port <= 65535 for port in (args.broker_port, args.controller_port)) \
            or args.broker_port == args.controller_port:
        parser.error("Use two distinct unprivileged private listener ports")
    output = fixture.owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    report = plan(args)
    fixture.save(output / "plan.json", report)
    try:
        if args.mode == "prepare":
            prepare(args, output, report)
        elif args.mode == "probe":
            probe(args, output, report)
    except BaseException as error:
        report["status"] = "FAILED"
        report.setdefault("error", {"class": type(error).__name__, "message": str(error)})
        raise
    finally:
        fixture.save(output / "report.json", report)
    print(json.dumps({"status": report["status"], "output": str(output),
                      "LP013_complete": False, "release_performance_pass": False}), flush=True)


if __name__ == "__main__":
    main()
