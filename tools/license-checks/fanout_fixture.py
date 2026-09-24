#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Plan/probe LP009: three full 10M-row tables and actual runtime profiles across four owned BEs."""

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid

import multinode_baseline_cluster as multinode
from stream_load_fixture import ROOT, digest, owned, save, utc


SOURCE = Path(__file__).resolve()
SQL_SOURCE = SOURCE.with_name("LicenseFanoutFixtureSql.java")
CANONICAL = ROOT / "docs/license-performance-cases-20260922.json"
ROWS = 10000000
BUCKETS = (64, 256, 1024)
INTEGRITY_RANGE_ROWS = 500000
PROFILE_LIMIT = 16 * 1024 * 1024
QUERY_ID = r"[0-9a-f]{1,16}-[0-9a-f]{1,16}"
SETTINGS = ["SET enable_sql_cache=false", "SET enable_query_cache=false",
            "SET enable_short_circuit_query=false", "SET query_timeout=600", "SET insert_timeout=600",
            "SET exec_mem_limit=536870912"]


class Cancelled(RuntimeError):
    """An explicit signal cancels work but still runs the bounded SQL cleanup."""


class Cancellation:
    def __enter__(self):
        self.requested = False
        self.previous = {value: signal.getsignal(value) for value in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        for value in self.previous:
            signal.signal(value, self.cancel)
        return self

    def cancel(self, signum, frame):
        if not self.requested:
            self.requested = True
            raise Cancelled("Fanout probe cancelled by signal " + str(signum))
        # Repeated TERM must not interrupt the bounded finally cleanup.

    def __exit__(self, kind, value, traceback):
        for signum, previous in self.previous.items():
            signal.signal(signum, previous)


def require(value, message):
    if not value:
        raise ValueError(message)


def floor_sum(n, modulus, coefficient, constant):
    """Sum floor((coefficient*k + constant)/modulus) for k in [0,n), using integer arithmetic."""
    total = 0
    while True:
        if coefficient >= modulus:
            total += (n - 1) * n * (coefficient // modulus) // 2
            coefficient %= modulus
        if constant >= modulus:
            total += n * (constant // modulus)
            constant %= modulus
        upper = coefficient * n + constant
        if upper < modulus:
            return total
        n, constant = divmod(upper, modulus)
        coefficient, modulus = modulus, coefficient


def expected_groups(rows=ROWS):
    result = []
    for group in range(min(rows, 1024)):
        count = (rows - 1 - group) // 1024 + 1
        total = count * group + 1024 * count * (count - 1) // 2
        total -= 100000 * floor_sum(count, 100000, 1024, group)
        result.append({"grp": group, "sum_v": total, "n": count})
    return result


def expected_integrity(rows=ROWS):
    def modulo_sum(divisor):
        cycles, remainder = divmod(rows, divisor)
        return cycles * divisor * (divisor - 1) // 2 + remainder * (remainder - 1) // 2
    return {"n": rows, "distinct_ids": rows, "min_id": 0, "max_id": rows - 1,
            "sum_id": rows * (rows - 1) // 2, "sum_grp": modulo_sum(1024),
            "sum_v": modulo_sum(100000), "bad_rows": 0}


def expected_integrity_range(lower, upper):
    require(0 <= lower < upper <= ROWS, "Invalid integrity range")
    high, low = expected_integrity(upper), expected_integrity(lower)
    return {key: (lower if key == "min_id" else upper - 1 if key == "max_id" else high[key] - low[key])
            for key in high}


def integer_rows(rows, fields):
    result = []
    for row in rows:
        require(set(row) == set(fields), "Unexpected result columns")
        require(all(isinstance(row[key], str) and re.fullmatch(r"-?\d+", row[key]) for key in fields),
                "Expected non-NULL exact integer result values")
        result.append({key: int(row[key]) for key in fields})
    return result


def check_groups(rows, expected):
    actual = integer_rows(rows, ("grp", "sum_v", "n"))
    require(len(actual) == 1024 and len({row["grp"] for row in actual}) == 1024,
            "Grouping is missing rows or contains duplicate groups")
    require(sorted(actual, key=lambda row: row["grp"]) == expected, "Full grouped result differs from Python model")
    return actual


def scan_counter(value):
    if re.fullmatch(r"\d+", value):
        return int(value)
    match = re.fullmatch(r"[0-9.]+[KMBT] \((\d+)\)", value)
    require(match, "Runtime counter lacks an exact integer value")
    return int(match.group(1))


def parse_profile(text, query_id, table, expected_ips, tablet_ids):
    """Read runtime detail only; EXPLAIN/merged plans cannot supply the scan evidence."""
    require(re.fullmatch(QUERY_ID, query_id), "Malformed query ID")
    require(re.search(r"(?m)^\s*- Profile ID: " + re.escape(query_id) + r"\s*$", text), "Wrong profile ID")
    require(re.search(r"(?m)^\s*- Task State: OK\s*$", text), "Query profile is not completed OK")
    require(re.search(r"(?m)^\s*- Is Cached: No\s*$", text), "Cached execution is not a fanout observation")
    statement = re.search(r"(?m)^\s*- Sql Statement: (.+)$", text)
    require(statement and re.search(r"\b" + re.escape(table) + r"\b", statement.group(1)),
            "Profile belongs to another table/query")
    instances = re.search(r"(?m)^\s*- Instances Num Per BE: (.+)$", text)
    require(instances, "Missing actual instance summary")
    instance_pairs = []
    for entry in instances.group(1).split(","):
        match = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+):28060:(\d+)", entry.strip())
        require(match, "Unexpected runtime instance address/count")
        instance_pairs.append((match.group(1), match.group(2)))
    require(len(instance_pairs) == 4 and {host for host, count in instance_pairs} == set(expected_ips)
            and all(int(count) > 0 for host, count in instance_pairs), "Instance summary does not cover four owned BEs")
    total = re.search(r"(?m)^\s*- Total Instances Num: (\d+)\s*$", text)
    require(total and int(total.group(1)) == sum(int(count) for host, count in instance_pairs),
            "Total instance count disagrees with per-BE runtime summary")
    marker = "DetailProfile(" + query_id + "):"
    require(text.count(marker) == 1, "Detailed runtime profile is absent or ambiguous")
    detail = text.split(marker, 1)[1]
    fragment = host = pipeline = task = None
    task_state = None
    scan = None
    scans = []
    fragment_hosts = set()
    for line in detail.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if scan is not None and stripped and indent <= scan["indent"]:
            scan = None
        match = re.fullmatch(r"Fragment (\d+):", stripped)
        if match:
            fragment, host, pipeline, task = int(match.group(1)), None, None, None
            task_state = None
            continue
        match = re.fullmatch(r"(FragmentLevelProfile:|Pipeline (\d+))"
                             r"\(host=TNetworkAddress\(hostname:(\d+\.\d+\.\d+\.\d+), port:(\d+)\)\):", stripped)
        if match:
            host, port = match.group(3), int(match.group(4))
            require(fragment is not None and host in expected_ips and port == 29050,
                    "Detailed profile contains an unowned or unbound BE")
            fragment_hosts.add((fragment, host))
            pipeline = int(match.group(2)) if match.group(2) is not None else None
            task, task_state = None, None
            continue
        match = re.fullmatch(r"PipelineTask\(index=(\d+)\):", stripped)
        if match:
            require(host is not None and pipeline is not None, "Runtime task has no BE/pipeline parent")
            task, task_state = int(match.group(1)), None
            continue
        if stripped.startswith("- TaskState: "):
            task_state = stripped.removeprefix("- TaskState: ")
        if stripped.startswith("OLAP_SCAN_OPERATOR("):
            require(host is not None and pipeline is not None and task is not None
                    and task_state == "FINALIZED", "Scan operator has no finalized runtime task")
            require(re.search(r"table_name=" + re.escape(table) + r"\(", stripped),
                    "Scan operator belongs to another table")
            scan = {"fragment": fragment, "be_ip": host, "heartbeat_port": 29050,
                    "pipeline": pipeline, "task_index": task, "task_state": task_state,
                    "operator": stripped, "indent": indent}
            scans.append(scan)
        elif scan is not None:
            match = re.fullmatch(r"- TabletIds: \[([0-9, ]+)\]", stripped)
            if match:
                require("tablet_ids" not in scan, "Duplicate tablet range field in one runtime scan")
                scan["tablet_ids"] = [int(value.strip()) for value in match.group(1).split(",")]
            elif stripped.startswith("- ScanRows: "):
                require("scan_rows" not in scan, "Ambiguous runtime scan row counter")
                scan["scan_rows"] = scan_counter(stripped.removeprefix("- ScanRows: "))
    require(scans, "No real OLAP runtime scan tasks")
    by_be = {host: {"tablet_ids": set(), "scan_rows": 0, "runtime_scan_tasks": 0} for host in expected_ips}
    seen_tasks = set()
    for scan in scans:
        identity = tuple(scan[key] for key in ("fragment", "be_ip", "pipeline", "task_index", "operator"))
        require(identity not in seen_tasks, "Duplicate runtime scan task")
        seen_tasks.add(identity)
        require(scan.get("tablet_ids") and "scan_rows" in scan, "Incomplete runtime tablet/scan row evidence")
        require(len(set(scan["tablet_ids"])) == len(scan["tablet_ids"]), "Duplicate tablet in one range list")
        value = by_be[scan["be_ip"]]
        value["tablet_ids"].update(scan["tablet_ids"])
        value["scan_rows"] += scan["scan_rows"]
        value["runtime_scan_tasks"] += 1
        scan.pop("indent")
    require(all(value["tablet_ids"] and value["scan_rows"] > 0 for value in by_be.values()),
            "Registered/assigned BEs without actual scanned rows cannot prove four-BE fanout")
    all_tablets = set().union(*(value["tablet_ids"] for value in by_be.values()))
    require(all_tablets == set(tablet_ids), "Runtime ranges do not cover exactly the actual table tablets")
    require(sum(len(value["tablet_ids"]) for value in by_be.values()) == len(all_tablets),
            "Replication-one tablets unexpectedly appear on more than one BE")
    for value in by_be.values():
        value["tablet_ids"] = sorted(value["tablet_ids"])
    return {"query_id": query_id, "instances_per_be_brpc_address": dict(instance_pairs),
            "total_instances": int(total.group(1)), "fragment_be_pairs": sorted(fragment_hosts),
            "runtime_task_identity": "fragment ordinal / heartbeat BE / pipeline / task index; not a fabricated UUID",
            "actual_scans": scans, "per_be": by_be, "actual_tablet_count": len(all_tablets)}


def query_sql(table):
    return f"SELECT grp,SUM(v) AS sum_v,COUNT(*) AS n FROM license_perf.{table} GROUP BY grp"


def integrity_sql(table, lower=None, upper=None):
    distinct = "" if lower is None else "COUNT(DISTINCT id) AS distinct_ids,"
    if lower is not None:
        require(0 <= lower < upper <= ROWS, "Invalid integrity SQL range")
    predicate = "" if lower is None else f" WHERE id>={lower} AND id<{upper}"
    return (f"SELECT COUNT(*) AS n,{distinct}MIN(id) AS min_id,MAX(id) AS max_id,"
            f"SUM(id) AS sum_id,SUM(grp) AS sum_grp,SUM(v) AS sum_v,"
            f"SUM(IF(id<0 OR id>={ROWS} OR grp<>id%1024 OR v<>id%100000 OR payload IS NULL "
            f"OR payload<>MD5(CAST(id AS STRING)),1,0)) AS bad_rows FROM license_perf.{table}{predicate}")


def variant_definitions(token, canonical):
    require(re.fullmatch(r"[0-9a-f]{16}", token), "Malformed fixture table ownership token")
    data = canonical["datasets"]["bench_fanout"]
    require(data["rows"] == ROWS and tuple(data["bucket_variants"]) == BUCKETS
            and data["schema_ref"] == "bench_small" and data["replication_num"] == 1,
            "Canonical fanout dataset changed; update the fixture explicitly")
    ddl = canonical["datasets"]["bench_small"]["setup_sql"][1]
    variants = []
    for buckets in BUCKETS:
        table = f"lp009_{token}_{buckets}"
        create = ddl.replace("license_perf.point_rows", "license_perf." + table).replace("BUCKETS 16", f"BUCKETS {buckets}")
        require(create.count(f"BUCKETS {buckets}") == 1, "Canonical DDL bucket replacement failed")
        variants.append({"buckets": buckets, "table": table, "create_sql": create,
                         "insert_sql": f"INSERT INTO license_perf.{table} SELECT number,CAST(number%1024 AS INT),"
                         f"number%100000,MD5(CAST(number AS STRING)) FROM numbers(\"number\"=\"{ROWS}\")",
                         "integrity_sql": integrity_sql(table), "group_sql": query_sql(table),
                         "integrity_ranges": [{"lower": lower, "upper": min(lower + INTEGRITY_RANGE_ROWS, ROWS),
                             "sql": integrity_sql(table, lower, min(lower + INTEGRITY_RANGE_ROWS, ROWS)),
                             "expected": expected_integrity_range(lower, min(lower + INTEGRITY_RANGE_ROWS, ROWS))}
                             for lower in range(0, ROWS, INTEGRITY_RANGE_ROWS)]})
    return variants


def make_plan(cluster_path, output):
    cluster_path = owned(cluster_path)
    cluster = multinode.validate_plan(multinode.read(cluster_path), cluster_path)
    canonical = json.loads(CANONICAL.read_text())
    output = owned(output)
    output.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex[:16]
    variants = variant_definitions(token, canonical)
    plan = {"schema": 1, "case_id": "LP-009", "case_status": "not_run", "status": "PLANNED",
            "scope": "Same-host isolated 3FE/4BE functional prerequisite, not multi-host or performance acceptance",
            "output": str(output), "token": token, "cluster_plan": str(cluster_path),
            "cluster_plan_sha256": digest(cluster_path), "canonical_sha256": digest(CANONICAL),
            "rows_per_variant": ROWS, "bucket_variants": list(BUCKETS), "settings": SETTINGS,
            "expected_groups": expected_groups(), "expected_integrity": expected_integrity(),
            "variants": variants, "expected_be_ips": [node["ip"] for node in cluster["nodes"][3:]],
            "started_services": 0, "network_requests": 0,
            "source_sha256": {str(path): digest(path) for path in (SOURCE, SQL_SOURCE, multinode.SOURCE)}}
    save(output / "plan.json", plan)
    return plan


class ClusterGuard:
    def __init__(self, plan):
        path = owned(plan["cluster_plan"])
        require(digest(path) == plan["cluster_plan_sha256"], "Cluster plan changed")
        self.plan = multinode.validate_plan(multinode.read(path), path)
        state = multinode.read(Path(self.plan["workdir"]) / "cluster.json")
        require(state.get("status") == "MEMBERSHIP_READY" and state["plan_sha256"] == digest(path),
                "The true seven-node topology is not ready for this frozen plan")
        self.supervisor = state["supervisor"]
        require(self.supervisor["kind"] == "supervisor" and self.supervisor["installation"] == str(path)
                and self.supervisor["namespace"] == state["namespace"]
                and state["namespace"] != self.plan["host_namespace"], "Unowned outer supervisor")
        self.nodes = {}
        for node in self.plan["nodes"]:
            record = multinode.validate_node_record(self.plan, node, multinode.read(node["state_path"]))
            require(record["status"] == "SERVICE_STARTED" and record.get("service"), "Node service is not live")
            require(record["keeper"] == state["nodes"][node["name"]]["keeper"], "Keeper changed after membership")
            require(record["namespace"] != state["namespace"], "Node shares the outer namespace")
            self.nodes[node["name"]] = record
        require(len({record["namespace"] for record in self.nodes.values()}) == 7,
                "Seven nodes must have distinct private namespaces")
        self.check()

    def check(self):
        require(os.readlink("/proc/self/ns/net") == self.nodes["fe1"]["namespace"],
                "Run probe inside the owned fe1 keeper namespace")
        require(multinode.same_process(self.supervisor), "Outer supervisor exited")
        for record in self.nodes.values():
            require(multinode.same_process(record["keeper"]) and multinode.same_process(record["service"]),
                    "A frozen node keeper/service identity is no longer live")


class Sql:
    def __init__(self, args, guard, output, deadline):
        self.args, self.guard, self.output, self.deadline = args, guard, output, deadline
        self.sequence = 0
        dependencies = []
        lib = Path(guard.plan["package"]) / "fe/lib"
        for prefix in ("mariadb-java-client", "jackson-core", "jackson-databind", "jackson-annotations"):
            matches = list(lib.glob(prefix + "-*.jar"))
            require(len(matches) == 1, "Ambiguous installed JDBC dependency")
            dependencies.append(matches[0])
        self.classpath = os.pathsep.join(map(str, [output, *dependencies]))
        self.java = Path(guard.plan["java_home"]) / "bin/java"
        result = subprocess.run([str(self.java.with_name("javac")), "--release", "8", "-encoding", "UTF-8",
                                 "-cp", self.classpath, "-d", str(output), str(SQL_SOURCE)],
                                capture_output=True, text=True, timeout=60)
        (output / "compile.log").write_text(result.stdout + result.stderr)
        require(result.returncode == 0, "Fanout helper compilation failed")
        save(output / "dependencies.json", {str(path): digest(path) for path in dependencies})

    def execute(self, statements, cleanup=False):
        self.guard.check()
        remaining = int(self.deadline - time.monotonic())
        timeout = 60 if cleanup else min(600, remaining - 15)
        require(timeout > 0, "Fanout probe whole-run deadline exceeded")
        self.sequence += 1
        path = self.output / f"sql-{self.sequence:03d}.json"
        save(path, {"query_port": 29030, "user": self.args.user, "password_env": self.args.password_env,
                    "timeout_seconds": timeout, "sql": statements})
        try:
            result = subprocess.run([str(self.java), "-Xmx256m", "-cp", self.classpath,
                                     "LicenseFanoutFixtureSql", str(path)], capture_output=True, text=True,
                                    timeout=timeout + 15)
        except BaseException as error:
            save(path.with_suffix(".result.json"), {"success": False, "error_class": type(error).__name__,
                 "structured_sql_result_available": False})
            raise
        try:
            body = json.loads(result.stdout)
        except ValueError:
            save(path.with_suffix(".result.json"), {"success": False, "exit_code": result.returncode,
                 "error": "Fanout helper returned no structured report"})
            raise RuntimeError("Fanout helper returned no structured report") from None
        save(path.with_suffix(".result.json"), body)
        require(result.returncode == 0 and body.get("success") is True, "Original SQL failed; errno/state preserved")
        require(len(body["statements"]) == len(statements), "Incomplete SQL statement sequence")
        self.guard.check()
        return body["statements"]


def profile_request(args, query_id):
    require(re.fullmatch(QUERY_ID, query_id), "Malformed profile query ID")
    connection = http.client.HTTPConnection("127.0.0.1", 28030, timeout=10)
    credentials = (args.user + ":" + os.environ.get(args.password_env, "")).encode()
    started = time.monotonic()
    try:
        connection.request("GET", "/api/profile/text?query_id=" + query_id,
                           headers={"Authorization": "Basic " + base64.b64encode(credentials).decode()})
        response = connection.getresponse()
        require(response.status == 200, "Profile endpoint must return HTTP 200 without redirects")
        sock = connection.sock or response.fp.raw._sock
        data = bytearray()
        while True:
            remaining = 20 - (time.monotonic() - started)
            require(remaining > 0, "Profile response deadline exceeded")
            sock.settimeout(min(10, remaining))
            chunk = response.read1(min(65536, PROFILE_LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            require(len(data) <= PROFILE_LIMIT, "Profile exceeds archive bound; cannot claim complete evidence")
        return data.decode("utf-8")
    finally:
        connection.close()


def probe(args):
    plan_path = owned(args.plan)
    plan = json.loads(plan_path.read_text())
    output = owned(plan["output"])
    require(plan_path == output / "plan.json" and plan["rows_per_variant"] == ROWS
            and tuple(plan["bucket_variants"]) == BUCKETS, "Frozen fixture plan shape changed")
    require(digest(CANONICAL) == plan["canonical_sha256"], "Canonical specification changed after fixture planning")
    for name, expected in plan["source_sha256"].items():
        require(digest(name) == expected, "Fixture/ownership implementation changed after planning")
    require(plan["expected_groups"] == expected_groups() and plan["expected_integrity"] == expected_integrity(),
            "Frozen model changed")
    require(plan["variants"] == variant_definitions(plan["token"], json.loads(CANONICAL.read_text()))
            and plan["settings"] == SETTINGS, "Frozen SQL no longer matches the exact authorized fixture")
    require(not (output / "report.json").exists(), "Probe is single use; preserve earlier evidence")
    guard = ClusterGuard(plan)
    require(plan["expected_be_ips"] == [node["ip"] for node in guard.plan["nodes"][3:]],
            "Fixture BE address set differs from the real topology plan")
    multinode.check_bindings(guard.plan)
    report = {"case_id": "LP-009", "case_status": "not_run", "status": "FAIL", "scope": plan["scope"],
              "started_at_utc": utc(), "fixture_plan_sha256": digest(plan_path), "variants": [],
              "performance_pass_proven": False, "same_host_only": True, "license_enforcement_present": False,
              "owned_node_pins": guard.nodes, "cpu_affinity": sorted(os.sched_getaffinity(0))}
    save(output / "report.json", report)
    deadline = time.monotonic() + 3600
    try:
        sql = Sql(args, guard, output, deadline)
        membership = sql.execute(["SHOW FRONTENDS", "SHOW BACKENDS"])
        multinode.check_membership(membership[0]["rows"], membership[1]["rows"], guard.plan["nodes"],
                                   connected_ip=guard.plan["nodes"][0]["ip"])
        backend_hosts = {int(row["BackendId"]): row["Host"] for row in membership[1]["rows"]}
        sql.execute(["CREATE DATABASE IF NOT EXISTS license_perf"])
        for variant in plan["variants"]:
            table, buckets = variant["table"], variant["buckets"]
            require(table == f"lp009_{plan['token']}_{buckets}" and re.fullmatch(r"lp009_[0-9a-f]{16}_(64|256|1024)", table),
                    "Refuse an unowned temporary table name")
            item = {"table": table, "buckets": buckets, "status": "FAIL", "cleanup_confirmed": False}
            report["variants"].append(item)
            started_create = False
            try:
                existing = sql.execute([f"SHOW TABLES FROM license_perf LIKE '{table}'"])[0]["rows"]
                require(not existing, "Generated temporary table name already exists; do not touch it")
                started_create = True
                sql.execute([variant["create_sql"]])
                item["ddl"] = sql.execute([f"SHOW CREATE TABLE license_perf.{table}"])[0]
                sql.execute(SETTINGS + [variant["insert_sql"]])
                actual = sql.execute(SETTINGS + [variant["integrity_sql"]])[-1]["rows"]
                full_expected = {key: value for key, value in plan["expected_integrity"].items() if key != "distinct_ids"}
                require(integer_rows(actual, full_expected) == [full_expected],
                        "Ten-million-row ID/value/payload integrity oracle failed")
                item["integrity"] = actual
                item["integrity_ranges"] = []
                for interval in variant["integrity_ranges"]:
                    rows = sql.execute(SETTINGS + [interval["sql"]])[-1]["rows"]
                    require(integer_rows(rows, interval["expected"]) == [interval["expected"]],
                            "Full-coverage range ID uniqueness/value/payload oracle failed")
                    item["integrity_ranges"].append({"lower": interval["lower"], "upper": interval["upper"],
                                                     "actual": rows})
                item["verified_distinct_ids"] = sum(int(entry["actual"][0]["distinct_ids"])
                                                    for entry in item["integrity_ranges"])
                require(item["verified_distinct_ids"] == ROWS, "Range uniqueness did not cover all ten million IDs")
                metadata = sql.execute([f"SHOW TABLETS FROM license_perf.{table}"])[0]["rows"]
                tablet_ids = [int(row["TabletId"]) for row in metadata]
                require(len(tablet_ids) == buckets and len(set(tablet_ids)) == buckets,
                        "Actual replication-one tablet count differs from the bucket variant")
                placement = {str(identifier): backend_hosts[int(row["BackendId"])]
                             for identifier, row in zip(tablet_ids, metadata)}
                item["metadata_tablet_placement"] = placement
                result = sql.execute(SETTINGS + ["SET enable_profile=true", "SET profile_level=3",
                                                 variant["group_sql"], "SELECT LAST_QUERY_ID() AS query_id"])
                item["groups"] = check_groups(result[-2]["rows"], plan["expected_groups"])
                qrows = result[-1]["rows"]
                require(len(qrows) == 1 and set(qrows[0]) == {"query_id"}, "Missing same-session query ID")
                query_id = qrows[0]["query_id"]
                item["query_id"] = query_id
                profile_deadline = min(deadline, time.monotonic() + 90)
                for attempt in range(10):
                    require(time.monotonic() < profile_deadline, "Profile completion deadline exceeded")
                    guard.check()
                    text = profile_request(args, query_id)
                    name = f"profile-{buckets}-{attempt:02d}.txt"
                    (output / name).write_text(text)
                    try:
                        proof = parse_profile(text, query_id, table, plan["expected_be_ips"], tablet_ids)
                        for host, distribution in proof["per_be"].items():
                            require(all(placement[str(identifier)] == host for identifier in distribution["tablet_ids"]),
                                    "Runtime tablet BE differs from real metadata placement")
                        item["runtime_profile"] = {"path": name, "sha256": digest(output / name), "proof": proof}
                        break
                    except ValueError as error:
                        item["last_profile_validation_error"] = str(error)
                        if attempt == 9:
                            raise
                        time.sleep(.5)
                require("runtime_profile" in item, "No complete actual four-BE profile")
                item["status"] = "FUNCTIONAL_PASS"
            except BaseException as error:
                item["error_class"] = type(error).__name__
                raise
            finally:
                if started_create:
                    try:
                        sql.execute([f"DROP TABLE IF EXISTS license_perf.{table}"], cleanup=True)
                        after = sql.execute([f"SHOW TABLES FROM license_perf LIKE '{table}'"], cleanup=True)[0]["rows"]
                        item["cleanup_confirmed"] = not after
                    except Exception as error:
                        item["cleanup_error_class"] = type(error).__name__
                save(output / "report.json", report)
            require(item["cleanup_confirmed"], "Temporary table cleanup not confirmed")
        require(len(report["variants"]) == 3 and all(item["status"] == "FUNCTIONAL_PASS"
                and item["cleanup_confirmed"] for item in report["variants"]), "Incomplete fanout matrix")
        guard.check()
        report["status"] = "FIXTURE_PASS"
    except BaseException as error:
        report["error_class"] = type(error).__name__
        raise
    finally:
        report["finished_at_utc"] = utc()
        save(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "probe"), default="plan")
    parser.add_argument("--cluster-plan", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_FANOUT_PASSWORD")
    args = parser.parse_args()
    if args.mode == "plan":
        require(args.cluster_plan and args.output and not args.plan, "Plan needs cluster-plan and new output")
        result = make_plan(args.cluster_plan, args.output)
        print(json.dumps({"status": result["status"], "started_services": 0, "network_requests": 0,
                          "rows_per_variant": ROWS, "buckets": BUCKETS, "plan": result["output"] + "/plan.json"}))
    else:
        require(args.plan and not args.cluster_plan and not args.output, "Probe uses only an existing fixture plan")
        with Cancellation():
            result = probe(args)
        print(json.dumps({"status": result["status"], "case_status": "not_run", "performance_pass": False}))


if __name__ == "__main__":
    main()
