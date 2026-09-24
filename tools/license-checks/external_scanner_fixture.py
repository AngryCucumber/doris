#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""LP011 original FE plan plus BE scanner, with one plan and four complete independent reads."""

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import time

from resource_observer import check_identity, freeze_cluster
from stream_load_fixture import ROOT, digest, owned, save, utc


SQL = "SELECT id,payload FROM license_perf.point_rows"
PLAN_PATH = "/api/license_perf/point_rows/_query_plan"
ROWS = 1000000
TABLETS = 16
MAX_BODY = 2 * 1024 * 1024
BATCH_SIZES = (1024, 8192)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def be_scan_port(installation):
    text = (Path(installation) / "be/conf/be.conf").read_text()
    values = re.findall(r"(?m)^\s*be_port\s*=\s*(\d+)\s*(?:#.*)?$", text)
    require(len(values) == 1 and 0 < int(values[0]) < 65536, "Expected one explicit owned BE Thrift port")
    return int(values[0])


def model_digest(rows=ROWS):
    checksum = hashlib.sha256()
    for identifier in range(rows):
        payload = hashlib.md5(str(identifier).encode("ascii"), usedforsecurity=False).hexdigest()
        checksum.update(f"{identifier},{payload}\n".encode("ascii"))
    return checksum.hexdigest()


def parse_plan(http_status, body, be_port):
    require(http_status == 200 and isinstance(body, dict), "FE plan HTTP status or object mismatch")
    require(type(body.get("code")) is int and body["code"] == 0, "FE plan business status is not success")
    data = body.get("data")
    require(isinstance(data, dict) and type(data.get("status")) is int and data["status"] == 200,
            "FE plan data status is not success")
    plan = data.get("opaqued_query_plan")
    require(isinstance(plan, str) and 0 < len(plan) <= MAX_BODY, "Opaque plan is absent or oversized")
    try:
        decoded = base64.b64decode(plan, validate=True)
    except (ValueError, UnicodeError):
        raise ValueError("Opaque plan is not valid base64") from None
    require(bool(decoded), "Opaque plan is empty")
    partitions = data.get("partitions")
    require(isinstance(partitions, dict) and len(partitions) == TABLETS, "Expected exactly 16 scan tablets")
    tablets = []
    seen = set()
    for name, partition in partitions.items():
        require(isinstance(name, str) and re.fullmatch(r"[1-9][0-9]*", name), "Invalid tablet identifier")
        identifier = int(name)
        require(identifier < 2**63 and identifier not in seen, "Duplicate or oversized tablet identifier")
        seen.add(identifier)
        require(isinstance(partition, dict), "Invalid tablet metadata")
        routes = partition.get("routings")
        require(routes == [f"127.0.0.1:{be_port}"], "Tablet route is outside the one owned BE")
        tablets.append({"tablet_id": identifier, "host": "127.0.0.1", "port": be_port})
    return {"opaque_plan": plan, "plan_sha256": hashlib.sha256(plan.encode("ascii")).hexdigest(),
            "plan_bytes": len(plan), "tablets": sorted(tablets, key=lambda item: item["tablet_id"])}


def request_plan(port, user, password_env, record):
    # HTTPConnection does not consult proxy environment variables and does not follow redirects.
    secret = os.environ.get(password_env, "")
    token = base64.b64encode((user + ":" + secret).encode()).decode()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    started = time.monotonic()
    record["request_count"] = 1
    record["method"] = "POST"
    record["path"] = PLAN_PATH
    record["started_at_utc"] = utc()
    record["sql_sha256"] = hashlib.sha256(SQL.encode()).hexdigest()
    record["transport"] = "direct owned loopback HTTP; no proxy, no redirect, no retry"
    try:
        connection.request("POST", PLAN_PATH, body=json.dumps({"sql": SQL}).encode(),
                           headers={"Authorization": "Basic " + token, "Content-Type": "application/json"})
        response = connection.getresponse()
        record["http_status"] = response.status
        require(response.status == 200, "FE plan HTTP response was not 200")
        sock = connection.sock
        if sock is None and response.fp is not None:
            sock = response.fp.raw._sock
        require(sock is not None, "Cannot bound plan response read deadline")
        chunks = bytearray()
        while True:
            remaining = 15 - (time.monotonic() - started)
            require(remaining > 0, "FE plan response deadline exceeded")
            sock.settimeout(min(5, remaining))
            chunk = response.read1(min(65536, MAX_BODY + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            require(len(chunks) <= MAX_BODY, "FE plan response exceeded body bound")
        record["response_bytes"] = len(chunks)
        # Never archive the response body, authorization, cookies, or exception text.
        return response.status, json.loads(chunks)
    finally:
        connection.close()
        record["elapsed_nanos"] = int((time.monotonic() - started) * 1000000000)
        record["finished_at_utc"] = utc()


def save_private(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    require(Path(path).stat().st_mode & 0o777 == 0o600, "Private plan file permissions differ from 0600")


def check_report(report, plan_hash, expected_digest, expected_tablet_ids):
    require(report.get("status") == "FIXTURE_PASS", "Scanner helper did not pass")
    runs = report.get("runs", [])
    require([(run.get("batch_size"), run.get("attempt")) for run in runs]
            == [(batch, attempt) for batch in BATCH_SIZES for attempt in (0, 1)], "Incomplete scanner matrix")
    context_hashes = set()
    for run in runs:
        require(run.get("status") == "READ_PASS" and run.get("plan_sha256") == plan_hash,
                "Failed run or changed plan")
        require(run.get("rows_verified") == ROWS, "Incomplete verified row count")
        actual = run.get("complete_unordered_set", {})
        require(actual == {"rows": ROWS, "distinct_ids": ROWS, "min_id": 0, "max_id": ROWS - 1,
                           "sum_id": ROWS * (ROWS - 1) // 2, "sha256_sorted_actual_rows": expected_digest},
                "Incomplete or incorrect full unordered data model")
        tablets = run.get("tablets", [])
        identifiers = [step.get("tablet_id") for step in tablets]
        require(len(identifiers) == TABLETS and len(set(identifiers)) == TABLETS, "Tablet set is incomplete")
        require(identifiers == expected_tablet_ids, "Plan tablet list differs from the FE response")
        total = 0
        for step in tablets:
            require(step.get("open_status") == step.get("close_status") == "OK"
                    and step.get("closed") is True and step.get("close_attempted") is True,
                    "Open or cleanup was not confirmed")
            context = step.get("context_id_sha256")
            require(isinstance(context, str) and re.fullmatch(r"[0-9a-f]{64}", context)
                    and context not in context_hashes, "Missing or reused context identity")
            context_hashes.add(context)
            batches = step.get("batches", [])
            require(1 <= len(batches) <= 4096, "Missing or excessive scanner batches")
            offset = 0
            for index, batch in enumerate(batches):
                require(batch.get("status") == "OK" and batch.get("request_offset") == offset,
                        "Batch status or offset progression mismatch")
                rows = batch.get("rows")
                require(type(rows) is int, "Missing integer batch row count")
                require(batch.get("eos") is (index == len(batches) - 1), "EOS must appear exactly at the end")
                if batch["eos"]:
                    require(rows == 0, "EOS contains unconsumed rows")
                else:
                    require(0 < rows <= run["batch_size"] and batch.get("arrow_rows") == rows,
                            "Actual batch rows exceed the declared scanner contract")
                    require(0 < batch.get("arrow_ipc_bytes", 0) <= 16 * 1024 * 1024, "IPC byte bound exceeded")
                offset += rows
                require(batch.get("next_offset") == offset, "Incorrect returned offset ledger")
            require(step.get("rows") == offset and step.get("eos") is True, "Tablet was not completely consumed")
            total += offset
        require(total == ROWS, "Rows across tablets do not cover the complete model")
    require(len(context_hashes) == report.get("unique_context_count") == 4 * TABLETS,
            "Scanner opens were not independent")


def assert_pins(state, pins):
    require(os.readlink("/proc/self/ns/net") == state["namespace"], "Fixture namespace changed")
    for pin in pins.values():
        check_identity(pin, state["namespace"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_BASELINE_PASSWORD")
    args = parser.parse_args()
    state, pins = freeze_cluster(args.cluster_record)
    be_port = be_scan_port(state["installation"])
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    report = {"case_id": "LP-011", "case_status": "not_run", "status": "FAIL", "started_at_utc": utc(),
              "scope": "Original A external scanner data/plan reuse; not license or performance acceptance",
              "cross_expiry_enforcement_proven": False, "performance_pass_proven": False,
              "cluster_record_sha256": digest(args.cluster_record), "namespace": state["namespace"],
              "service_pins": pins, "cpu_affinity": sorted(os.sched_getaffinity(0)),
              "java_home": state["java_home"], "fe_jar_sha256": state["fe_jar_sha256"],
              "be_binary_sha256": state["be_binary_sha256"], "be_code_or_protocol_modified": False,
              "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in (
                  Path(__file__).resolve(), ROOT / "tools/license-checks/LicenseExternalScannerFixture.java",
                  ROOT / "tools/license-checks/resource_observer.py",
                  ROOT / "tools/license-checks/stream_load_fixture.py")}}
    try:
        expected = model_digest()
        report["independent_python_model"] = {"rows": ROWS, "sha256_sorted_rows": expected,
                                               "encoding": "ASCII id, comma, MD5(decimal id), LF in ascending id order"}
        jars = sorted((Path(state["package"]) / "fe/lib").glob("*.jar"))
        require(bool(jars), "No installed dependencies found")
        report["dependencies"] = {str(path): digest(path) for path in jars}
        classpath = os.pathsep.join(map(str, [output, *jars]))
        java = Path(state["java_home"]) / "bin/java"
        compile_result = subprocess.run([str(java.with_name("javac")), "--release", "17", "-encoding", "UTF-8",
                                         "-cp", classpath, "-d", str(output),
                                         str(ROOT / "tools/license-checks/LicenseExternalScannerFixture.java")],
                                        capture_output=True, text=True, timeout=90)
        (output / "compile.log").write_text(compile_result.stdout + compile_result.stderr)
        require(compile_result.returncode == 0, "Scanner helper compilation failed")
        self_test = subprocess.run([str(java), "-Xmx128m", "-cp", classpath,
                                    "LicenseExternalScannerFixture", "--self-test",
                                    str(output / "java-offline-tests.json")],
                                   capture_output=True, text=True, timeout=30)
        (output / "java-offline-tests.log").write_text(self_test.stdout + self_test.stderr)
        require(self_test.returncode == 0, "Scanner Java offline oracle tests failed")
        report["java_offline_tests"] = json.loads((output / "java-offline-tests.json").read_text())
        require(report["java_offline_tests"].get("status") == "SELF_TEST_PASS"
                and report["java_offline_tests"].get("count") == 10, "Scanner offline tests incomplete")
        assert_pins(state, pins)
        plan_record = report["fe_plan"] = {}
        http_status, body = request_plan(state["http_port"], args.user, args.password_env, plan_record)
        plan = parse_plan(http_status, body, be_port)
        report["plan"] = {key: value for key, value in plan.items() if key != "opaque_plan"}
        config = {**plan, "be_port": be_port, "user": args.user, "password_env": args.password_env,
                  "namespace": state["namespace"], "host_namespace": state["host_namespace"],
                  "service_pins": list(pins.values()), "expected_sha256": expected}
        save_private(output / "scanner-config.private.json", config)
        report["private_plan_file"] = {"path": "scanner-config.private.json", "mode": "0600",
                                        "contains_password": False, "opaque_plan_must_not_be_published": True}
        assert_pins(state, pins)
        with (output / "client.log").open("w") as log:
            process = subprocess.Popen([str(java), "-Xms128m", "-Xmx256m", "-XX:MaxDirectMemorySize=256m",
                                        "--add-opens=java.base/java.nio=ALL-UNNAMED", "-cp", classpath,
                                        "LicenseExternalScannerFixture", str(output / "scanner-config.private.json"),
                                        str(output / "scanner-result.json")], stdout=log, stderr=log)
            try:
                process.wait(timeout=340)
            except BaseException:
                process.terminate()  # Permit the bounded shutdown hook to close a received context.
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                raise
        report["helper_exit_code"] = process.returncode
        if (output / "scanner-result.json").exists():
            report["scanner_result"] = json.loads((output / "scanner-result.json").read_text())
        require(process.returncode == 0, "Scanner helper failed; partial run/cleanup evidence preserved")
        check_report(report["scanner_result"], plan["plan_sha256"], expected,
                     [tablet["tablet_id"] for tablet in plan["tablets"]])
        assert_pins(state, pins)
        report["status"] = "FIXTURE_PASS"
    except BaseException as error:
        report["error_class"] = type(error).__name__
        raise
    finally:
        if "scanner_result" not in report and (output / "scanner-result.json").exists():
            report["scanner_result"] = json.loads((output / "scanner-result.json").read_text())
        report["finished_at_utc"] = utc()
        save(output / "report.json", report)
    print(json.dumps({"status": report["status"], "plan_requests": 1, "full_reads": 4,
                      "rows_verified": 4 * ROWS, "report": str(output / "report.json")}))


if __name__ == "__main__":
    main()
