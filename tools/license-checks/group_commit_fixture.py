#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Build and run the LP014 original-release Group Commit fixture inside an owned private cluster."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from stream_load_fixture import ROOT, ROW_BYTES, SEED, digest, expected, owned, record, save, utc, validate_cluster


BATCH_ROWS = (1, 100, 1000, 10000)
FULL_PREPARE = (True, False)
REPETITIONS = 2
TOTAL_ROWS = sum(BATCH_ROWS) * len(FULL_PREPARE) * REPETITIONS
DRIVER_NAME = "mysql-connector-j-8.0.33.jar"


def interval_model(start, count):
    end = start + count
    before, after = expected(start), expected(end)
    return {"n": count, "distinct_ids": count, "min_id": start, "max_id": end - 1,
            "sum_id": after["sum_id"] - before["sum_id"],
            "sum_grp": after["sum_grp"] - before["sum_grp"],
            "sum_v": after["sum_v"] - before["sum_v"], "bad_rows": 0}


def generate_inputs(output):
    started_at, started = utc(), time.perf_counter_ns()
    full_hash, cases, next_id = hashlib.sha256(), [], 0
    input_path = output / "input.csv"
    with input_path.open("xb") as stream:
        for full_prepare in FULL_PREPARE:
            for batch in BATCH_ROWS:
                for repeat in range(REPETITIONS):
                    checksum = hashlib.sha256()
                    for identifier in range(next_id, next_id + batch):
                        value = record(identifier)
                        stream.write(value)
                        checksum.update(value)
                        full_hash.update(value)
                    cases.append({"full_prepare": full_prepare, "batch_rows": batch, "repeat": repeat,
                                  "id_start": next_id, "input_bytes": batch * ROW_BYTES,
                                  "input_sha256": checksum.hexdigest(), "model": interval_model(next_id, batch)})
                    next_id += batch
    manifest = {"seed": SEED, "rows": TOTAL_ROWS, "full_ingest_fixture_target_rows": 10000000,
                "full_target_ingested": False, "row_bytes_including_lf": ROW_BYTES,
                "batch_rows": list(BATCH_ROWS), "full_prepare": list(FULL_PREPARE), "repetitions": REPETITIONS,
                "input_path": str(input_path), "input_sha256": full_hash.hexdigest(),
                "input_bytes": input_path.stat().st_size, "model": expected(TOTAL_ROWS), "cases": cases,
                "started_at_utc": started_at, "finished_at_utc": utc(),
                "generation_elapsed_nanos": time.perf_counter_ns() - started,
                "generation_excluded_from_request_timing": True,
                "generator_source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in (
                    Path(__file__), ROOT / "tools/license-checks/stream_load_fixture.py")}}
    if next_id != TOTAL_ROWS or input_path.stat().st_size != TOTAL_ROWS * ROW_BYTES:
        raise ValueError("Group Commit input violated the frozen batch/width model")
    save(output / "input.json", manifest)
    return manifest


def run(args):
    state, _ = validate_cluster(args.cluster_record)
    driver = args.driver.resolve()
    if driver.name != DRIVER_NAME or not driver.is_file():
        raise ValueError("Use the existing frozen MySQL Connector/J 8.0.33 JAR; the tool never downloads dependencies")
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    manifest = generate_inputs(output)
    source = ROOT / "tools/license-checks/LicenseGroupCommitFixture.java"
    dependencies = [driver]
    for name in ("jackson-core", "jackson-databind", "jackson-annotations"):
        matches = list((Path(state["package"]) / "fe/lib").glob(name + "-*.jar"))
        if len(matches) != 1:
            raise ValueError("Expected one packaged Jackson dependency: " + name)
        dependencies.append(matches[0])
    table = "gc_fixture_" + uuid.uuid4().hex[:12]
    config = {"query_port": state["query_port"], "namespace": state["namespace"],
              "host_namespace": state["host_namespace"], "user": args.user, "password_env": args.password_env,
              "table": table, "input_manifest": manifest, "report_path": str(output / "jdbc-result.json"),
              "poll_interval_ms": 100, "visibility_timeout_ms": 60000,
              "group_commit_interval_ms": 1000, "group_commit_data_bytes": 134217728}
    config_path = output / "jdbc-config.json"
    save(config_path, config)
    java = Path(state["java_home"]) / "bin/java"
    classpath = os.pathsep.join(map(str, [output, *dependencies]))
    report = {"case_id": "LP-014", "status": "RUNNING", "started_at_utc": utc(),
              "scope": "Original A Group Commit correctness/reachability; no license-state or performance qualification",
              "cluster_record_sha256": digest(args.cluster_record), "fe_jar_sha256": state["fe_jar_sha256"],
              "be_binary_sha256": state["be_binary_sha256"], "namespace": state["namespace"],
              "java_home": state["java_home"], "table": "license_perf." + table, "input_manifest": manifest,
              "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in (
                  Path(__file__), source, ROOT / "tools/license-checks/stream_load_fixture.py")},
              "dependencies": {str(path): digest(path) for path in dependencies}, "credentials_recorded": False}
    save(output / "report.json", report)
    try:
        build = subprocess.run([str(java.with_name("javac")), "--release", "8", "-encoding", "UTF-8",
                                "-cp", classpath, "-d", str(output), str(source)],
                               capture_output=True, text=True, timeout=60)
        save(output / "helper-build.json", {"exit_code": build.returncode, "stdout": build.stdout,
                                           "stderr": build.stderr, "source_sha256": digest(source)})
        if build.returncode:
            raise RuntimeError("Group Commit fixture helper compilation failed")
        result = subprocess.run([str(java), "-Xmx512m", "-cp", classpath, "LicenseGroupCommitFixture", str(config_path)],
                                capture_output=True, text=True, timeout=1200)
        # Connection exceptions can carry properties; the helper writes only structured safe failures.
        report["helper_exit_code"] = result.returncode
        if not (output / "jdbc-result.json").is_file():
            raise RuntimeError("Group Commit helper did not return its structured report")
        jdbc = json.loads((output / "jdbc-result.json").read_text())
        report["jdbc_result"] = jdbc
        if result.returncode or jdbc.get("status") != "FIXTURE_PASS" or not jdbc.get("table_removed"):
            raise RuntimeError("Group Commit fixture failed or cleanup was not confirmed; inspect jdbc-result.json")
        if len(jdbc["batches"]) != len(manifest["cases"]):
            raise RuntimeError("Group Commit fixture did not execute every frozen batch and repetition")
        report["status"] = "FIXTURE_PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["failure"] = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
        raise
    finally:
        report["finished_at_utc"] = utc()
        save(output / "report.json", report)
    print(json.dumps({"status": report["status"], "report": str(output / "report.json")}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_BASELINE_PASSWORD")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
