#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""LP015 original-A DML and explicit transaction fixture; no production code or global configuration changes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

from stream_load_fixture import ROOT, digest, owned, save, utc, validate_cluster


DRIVER_NAME = "mysql-connector-j-8.0.33.jar"
MIX_ERROR = "Transaction insert can not insert into values and insert into select at the same time"
QUERY_ERROR = "This is in a transaction, only insert, update, delete, commit, rollback is acceptable."


def rows(start, end, updated=False):
    return [[identifier, identifier % 1024, identifier % 100000 + (1000000 if updated else 0),
             ("u_" if updated else "") + hashlib.md5(str(identifier).encode(), usedforsecurity=False).hexdigest()]
            for identifier in range(start, end)]


def model(values):
    values = sorted(values)
    data = "".join(",".join(map(str, row)) + "\n" for row in values).encode("ascii")
    return {"rows": len(values), "distinct_ids": len({row[0] for row in values}),
            "min_id": values[0][0] if values else None, "max_id": values[-1][0] if values else None,
            "sum_id": sum(row[0] for row in values), "sum_grp": sum(row[1] for row in values),
            "sum_v": sum(row[2] for row in values), "canonical_csv_sha256": hashlib.sha256(data).hexdigest()}


def insert_select(start, end):
    return ("INSERT INTO {{table}} SELECT id,grp,v,payload FROM license_perf.point_rows "
            f"WHERE id >= {start} AND id < {end}")


def insert_values(start, end):
    literals = ",".join(f"({identifier},{grp},{value},'{payload}')" for identifier, grp, value, payload in rows(start, end))
    return "INSERT INTO {{table}} VALUES " + literals


def build_manifest():
    snapshots = {"empty": model([]), "insert100": model(rows(0, 100)), "update100": model(rows(0, 100, True)),
                 "seed200": model(rows(0, 200)), "committed200": model(rows(100, 200, True) + rows(200, 300)),
                 "start_noop300": model(rows(100, 200, True) + rows(200, 400)), "source600": model(rows(0, 600))}

    def op(sql, visible, *, affected=None, error=None):
        result = {"sql": sql, "visible_model": visible}
        if affected is not None:
            result["affected_rows"] = affected
        if error is not None:
            result.update({"expected_error": error, "expected_errno": 1105, "expected_sql_state": "HY000"})
        return result

    delete = "DELETE FROM {{table}} WHERE id >= 0 AND id < 100"
    update = "UPDATE {{table}} SET v=v+1000000, payload=CONCAT('u_',payload) WHERE id >= 100 AND id < 200"
    txn_ops = [op(delete, "seed200", affected=100), op(update, "seed200", affected=100),
               op(insert_select(200, 300), "seed200", affected=100)]
    phases = [
        {"name": "standalone_insert_select_100", "kind": "standalone", "before": "empty",
         "operations": [op(insert_select(0, 100), "insert100", affected=100)], "after": "insert100"},
        {"name": "standalone_update_100", "kind": "standalone", "before": "insert100", "operations": [op(
            "UPDATE {{table}} SET v=v+1000000, payload=CONCAT('u_',payload) WHERE id >= 0 AND id < 100",
            "update100", affected=100)], "after": "update100"},
        {"name": "standalone_delete_100", "kind": "standalone", "before": "update100",
         "operations": [op(delete, "empty", affected=100)], "after": "empty"},
        {"name": "seed_committed_rows", "kind": "setup", "before": "empty",
         "operations": [op(insert_select(0, 200), "seed200", affected=200)], "after": "seed200"},
        {"name": "begin_dml_rollback", "kind": "supported_transaction", "before": "seed200", "begin": "BEGIN",
         "operations": txn_ops, "end": "ROLLBACK", "after": "seed200", "transaction_status": "ABORTED"},
        {"name": "begin_dml_commit", "kind": "supported_transaction", "before": "seed200", "begin": "BEGIN",
         "operations": txn_ops, "end": "COMMIT", "after": "committed200", "transaction_status": "VISIBLE"},
        {"name": "begin_select_rejected", "kind": "unsupported_rejected", "before": "committed200", "begin": "BEGIN",
         "operations": [op("SELECT 1", "committed200", error=QUERY_ERROR)], "end": "ROLLBACK", "after": "committed200"},
        {"name": "insert_select_then_values_rejected", "kind": "unsupported_rejected", "before": "committed200",
         "begin": "BEGIN", "operations": [op(insert_select(400, 500), "committed200", affected=100),
                                            op(insert_values(500, 600), "committed200", error=MIX_ERROR)],
         "end": "ROLLBACK", "after": "committed200", "transaction_status": "ABORTED"},
        {"name": "insert_values_then_select_rejected", "kind": "unsupported_rejected", "before": "committed200",
         "begin": "BEGIN", "operations": [op(insert_values(400, 500), "committed200", affected=100),
                                            op(insert_select(500, 600), "committed200", error=MIX_ERROR)],
         "end": "ROLLBACK", "after": "committed200", "transaction_status": "ABORTED"},
        {"name": "start_transaction_ack_is_not_begin", "kind": "unsupported_ack_only", "before": "committed200",
         "begin": "START TRANSACTION", "operations": [op("SELECT 1", "committed200"),
                                                        op(insert_select(300, 400), "start_noop300", affected=100)],
         "end": "ROLLBACK", "after": "start_noop300", "transaction_status": "VISIBLE"},
    ]
    return {"case_id": "LP-015", "seed": 20260922, "source_rows_checked": 600,
            "source_payload": "MD5(decimal id), without ingest padding", "update_v_delta": 1000000,
            "update_payload_prefix": "u_", "models": snapshots, "phases": phases,
            "dml_rows_per_operation": 100, "full_1000_transactions_per_client_executed": False,
            "source_write_permitted": False, "transaction_order": "DELETE then UPDATE then INSERT SELECT on disjoint IDs"}


def run(args):
    state, _ = validate_cluster(args.cluster_record)
    driver = args.driver.resolve()
    if driver.name != DRIVER_NAME or not driver.is_file():
        raise ValueError("Use the existing MySQL Connector/J 8.0.33 JAR")
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    manifest = build_manifest()
    save(output / "model.json", manifest)
    source = ROOT / "tools/license-checks/LicenseDmlTransactionFixture.java"
    dependencies = [driver]
    for name in ("jackson-core", "jackson-databind", "jackson-annotations"):
        matches = list((Path(state["package"]) / "fe/lib").glob(name + "-*.jar"))
        if len(matches) != 1:
            raise ValueError("Expected one packaged Jackson dependency: " + name)
        dependencies.extend(matches)
    config = {"namespace": state["namespace"], "host_namespace": state["host_namespace"],
              "query_port": state["query_port"], "user": args.user, "password_env": args.password_env,
              "table": "dml_fixture_" + uuid.uuid4().hex[:12], "manifest": manifest,
              "report_path": str(output / "jdbc-result.json"), "poll_interval_ms": 100, "visibility_timeout_ms": 30000}
    save(output / "jdbc-config.json", config)
    java = Path(state["java_home"]) / "bin/java"
    classpath = os.pathsep.join(map(str, [output, *dependencies]))
    report = {"case_id": "LP-015", "status": "RUNNING", "started_at_utc": utc(),
              "scope": "Original-A DML/transaction capability and content; no sustained or license-state/performance qualification",
              "namespace": state["namespace"], "cluster_record_sha256": digest(args.cluster_record),
              "fe_jar_sha256": state["fe_jar_sha256"], "be_binary_sha256": state["be_binary_sha256"],
              "java_home": state["java_home"], "table": "license_perf." + config["table"], "manifest": manifest,
              "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in (
                  Path(__file__), source, ROOT / "tools/license-checks/stream_load_fixture.py")},
              "dependencies": {str(path): digest(path) for path in dependencies}, "credentials_recorded": False}
    save(output / "report.json", report)
    try:
        build = subprocess.run([str(java.with_name("javac")), "--release", "8", "-encoding", "UTF-8", "-cp", classpath,
                                "-d", str(output), str(source)], capture_output=True, text=True, timeout=60)
        save(output / "helper-build.json", {"exit_code": build.returncode, "stdout": build.stdout, "stderr": build.stderr})
        if build.returncode:
            raise RuntimeError("DML fixture compilation failed")
        process = subprocess.run([str(java), "-Xmx256m", "-cp", classpath, "LicenseDmlTransactionFixture",
                                  str(output / "jdbc-config.json")], capture_output=True, text=True, timeout=600)
        report["helper_exit_code"] = process.returncode
        if not (output / "jdbc-result.json").is_file():
            raise RuntimeError("DML helper did not produce a structured result")
        jdbc = json.loads((output / "jdbc-result.json").read_text())
        report["jdbc_result"] = jdbc
        if process.returncode or jdbc.get("status") != "FIXTURE_PASS" or not jdbc.get("table_removed"):
            raise RuntimeError("DML fixture failed or cleanup was not confirmed; inspect jdbc-result.json")
        if len(jdbc["phases"]) != len(manifest["phases"]):
            raise RuntimeError("Not every frozen phase was executed")
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
