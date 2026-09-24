#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Prove original Flight batch/connection paths against the complete million-row model."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from stream_load_fixture import ROOT, digest, owned, save, utc, validate_cluster


def port(installation, service):
    config = (installation / service / "conf" / (service + ".conf")).read_text()
    values = re.findall(r"(?m)^arrow_flight_sql_port\s*=\s*(\d+)\s*$", config)
    if len(values) != 1 or not 0 < int(values[0]) < 65536:
        raise ValueError("Expected one explicit owned Flight port")
    return int(values[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_BASELINE_PASSWORD")
    args = parser.parse_args()
    state, _ = validate_cluster(args.cluster_record)  # Before compilation, requests or output creation.
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    report = {"case_id": "LP-010", "case_status": "not_run", "status": "FAIL", "started_at_utc": utc(),
              "scope": "Original A functional fixture; no license-state, expiry or performance qualification",
              "cluster_record_sha256": digest(args.cluster_record), "namespace": state["namespace"],
              "fe_jar_sha256": state["fe_jar_sha256"], "be_binary_sha256": state["be_binary_sha256"],
              "cpu_affinity": sorted(os.sched_getaffinity(0)), "java_home": state["java_home"],
              "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in (
                  Path(__file__).resolve(), ROOT / "tools/license-checks/LicenseFlightFixture.java",
                  ROOT / "tools/license-checks/stream_load_fixture.py")},
              "license_denial_proven": False, "performance_pass_proven": False}
    try:
        checksum = hashlib.sha256()
        started = time.perf_counter_ns()
        for identifier in range(1000000):
            payload = hashlib.md5(str(identifier).encode("ascii"), usedforsecurity=False).hexdigest()
            checksum.update(f"{identifier},{payload}\n".encode("ascii"))
        report["independent_model"] = {"rows": 1000000, "sha256": checksum.hexdigest(),
                                       "encoding": "ASCII decimal id, comma, lowercase MD5(decimal id), LF",
                                       "generation_nanos_excluded_from_query": time.perf_counter_ns() - started}
        installation = Path(state["installation"])
        config = {"fe_flight_port": port(installation, "fe"), "be_flight_port": port(installation, "be"),
                  "user": args.user, "password_env": args.password_env, "expected_sha256": checksum.hexdigest()}
        save(output / "configuration.json", config)
        # Use exactly the installed dependency set; no library is downloaded or repackaged.
        jars = sorted((Path(state["package"]) / "fe/lib").glob("*.jar"))
        report["dependencies"] = {str(path): digest(path) for path in jars}
        classpath = os.pathsep.join(map(str, [output, *jars]))
        java = Path(state["java_home"]) / "bin/java"
        compile_result = subprocess.run([str(java.with_name("javac")), "--release", "17", "-encoding", "UTF-8",
                                         "-cp", classpath, "-d", str(output),
                                         str(ROOT / "tools/license-checks/LicenseFlightFixture.java")],
                                        capture_output=True, text=True, timeout=90)
        (output / "compile.log").write_text(compile_result.stdout + compile_result.stderr)
        if compile_result.returncode:
            raise RuntimeError("Flight helper compilation failed")
        with (output / "client.log").open("w") as log:
            process = subprocess.run([str(java), "-Xms256m", "-Xmx512m", "-XX:MaxDirectMemorySize=512m",
                                      "--add-opens=java.base/java.nio=ALL-UNNAMED", "-cp", classpath,
                                      "LicenseFlightFixture", str(output / "configuration.json"),
                                      str(output / "flight-result.json")],
                                     stdout=log, stderr=log, timeout=300)
        report["helper_exit_code"] = process.returncode
        if (output / "flight-result.json").exists():
            report["flight_result"] = json.loads((output / "flight-result.json").read_text())
        if process.returncode or report.get("flight_result", {}).get("status") != "FIXTURE_PASS":
            raise RuntimeError("Flight fixture failed; preserved client and partial result records")
        queries = report["flight_result"]["queries"]
        if len(queries) != 12 or any(row["rows"] != 1000000 or row["sha256"] != checksum.hexdigest()
                                     for row in queries):
            raise ValueError("Complete connection/batch matrix was not verified")
        report["status"] = "FIXTURE_PASS"
    except Exception as error:
        report["error_class"] = type(error).__name__
        raise
    finally:
        report["finished_at_utc"] = utc()
        save(output / "report.json", report)
    print(json.dumps({"status": report["status"], "queries": 12, "rows_verified": 12000000,
                      "report": str(output / "report.json")}))


if __name__ == "__main__":
    main()
