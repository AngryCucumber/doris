#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Measure P1 core costs using explicit built bytecode; never grants an SQL performance acceptance."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PROBE = HERE / "LicenseCoreCostProbe.java"
TARGETS = ("LicenseSnapshot", "LicenseClock", "LicenseVerifier", "LicenseTrustStore", "LicenseText")


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def integer(value):
    number = int(value)
    if number < 1 or number > 20_000_000:
        raise argparse.ArgumentTypeError("Expected 1..20000000")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--fe-lib", type=Path, required=True)
    parser.add_argument("--classes-from", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--hot-operations", type=integer, default=1_000_000)
    parser.add_argument("--management-operations", type=integer, default=200)
    parser.add_argument("--warmup-rounds", type=integer, default=4)
    parser.add_argument("--samples", type=integer, default=7)
    parser.add_argument("--forks", type=integer, default=3)
    args = parser.parse_args(argv)
    if args.forks > 10 or args.samples > 30 or args.warmup_rounds > 30:
        parser.error("Bounded harness: forks <= 10, samples/warmup rounds <= 30")
    for name in ("java_home", "fe_lib", "classes_from", "report"):
        setattr(args, name, getattr(args, name).resolve())
    report = {"schema_version": 1, "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "status": "RUNNING", "cpu_affinity": "0-4", "release_performance_gate": False,
              "scope": "P1 isolated single-thread operation costs, not SQL A/B, P3 classification or LP023 acceptance",
              "limitations": ["Simple harness, not JMH; dispatch/loop and instrumentation overhead included",
                              "Thread allocations include small measurement overhead; no baseline subtraction",
                              "No SQL workload, concurrent FE requests, end-to-end latency or distributed load",
                              "Host scheduling, JIT, thermal/frequency variation and background builds may affect samples"],
              "environment": {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version},
              "commands": [], "forks": []}
    temporary = None

    def run(command, timeout=180):
        result = subprocess.run([str(part) for part in command], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=timeout, check=False)
        redact = lambda text: text.replace(str(temporary), "<ephemeral-cost-dir>")
        report["commands"].append({"argv": [redact(str(part)) for part in command],
                                   "exit_code": result.returncode, "stderr": redact(result.stderr.strip())})
        if result.returncode != 0:
            raise RuntimeError("Cost probe command failed; inspect recorded stderr")
        return result.stdout

    try:
        jars = []
        for artifact in ("jackson-core", "jackson-databind", "jackson-annotations"):
            matches = list(args.fe_lib.glob(artifact + "-*.jar"))
            if len(matches) != 1:
                raise RuntimeError("Expected exactly one actual FE dependency for " + artifact)
            jars.append(matches[0].resolve())
        report["dependency_sha256"] = {str(path): digest_file(path) for path in jars}
        report["built_artifact"] = {"path": str(args.classes_from), "sha256":
                                    digest_file(args.classes_from) if args.classes_from.is_file() else None}
        targets = {}
        for name in TARGETS:
            relative = "org/apache/doris/massdb/license/" + name + ".class"
            if args.classes_from.is_dir():
                contents = (args.classes_from / relative).read_bytes()
            else:
                with zipfile.ZipFile(args.classes_from) as archive:
                    contents = archive.read(relative)
            targets[name] = {"major": int.from_bytes(contents[6:8], "big"),
                             "sha256": hashlib.sha256(contents).hexdigest()}
            if targets[name]["major"] != 52:
                raise RuntimeError("P1 target must use class major 52")
        report["actual_target_classes"] = targets
        sources = [PROBE, Path(__file__), *(ROOT / "fe/fe-core/src/main/java" /
                   ("org/apache/doris/massdb/license/" + name + ".java") for name in TARGETS)]
        report["reference_source_sha256"] = {str(path.relative_to(ROOT)): digest_file(path) for path in sources}
        report["parameters"] = {key: getattr(args, key) for key in
                                 ("hot_operations", "management_operations", "warmup_rounds", "samples", "forks")}
        with tempfile.TemporaryDirectory(prefix="massdb-license-cost-") as directory:
            temporary = Path(directory)
            classpath = os.pathsep.join(str(path) for path in [temporary, args.classes_from, *jars])
            run([args.java_home / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-cp", classpath,
                 "-d", temporary, PROBE])
            for fork in range(args.forks):
                output = run(["taskset", "--cpu-list", "0-4", args.java_home / "bin/java", "-Xms512m", "-Xmx512m",
                              "-XX:+UseG1GC", "-cp", classpath, "LicenseCoreCostProbe", args.hot_operations,
                              args.management_operations, args.warmup_rounds, args.samples])
                result = json.loads(output)
                if not result["java_runtime"].startswith("17."):
                    raise RuntimeError("This cost record requires the project JDK 17 runtime")
                if not result["thread_allocation_supported"]:
                    raise RuntimeError("Thread allocation accounting unavailable on selected JDK")
                if result["clock_suspect_at_end"]:
                    raise RuntimeError("Clock became suspect during measurement; samples unsuitable")
                report["forks"].append(result)
        aggregate = {}
        for fork in report["forks"]:
            for measurement in fork["measurements"]:
                aggregate.setdefault(measurement["name"], []).extend(measurement["samples"])
        report["summary"] = {}
        for name, samples in aggregate.items():
            costs = [sample["ns_per_operation"] for sample in samples]
            allocations = [sample["allocated_bytes_per_operation"] for sample in samples]
            report["summary"][name] = {"samples": len(samples), "ns_per_operation_median": statistics.median(costs),
                                       "ns_per_operation_min": min(costs), "ns_per_operation_max": max(costs),
                                       "allocated_bytes_per_operation_median": statistics.median(allocations),
                                       "gc_collections_total": sum(sample["gc_collections"] for sample in samples),
                                       "gc_millis_total": sum(sample["gc_millis"] for sample in samples)}
        report["status"] = "MEASURED"
    except Exception as error:
        report["status"] = "ERROR"
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["temporary_directory_removed"] = temporary is not None and not temporary.exists()
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "forks_completed": len(report["forks"]),
                      "report": str(args.report)}))
    return 0 if report["status"] == "MEASURED" else 1


if __name__ == "__main__":
    sys.exit(main())
