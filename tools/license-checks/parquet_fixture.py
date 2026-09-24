#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Create and independently read the local LP008 100 x 10000 Parquet input; no service traffic."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/license-performance-cases-20260922.json"
JAVA_SOURCE = Path(__file__).with_name("LicenseParquetFixture.java")
FILES, ROWS, SEED = 100, 10000, 20260922


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def expected(index):
    """Independent Python model; no data or digest from the Java writer is trusted."""
    start, end = index * ROWS, (index + 1) * ROWS
    row_digest, payload_digest = hashlib.sha256(), hashlib.sha256()
    groups, values = [], []
    for identifier in range(start, end):
        group, value = identifier % 1024, identifier % 100000
        payload = hashlib.md5(str(identifier).encode("ascii"), usedforsecurity=False).hexdigest()
        row_digest.update(f"{identifier}\t{group}\t{value}\t{payload}\n".encode("ascii"))
        payload_digest.update((payload + "\n").encode("ascii"))
        groups.append(group)
        values.append(value)
    return {"rows": ROWS, "footer_rows": ROWS, "min_id": start, "max_id": end - 1,
            "sum_id": (start + end - 1) * ROWS // 2,
            "min_grp": min(groups), "max_grp": max(groups), "sum_grp": sum(groups),
            "min_v": min(values), "max_v": max(values), "sum_v": sum(values),
            "min_payload_bytes": 32, "max_payload_bytes": 32,
            "rows_sha256": row_digest.hexdigest(), "payloads_sha256": payload_digest.hexdigest()}


def validate(actual, model):
    failures = [name for name, value in model.items() if actual.get(name) != value]
    if failures:
        raise ValueError("Reader/model disagreement: " + ", ".join(failures))


def select_jars(directory):
    # Explicit local dependencies; never put unrelated JDBC/cloud/service jars on the classpath.
    prefixes = ["parquet-avro", "parquet-common", "parquet-column", "parquet-encoding",
                "parquet-format-structures", "parquet-hadoop", "parquet-jackson", "parquet-variant",
                "avro", "hadoop-common", "hadoop-mapreduce-client-core", "hadoop-annotations",
                "hadoop-shaded-guava", "hadoop-auth", "jackson-core", "jackson-databind",
                "jackson-annotations", "slf4j-api", "log4j-api", "log4j-core", "log4j-slf4j2-impl",
                "commons-logging", "commons-configuration2", "commons-lang3", "commons-text",
                "commons-collections", "commons-collections4", "commons-io", "guava", "failureaccess",
                "woodstox-core", "stax2-api", "jts-core", "fastutil"]
    jars = []
    for prefix in prefixes:
        matches = sorted(path for path in directory.glob(prefix + "-*.jar")
                         if re.fullmatch(re.escape(prefix) + r"-\d[^/]*\.jar", path.name))
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one installed dependency for {prefix}, got {matches}")
        jars.append(matches[0].resolve())
    return jars


def run(args):
    started, started_ns = datetime.now(timezone.utc).isoformat(), time.perf_counter_ns()
    target = args.output.resolve()
    if ROOT / ".build-records" not in target.parents or target.exists():
        raise ValueError("Use a new directory under this checkout's .build-records")
    if args.cpu not in os.sched_getaffinity(0):
        raise ValueError("Requested CPU is outside this process's allowed affinity")
    # The Python model, dependency hashing, javac, generator and reader all share one CPU.
    os.sched_setaffinity(0, {args.cpu})
    canonical = json.loads(MANIFEST.read_text())
    case = next(item for item in canonical["cases"] if item["id"] == "LP-008")
    if "100个Parquet文件，每文件10000" not in case["data"]["fixture"] or case["status"] != "not_run":
        raise ValueError("Canonical fixture/status changed; review the tool before generating evidence")
    source_sql = canonical["datasets"]["bench_small"]["setup_sql"][-1]
    if canonical["datasets"]["bench_small"]["seed"] != SEED or not all(
            text in source_sql for text in ["number % 1024", "number % 100000", "MD5(CAST(number AS STRING))"]):
        raise ValueError("Canonical bench_small model changed")
    jars = select_jars(args.fe_lib.resolve())
    java, javac = args.java_home / "bin/java", args.java_home / "bin/javac"
    if not java.is_file() or not javac.is_file():
        raise ValueError("An existing complete JDK is required")
    target.mkdir(parents=True)
    classes = target / "classes"
    classes.mkdir()
    classpath = os.pathsep.join(str(path) for path in jars)
    inputs = {"schema_version": 1, "case_id": "LP-008", "case_status": "not_run", "seed": SEED,
              "files": FILES, "rows_per_file": ROWS, "total_rows": FILES * ROWS,
              "canonical_manifest_sha256": digest(MANIFEST), "canonical_case": case,
              "model": {"source": "datasets.bench_small", "source_insert_sql": source_sql,
                        "id": "file_index * 10000 + row_index; both indexes zero based",
                        "grp": "id % 1024", "v": "id % 100000", "payload": "lowercase MD5(decimal id ASCII)",
                        "ordering": "ascending id; seed labels the canonical fixture, no PRNG used"},
              "format": {"compression": "UNCOMPRESSED", "dictionary": False,
                         "row_group_bytes": 8 * 1024 * 1024, "page_bytes": 64 * 1024,
                         "required_columns": {"id": "INT64", "grp": "INT32", "v": "INT64",
                                              "payload": "BINARY UTF8 (32 ASCII bytes)"}},
              "sources": {str(path.relative_to(ROOT)): digest(path) for path in [JAVA_SOURCE, Path(__file__)]},
              "classpath": [{"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}
                            for path in jars], "classpath_string": classpath,
              "java_home": str(args.java_home.resolve()), "host": platform.uname()._asdict(),
              "cpu_affinity": sorted(os.sched_getaffinity(0)), "java_heap_limit": "512m",
              "started_at_utc": started, "generation_excluded_from_performance_windows": True}
    save(target / "input-manifest.json", inputs)
    commands = []

    def invoke(name, command, timeout):
        start = time.perf_counter_ns()
        with (target / (name + ".log")).open("w", encoding="utf-8") as log:
            result = subprocess.run([str(value) for value in command], stdout=log,
                                    stderr=subprocess.STDOUT, timeout=timeout, check=False)
        commands.append({"name": name, "argv": [str(value) for value in command],
                         "timeout_seconds": timeout, "returncode": result.returncode,
                         "elapsed_nanos": time.perf_counter_ns() - start})
        save(target / "commands.json", commands)
        if result.returncode:
            raise RuntimeError(f"{name} failed; see {target / (name + '.log')}")

    invoke("compile", [javac, "-J-Xmx256m", "-J-XX:ActiveProcessorCount=1", "-cp", classpath,
                       "-d", classes, JAVA_SOURCE], 60)
    base = [java, "-Xms32m", "-Xmx512m", "-XX:ActiveProcessorCount=1", "-cp",
            str(classes) + os.pathsep + classpath, "LicenseParquetFixture"]
    data = target / "parquet"
    invoke("generate", base + ["generate", data, str(FILES), str(ROWS), target / "writer-report.json"], 240)
    invoke("read", base + ["read", data, str(FILES), str(ROWS), target / "reader-report.json"], 240)
    actual = json.loads((target / "reader-report.json").read_text())["files"]
    names = [f"part-{index:05d}.parquet" for index in range(FILES)]
    if sorted(path.name for path in data.iterdir()) != names or [item["name"] for item in actual] != names:
        raise ValueError("Unexpected or missing file set")
    outputs = []
    for index, item in enumerate(actual):
        model = expected(index)
        validate(item, model)
        path = data / item["name"]
        outputs.append({"name": item["name"], "bytes": path.stat().st_size, "sha256": digest(path),
                        "expected": model, "verified_by_independent_reader": True})
    # Regenerate the complete first file and compare bytes, without rewriting the original evidence.
    invoke("reproduce_first", base + ["generate", target / "reproduced", "1", str(ROWS),
                                     target / "reproduced-writer-report.json"], 60)
    reproduced = digest(target / "reproduced" / names[0])
    if reproduced != outputs[0]["sha256"]:
        raise ValueError("First file byte reproducibility failed")
    # Prove the low-level reader rejects a truncated physical file.
    truncated = target / "truncated-negative"
    truncated.mkdir()
    with (data / names[0]).open("rb") as source, (truncated / names[0]).open("xb") as destination:
        destination.write(source.read(128))
    try:
        invoke("truncated_negative", base + ["read", truncated, "1", str(ROWS),
                                           target / "truncated-reader-report.json"], 30)
    except RuntimeError:
        reason = (target / "truncated_negative.log").read_text(encoding="utf-8")
        if not any(text in reason.lower() for text in ["not a parquet file", "magic", "eofexception", "footer"]):
            raise ValueError("Truncated input failed for an unrelated reason; inspect its log")
        rejected_truncated = True
    else:
        raise ValueError("Truncated physical Parquet was incorrectly accepted")
    changed = dict(actual[0], payloads_sha256="0" * 64)
    try:
        validate(changed, outputs[0]["expected"])
    except ValueError:
        rejected_model = True
    else:
        raise ValueError("Changed payload digest was incorrectly accepted")
    report = {"schema_version": 1, "case_id": "LP-008", "case_status": "not_run",
              "status": "local_input_generated_and_independently_verified", "files": outputs,
              "total_files": FILES, "total_rows": sum(item["expected"]["rows"] for item in outputs),
              "total_bytes": sum(item["bytes"] for item in outputs),
              "totals": {name: sum(item["expected"][name] for item in outputs)
                         for name in ["sum_id", "sum_grp", "sum_v"]},
              "writer": "AvroParquetWriter<GenericRecord> with explicit installed JAR classpath",
              "reader": "Separate JVM: ParquetFileReader + ColumnIO + GroupRecordConverter; no Avro reader",
              "model": "Separate Python hashlib/arithmetic, full ordered row and payload SHA-256 per file",
              "first_file_reproduced_byte_identically": True,
              "negative_checks": {"truncated_file_rejected": rejected_truncated,
                                  "changed_payload_digest_rejected": rejected_model},
              "input_manifest_sha256": digest(target / "input-manifest.json"),
              "reader_report_sha256": digest(target / "reader-report.json"),
              "writer_report_sha256": digest(target / "writer-report.json"),
              "compiled_class_sha256": digest(classes / "LicenseParquetFixture.class"),
              "commands_sha256": digest(target / "commands.json"),
              "started_at_utc": started, "finished_at_utc": datetime.now(timezone.utc).isoformat(),
              "elapsed_nanos": time.perf_counter_ns() - started_ns,
              "s3_service_started": False, "sql_or_http_requests_sent": False,
              "external_read_reachability_proven": False, "performance_pass_proven": False}
    save(target / "fixture-report.json", report)
    print(json.dumps({key: report[key] for key in ["status", "total_files", "total_rows", "total_bytes",
                                               "totals", "negative_checks", "elapsed_nanos"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--fe-lib", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    run(parser.parse_args())
