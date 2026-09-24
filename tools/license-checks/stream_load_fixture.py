#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Generate LP012 fixed-width CSV and prove Stream Load commit/visibility in a private test cluster."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import unquote, urlsplit
import uuid


ROOT = Path(__file__).resolve().parents[2]
ROW_BYTES = 128
SEED = 20260922
MAX_ROWS = 10000000
PADDING = hashlib.sha256(str(SEED).encode("ascii")).hexdigest() * 2


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def owned(path):
    path = Path(path).resolve()
    if ROOT / ".build-records" not in path.parents:
        raise ValueError("Fixture inputs and reports must remain in this checkout's .build-records")
    return path


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def record(identifier):
    prefix = f"{identifier},{identifier % 1024},{identifier % 100000},"
    payload = hashlib.md5(str(identifier).encode("ascii"), usedforsecurity=False).hexdigest()
    payload += PADDING[:ROW_BYTES - len(prefix) - len(payload) - 1]
    value = (prefix + payload + "\n").encode("ascii")
    if len(value) != ROW_BYTES:
        raise ValueError("Fixture row does not have the promised byte length")
    return value


def expected(rows):
    def modulo_sum(divisor):
        cycles, remainder = divmod(rows, divisor)
        return cycles * divisor * (divisor - 1) // 2 + remainder * (remainder - 1) // 2
    return {"n": rows, "distinct_ids": rows, "min_id": 0, "max_id": rows - 1,
            "sum_id": rows * (rows - 1) // 2, "sum_grp": modulo_sum(1024),
            "sum_v": modulo_sum(100000), "bad_rows": 0}


def generate(args):
    target = owned(args.output)
    manifest = target.with_suffix(target.suffix + ".json")
    if target.exists() or manifest.exists():
        raise ValueError("Use a new fixture output; existing evidence is never overwritten")
    target.parent.mkdir(parents=True, exist_ok=True)
    started_at, started = utc(), time.perf_counter_ns()
    checksum = hashlib.sha256()
    with target.open("xb", buffering=1024 * 1024) as stream:
        for identifier in range(args.rows):
            row = record(identifier)
            stream.write(row)
            checksum.update(row)
    report = {"schema_version": 1, "case_id": "LP-012", "seed": SEED,
              "rows": args.rows, "full_target_rows": MAX_ROWS, "row_bytes_including_lf": ROW_BYTES,
              "format": "ASCII subset of UTF-8 CSV; comma separator; LF; no header or quoting",
              "columns": ["id", "grp", "v", "payload"], "id_start": 0,
              "expressions": {"id": "ascending 0..rows-1", "grp": "id % 1024", "v": "id % 100000",
                              "payload": "MD5(decimal id) followed by repeated SHA256(decimal seed), truncated to width"},
              "input_path": str(target), "input_sha256": checksum.hexdigest(), "input_bytes": target.stat().st_size,
              "expected": expected(args.rows), "generator_sha256": digest(Path(__file__)),
              "started_at_utc": started_at, "finished_at_utc": utc(),
              "generation_elapsed_nanos": time.perf_counter_ns() - started,
              "generation_excluded_from_load_timing": True}
    if report["input_bytes"] != args.rows * ROW_BYTES:
        raise ValueError("Generated input size mismatch")
    save(manifest, report)
    print(json.dumps({"status": "GENERATED", "rows": args.rows, "manifest": str(manifest)}), flush=True)


def validate_cluster(path):
    state = json.loads(owned(path).read_text())
    namespace = os.readlink("/proc/self/ns/net")
    if namespace != state["namespace"] or namespace == state["host_namespace"]:
        raise ValueError("Run the fixture inside the recorded private network namespace")
    installation = owned(state["installation"])
    for component in ("fe", "be"):
        pid = int((installation / component / "bin" / (component + ".pid")).read_text().strip())
        if pid <= 1 or os.readlink(f"/proc/{pid}/ns/net") != namespace:
            raise ValueError("Recorded fixture service is not live in this private namespace")
        command = Path(f"/proc/{pid}/cmdline").read_bytes()
        if str(installation / component).encode() not in command:
            raise ValueError("Fixture process ownership does not match the checkout installation")
    config = (installation / "be/conf/be.conf").read_text()
    ports = re.findall(r"(?m)^webserver_port\s*=\s*(\d+)\s*$", config)
    if len(ports) != 1:
        raise ValueError("Cannot uniquely identify the private BE HTTP port")
    return state, int(ports[0])


class SqlOracle:
    def __init__(self, args, state, output):
        self.args, self.state, self.output = args, state, output
        lib = Path(state["package"]) / "fe/lib"
        dependencies = []
        for name in ("mariadb-java-client", "jackson-core", "jackson-databind", "jackson-annotations"):
            matches = list(lib.glob(name + "-*.jar"))
            if len(matches) != 1:
                raise ValueError("Expected one packaged dependency for " + name)
            dependencies.append(matches[0])
        self.classpath = os.pathsep.join(map(str, [output, *dependencies]))
        self.java = Path(state["java_home"]) / "bin/java"
        result = subprocess.run([str(self.java.with_name("javac")), "--release", "8", "-encoding", "UTF-8",
                                 "-cp", self.classpath, "-d", str(output),
                                 str(ROOT / "tools/license-checks/LicenseFixtureSql.java")],
                                capture_output=True, text=True, timeout=60, check=True)
        self.sequence = 0
        save(output / "sql-helper-build.json", {"exit_code": result.returncode,
             "source_sha256": digest(ROOT / "tools/license-checks/LicenseFixtureSql.java"),
             "dependencies": {str(path): digest(path) for path in dependencies}})

    def execute(self, statements, *, continue_on_error=False, user=None, password_env=None):
        self.sequence += 1
        path = self.output / f"sql-{self.sequence:03d}.json"
        save(path, {"query_port": self.state["query_port"], "user": user or self.args.user,
                    "password_env": password_env or self.args.password_env, "sql": statements,
                    "continue_on_error": continue_on_error})
        result = subprocess.run([str(self.java), "-cp", self.classpath, "LicenseFixtureSql", str(path)],
                                capture_output=True, text=True, timeout=90)
        try:
            response = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise RuntimeError("Fixture SQL helper did not return a structured result") from None
        save(path.with_suffix(".result.json"), response)
        if result.returncode or (not continue_on_error and response.get("success") is not True):
            # No process arguments, JDBC properties or password-bearing environment is archived.
            raise RuntimeError("Fixture SQL failed; inspect the isolated FE service logs")
        if response.get("connection_error") or len(response.get("statements", [])) != len(statements):
            raise RuntimeError("Fixture SQL did not execute the complete requested statement sequence")
        return response["statements"]


def upload(args, state, be_port, batch, label, output, name):
    path = f"/api/license_perf/{args.table}/_stream_load"
    current = f"http://127.0.0.1:{state['http_port']}{path}"
    # Feed authorization through curl's stdin config, never a logged process argument or file.
    secret = os.environ.get(args.password_env, "")
    token = base64.b64encode((args.user + ":" + secret).encode()).decode()
    config = 'header = "Authorization: Basic ' + token + '"\n'
    hops = []
    started_at, started = utc(), time.perf_counter_ns()
    for hop in range(2):
        header_file, body_file = output / f"{name}-{hop}.headers", output / f"{name}-{hop}.json"
        result = subprocess.run([args.curl, "--config", "-", "--silent", "--show-error", "--noproxy", "*",
                                 "--connect-timeout", "10", "--max-time", "120", "--proto", "=http",
                                 "--max-redirs", "0", "--request", "PUT", "--upload-file", str(batch),
                                 "--header", "Expect: 100-continue", "--header", "format: csv",
                                 "--header", "column_separator: ,", "--header", "columns: id,grp,v,payload",
                                 "--header", "strict_mode: true", "--header", "max_filter_ratio: 0",
                                 "--header", "label: " + label, "--dump-header", "-",
                                 "--output", str(body_file), "--write-out",
                                 "\n__FIXTURE_HTTP_STATUS__%{http_code}\n", current],
                                input=config, capture_output=True, text=True, timeout=130)
        if result.returncode:
            raise RuntimeError("Stream Load HTTP transport failed; curl exit " + str(result.returncode))
        headers, marker, code = result.stdout.rpartition("\n__FIXTURE_HTTP_STATUS__")
        if not marker:
            raise RuntimeError("Missing HTTP status from Stream Load transport")
        status = int(code.strip())
        # This FE embeds userinfo in Location. Parse only in memory, never archive credentials.
        sanitized = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1<redacted>@", headers)
        sanitized = re.sub(r"(?im)^(authorization|set-cookie):.*$", r"\1: <redacted>", sanitized)
        header_file.write_text(sanitized)
        hop_record = {"url": current, "http_status": status, "response_headers": header_file.name,
                      "response_body": body_file.name}
        hops.append(hop_record)
        if status == 307 and hop == 0:
            location = re.findall(r"(?im)^location:\s*(\S+)\s*$", headers)
            if len(location) != 1:
                raise ValueError("FE Stream Load did not provide exactly one redirect")
            target = urlsplit(location[0])
            if (target.scheme != "http" or target.hostname != "127.0.0.1" or target.port != be_port
                    or target.path != path or target.query or target.fragment):
                raise ValueError("FE redirect is outside the explicitly owned private BE endpoint")
            if ((target.username is not None and unquote(target.username) != args.user)
                    or (target.password is not None and unquote(target.password) != secret)):
                raise ValueError("FE redirect changed the authenticated account")
            current = f"http://127.0.0.1:{be_port}{path}"
            continue
        if status != 200 or hop != 1:
            raise RuntimeError("Expected FE 307 followed by BE HTTP 200")
        receipt = json.loads(body_file.read_text())
        return {"label": label, "started_at_utc": started_at, "finished_at_utc": utc(),
                "elapsed_nanos_including_redirect": time.perf_counter_ns() - started,
                "input_bytes": batch.stat().st_size, "input_sha256": digest(batch),
                "hops": hops, "receipt": receipt}
    raise RuntimeError("Stream Load redirect did not finish")


def visibility_sql(table):
    padding_length = (f"{ROW_BYTES} - LENGTH(CAST(id AS STRING)) - LENGTH(CAST(grp AS STRING))"
                      " - LENGTH(CAST(v AS STRING)) - 4 - 32")
    payload = f"CONCAT(MD5(CAST(id AS STRING)), SUBSTRING('{PADDING}', 1, {padding_length}))"
    return ("SELECT COUNT(*) AS n, COUNT(DISTINCT id) AS distinct_ids, MIN(id) AS min_id, MAX(id) AS max_id, "
            "SUM(id) AS sum_id, SUM(grp) AS sum_grp, SUM(v) AS sum_v, "
            f"SUM(IF(grp != id % 1024 OR v != id % 100000 OR payload != {payload}, 1, 0)) AS bad_rows "
            f"FROM license_perf.{table}")


def assert_visibility(sql, table, wanted):
    response = sql.execute([visibility_sql(table)])[0]
    actual = {key: int(value) for key, value in response["rows"][0].items()}
    if actual != wanted:
        raise ValueError("Committed Stream Load content differs from the deterministic oracle")
    return {"checked_at_utc": utc(), "actual": actual, "expected": wanted,
            "sql_elapsed_nanos": response["elapsed_nanos"]}


def load(args):
    state, be_port = validate_cluster(args.cluster_record)
    input_path = owned(args.input)
    manifest = json.loads(input_path.with_suffix(input_path.suffix + ".json").read_text())
    rows = manifest["rows"]
    if (type(rows) is not int or not 1 <= rows <= MAX_ROWS or manifest["seed"] != SEED
            or manifest["row_bytes_including_lf"] != ROW_BYTES or input_path.stat().st_size != rows * ROW_BYTES
            or digest(input_path) != manifest["input_sha256"] or manifest["expected"] != expected(rows)):
        raise ValueError("Input manifest, bytes or independent expected totals do not match")
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    prefix = args.label_prefix or "lp012_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "_" + uuid.uuid4().hex[:8]
    if not re.fullmatch(r"[A-Za-z0-9_]{1,80}", prefix):
        raise ValueError("Label prefix must contain 1..80 safe ASCII characters")
    report = {"case_id": "LP-012", "status": "RUNNING", "scope": "Original-release fixture reachability; not full LP012, sustained throughput, license behavior or A/B success",
              "started_at_utc": utc(), "input_manifest": manifest, "namespace": state["namespace"],
              "table": "license_perf." + args.table, "batch_rows": args.batch_rows, "label_prefix": prefix,
              "source_sha256": {str(Path(__file__).relative_to(ROOT)): digest(Path(__file__))},
              "loads": [], "credentials_recorded": False}
    save(output / "report.json", report)
    try:
        sql = SqlOracle(args, state, output)
        ddl = (f"CREATE TABLE IF NOT EXISTS license_perf.{args.table} (id BIGINT NOT NULL, grp INT NOT NULL, "
               "v BIGINT NOT NULL, payload VARCHAR(128) NOT NULL) DUPLICATE KEY(id) "
               'DISTRIBUTED BY HASH(id) BUCKETS 16 PROPERTIES ("replication_num"="1")')
        report["setup"] = sql.execute(["CREATE DATABASE IF NOT EXISTS license_perf", ddl,
                                     f"SHOW CREATE TABLE license_perf.{args.table}",
                                     f"SELECT COUNT(*) AS n FROM license_perf.{args.table}"])
        if int(report["setup"][-1]["rows"][0]["n"]) != 0:
            raise ValueError("Fixture target must be empty; use a new dedicated fixture table")
        if "DUPLICATE KEY" not in str(report["setup"][-2]["rows"]):
            raise ValueError("Duplicate-label oracle requires a DUPLICATE KEY table")
        completed = 0
        first_batch = output / "first-batch.csv"
        with input_path.open("rb") as stream:
            index = 0
            while completed < rows:
                batch_rows = min(args.batch_rows, rows - completed)
                batch = first_batch if index == 0 else output / "current-batch.csv"
                data = stream.read(batch_rows * ROW_BYTES)
                if len(data) != batch_rows * ROW_BYTES or data.count(b"\n") != batch_rows:
                    raise ValueError("Input batch violated the fixed-width row contract")
                batch.write_bytes(data)
                label = f"{prefix}_w00_c00_b{index:06d}"
                result = upload(args, state, be_port, batch, label, output, f"batch-{index:06d}")
                report["loads"].append(result)
                receipt = result["receipt"]
                if (receipt.get("Status") != "Success" or receipt.get("Label") != label
                        or int(receipt.get("NumberTotalRows", -1)) != batch_rows
                        or int(receipt.get("NumberLoadedRows", -1)) != batch_rows
                        or int(receipt.get("NumberFilteredRows", -1)) != 0
                        or int(receipt.get("NumberUnselectedRows", -1)) != 0
                        or int(receipt.get("TxnId", 0)) <= 0):
                    raise ValueError("Stream Load did not confirm a fully loaded zero-filter successful transaction")
                completed += batch_rows
                index += 1
                save(output / "report.json", report)
        report["visibility_before_repeat"] = assert_visibility(sql, args.table, expected(rows))
        first = report["loads"][0]
        repeated = upload(args, state, be_port, first_batch, first["label"], output, "duplicate-label")
        report["duplicate_label"] = repeated
        receipt = repeated["receipt"]
        if (receipt.get("Status") != "Label Already Exists" or receipt.get("Label") != first["label"]
                or receipt.get("ExistingJobStatus") != "FINISHED"):
            raise ValueError("Duplicate label did not identify a finished existing import")
        report["visibility_after_repeat"] = assert_visibility(sql, args.table, expected(rows))
        report["status"] = "FIXTURE_PASS"
        report["verified_rows"] = completed
        report["full_10000000_row_target_executed"] = rows == MAX_ROWS
        print(json.dumps({"status": report["status"], "rows": completed, "report": str(output / "report.json")}), flush=True)
    except Exception as error:
        report["status"] = "FAIL"
        report["failure"] = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
        raise
    finally:
        report["finished_at_utc"] = utc()
        save(output / "report.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generator = commands.add_parser("generate", help="Generate outside timed load windows; default 10000000 rows")
    generator.add_argument("--output", type=Path, required=True)
    generator.add_argument("--rows", type=int, default=MAX_ROWS)
    loader = commands.add_parser("load", help="Prove FE redirect, committed rows and duplicate-label idempotence")
    loader.add_argument("--input", type=Path, required=True)
    loader.add_argument("--output", type=Path, required=True)
    loader.add_argument("--cluster-record", type=Path, required=True)
    loader.add_argument("--table", default="ingest_fixture_rows")
    loader.add_argument("--batch-rows", type=int, choices=(1000, 10000), default=10000)
    loader.add_argument("--label-prefix")
    loader.add_argument("--user", default="root")
    loader.add_argument("--password-env", default="MASSDB_BASELINE_PASSWORD")
    loader.add_argument("--curl", default="curl")
    args = parser.parse_args()
    if args.command == "generate":
        if not 1 <= args.rows <= MAX_ROWS:
            parser.error("rows must be within 1..10000000")
        generate(args)
    else:
        if not re.fullmatch(r"ingest_fixture_rows(?:_[a-z0-9_]+)?", args.table) or len(args.table) > 64:
            parser.error("Use a dedicated ingest_fixture_rows[_suffix] table")
        load(args)


if __name__ == "__main__":
    main()
