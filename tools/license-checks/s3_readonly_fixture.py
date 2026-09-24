#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Serve real LP008 Parquet bytes in the owned private namespace and probe original S3 TVF paths."""

import argparse
from collections import Counter
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import threading
import time
from urllib.parse import parse_qs, quote, unquote, urlsplit
import uuid
import xml.etree.ElementTree as ET

from stream_load_fixture import ROOT, SqlOracle, digest, expected, owned, save, utc, validate_cluster


BUCKET = "lp008-fixture"
PREFIX = "lp008/"
PUBLIC_ACCESS = "lp008-test"
PUBLIC_SECRET = "lp008-public-fixture-only"
XML_NS = "http://s3.amazonaws.com/doc/2006-03-01/"
LAST_MODIFIED = "2026-09-22T00:00:00.000Z"
SESSION_SQL = ["SET enable_sql_cache=false", "SET enable_query_cache=false", "SET enable_file_cache=false",
               "SET query_timeout=60", "SET insert_timeout=60"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def byte_range(value, size):
    if value is None:
        return 0, size - 1, 200
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
    if not match or not any(match.groups()):
        raise ValueError("InvalidRange")
    first, last = match.groups()
    if not first:
        require(int(last) > 0, "InvalidRange")
        return max(0, size - int(last)), size - 1, 206
    start, end = int(first), min(int(last), size - 1) if last else size - 1
    require(0 <= start <= end < size, "InvalidRange")
    return start, end, 206


class Store:
    def __init__(self, fixture_report, output):
        self.manifest = json.loads(owned(fixture_report).read_text())
        require(self.manifest.get("status") == "local_input_generated_and_independently_verified",
                "Parquet input must have independent full-read evidence")
        require(self.manifest["total_files"] == 100 and len(self.manifest["files"]) == 100
                and self.manifest["total_rows"] == 1000000,
                "Expected canonical 100 x 10000 Parquet input")
        directory = owned(fixture_report).parent / "parquet"
        self.objects = {}
        for index, item in enumerate(self.manifest["files"]):
            require(item["name"] == f"part-{index:05d}.parquet", "Unexpected canonical object ordering")
            path = owned(directory / item["name"])
            require(path.stat().st_size == item["bytes"] and digest(path) == item["sha256"], "Input file changed")
            checksum = hashlib.md5(usedforsecurity=False)
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    checksum.update(block)
            self.objects[PREFIX + item["name"]] = {**item, "path": path, "etag": '"' + checksum.hexdigest() + '"'}
        self.lock = threading.Lock()
        self.idle = threading.Condition(self.lock)
        self.active_requests = 0
        self.phase = "protocol_self_test"
        self.events = []
        self.log = (output / "requests.jsonl").open("x", encoding="utf-8")

    def record(self, **event):
        with self.lock:
            item = {"sequence": len(self.events) + 1, "phase": self.phase, "at_utc": utc(), **event}
            self.events.append(item)
            self.log.write(json.dumps(item, ensure_ascii=False) + "\n")
            self.log.flush()

    def begin(self, phase):
        with self.idle:
            require(self.idle.wait_for(lambda: self.active_requests == 0, timeout=15),
                    "Previous S3 requests did not finish before phase transition")
            self.phase = phase

    def request_started(self):
        with self.idle:
            self.active_requests += 1
            return self.phase

    def request_finished(self):
        with self.idle:
            self.active_requests -= 1
            self.idle.notify_all()

    def summary(self, phase):
        with self.idle:
            require(self.idle.wait_for(lambda: self.active_requests == 0, timeout=15),
                    "S3 request completion counters did not become quiescent")
            events = [item.copy() for item in self.events if item["phase"] == phase]
        requests = [item for item in events if item["kind"] == "http"]
        return {"tcp_accepts": sum(item["kind"] == "tcp_accept" for item in events),
                "requests": len(requests), "operations": dict(Counter(item["operation"] for item in requests)),
                "statuses": dict(Counter(str(item["status"]) for item in requests)),
                "response_body_bytes": sum(item["sent_bytes"] for item in requests),
                "get_objects": sorted({item["key"] for item in requests
                                       if item["operation"] == "GetObject" and item["status"] in (200, 206)}),
                "range_requests": sum(item.get("range") is not None for item in requests),
                "first_sequence": min((item["sequence"] for item in events), default=None),
                "last_sequence": max((item["sequence"] for item in events), default=None)}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        self.store.record(kind="tcp_accept", loopback=address[0] == "127.0.0.1")
        return connection, address


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LP008ReadOnlyFixture/1"

    def log_message(self, *args):
        pass  # Never echo raw URLs, signatures, Authorization, cookies or other headers.

    def reply(self, status, body=b"", headers=None, source=None, start=0, length=None):
        self.status = status
        length = len(body) if length is None else length
        self.send_response(status)
        self.send_header("Content-Length", str(length))
        self.send_header("Connection", "close")
        self.send_header("x-amz-request-id", "lp008-readonly-fixture")
        self.send_header("x-amz-bucket-region", "us-east-1")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True
        if self.command == "HEAD":
            return
        if source is None:
            self.wfile.write(body)
            self.sent_bytes = len(body)
        else:
            with source.open("rb") as stream:
                stream.seek(start)
                remaining = length
                while remaining:
                    block = stream.read(min(256 * 1024, remaining))
                    require(block, "Input changed during request")
                    self.wfile.write(block)
                    self.sent_bytes += len(block)
                    remaining -= len(block)

    def error(self, status, code, headers=None):
        root = ET.Element("Error")
        ET.SubElement(root, "Code").text = code
        ET.SubElement(root, "Message").text = "Read-only isolated test fixture"
        self.reply(status, ET.tostring(root, encoding="utf-8"),
                   {"Content-Type": "application/xml", **(headers or {})})

    def listing(self, query):
        allowed = {"list-type", "prefix", "delimiter", "max-keys", "continuation-token", "start-after", "encoding-type"}
        require(set(query) <= allowed and query.get("list-type") == "2", "InvalidArgument")
        prefix = query.get("prefix", "")
        delimiter = query.get("delimiter", "")
        require(delimiter in ("", "/"), "InvalidArgument")
        require(query.get("encoding-type", "") in ("", "url"), "InvalidArgument")
        limit = min(37, int(query.get("max-keys", "1000")))
        require(1 <= limit <= 1000, "InvalidArgument")
        entries = {}
        for key in sorted(self.server.store.objects):
            if not key.startswith(prefix) or key <= query.get("start-after", ""):
                continue
            suffix = key[len(prefix):]
            if delimiter and delimiter in suffix:
                entries[prefix + suffix.split(delimiter)[0] + delimiter] = "prefix"
            else:
                entries[key] = "object"
        keys = sorted(entries)
        token = query.get("continuation-token", "0")
        require(re.fullmatch(r"\d+", token) is not None, "InvalidArgument")
        offset = int(token)
        require(0 <= offset <= len(keys), "InvalidArgument")
        selected = keys[offset:offset + limit]
        truncated = offset + len(selected) < len(keys)
        root = ET.Element("ListBucketResult", xmlns=XML_NS)

        def add(parent, name, value):
            ET.SubElement(parent, name).text = str(value)

        encoded = lambda value: quote(value, safe="") if query.get("encoding-type") == "url" else value
        for name, value in {"Name": BUCKET, "Prefix": encoded(prefix), "KeyCount": len(selected),
                            "MaxKeys": query.get("max-keys", "1000"), "IsTruncated": str(truncated).lower()}.items():
            add(root, name, value)
        if delimiter:
            add(root, "Delimiter", encoded(delimiter))
        if "encoding-type" in query:
            add(root, "EncodingType", "url")
        if "continuation-token" in query:
            add(root, "ContinuationToken", token)
        if truncated:
            add(root, "NextContinuationToken", offset + len(selected))
        for key in selected:
            if entries[key] == "prefix":
                add(ET.SubElement(root, "CommonPrefixes"), "Prefix", encoded(key))
            else:
                item = self.server.store.objects[key]
                row = ET.SubElement(root, "Contents")
                for name, value in {"Key": encoded(key), "LastModified": LAST_MODIFIED,
                                    "ETag": item["etag"], "Size": item["bytes"], "StorageClass": "STANDARD"}.items():
                    add(row, name, value)
        self.reply(200, ET.tostring(root, encoding="utf-8"), {"Content-Type": "application/xml"})

    def dispatch(self):
        phase = self.server.store.request_started()
        self.status, self.sent_bytes, self.operation, self.key = 500, 0, "Rejected", None
        range_value = self.headers.get("Range")
        started = time.perf_counter_ns()
        try:
            require(self.client_address[0] == "127.0.0.1", "AccessDenied")
            if self.command not in ("GET", "HEAD"):
                return self.error(403, "AccessDenied")
            target = urlsplit(self.path)
            path = unquote(target.path, errors="strict")
            query_lists = parse_qs(target.query, keep_blank_values=True)
            require(all(len(values) == 1 for values in query_lists.values()), "InvalidArgument")
            query = {key: values[0] for key, values in query_lists.items()}
            if path == "/" and not query:
                self.operation = "EndpointProbe"
                return self.reply(200)
            if path in ("/" + BUCKET, "/" + BUCKET + "/"):
                if self.command == "HEAD" and not query:
                    self.operation = "HeadBucket"
                    return self.reply(200)
                self.operation = "ListObjectsV2"
                return self.listing(query)
            if not path.startswith("/" + BUCKET + "/"):
                return self.error(404, "NoSuchBucket")
            self.key = path[len(BUCKET) + 2:]
            if self.key not in self.server.store.objects:
                return self.error(404, "NoSuchKey")
            require(set(query) <= {"x-id"}, "InvalidArgument")
            item = self.server.store.objects[self.key]
            self.operation = "HeadObject" if self.command == "HEAD" else "GetObject"
            if self.headers.get("If-Match") not in (None, item["etag"], "*"):
                return self.error(412, "PreconditionFailed")
            if self.headers.get("If-None-Match") in (item["etag"], "*"):
                return self.reply(304, headers={"ETag": item["etag"]})
            try:
                start, end, status = byte_range(range_value, item["bytes"])
            except ValueError:
                return self.error(416, "InvalidRange", {"Content-Range": "bytes */" + str(item["bytes"])})
            headers = {"Content-Type": "application/octet-stream", "Accept-Ranges": "bytes", "ETag": item["etag"],
                       "Last-Modified": "Tue, 22 Sep 2026 00:00:00 GMT"}
            if status == 206:
                headers["Content-Range"] = f"bytes {start}-{end}/{item['bytes']}"
            self.reply(status, headers=headers, source=item["path"], start=start, length=end - start + 1)
        except (ValueError, UnicodeError):
            self.error(400, "InvalidArgument")
        except (BrokenPipeError, ConnectionResetError):
            self.status = 499
        finally:
            agent = self.headers.get("User-Agent", "").lower()
            family = "aws-java" if "aws-sdk-java" in agent else "aws-cpp" if "aws-sdk-cpp" in agent else "other"
            try:
                safe_key = self.key if self.key in self.server.store.objects else None
                self.server.store.record(kind="http", phase=phase, method=self.command, operation=self.operation, key=safe_key,
                                         range=range_value if range_value and re.fullmatch(r"bytes=[0-9,-]{1,80}", range_value) else None,
                                         status=self.status, sent_bytes=self.sent_bytes, client_family=family,
                                         signed_request_present=self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 "),
                                         elapsed_nanos=time.perf_counter_ns() - started)
            finally:
                self.server.store.request_finished()

    do_GET = do_HEAD = do_PUT = do_POST = do_DELETE = do_PATCH = do_OPTIONS = dispatch


def protocol_checks(server, store):
    def request(method, path, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    key = PREFIX + "part-00000.parquet"
    path = "/" + BUCKET + "/" + key
    original = store.objects[key]["path"].read_bytes()
    status, headers, body = request("HEAD", path)
    require(status == 200 and int(headers["Content-Length"]) == len(original) and body == b"", "HEAD mismatch")
    status, _, body = request("GET", path)
    require(status == 200 and body == original, "Full object differs from actual Parquet")
    for span, first, last in [("bytes=0-3", 0, 4), ("bytes=-8", len(original) - 8, len(original)),
                              ("bytes=100-", 100, len(original))]:
        status, headers, body = request("GET", path, {"Range": span})
        require(status == 206 and body == original[first:last] and headers["Content-Range"] ==
                f"bytes {first}-{last - 1}/{len(original)}", "Range mismatch")
    require(request("GET", path, {"Range": "bytes=9999999-"})[0] == 416, "Range overflow accepted")
    require(request("GET", path, {"Range": "bytes=0-1,4-5"})[0] == 416, "Unsupported multi-range accepted")
    require(request("GET", path, {"If-Match": '"wrong"'})[0] == 412, "ETag precondition ignored")
    require(request("PUT", path)[0] == 403 and digest(store.objects[key]["path"]) == store.objects[key]["sha256"],
            "Mutation changed a source object")
    require(request("GET", "/" + BUCKET + "/../input-manifest.json")[0] == 404, "Traversal escaped fixed objects")
    seen, token = [], ""
    while True:
        status, _, body = request("GET", "/" + BUCKET + "?list-type=2&prefix=lp008%2F&max-keys=17"
                                 + ("&continuation-token=" + token if token else ""))
        require(status == 200, "ListObjectsV2 failed")
        root = ET.fromstring(body)
        ns = {"s": XML_NS}
        seen.extend(row.text for row in root.findall("s:Contents/s:Key", ns))
        if root.findtext("s:IsTruncated", namespaces=ns) == "false":
            break
        token = root.findtext("s:NextContinuationToken", namespaces=ns)
        require(token is not None and len(seen) <= 100, "Broken listing continuation")
    require(seen == sorted(store.objects), "Pagination missed/duplicated actual objects")
    return {"full_object_equals_source": True, "head_and_three_ranges": True, "pagination_100_objects": True,
            "range_errors_etag_mutation_traversal_rejected": True}


def check_result(result):
    rows = result.get("rows", [])
    require(result.get("success") and len(rows) == 1, "Expected one successful aggregate row")
    actual = {name.lower(): int(value) for name, value in rows[0].items()}
    require(actual == expected(1000000), "SQL full-row model differs: " + str(actual))


def query(from_clause):
    return ("SELECT COUNT(*) AS n, COUNT(DISTINCT id) AS distinct_ids, MIN(id) AS min_id, MAX(id) AS max_id, "
            "SUM(id) AS sum_id, SUM(grp) AS sum_grp, SUM(v) AS sum_v, "
            "SUM(IF(id IS NULL OR grp IS NULL OR v IS NULL OR payload IS NULL OR grp != id % 1024 "
            "OR v != id % 100000 OR payload != MD5(CAST(id AS STRING)),1,0)) AS bad_rows FROM " + from_clause)


def probe(args):
    state, _ = validate_cluster(args.cluster_record)
    require(args.cpu in os.sched_getaffinity(0), "CPU is outside allowed affinity")
    os.sched_setaffinity(0, {args.cpu})
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    report = {"case_id": "LP-008", "case_status": "not_run", "status": "RUNNING", "started_at_utc": utc(),
              "namespace": state["namespace"], "cluster_record_sha256": digest(args.cluster_record),
              "fe_jar_sha256": state["fe_jar_sha256"], "be_binary_sha256": state["be_binary_sha256"],
              "parquet_report_sha256": digest(args.parquet_report), "cpu_affinity": sorted(os.sched_getaffinity(0)),
              "signature_verification_implemented": False, "credentials": "public nonsecret fixture strings only",
              "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in
                                [Path(__file__), ROOT / "tools/license-checks/stream_load_fixture.py",
                                 ROOT / "tools/license-checks/LicenseFixtureSql.java"]},
              "license_denial_proven": False, "performance_pass_proven": False, "requests_by_stage": {}}
    save(output / "report.json", report)
    store, server, worker, sql, created = None, None, None, None, False
    table = "license_perf.lp008_external_" + uuid.uuid4().hex[:12]
    try:
        store = Store(args.parquet_report, output)
        server = Server(("127.0.0.1", 0), Handler)
        server.store = store
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        report["endpoint"] = f"http://127.0.0.1:{server.server_port}"
        report["protocol_self_test"] = protocol_checks(server, store)
        report["requests_by_stage"]["protocol_self_test"] = store.summary("protocol_self_test")
        tvf = (f'S3("uri"="s3://{BUCKET}/{PREFIX}*.parquet", "s3.endpoint"="{report["endpoint"]}", '
               f'"s3.region"="us-east-1", "s3.access_key"="{PUBLIC_ACCESS}", "s3.secret_key"="{PUBLIC_SECRET}", '
               '"use_path_style"="true", "format"="parquet")')
        report["tvf_sql"] = tvf
        sql = SqlOracle(args, state, output)

        def execute(phase, statement):
            store.begin(phase)
            try:
                return sql.execute(SESSION_SQL + [statement])[-1]
            finally:
                report["requests_by_stage"][phase] = store.summary(phase)
                save(output / "report.json", report)

        schema = execute("schema", "DESC FUNCTION " + tvf)
        report["schema_result"] = schema
        fields = [{name.lower(): value for name, value in row.items()} for row in schema.get("rows", [])]
        require([row.get("field") for row in fields] == ["id", "grp", "v", "payload"], "Schema column mismatch")
        types = [row.get("type", "").lower() for row in fields]
        require(types[:3] == ["bigint", "int", "bigint"] and
                (types[3] in ("text", "string") or types[3].startswith("varchar")), "Schema type mismatch")
        report["external_select"] = execute("external_select", query(tvf))
        check_result(report["external_select"])
        # The random table name belongs solely to this invocation, including an uncertain CREATE acknowledgement.
        created = True
        report["create_table"] = execute("create_table", f"CREATE TABLE {table} "
            '(id BIGINT NOT NULL, grp INT NOT NULL, v BIGINT NOT NULL, payload VARCHAR(32) NOT NULL) '
            'DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 16 PROPERTIES ("replication_num"="1")')
        report["insert_select"] = execute("insert_select", f"INSERT INTO {table} SELECT id,grp,v,payload FROM " + tvf)
        report["internal_result"] = execute("internal_verify", query(table))
        check_result(report["internal_result"])
        require(report["requests_by_stage"]["schema"]["operations"].get("ListObjectsV2", 0) >= 1
                and report["requests_by_stage"]["schema"]["get_objects"], "Schema did not reach real object bytes")
        for phase in ("external_select", "insert_select"):
            observed = report["requests_by_stage"][phase]
            require(observed["get_objects"] == sorted(store.objects), phase + " did not fetch all 100 real objects")
            require(observed["range_requests"] >= 100 and set(observed["statuses"]) <= {"200", "206"},
                    phase + " did not preserve successful ranged reads")
        require(report["requests_by_stage"]["internal_verify"]["requests"] == 0,
                "Internal table verification unexpectedly read external source")
        report["status"] = "ORIGINAL_S3_SCHEMA_SELECT_INSERT_REACHABLE"
    except Exception as error:
        report["status"] = "FAILED"
        report["failure_type"] = type(error).__name__
        report["failure"] = str(error)
        raise
    finally:
        try:
            if created:
                store.begin("cleanup")
                report["cleanup"] = sql.execute([f"DROP TABLE IF EXISTS {table}",
                                                f"SHOW TABLES FROM license_perf LIKE '{table.split('.')[1]}'"])
                require(report["cleanup"][-1].get("rows") == [], "Temporary destination was not removed")
        except Exception as error:
            report["status"] = "FAILED"
            report["cleanup_failure_type"] = type(error).__name__
            report["cleanup_failure"] = str(error)
            raise
        finally:
            if server:
                server.shutdown()
                server.server_close()
                worker.join(timeout=10)
                report["server_stopped"] = not worker.is_alive()
            if store:
                report["requests_by_stage"]["cleanup"] = store.summary("cleanup")
                store.log.close()
                report["requests_sha256"] = digest(output / "requests.jsonl")
            report["finished_at_utc"] = utc()
            save(output / "report.json", report)
    print(json.dumps({name: report[name] for name in ["status", "case_status", "endpoint", "server_stopped",
                                                    "requests_by_stage", "performance_pass_proven"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-record", type=Path, required=True)
    parser.add_argument("--parquet-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_BASELINE_PASSWORD")
    probe(parser.parse_args())
