#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Plan, then explicitly probe real original-A FE pages. Never starts a database."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import itertools
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BROWSER = HERE / "LicenseUiBaselineFixture.cjs"
PREFIXES = ("", "/proxy/fe", "/gateway/cluster/fe/default")
LANGUAGES = ("zh-CN", "en")
ROLES = ("admin", "reader", "unprivileged")
POINT_SQL = ("SELECT id, grp, v, payload FROM license_perf.point_rows "
             "WHERE id IN (0, 7, 999999) ORDER BY id")
QUERY_PATH = "/api/query/internal/license_perf"
MAX_JSON = 2 * 1024 * 1024
MAX_RESOURCE = 64 * 1024 * 1024
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade"}
BENCHMARK_SCRIPTS = {HERE / name for name in (
    "measure_license_primitives.py", "run_performance_baseline.py", "calibrate_read_capacity.py",
    "measure_core_cost.py")}
BENCHMARK_JAVA = {"LicensePrimitiveCostProbe", "LicenseCoreCostProbe", "LicenseJdbcBaseline"}


def require(value, message):
    if not value:
        raise ValueError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def owned(path):
    path = Path(path).resolve()
    require(ROOT / ".build-records" in path.parents, "Use this checkout's .build-records")
    return path


def read_json(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= MAX_JSON, "JSON input exceeds its bound")
    return json.loads(raw)


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    os.replace(temporary, path)


def incomplete():
    return {"LP021_complete": False, "LP022_complete": False, "full_goal_complete": False,
            "AA_precision": "not_run", "background_query_write": "not_selected",
            "B_P2U_overlay": "not_implemented", "formal_contexts_10_50": "not_run",
            "remaining": ["300-second formal refresh windows and five A/A/A/B pairs", "qualified paired background rates",
                          "full model checks in every formal paired window", "all widths/resize/visibility/session negatives",
                          "License tab/import/receipt polling and actual candidate B"]}


def refresh_cadence_plan(enabled, background_selected):
    if not enabled:
        return None
    require(background_selected, "Refresh cadence requires an explicit constant read/write background")
    events = [{"offset_ms": offset, "kind": "refresh",
               "target": "Home" if offset < 100000 else "Playground" if offset < 200000 else "Configuration",
               "operation": "tree_button" if 100000 <= offset < 200000 else "document_reload"}
              for offset in range(10000, 300000, 10000)]
    events.extend({"offset_ms": offset, "kind": "navigate", "target": target, "operation": "route_navigation"}
                  for offset, target in ((95000, "Playground"), (195000, "Configuration")))
    events.sort(key=lambda item: item["offset_ms"])
    return {"schema_version": 1, "duration_ms": 300000, "refresh_interval_ms": 10000,
            "action_timeout_ms": 20000, "initial_page": "Home", "scope": "single_context_original_A_refresh_subset",
            "events": [dict(event, sequence=index) for index, event in enumerate(events)]}


def audit_refresh_cadence(schedule, browser, expected_auth):
    require(schedule == refresh_cadence_plan(True, True), "Refresh schedule is not the frozen original-A cadence")
    cadence = browser.get("refresh_cadence", {})
    require(cadence.get("schedule") == schedule, "Browser refresh schedule differs from the frozen input")
    actual = cadence.get("events", [])
    require(isinstance(actual, list) and len(actual) == len(schedule["events"]), "Refresh events are incomplete")
    epoch = cadence.get("epoch_ms")
    require(type(epoch) in (int, float) and epoch >= 0, "Missing browser refresh epoch")
    successful, missed, failed, queued, business_refreshes, denied = 0, 0, 0, 0, 0, 0
    network = {item["id"]: item for item in browser.get("network", [])}
    require(len(network) == len(browser.get("network", [])), "Network receipt IDs are duplicated")
    claimed = set()
    bounds = browser.get("background", {})
    start_unix = bounds.get("start_receipt", {}).get("unix_millis")
    end_unix = bounds.get("end_receipt", {}).get("unix_millis")
    require(type(start_unix) is int and type(end_unix) is int and start_unix < end_unix,
            "Refresh cadence has no real background interval")
    previous_finished, aborted = epoch, False
    for expected, event in zip(schedule["events"], actual):
        require(all(event.get(key) == value for key, value in expected.items()), "Refresh event identity changed")
        require(event.get("scheduled_ms") == epoch + expected["offset_ms"], "Refresh arrivals were rebased")
        require(event.get("deadline_ms") == min(epoch + schedule["duration_ms"],
                                                event["scheduled_ms"] + schedule["action_timeout_ms"]),
                "Refresh action deadline changed")
        status = event.get("status")
        require(status in ("PASS", "FAIL", "TIMEOUT", "QUEUE_DEADLINE_MISS", "NOT_SENT_ABORTED"), "Unknown refresh status")
        if status in ("PASS", "FAIL", "TIMEOUT"):
            require(not aborted and event.get("started_ms", -1) >= previous_finished,
                    "Refresh receipts overlap or send after a terminal page failure")
            require(event.get("started_ms", -1) >= event["scheduled_ms"]
                    and event.get("finished_ms", -1) >= event["started_ms"]
                    and event.get("queue_ms") == event["started_ms"] - event["scheduled_ms"]
                    and event.get("e2e_ms") == event["finished_ms"] - event["scheduled_ms"],
                    "Refresh latency omitted queue time or changed clock origin")
            queued += event["queue_ms"] > 0
            previous_finished = event["finished_ms"]
        if status == "PASS":
            endpoint = {"Home": "hardware", "Playground": "databases", "Configuration": "configuration"}[event["target"]]
            expected_denial = browser["cell"]["role"] != "admin" and (event["target"] != "Playground" or expected_auth)
            require(event["finished_ms"] <= event["deadline_ms"] and event.get("oracle_verified") is True
                    and event.get("expected_endpoint") == endpoint and event.get("expected_original_denial") is expected_denial
                    and len(event.get("matched_network_ids", [])) == 1,
                    "Refresh PASS lacks actual request/oracle evidence")
            identifier = event["matched_network_ids"][0]
            require(identifier in network and identifier not in claimed, "Refresh request is missing or reused")
            claimed.add(identifier)
            request = network[identifier]
            actual_requests = [item["id"] for item in network.values() if item.get("action") == event.get("action_id")
                               and item.get("endpoint") == endpoint]
            require(actual_requests == event["matched_network_ids"], "Unexpected duplicate/background refresh request")
            require(event.get("action_id") == f"cadence-{event['sequence']}" and request.get("action") == event["action_id"]
                    and request.get("endpoint") == endpoint and request.get("method") == "GET"
                    and request.get("http_status") == 200 and request.get("content_type") == "json"
                    and request.get("failed") is False and not request.get("parse_failed")
                    and request.get("business_code") == (401 if expected_denial else 0)
                    and request.get("original_permission_denial" if expected_denial else "business_success") is True,
                    "Refresh request evidence contradicts its oracle")
            require(request.get("start_ms", -1) >= event["started_ms"]
                    and request.get("finished_ms", -1) >= request["start_ms"]
                    and request["finished_ms"] <= event["finished_ms"]
                    and start_unix <= event.get("started_unix_millis", -1)
                    <= event.get("finished_unix_millis", -1) <= end_unix,
                    "Refresh request is outside its action or real background interval")
            successful += 1
            denied += expected_denial
            business_refreshes += not expected_denial and event["kind"] == "refresh"
        elif status in ("QUEUE_DEADLINE_MISS", "NOT_SENT_ABORTED"):
            require(event.get("started_ms") is None and event.get("matched_network_ids") == [],
                    "An unsent refresh cannot have a request")
            require(event.get("recorded_ms", -1) >= event["deadline_ms"] if status == "QUEUE_DEADLINE_MISS" else aborted,
                    "An unsent refresh reason contradicts its deadline or page state")
            missed += 1
        else:
            failed += 1
            aborted = True
    passed = successful == len(actual) and cadence.get("status") == "PASS"
    require(cadence.get("status") != "PASS" or passed, "Refresh summary hides failed or missed arrivals")
    require(not passed or cadence.get("background_window_verified") is True, "Refresh window was not verified against the background")
    return {"status": "PASS" if passed else "FAIL", "planned_events": len(actual), "verified_events": successful,
            "missed_events": missed, "failed_events": failed, "events_with_queue": queued,
            "successful_business_refreshes": business_refreshes, "original_permission_denials_verified": denied,
            "planned_refreshes": 29, "planned_navigation_events": 2, "formal_performance_pass": False}


def account_config(path):
    value = read_json(path)
    require(isinstance(value, dict) and set(value) == {"schema_version", "accounts"}
            and value["schema_version"] == 1, "Invalid account reference schema")
    accounts = value["accounts"]
    require(isinstance(accounts, list) and len(accounts) == 3, "Provide admin, reader and unprivileged references")
    require({a.get("role") for a in accounts} == set(ROLES), "Account roles must be unique and complete")
    for account in accounts:
        require(set(account) == {"role", "username", "host", "password_env"}, "Only account references are allowed")
        require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", account["username"]), "Use simple synthetic usernames")
        require(re.fullmatch(r"[A-Za-z0-9_.%:-]{1,128}", account["host"]), "Invalid account host binding")
        require(re.fullmatch(r"MASSDB_UI_[A-Z0-9_]+_PASSWORD", account["password_env"]), "Use dedicated password environment names")
    require(len({a["username"] for a in accounts}) == 3, "Do not reuse one account for multiple roles")
    require(len({a["password_env"] for a in accounts}) == 3, "Use independent password environment references")
    return sorted(accounts, key=lambda a: ROLES.index(a["role"]))


def cpus(text):
    require(re.fullmatch(r"\d+(,\d+)*", text), "CPUs must be an explicit comma-separated set")
    result = sorted(set(map(int, text.split(","))))
    require(len(result) <= 16, "Browser fixture CPU set exceeds its bound")
    return result


def is_benchmark_command(cwd, arguments):
    """Resolve relative argv against actual process cwd, not against this controller's cwd."""
    directory = Path(cwd)
    for argument in arguments:
        if argument in BENCHMARK_JAVA and (directory == ROOT or ROOT in directory.parents):
            return True
        if argument.endswith(".py"):
            candidate = Path(argument)
            candidate = candidate if candidate.is_absolute() else directory / candidate
            if candidate.resolve() in BENCHMARK_SCRIPTS:
                return True
    return False


def require_no_benchmark():
    for path in Path("/proc").iterdir():
        if not path.name.isdigit() or int(path.name) == os.getpid():
            continue
        try:
            cwd = os.readlink(path / "cwd")
            arguments = [arg.decode("utf-8", errors="replace") for arg in (path / "cmdline").read_bytes().split(b"\0") if arg]
            if is_benchmark_command(cwd, arguments):
                raise ValueError("Owned benchmark controller/client is live; UI probe refused")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue


def make_plan(args):
    output = owned(args.output)
    require(not output.exists(), "Use a new output directory")
    require(bool(args.cluster_record) != bool(args.cluster_plan), "Choose single-node record or multi-node plan")
    require(args.accounts and args.node and args.chromium and args.cpus, "Plan requires accounts, node, chromium and CPUs")
    account_path = owned(args.accounts)
    accounts = account_config(account_path)
    cluster_path = owned(args.cluster_record or args.cluster_plan)
    cluster = read_json(cluster_path)
    if args.cluster_plan:
        require(isinstance(cluster.get("nodes"), list), "Missing multi-node topology")
        targets = [node["name"] for node in cluster["nodes"] if node.get("component") == "fe"]
        require(targets == ["fe1", "fe2", "fe3"], "Expected actual three-FE topology")
    else:
        require(all(k in cluster for k in ("installation", "namespace", "host_namespace", "http_port")),
                "Missing single-node installation facts")
        targets = ["fe1"]
    resource = {"cpus": cpus(args.cpus), "rss_limit_mib": args.rss_limit_mib,
                "reserve_mib": args.reserve_mib, "cell_timeout_seconds": args.cell_timeout_seconds,
                "whole_timeout_seconds": args.whole_timeout_seconds}
    validate_resources(resource)
    runtime = {"node": str(Path(args.node).resolve()), "chromium": str(Path(args.chromium).resolve()),
               "playwright": str(ROOT / "ui/node_modules/playwright"),
               "allow_no_browser_sandbox": args.allow_no_browser_sandbox}
    for name in ("node", "chromium"):
        require(Path(runtime[name]).is_file(), "Explicit browser runtime executable is missing")
        runtime[name + "_sha256"] = sha(runtime[name])
    cells = [{"id": f"cell-{number:03d}", "target": target, "prefix": prefix,
              "language": language, "role": role}
             for number, (target, prefix, language, role) in enumerate(
                 itertools.product(targets, PREFIXES, LANGUAGES, ROLES), 1)]
    sources = [Path(__file__), BROWSER, ROOT / "ui/package-lock.json", HERE / "stream_load_fixture.py",
               HERE / "multinode_baseline_cluster.py", HERE / "fanout_fixture.py"]
    value = {"schema_version": 1, "tool": str(Path(__file__).resolve()), "status": "PLANNED_NOT_RUN",
             "created_at_utc": utc(), "output": str(output), "cluster_kind": "multi" if args.cluster_plan else "single",
             "cluster_path": str(cluster_path), "cluster_sha256": sha(cluster_path),
             "account_path": str(account_path), "account_sha256": sha(account_path), "accounts": accounts,
             "resources": resource, "runtime": runtime, "cells": cells,
             "source_sha256": {str(path): sha(path) for path in sources}, **incomplete()}
    cadence = refresh_cadence_plan(args.refresh_cadence, bool(args.background))
    if cadence:
        require(resource["cell_timeout_seconds"] >= 420, "Refresh cadence needs 420 seconds for login/window/cleanup")
        value["refresh_cadence"] = cadence
    if args.background:
        import ui_background_fixture as background
        value["background"] = background.freeze(sys.modules[__name__], args.background, cluster, resource, len(cells))
        value["background_query_write"] = "planned_not_run"
    output.mkdir(parents=True, mode=0o700)
    save(output / "plan.json", value)
    return {"status": value["status"], "plan": str(output / "plan.json"), "cells": len(cells)}


def validate_resources(resource):
    require(set(resource) == {"cpus", "rss_limit_mib", "reserve_mib", "cell_timeout_seconds", "whole_timeout_seconds"},
            "Incomplete resource profile")
    require(resource["cpus"] and all(type(v) is int and v >= 0 for v in resource["cpus"]), "Invalid CPU set")
    for name, lower, upper in (("rss_limit_mib", 512, 8192), ("reserve_mib", 512, 16384),
                              ("cell_timeout_seconds", 30, 600), ("whole_timeout_seconds", 60, 259200)):
        require(type(resource[name]) is int and lower <= resource[name] <= upper, "Resource bound is invalid")


def proc(pid):
    path = Path("/proc") / str(pid)
    fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "ppid": int(fields[1]), "start_ticks": int(fields[19]), "state": fields[0],
            "namespace": os.readlink(path / "ns/net"), "exe": os.readlink(path / "exe"),
            "command_sha256": sha(path / "cmdline")}


def same(pin):
    try:
        now = proc(pin["pid"])
        return now["state"] not in ("Z", "X") and all(now[key] == pin[key]
                for key in ("start_ticks", "namespace", "exe", "command_sha256"))
    except (OSError, ValueError):
        return False


class Guard:
    def __init__(self, plan):
        require(sha(plan["cluster_path"]) == plan["cluster_sha256"], "Cluster input changed after planning")
        self.pins = []
        if plan["cluster_kind"] == "multi":
            from fanout_fixture import ClusterGuard
            self.multi = ClusterGuard({"cluster_plan": plan["cluster_path"],
                                       "cluster_plan_sha256": plan["cluster_sha256"]})
            self.targets = [{"name": n["name"], "host": n["ip"], "port": n["ports"]["http_port"],
                             "query_port": n["ports"]["query_port"]}
                            for n in self.multi.plan["nodes"] if n["component"] == "fe"]
            package = Path(self.multi.plan["package"])
            self._cluster_check = self.multi.check
        else:
            from stream_load_fixture import validate_cluster
            state, _ = validate_cluster(plan["cluster_path"])
            installation = owned(state["installation"])
            package = Path(state["package"])
            for component in ("fe", "be"):
                pid = int((installation / component / "bin" / (component + ".pid")).read_text())
                pin = proc(pid)
                require(pin["namespace"] == state["namespace"], "Service namespace mismatch")
                self.pins.append(pin)
            supervisor = proc(int(state["supervisor_pid"]))
            command = Path(f"/proc/{supervisor['pid']}/cmdline").read_bytes()
            require(str(HERE / "isolated_baseline_cluster.py").encode() in command
                    and supervisor["namespace"] == state["namespace"], "Unowned cluster supervisor")
            self.pins.append(supervisor)
            self.namespace = state["namespace"]
            self._cluster_check = self._single_check
            self.targets = [{"name": "fe1", "host": "127.0.0.1", "port": int(state["http_port"]),
                             "query_port": int(state["query_port"])}]
            fe_config = (installation / "fe/conf/fe.conf").read_text()
            ports = re.findall(r"(?m)^http_port\s*=\s*(\d+)\s*$", fe_config)
            require(ports == [str(state["http_port"])], "HTTP port differs from owned FE configuration")
            require(sha(installation / "fe/lib/doris-fe.jar") == state["fe_jar_sha256"], "Installed FE JAR changed")
        self.jar = package / "fe/lib/doris-fe.jar"
        require(ROOT in self.jar.resolve().parents, "Original package must belong to this checkout")
        self.jar_sha256 = sha(self.jar)
        with zipfile.ZipFile(self.jar) as archive:
            require(not any(name.startswith("org/apache/doris/massdb/license/") for name in archive.namelist()),
                    "Original-A probe rejects a FE JAR containing the new license core")
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
        require(not any(line.split()[1] == "00000000" for line in routes if len(line.split()) > 2),
                "Private fixture namespace must not have a default route")
        self.check()

    def check(self):
        require_no_benchmark()
        self._cluster_check()

    def _single_check(self):
        require(os.readlink("/proc/self/ns/net") == self.namespace and all(same(pin) for pin in self.pins),
                "Owned cluster identity changed or exited")


def json_request(target, account, method, path, body=None):
    """Independent bounded preflight. Never archives response/header/credential contents."""
    password = account["password"]
    token = base64.b64encode((account["username"] + ":" + password).encode("ascii")).decode("ascii")
    headers = {"Authorization": "Basic " + token, "Content-Type": "application/json", "X-Doris-Stream": "false"}
    deadline = min(target.get("deadline", float("inf")), time.monotonic() + 20)
    require(time.monotonic() < deadline, "Preflight deadline exceeded")
    connection = http.client.HTTPConnection(target["host"], target["port"], timeout=10)
    session = None
    try:
        connection.request(method, path, None if body is None else json.dumps(body), headers)
        response = connection.getresponse()
        for key, value in response.getheaders():
            if key.lower() == "set-cookie":
                cookies = SimpleCookie()
                cookies.load(value)
                if "PALO_SESSION_ID" in cookies:
                    session = cookies["PALO_SESSION_ID"].value
        raw = bytearray()
        expected_length = response.length
        sock = connection.sock or response.fp.raw._sock
        while True:
            if response.isclosed():
                break
            remaining = deadline - time.monotonic()
            require(remaining > 0, "Preflight response deadline exceeded")
            sock.settimeout(min(10, remaining))
            chunk = response.read1(min(65536, MAX_JSON + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            require(len(raw) <= MAX_JSON, "Preflight response exceeds bound")
        require(expected_length is None or len(raw) == expected_length, "Truncated preflight body")
        require(response.status == 200 and len(raw) <= MAX_JSON, "Preflight HTTP transport/size failure")
        require("json" in response.getheader("Content-Type", "").lower(), "Preflight did not return JSON")
        parsed = json.loads(raw)
        require(type(parsed.get("code")) is int and parsed["code"] == 0 and parsed.get("msg") == "success",
                "Preflight business request failed")
        return parsed["data"]
    finally:
        connection.close()
        if session is not None:
            logout = http.client.HTTPConnection(target["host"], target["port"], timeout=5)
            try:
                logout.request("POST", "/rest/v1/logout", headers={"Cookie": "PALO_SESSION_ID=" + session})
                response = logout.getresponse()
                raw = response.read(4097)
                require(response.status == 200 and len(raw) <= 4096 and json.loads(raw).get("code") == 0,
                        "Preflight session logout was not confirmed")
            finally:
                logout.close()


def sql(target, admin, statement):
    data = json_request(target, admin, "POST", QUERY_PATH, {"is_sync": True, "stmt": statement, "limit": 1000})
    require(isinstance(data, dict) and data.get("type") == "result_set", "Preflight SQL did not return rows")
    names = [column["name"] for column in data["meta"]]
    rows = data["data"]
    require(len(names) == len(set(names)) and all(len(row) == len(names) for row in rows), "SQL row shape mismatch")
    return [dict(zip(names, row)) for row in rows]


def privilege_summary(rows, role):
    require(len(rows) == 1 and "GlobalPrivs" in rows[0], "Cannot identify exact account grants")
    global_privs = str(rows[0]["GlobalPrivs"]).lower()
    admin = "admin_priv" in global_privs
    node = "node_priv" in global_privs
    require(admin if role == "admin" else not (admin or node), "Account privileges contradict selected role")
    # Preserve no comment, password-presence field, role text or arbitrary grant string.
    return {"role": role, "global_admin": admin, "global_node": node, "verified": True}


def preflight(guard, accounts, deadline):
    admin = next(a for a in accounts if a["role"] == "admin")
    result = {}
    for target in guard.targets:
        guard.check()
        target = dict(target, deadline=deadline)
        hardware = json_request(target, admin, "GET", "/rest/v1/hardware_info/fe/")
        version = hardware.get("VersionInfo", {})
        require(all(isinstance(version.get(k), str) and version[k] for k in ("Version", "Git")),
                "Missing actual FE build metadata")
        config = json_request(target, admin, "GET", "/rest/v1/config/fe/")
        config_rows = {row["Name"]: str(row["Value"]) for row in config.get("rows", [])}
        auth_keys = [k for k in ("enable_all_http_auth", "experimental_enable_all_http_auth") if k in config_rows]
        require(len(auth_keys) == 1 and config_rows[auth_keys[0]].lower() in ("true", "false"), "Ambiguous HTTP auth config")
        require(config_rows.get("http_port") == str(target["port"]), "Target HTTP port differs from actual FE")
        frontends = sql(target, admin, "SHOW FRONTENDS")
        selected = [row for row in frontends if str(row.get("HttpPort")) == str(target["port"])
                    and (row.get("Host") == target["host"] or
                         (len(guard.targets) == 1 and len(frontends) == 1))]
        require(len(selected) == 1 and str(selected[0].get("Alive")).lower() == "true", "FE membership is not live/unambiguous")
        require(str(selected[0].get("IsMaster")).lower() in ("true", "false"), "Missing FE master role")
        schema = sql(target, admin, "DESCRIBE license_perf.point_rows")
        require([row.get("Field") for row in schema] == ["id", "grp", "v", "payload"], "Unexpected fixture schema")
        tables = sql(target, admin, "SHOW TABLES FROM license_perf")
        table_names = sorted(str(next(iter(row.values()))) for row in tables)
        require("point_rows" in table_names, "Point dataset is not present")
        points = sql(target, admin, POINT_SQL)
        require(points == [{"id": i, "grp": i % 1024, "v": i % 100000,
                            "payload": hashlib.md5(str(i).encode("ascii"), usedforsecurity=False).hexdigest()}
                           for i in (0, 7, 999999)] or
                [{k: str(v) for k, v in row.items()} for row in points] ==
                [{"id": str(i), "grp": str(i % 1024), "v": str(i % 100000),
                  "payload": hashlib.md5(str(i).encode("ascii"), usedforsecurity=False).hexdigest()}
                 for i in (0, 7, 999999)], "Independent point oracle failed")
        grants = []
        for account in accounts:
            grants.append(privilege_summary(sql(target, admin,
                "SHOW GRANTS FOR '" + account["username"] + "'@'" + account["host"] + "'"), account["role"]))
        result[target["name"]] = {"version": version["Version"], "git": version["Git"],
            "http_port": target["port"], "auth_all": config_rows[auth_keys[0]].lower() == "true",
            "fe_role": "master" if str(selected[0]["IsMaster"]).lower() == "true" else "follower",
            "schema": [{k: None if v == "NULL" else v for k, v in row.items()} for row in schema],
            "tables": table_names, "grants": grants, "independent_point_oracle": True}
    require(sum(v["fe_role"] == "master" for v in result.values()) == 1, "Expected exactly one current Master")
    return result


def upstream_path(path, prefix):
    parsed = urlsplit(path)
    require(not parsed.scheme and not parsed.netloc and not parsed.fragment, "Proxy only accepts origin-form paths")
    require(not re.search(r"%(?:2f|5c|2e)", parsed.path, re.I) and "\\" not in parsed.path
            and ".." not in parsed.path.split("/"), "Ambiguous proxy path")
    require(not prefix or parsed.path.startswith(prefix + "/"), "Request escaped deployment prefix")
    stripped = parsed.path[len(prefix):] or "/"
    require(stripped.startswith("/") and not stripped.startswith("//"), "Invalid upstream path")
    return stripped + ("?" + parsed.query if parsed.query else "")


def redirect_location(value, target, prefix, origin):
    parsed = urlsplit(value)
    require(not parsed.username and not parsed.password, "Credential-bearing redirect refused")
    if parsed.netloc:
        require(parsed.hostname == target["host"] and parsed.port == target["port"]
                and parsed.scheme == "http", "Off-target redirect refused")
    require(parsed.path.startswith("/") and not parsed.path.startswith("//"), "Relative redirect unsupported")
    return origin + prefix + parsed.path + ("?" + parsed.query if parsed.query else "")


class PrefixProxy:
    """Forwards actual FE bytes/status; never serves fixtures, HTML fallbacks, or fake JSON."""
    def __init__(self, target, prefix, guard, deadline):
        self.target, self.prefix, self.guard, self.deadline = target, prefix, guard, deadline
        self.counts = {"requests": 0, "forwarded": 0, "rejected": 0, "bytes": 0}
        self.slots = threading.BoundedSemaphore(16)
        self.lock = threading.Lock()
        self.handlers = set()
        self.clients = set()
        self.upstreams = set()
        self.closing = False
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                connection = None
                acquired = proxy.slots.acquire(blocking=False)
                if not acquired:
                    self.send_error(503)
                    return
                self.connection.settimeout(15)
                with proxy.lock:
                    proxy.handlers.add(threading.current_thread())
                    proxy.clients.add(self.connection)
                try:
                    require(not proxy.closing, "Proxy is closing")
                    proxy.guard.check()
                    require(time.monotonic() < proxy.deadline, "Proxy deadline")
                    path = upstream_path(self.path, proxy.prefix)
                    require(not self.headers.get("Transfer-Encoding"), "Chunked client bodies are outside fixture")
                    length = int(self.headers.get("Content-Length", "0"))
                    require(0 <= length <= 65536, "Request body exceeds bound")
                    body = self.rfile.read(length) if length else None
                    if self.command == "POST":
                        require(path in ("/rest/v1/login", "/rest/v1/logout", QUERY_PATH), "Unplanned POST refused")
                        if path == QUERY_PATH:
                            require(json.loads(body) == {"stmt": POINT_SQL}, "Only the fixed read-only UI query is allowed")
                    headers = {key: value for key, value in self.headers.items()
                               if key.lower() not in HOP_HEADERS | {"host"}}
                    connection = http.client.HTTPConnection(target["host"], target["port"], timeout=15)
                    with proxy.lock:
                        proxy.upstreams.add(connection)
                    connection.request(self.command, path, body, headers)
                    response = connection.getresponse()
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() in HOP_HEADERS:
                            continue
                        if key.lower() == "location":
                            value = redirect_location(value, target, prefix, proxy.origin)
                        self.send_header(key, value)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    count = 0
                    while True:
                        require(time.monotonic() < proxy.deadline, "Proxy response deadline")
                        chunk = response.read1(65536)
                        if not chunk:
                            break
                        count += len(chunk)
                        require(count <= MAX_RESOURCE, "Response exceeds bound")
                        self.wfile.write(chunk)
                    with proxy.lock:
                        proxy.counts["forwarded"] += 1
                        proxy.counts["bytes"] += count
                except (OSError, ValueError, http.client.HTTPException, TypeError):
                    with proxy.lock:
                        proxy.counts["rejected"] += 1
                    self.close_connection = True
                finally:
                    with proxy.lock:
                        proxy.counts["requests"] += 1
                    if connection:
                        connection.close()
                    with proxy.lock:
                        proxy.handlers.discard(threading.current_thread())
                        proxy.clients.discard(self.connection)
                        proxy.upstreams.discard(connection)
                    self.close_connection = True
                    proxy.slots.release()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.timeout = 1
        self.origin = "http://127.0.0.1:" + str(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.close()

    def close(self):
        if self.closing:
            return not self.thread.is_alive() and not self.handlers
        self.closing = True
        self.server.shutdown()
        self.server.server_close()
        with self.lock:
            clients, upstreams, handlers = list(self.clients), list(self.upstreams), list(self.handlers)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        for upstream in upstreams:
            upstream.close()
        self.thread.join(timeout=5)
        deadline = time.monotonic() + 5
        for handler in handlers:
            handler.join(timeout=max(0, deadline - time.monotonic()))
        return not self.thread.is_alive() and not self.handlers


def descendants(parent, profile, parent_pin):
    entries = {}
    for path in Path("/proc").iterdir():
        if path.name.isdigit():
            try:
                value = proc(int(path.name))
                if value["namespace"] == os.readlink("/proc/self/ns/net"):
                    entries[value["pid"]] = value
            except (OSError, ValueError):
                pass
    # PID reuse must not enroll another process's descendants after Node exits.
    ids = {parent} if parent_pin and same(parent_pin) else set()
    for _ in range(16):
        added = {pid for pid, value in entries.items() if value["ppid"] in ids}
        if added <= ids:
            break
        ids |= added
    # Chromium can detach and outlive Node. Exact owned profile token also pins that browser.
    marker = ("--user-data-dir=" + str(profile)).encode()
    for pid in entries:
        try:
            if marker in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0"):
                ids.add(pid)
        except OSError:
            pass
    for _ in range(16):
        added = {pid for pid, value in entries.items() if value["ppid"] in ids}
        if added <= ids:
            break
        ids |= added
    return [entries[pid] for pid in ids if pid in entries and entries[pid]["state"] not in ("Z", "X")]


def rss_mib(pins):
    result = 0
    for pin in pins:
        if same(pin):
            try:
                match = re.search(r"(?m)^VmRSS:\s+(\d+) kB$", Path(f"/proc/{pin['pid']}/status").read_text())
                result += int(match[1]) if match else 0
            except OSError:
                pass
    return result / 1024


def stop_owned(pins):
    for sig, duration in ((signal.SIGTERM, 5), (signal.SIGKILL, 2)):
        for pin in reversed(pins):
            if same(pin):
                try:
                    os.kill(pin["pid"], sig)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + duration
        while any(same(pin) for pin in pins) and time.monotonic() < deadline:
            time.sleep(0.1)
    return all(not same(pin) for pin in pins)


def cleanup_browser(process, pins, profile, proxy):
    """Attempt every independent cleanup; a failed wait must not retain private cookies."""
    import shutil
    result = {"owned_children_exited": False, "proxy_handlers_closed": False,
              "private_profile_removed": False, "errors": []}

    def attempt(name, operation):
        try:
            return operation()
        except BaseException as error:
            result["errors"].append({"operation": name, "error_class": type(error).__name__})
            return False

    result["owned_children_exited"] = attempt("stop_owned", lambda: stop_owned(pins))
    if process is not None:
        attempt("reap_node", lambda: process.wait(timeout=5))
    result["proxy_handlers_closed"] = attempt("close_proxy", proxy.close)
    attempt("remove_private_profile", lambda: shutil.rmtree(profile))
    result["private_profile_removed"] = not profile.exists()
    return result


class ChildDiagnostics:
    """Drain bounded child pipes without archiving raw exception or credential text."""

    def __init__(self):
        self.streams = {name: {"bytes": 0, "sha256": hashlib.sha256(), "categories": set(), "tail": b""}
                        for name in ("stdout", "stderr")}

    def add(self, name, chunk):
        value = self.streams[name]
        value["bytes"] += len(chunk)
        value["sha256"].update(chunk)
        inspected = value["tail"] + chunk
        for category in ("TimeoutError", "TypeError", "RangeError", "SyntaxError", "Error"):
            if re.search(rb"\b" + category.encode("ascii") + rb"\b", inspected):
                value["categories"].add(category)
        value["tail"] = inspected[-32:]

    def drain(self, process):
        for name in self.streams:
            stream = getattr(process, name)
            # Bound work per sampling iteration even if a broken child floods a pipe.
            for _ in range(64):
                try:
                    chunk = os.read(stream.fileno(), 16384)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                self.add(name, chunk)

    def within_bound(self):
        return sum(value["bytes"] for value in self.streams.values()) <= 1048576

    def receipt(self):
        return {"raw_text_archived": False, "within_one_mib_bound": self.within_bound(), "streams": {
            name: {"bytes": value["bytes"], "sha256": value["sha256"].hexdigest(),
                   "recognized_error_categories": sorted(value["categories"])}
            for name, value in self.streams.items()}}


def run_browser(plan, cell, target, account, expected, guard, end, background=None):
    directory = owned(Path(plan["output"]) / cell["id"])
    directory.mkdir(mode=0o700)
    profile = directory / "private-profile"
    profile.mkdir(mode=0o700)
    deadline = min(end, time.monotonic() + plan["resources"]["cell_timeout_seconds"])
    process, pins, peak, failure = None, {}, 0, None
    diagnostics = ChildDiagnostics()
    with PrefixProxy(target, cell["prefix"], guard, deadline) as proxy:
        config = {"cell": cell, "origin": proxy.origin, "expected": expected,
                  "account": {"username": account["username"], "password": account["password"]},
                  "profile": str(profile), "output": str(directory / "browser.json"),
                  "runtime": plan["runtime"], "point_sql": POINT_SQL,
                  "timeout_ms": min(20000, int((deadline - time.monotonic()) * 1000))}
        if background is not None:
            config["background"] = background.browser_config()
        if plan.get("refresh_cadence"):
            config["refresh_cadence"] = plan["refresh_cadence"]
        environment = {key: os.environ[key] for key in ("PATH", "HOME", "LANG") if key in os.environ}
        environment.update(NODE_OPTIONS="", NO_PROXY="*", no_proxy="*")
        try:
            process = subprocess.Popen([plan["runtime"]["node"], str(BROWSER)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, start_new_session=True)
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
            pins[process.pid] = proc(process.pid)
            process.stdin.write(json.dumps(config).encode("utf-8"))
            process.stdin.close()
            while process.poll() is None:
                diagnostics.drain(process)
                require(diagnostics.within_bound(), "Browser diagnostic output exceeded its bound")
                guard.check()
                if background is not None:
                    background.coordinate()
                current = descendants(process.pid, profile, pins.get(process.pid))
                pins.update({pin["pid"]: pin for pin in current})
                companions = background.check() if background is not None else []
                peak = max(peak, rss_mib(current + companions + [proc(os.getpid())]))
                require(os.sched_getaffinity(0) == set(plan["resources"]["cpus"]), "Controller CPU affinity changed")
                require(all(os.sched_getaffinity(pin["pid"]) <= set(plan["resources"]["cpus"])
                            for pin in current if same(pin)), "Browser child escaped declared CPU affinity")
                require(peak <= plan["resources"]["rss_limit_mib"], "Browser process tree exceeded RSS budget")
                require(time.monotonic() < deadline, "Browser cell/whole-run deadline exceeded")
                time.sleep(0.2)
        except BaseException as error:
            failure = type(error).__name__
        finally:
            if process is not None:
                try:
                    pins.update({pin["pid"]: pin for pin in descendants(process.pid, profile, pins.get(process.pid))})
                except (OSError, ValueError) as error:
                    failure = failure or type(error).__name__
            cleanup = cleanup_browser(process, list(pins.values()), profile, proxy)
            if process is not None:
                try:
                    diagnostics.drain(process)
                    if not diagnostics.within_bound():
                        failure = failure or "DiagnosticOutputLimit"
                finally:
                    process.stdout.close()
                    process.stderr.close()
        clean = cleanup["owned_children_exited"]
        proxy_closed = cleanup["proxy_handlers_closed"]
        browser_path = directory / "browser.json"
        browser = read_json(browser_path) if browser_path.exists() else None
        cadence_audit = None
        if plan.get("refresh_cadence") and browser:
            try:
                cadence_audit = audit_refresh_cadence(plan["refresh_cadence"], browser, expected["auth_all"])
                if cadence_audit["status"] != "PASS":
                    failure = failure or "RefreshCadenceFailed"
            except (ValueError, TypeError, KeyError) as error:
                failure = failure or type(error).__name__
        record = {"cell": cell, "status": "FAIL" if failure or cleanup["errors"] or not clean
                  or not cleanup["private_profile_removed"] or not proxy_closed or not browser
                  or process.returncode != 0 else browser.get("status", "FAIL"),
                  "error_class": failure, "browser_report_sha256": sha(browser_path) if browser else None,
                  "rss_peak_mib_sampled": peak, "proxy_counts": dict(proxy.counts),
                  "owned_children_exited": clean, "private_profile_removed": cleanup["private_profile_removed"],
                  "cleanup_errors": cleanup["errors"],
                  "refresh_cadence_audit": cadence_audit,
                  "proxy_handlers_closed": proxy_closed,
                  "browser_graceful_close_confirmed": bool(browser and browser.get("browser_context_closed")),
                  "server_session_logout_confirmed": bool(browser and browser.get("server_session_logout_confirmed")),
                  "node_exit_code": process.returncode if process else None, "fe_role": expected["fe_role"]}
        save(directory / "controller.json", record)
        save(directory / "stdio.json", diagnostics.receipt())
        if failure in ("InterruptedError", "KeyboardInterrupt", "SystemExit"):
            raise InterruptedError("UI probe interrupted after owned child cleanup")
        return record


def probe(args):
    plan_path = owned(args.plan)
    plan = read_json(plan_path)
    require_no_benchmark()
    require(plan.get("schema_version") == 1 and plan.get("tool") == str(Path(__file__).resolve())
            and plan_path == owned(plan["output"]) / "plan.json", "Invalid UI fixture plan")
    require(not (Path(plan["output"]) / "report.json").exists(), "A UI plan cannot be reprobed")
    import ui_background_fixture as background_module
    background_input = background_module.validate_probe(sys.modules[__name__], plan, args.background)
    require(bool(plan.get("refresh_cadence")) == args.refresh_cadence,
            "Probe must explicitly retain the planned refresh-cadence mode")
    if args.refresh_cadence:
        require(plan["refresh_cadence"] == refresh_cadence_plan(True, bool(background_input)), "Frozen refresh schedule changed")
    for path, digest in plan["source_sha256"].items():
        require(sha(path) == digest, "Frozen UI fixture source/lockfile changed")
    require(sha(plan["account_path"]) == plan["account_sha256"]
            and account_config(plan["account_path"]) == plan["accounts"], "Account references changed")
    validate_resources(plan["resources"])
    required_cpus = set(plan["resources"]["cpus"])
    require(required_cpus <= os.sched_getaffinity(0), "Requested CPUs not available to controller")
    os.sched_setaffinity(0, required_cpus)
    for name in ("node", "chromium"):
        require(sha(plan["runtime"][name]) == plan["runtime"][name + "_sha256"], "Browser runtime changed")
    available = int(re.search(r"(?m)^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text())[1]) / 1024
    require(available >= plan["resources"]["rss_limit_mib"] + plan["resources"]["reserve_mib"], "Insufficient memory headroom")
    require((Path(plan["runtime"]["playwright"]) / "package.json").is_file(), "Installed pinned Playwright is missing")
    require(read_json(Path(plan["runtime"]["playwright"]) / "package.json").get("version") == "1.63.0",
            "Playwright differs from repository lock version")
    accounts = []
    for reference in plan["accounts"]:
        require(reference["password_env"] in os.environ, "Explicit password environment variable is unset")
        secret = os.environ[reference["password_env"]]
        require(len(secret) <= 1024 and all(32 <= ord(c) < 127 for c in secret), "Use bounded ASCII synthetic credentials")
        accounts.append(dict(reference, password=secret))
    guard = Guard(plan)
    required_cells = [(t["name"], p, l, r) for t in guard.targets for p in PREFIXES for l in LANGUAGES for r in ROLES]
    require([(c["target"], c["prefix"], c["language"], c["role"]) for c in plan["cells"]] == required_cells,
            "Plan must retain all targets, three prefixes, two languages and three roles")
    require([c["id"] for c in plan["cells"]] == [f"cell-{i:03d}" for i in range(1, len(required_cells) + 1)],
            "Cell directory identities differ from deterministic plan")
    report = {"schema_version": 1, "status": "RUNNING", "started_at_utc": utc(),
              "plan_sha256": sha(plan_path), "actual_fe_jar_sha256": guard.jar_sha256,
              "actual_cpu_affinity": sorted(os.sched_getaffinity(0)), "cells": [],
              "subcase": "fixed_refresh_cadence" if plan.get("refresh_cadence") else "functional_navigation",
              "scope": "One browser context at a time; real original-A functional subset only", **incomplete()}
    save(Path(plan["output"]) / "report.json", report)
    end = time.monotonic() + plan["resources"]["whole_timeout_seconds"]
    def interrupted(_signum, _frame):
        raise InterruptedError("UI fixture interrupted")
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        expected = preflight(guard, accounts, end)
        report["preflight"] = expected
        background_schedules = None
        for cell in plan["cells"]:
            require(time.monotonic() < end, "Whole-run deadline exceeded")
            target = next(t for t in guard.targets if t["name"] == cell["target"])
            account = next(a for a in accounts if a["role"] == cell["role"])
            background = None
            cell_report = None
            if background_input:
                admin = next(a for a in accounts if a["role"] == "admin")
                background = background_module.Background(sys.modules[__name__], plan, guard, target, cell, admin, end)
            try:
                cell_expected = dict(expected[cell["target"]])
                if background is not None:
                    background.start()
                    # The confirmed owned write target is visible to ADMIN during this cell.
                    # Preflight ran before CREATE; preserve its baseline list and add only our attested table.
                    table = background.config["table"].split(".", 1)[1]
                    require(table not in cell_expected["tables"], "Owned background table unexpectedly predates the cell")
                    cell_expected["tables"] = sorted([*cell_expected["tables"], table])
                cell_report = run_browser(plan, cell, target, account, cell_expected, guard, end, background)
            finally:
                if background is not None:
                    evidence = background.finish()
                    cell_report = cell_report or {"cell": cell, "status": "FAIL"}
                    cell_report["background"] = evidence
                    if evidence["status"] != "PASS":
                        cell_report["status"] = "FAIL"
                    schedule = tuple(evidence["summary"].get(key) for key in
                                     ("read_schedule_sha256", "write_schedule_sha256"))
                    if background_schedules is None:
                        background_schedules = schedule
                    cell_report["background_schedules_match_first_cell"] = schedule == background_schedules and all(schedule)
                    if not cell_report["background_schedules_match_first_cell"]:
                        cell_report["status"] = "FAIL"
                if cell_report is not None:
                    report["cells"].append(cell_report)
                    save(Path(plan["output"]) / "report.json", report)
            if background is not None:
                require(cell_report["background"]["cleanup_confirmed"], "Background cleanup unconfirmed; next cell refused")
        if background_input:
            report["background_query_write"] = "functional_coexistence_pass" if all(
                c.get("background", {}).get("status") == "PASS" for c in report["cells"]) else "failed_or_partial"
        report["status"] = "FUNCTIONAL_SUBSET_PASS" if all(c["status"] == "PASS" for c in report["cells"]) else "PARTIAL_OR_FAILED"
    except BaseException as error:
        report["status"], report["failure_class"] = "FAIL", type(error).__name__
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        report["cells_not_executed"] = [c["id"] for c in plan["cells"] if c["id"] not in {r["cell"]["id"] for r in report["cells"]}]
        report["finished_at_utc"] = utc()
        save(Path(plan["output"]) / "report.json", report)
    return {"status": report["status"], "report": str(Path(plan["output"]) / "report.json"), **incomplete(),
            "background_query_write": report["background_query_write"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "probe"), default="plan")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--cluster-record", type=Path)
    parser.add_argument("--cluster-plan", type=Path)
    parser.add_argument("--accounts", type=Path)
    parser.add_argument("--background", type=Path, help="Explicit frozen read/write background input; never implicit")
    parser.add_argument("--refresh-cadence", action="store_true", help="Explicit single-context LP021 refresh subcase")
    parser.add_argument("--node", type=Path)
    parser.add_argument("--chromium", type=Path)
    parser.add_argument("--cpus")
    parser.add_argument("--rss-limit-mib", type=int, default=2048)
    parser.add_argument("--reserve-mib", type=int, default=2048)
    parser.add_argument("--cell-timeout-seconds", type=int, default=180)
    parser.add_argument("--whole-timeout-seconds", type=int, default=7200)
    parser.add_argument("--allow-no-browser-sandbox", action="store_true")
    args = parser.parse_args(argv)
    try:
        require(args.plan if args.mode == "probe" else args.output, "Specify plan input or new plan output")
        result = probe(args) if args.mode == "probe" else make_plan(args)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["status"] in ("PLANNED_NOT_RUN", "FUNCTIONAL_SUBSET_PASS") else 2
    except Exception:
        # Never serialize exception text: file paths or libraries may reflect credentials.
        print(json.dumps({"status": "FAIL", "error": "UI_FIXTURE_INPUT_OR_RUNTIME_FAILURE"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
