#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Explicit original-A concurrent UI functional windows, never an A/A qualification.

The existing navigation fixture is unchanged. Each window has one homogeneous
identity/language/prefix and real simultaneous contexts, optionally accompanied by
ONE explicitly selected read/write background. No SQL or browser runs on import.
"""

import argparse
from contextlib import ExitStack
import itertools
import json
import os
import re
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import ui_baseline_fixture as base
import ui_background_fixture as background_module

MAX_BROWSER_REPORT = 32 * 1024 * 1024
PREPARATION_CONCURRENCY = 4
MAX_PREPARATION_REPORT = 65536


def read_browser_report(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BROWSER_REPORT + 1)
    base.require(len(raw) <= MAX_BROWSER_REPORT, "Browser report exceeds bound")
    return json.loads(raw)


class BackgroundApi:
    """Only this window's larger browser receipt has the concurrent report bound."""

    def __init__(self, browser_path):
        self.browser_path = base.owned(browser_path)

    def __getattr__(self, name):
        return getattr(base, name)

    def read_json(self, path):
        if Path(path).resolve() == self.browser_path:
            return read_browser_report(path)
        return base.read_json(path)

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "LicenseUiConcurrentFixture.cjs"
PERFORMANCE = base.ROOT / "docs/license-performance-cases-20260922.json"


def flags():
    return {"AA_qualified": False, "LP021_complete": False, "LP022_complete": False,
            "full_goal_complete": False, "business_background_precision_qualified": False,
            "scope": "Original-A concurrent UI functional windows; business A/A gates unchanged",
            "page_p99_status": "not_claimed_when_samples_insufficient",
            "B_P2U_overlay": "not_implemented", "navigation": "separate_existing_navigation_fixture"}


def cells(kind):
    targets = ("fe1",) if kind == "single" else ("fe1", "fe2", "fe3")
    counts = (1, 10, 50) if kind == "single" else (1, 10)
    return [{"id": f"cell-{index:03d}", "target": target, "prefix": prefix,
             "language": language, "role": role, "contexts": count}
            for index, (target, prefix, language, role, count) in enumerate(itertools.product(
                targets, base.PREFIXES, base.LANGUAGES, base.ROLES, counts), 1)]


def plan(args):
    # Reuse the existing planner's safe path/account/runtime validation; it writes
    # only this new output directory. Its own stored navigation plans are untouched.
    selected_background = args.background
    args.background, args.refresh_cadence = None, False
    try:
        value = base.make_plan(args)
    finally:
        args.background = selected_background
    path = Path(value["plan"])
    result = base.read_json(path)
    result["tool"] = str(Path(__file__).resolve())
    result["cells"] = cells(result["cluster_kind"])
    result["case_id"] = "LP-021" if result["cluster_kind"] == "single" else "LP-022_A_prerequisite"
    result["cadence"] = base.refresh_cadence_plan(True, True)
    result["duration_seconds"] = 300
    result["preparation_concurrency"] = PREPARATION_CONCURRENCY
    result["stop_on_failed_window"] = bool(args.stop_on_failed_window)
    result["proxy_policy"] = "one bounded transparent proxy per actual browser context"
    result["background_instances_per_window"] = 1 if selected_background else 0
    result["resource_bounds"] = {"network_records_per_context": 2000, "browser_report_bytes": 33554432,
                                 "proxy_connections_per_context": 16, "browser_processes": 1}
    canonical = base.read_json(PERFORMANCE)
    contract = canonical["measurement_policy"].get("ui_measurement_contract")
    base.require(isinstance(contract, dict) and contract, "Explicit UI/business measurement decision is missing")
    result["measurement_contract"] = {"path": str(PERFORMANCE), "sha256": base.sha(PERFORMANCE),
                                      "ui_measurement_contract": contract}
    base.require(result["resources"]["cell_timeout_seconds"] >= 420,
                 "Concurrent setup/window/cleanup needs at least 420 seconds")
    base.require(result["resources"]["whole_timeout_seconds"] >= len(result["cells"]) * 360,
                 "Whole deadline must preserve every 300-second context-count window")
    for source in (Path(__file__), DRIVER, HERE / "background_http_fixture.py", HERE / "ui_background_fixture.py", PERFORMANCE):
        result["source_sha256"][str(source)] = base.sha(source)
    if selected_background:
        result["background"] = background_module.freeze(base, selected_background,
            base.read_json(result["cluster_path"]), result["resources"], len(result["cells"]))
    result.update(flags())
    base.save(path, result)
    return {"status": "PLANNED_NOT_RUN", "plan": str(path), "windows": len(result["cells"]),
            "measurement_seconds_lower_bound": len(result["cells"]) * 300, **flags()}


def no_parallel_fixture():
    from background_http_fixture import no_active_benchmark
    no_active_benchmark()
    own = Path(__file__).resolve()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            cwd = Path(os.readlink(proc / "cwd"))
            arguments = (proc / "cmdline").read_bytes().split(b"\0")
            for raw in arguments:
                if not raw.endswith(b".py"):
                    continue
                candidate = Path(raw.decode("utf-8", errors="replace"))
                if (candidate if candidate.is_absolute() else cwd / candidate).resolve() == own:
                    raise ValueError("Another concurrent UI fixture is active")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue


def read_preparation_report(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_PREPARATION_REPORT + 1)
    base.require(len(raw) <= MAX_PREPARATION_REPORT, "Preparation report exceeds bound")
    return json.loads(raw)


def audit_preparation(value, count):
    base.require(isinstance(value, dict) and value.get("concurrency_limit") == PREPARATION_CONCURRENCY
                 and value.get("local_cap_millis") == 90000
                 and value.get("created_contexts") == value.get("ready_count") == count,
                 "Preparation did not retain the full context count")
    maximum = value.get("maximum_inflight")
    base.require(type(maximum) is int and 1 <= maximum <= min(count, PREPARATION_CONCURRENCY),
                 "Preparation concurrency differs from the frozen bound")
    records = value.get("records", [])
    base.require(len(records) == count and all(item.get("context") == index
                 and item.get("status") == "fulfilled" and 0 <= item.get("ready_ms", 90000) < 90000
                 for index, item in enumerate(records)), "Missing exact preparation readiness receipts")
    return True


def audit_browser(browser, cell, expected):
    base.require(browser.get("cell") == cell and browser.get("status") == "PASS", "Browser window failed")
    audit_preparation(browser.get("preparation"), cell["contexts"])
    group = browser.get("window", {})
    count = cell["contexts"]
    base.require(group.get("contexts") == count and group.get("status") == "PASS"
                 and browser.get("contexts_alive_at_release") == count
                 and browser.get("contexts_alive_after_window") == count, "Missing simultaneous context evidence")
    epoch = group.get("epoch_ms")
    base.require(type(epoch) in (float, int) and epoch >= 0, "Missing common clock epoch")
    records, receipts, ready = browser.get("contexts", []), group.get("receipts", []), group.get("ready", [])
    base.require(len(records) == len(receipts) == len(ready) == count, "Missing context receipts")
    schedule = base.refresh_cadence_plan(True, True)["events"]
    successes = denials = 0
    samples = {}
    for index, (record, receipt, prepared) in enumerate(zip(records, receipts, ready)):
        base.require(record.get("context") == receipt.get("context") == prepared.get("context") == index
                     and prepared.get("status") == "fulfilled" and prepared.get("ready_ms", epoch + 1) <= epoch
                     and receipt.get("ready_ms") == prepared["ready_ms"] and receipt.get("epoch_ms") == epoch
                     and receipt.get("status") == "PASS" and receipt.get("finished_ms", 0) >= epoch + 300000,
                     "Contexts did not share a complete window")
        base.require(record.get("context_closed") and record.get("server_session_logout_confirmed")
                     and not record.get("network_overflow") and record.get("blocked_requests") == 0
                     and record.get("page_error_events") == 0, "Context cleanup or browser errors")
        network = {item["id"]: item for item in record.get("network", [])}
        base.require(len(network) == len(record.get("network", [])), "Duplicate network identity")
        events = receipt.get("events", [])
        base.require(len(events) == len(schedule), "Cadence events missing")
        claimed = set()
        previous_end = epoch
        for event, planned in zip(events, schedule):
            base.require(all(event.get(key) == value for key, value in planned.items()), "Cadence changed")
            base.require(event.get("context") == index and event.get("status") == "PASS"
                         and event.get("scheduled_ms") == epoch + planned["offset_ms"]
                         and event.get("deadline_ms") == min(epoch + 300000, epoch + planned["offset_ms"] + 20000),
                         "Cadence timing identity changed")
            started, finished = event.get("started_ms", -1), event.get("finished_ms", -1)
            base.require(started >= max(previous_end, event["scheduled_ms"]) and started <= finished <= event["deadline_ms"]
                         and event.get("queue_ms") == started - event["scheduled_ms"]
                         and event.get("e2e_ms") == finished - event["scheduled_ms"], "Hidden queue or overlapping context actions")
            previous_end = finished
            endpoint = {"Home": "hardware", "Playground": "databases", "Configuration": "configuration"}[planned["target"]]
            denied = cell["role"] != "admin" and (planned["target"] != "Playground" or expected["auth_all"])
            identifiers = event.get("matched_network_ids", [])
            base.require(len(identifiers) == 1 and identifiers[0] in network and identifiers[0] not in claimed
                         and event.get("expected_original_denial") is denied and event.get("oracle_verified") is True
                         and event.get("expected_endpoint") == endpoint, "Missing independent API oracle")
            claimed.add(identifiers[0])
            request = network[identifiers[0]]
            matching = [item["id"] for item in network.values()
                        if item.get("action") == f"cadence-{planned['sequence']}" and item.get("endpoint") == endpoint]
            base.require(matching == identifiers and request.get("method") == "GET"
                         and request.get("http_status") == 200 and request.get("content_type") == "json"
                         and request.get("business_code") == (401 if denied else 0)
                         and request.get("original_permission_denial" if denied else "business_success") is True
                         and request.get("failed") is False
                         and started <= request.get("start_ms", -1) <= request.get("finished_ms", -1) <= finished,
                         "HTTP/JSON completion does not support the operation")
            successes += not denied
            denials += denied
            key = planned["target"] + ":" + planned["kind"]
            series = samples.setdefault(key, {"successful": [], "original_denials": []})
            series["original_denials" if denied else "successful"].append(event["e2e_ms"])
    return {"status": "PASS", "actual_contexts": count, "shared_window_seconds": 300,
            "successful_page_operations": successes, "original_permission_denials": denials,
            "page_samples": samples, "page_p99": None,
            "page_p99_status": "not_claimed_insufficient_samples", **flags()}


def write_config(process, payload, deadline, check):
    base.require(len(payload) <= 2097152, "Browser configuration exceeds bound")
    descriptor = process.stdin.fileno()
    os.set_blocking(descriptor, False)
    written = 0
    try:
        while written < len(payload):
            check()
            base.require(process.poll() is None, "Browser driver exited before configuration")
            remaining = deadline - time.monotonic()
            base.require(remaining > 0, "Browser configuration pipe deadline")
            if not select.select([], [descriptor], [], min(0.1, remaining))[1]:
                continue
            try:
                written += os.write(descriptor, payload[written:written + 65536])
            except BlockingIOError:
                continue
    finally:
        process.stdin.close()


def open_proxy(target, prefix, guard, deadline):
    proxy = base.PrefixProxy(target, prefix, guard, deadline)
    try:
        proxy.__enter__()
    except BaseException:
        # shutdown() waits for serve_forever(); it must not be called when the
        # serving thread never started. server_close() still releases the socket.
        proxy.server.server_close()
        proxy.closing = True
        raise
    return proxy


def resources(pins, role):
    samples = []
    for pin in pins:
        if not base.same(pin):
            continue
        process = Path("/proc") / str(pin["pid"])
        try:
            fields = (process / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[19]) != pin["start_ticks"]:
                continue
            io = {}
            for line in (process / "io").read_text().splitlines():
                key, value = line.split(":", 1)
                if key in ("rchar", "wchar", "read_bytes", "write_bytes"):
                    io[key] = int(value)
            samples.append({"role": role, "pid": pin["pid"], "start_ticks": pin["start_ticks"],
                            "cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                            "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE"), "io": io})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return samples


class ResourceGuardError(ValueError):
    def __init__(self, reason, snapshot):
        super().__init__(reason)
        self.reason, self.snapshot = reason, snapshot


def observe_rss(pin, role):
    """One bounded observation; vanished/changed identities remain null, never fabricated RSS zero."""
    item = {"role": role, "pid": pin["pid"], "start_ticks": pin["start_ticks"],
            "rss_bytes": None, "status": "UNAVAILABLE_OR_IDENTITY_CHANGED"}
    if not base.same(pin):
        return item
    try:
        text = (Path("/proc") / str(pin["pid"]) / "status").read_text()
        match = re.search(r"(?m)^VmRSS:\s+(\d+) kB$", text)
        if match and base.same(pin):
            item.update(rss_bytes=int(match[1]) * 1024, status="OBSERVED")
    except (FileNotFoundError, ProcessLookupError):
        pass
    return item


def rss_snapshot(groups):
    started = time.monotonic_ns()
    samples, identities = [], {}
    for role, pins in groups:
        for pin in pins:
            key = (pin["pid"], pin["start_ticks"])
            if pin["pid"] in identities:
                base.require(all(identities[pin["pid"]].get(key) == pin.get(key) for key in
                                 ("start_ticks", "namespace", "exe", "command_sha256")),
                             "Ambiguous process identity within RSS observation")
                next(item for item in samples if (item["pid"], item["start_ticks"]) == key).setdefault(
                    "additional_roles", []).append(role)
                continue
            identities[pin["pid"]] = pin
            samples.append(observe_rss(pin, role))
    observed = [item["rss_bytes"] for item in samples if item["status"] == "OBSERVED"]
    return {"schema_version": 1, "sample_started_monotonic_ns": started,
            "sample_finished_monotonic_ns": time.monotonic_ns(), "processes": samples,
            "observed_rss_sum_bytes": sum(observed) if observed else None,
            "unavailable_processes": sum(item["rss_bytes"] is None for item in samples),
            "measurement": "sum_of_observed_process_RSS_shared_pages_can_be_counted_repeatedly_not_PSS",
            "scope": "owned_node_chromium_background_and_controller_excludes_FE_BE",
            "simultaneous_atomic_snapshot": False}


def enforce_rss_snapshot(snapshot, limit_mib):
    measured = snapshot["observed_rss_sum_bytes"]
    if measured is None:
        raise ResourceGuardError("RSS_OBSERVATION_UNAVAILABLE", snapshot)
    if measured > limit_mib * 1024 * 1024:
        raise ResourceGuardError("CLIENT_RSS_LIMIT_EXCEEDED", snapshot)
    return measured / 1024 / 1024


def persist_resource_crossing(output, error, limit_mib):
    """Archive the already measured frame; a write failure cannot replace the resource cause."""
    try:
        base.require(len(json.dumps(error.snapshot).encode("utf-8")) <= 2097152,
                     "Resource crossing receipt exceeds bound")
        base.save(output / "resource-limit.json", {"reason": error.reason,
                  "rss_limit_mib": limit_mib, "snapshot": error.snapshot})
    except BaseException as evidence_error:
        return type(evidence_error).__name__
    return None


def service_pins(guard):
    if hasattr(guard, "multi"):
        return [(node["name"], base.proc(guard.multi.nodes[node["name"]]["service"]["pid"]))
                for node in guard.multi.plan["nodes"]]
    return list(zip(("fe", "be"), guard.pins[:2]))


def run_window(plan_value, cell, target, account, expected, guard, whole_deadline, background):
    output = base.owned(Path(plan_value["output"]) / cell["id"])
    output.mkdir(mode=0o700)
    profile = output / "private-profile"
    profile.mkdir(mode=0o700)
    deadline = min(whole_deadline, time.monotonic() + plan_value["resources"]["cell_timeout_seconds"])
    process, pins, peak, failure = None, {}, None, None
    last_sample = 0
    proxies, cleanup, audit = [], [], None
    failure_reason, resource_crossing, resource_evidence_error = None, None, None
    with ExitStack() as stack:
        try:
            for _ in range(cell["contexts"]):
                proxy = open_proxy(target, cell["prefix"], guard, deadline)
                proxies.append(proxy)
                stack.callback(proxy.close)
            config = {"cell": cell, "origins": [proxy.origin for proxy in proxies], "expected": expected,
                      "account": {"username": account["username"], "password": account["password"]},
                      "profile": str(profile), "output": str(output / "browser.json"), "runtime": plan_value["runtime"],
                      "preparation_concurrency": plan_value["preparation_concurrency"]}
            if background:
                config["background"] = background.browser_config()
            payload = json.dumps(config).encode("utf-8")
            base.require(len(payload) <= 2097152, "Browser configuration exceeds bound")
            environment = {key: os.environ[key] for key in ("PATH", "HOME", "LANG") if key in os.environ}
            environment.update(NODE_OPTIONS="", NO_PROXY="*", no_proxy="*")
            process = subprocess.Popen([plan_value["runtime"]["node"], str(DRIVER)], stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=environment, start_new_session=True)
            pins[process.pid] = base.proc(process.pid)
            write_config(process, payload, min(deadline, time.monotonic() + 10), guard.check)
            while process.poll() is None:
                guard.check()
                if background:
                    background.coordinate()
                live = base.descendants(process.pid, profile, pins.get(process.pid))
                pins.update({pin["pid"]: pin for pin in live})
                companions = background.check() if background else []
                snapshot = rss_snapshot([("node_chromium", live), ("background_jvm", companions),
                                         ("controller_and_proxies", [base.proc(os.getpid())])])
                measured = snapshot["observed_rss_sum_bytes"]
                if measured is not None:
                    peak = measured / 1024 / 1024 if peak is None else max(peak, measured / 1024 / 1024)
                # This is the same observation used for enforcement, not a later diagnostic re-sample.
                enforce_rss_snapshot(snapshot, plan_value["resources"]["rss_limit_mib"])
                if time.monotonic() - last_sample >= 1:
                    last_sample = time.monotonic()
                    samples = resources(live, "node_chromium")
                    samples += resources(companions, "background_jvm")
                    samples += resources([base.proc(os.getpid())], "controller_and_proxies")
                    for role, pin in service_pins(guard):
                        samples += resources([pin], role)
                    resource_path = output / "resources.jsonl"
                    base.require(not resource_path.exists() or resource_path.stat().st_size < 67108864, "Resource report exceeds bound")
                    with resource_path.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps({"controller_monotonic_ns": time.monotonic_ns(), "processes": samples, "rss_guard": snapshot}) + "\n")
                base.require(all(os.sched_getaffinity(pin["pid"]) <= set(plan_value["resources"]["cpus"])
                                 for pin in live if base.same(pin)), "Browser affinity changed")
                base.require(time.monotonic() < deadline, "Concurrent browser deadline")
                report = output / "browser.json"
                base.require(not report.exists() or report.stat().st_size <= 33554432, "Browser report exceeds bound")
                time.sleep(0.2)
        except BaseException as error:
            failure = type(error).__name__
            if isinstance(error, ResourceGuardError):
                failure_reason, resource_crossing = error.reason, error.snapshot
                resource_evidence_error = persist_resource_crossing(
                    output, error, plan_value["resources"]["rss_limit_mib"])
        finally:
            if process:
                try:
                    pins.update({pin["pid"]: pin for pin in base.descendants(process.pid, profile, pins.get(process.pid))})
                except (OSError, ValueError):
                    failure = failure or "ProcessEnumerationFailed"
            # Independently attempt every proxy close; failure in one never skips another.
            if not proxies:
                cleanup.append(base.cleanup_browser(process, list(pins.values()), profile, SimpleNamespace(close=lambda: True)))
            for index, proxy in enumerate(proxies):
                if index == 0:
                    cleanup.append(base.cleanup_browser(process, list(pins.values()), profile, proxy))
                else:
                    try:
                        cleanup.append({"proxy_handlers_closed": proxy.close(), "errors": []})
                    except BaseException as error:
                        cleanup.append({"proxy_handlers_closed": False, "errors": [type(error).__name__]})
    preparation_path = output / "preparation.json"
    preparation, preparation_error = None, None
    if preparation_path.exists():
        try:
            preparation = read_preparation_report(preparation_path)
            base.require(preparation.get("cell") == cell, "Preparation cell identity differs")
        except (OSError, ValueError, TypeError) as error:
            preparation_error = type(error).__name__
            failure = failure or "PreparationReceiptInvalid"
    browser_path = output / "browser.json"
    if browser_path.exists():
        try:
            browser = read_browser_report(browser_path)
            audit = audit_browser(browser, cell, expected)
            audit_preparation(preparation, cell["contexts"])
            base.require({key: value for key, value in preparation.items() if key not in ("schema_version", "cell")}
                         == browser["preparation"], "Preparation receipts differ")
        except (ValueError, TypeError, KeyError) as error:
            failure = failure or type(error).__name__
    else:
        failure = failure or "BrowserReportMissing"
    clean = bool(cleanup) and cleanup[0].get("owned_children_exited") and cleanup[0].get("private_profile_removed")
    clean = clean and all(item.get("proxy_handlers_closed") and not item.get("errors") for item in cleanup)
    record = {"cell": cell, "status": "PASS" if not failure and clean and audit
              and process and process.returncode == 0 else "FAIL", "failure_class": failure,
              "failure_reason": failure_reason, "resource_crossing_snapshot": resource_crossing,
              "resource_crossing_evidence_error": resource_evidence_error,
              "preparation": preparation, "preparation_evidence_error": preparation_error,
              "preparation_report_sha256": base.sha(preparation_path) if preparation_path.exists() else None,
              "node_exit_code": process.returncode if process else None, "cleanup": cleanup,
              "physical_cleanup_confirmed": bool(clean),
              "rss_peak_mib_sampled": peak, "proxy_counts": [dict(proxy.counts) for proxy in proxies],
              "resource_scope": "1s sampled per-process CPU/RSS/IO for controller, proxies, browser, background and FE/BE",
              "resource_limitations": ["GC allocation/pause, existing RPC and per-process network not supplied",
                                       "Exited processes and sub-sample peaks can be absent; no complete CPU accounting claim"],
              "audit": audit, "browser_report_sha256": base.sha(browser_path) if browser_path.exists() else None,
              **flags()}
    base.save(output / "controller.json", record)
    if failure in ("InterruptedError", "KeyboardInterrupt", "SystemExit"):
        raise InterruptedError("Concurrent UI interrupted after cleanup")
    return record


def require_cleanup_before_next_window(record):
    base.require(isinstance(record, dict), "Missing window receipt; next window refused")
    base.require(record.get("physical_cleanup_confirmed") is True,
                 "Unknown browser/proxy/profile cleanup; next window refused")
    if "background" in record:
        base.require(record["background"].get("cleanup_confirmed") is True,
                     "Unknown background cleanup; next window refused")


def window_stop_reason(record, stop_on_failed_window):
    """Evaluate only a finished, persisted window; cleanup always takes precedence."""
    try:
        require_cleanup_before_next_window(record)
    except ValueError:
        return {"code": "WINDOW_CLEANUP_UNCONFIRMED", "cell": record.get("cell", {}).get("id")
                if isinstance(record, dict) else None}
    if stop_on_failed_window and record.get("status") != "PASS":
        return {"code": "FAILED_WINDOW_POLICY", "cell": record["cell"]["id"]}
    return None


def execute_windows(value, guard, accounts, expected, end, background_input, report, output):
    for cell in value["cells"]:
        base.require(time.monotonic() < end, "Whole-run deadline")
        target = next(target for target in guard.targets if target["name"] == cell["target"])
        account = next(account for account in accounts if account["role"] == cell["role"])
        background = None
        record = None
        if background_input:
            admin = next(account for account in accounts if account["role"] == "admin")
            api = BackgroundApi(output / cell["id"] / "browser.json")
            background = background_module.Background(api, value, guard, target, cell, admin, end)
        try:
            if background:
                background.start()
            record = run_window(value, cell, target, account, expected[cell["target"]], guard, end, background)
        except BaseException as error:
            record = {"cell": cell, "status": "FAIL", "failure_class": type(error).__name__,
                      "physical_cleanup_confirmed": False}
            if background:
                record["background_failure"] = background_module.process_error(error, "start_or_window")
        finally:
            if background:
                try:
                    evidence = background.finish()
                except BaseException as error:
                    evidence = {"status": "FAIL", "cleanup_confirmed": False,
                                "failure_class": type(error).__name__}
                record = record or {"cell": cell, "status": "FAIL"}
                record["background"] = evidence
                if evidence["status"] != "PASS":
                    record["status"] = "FAIL"
            if record:
                report["windows"].append(record)
                base.save(output / "report.json", report)
        reason = window_stop_reason(record, value.get("stop_on_failed_window", False))
        if reason and reason["code"] == "WINDOW_CLEANUP_UNCONFIRMED":
            report["stop_reason"] = reason
            raise ValueError("Window cleanup unconfirmed; remaining matrix refused")
        for source, digest in value["source_sha256"].items():
            base.require(base.sha(source) == digest, "Frozen inputs changed during the window")
        if reason:
            report["stop_reason"] = reason
            break


def probe(args):
    no_parallel_fixture()
    path = base.owned(args.plan)
    value = base.read_json(path)
    base.require(value.get("tool") == str(Path(__file__).resolve()) and value.get("schema_version") == 1
                 and path == base.owned(value["output"]) / "plan.json", "Not a concurrent UI plan")
    output = base.owned(value["output"])
    base.require(not (output / "report.json").exists(), "Use a new plan after every attempted run")
    base.require(value.get("cells") == cells(value["cluster_kind"]) and value.get("duration_seconds") == 300
                 and value.get("cadence") == base.refresh_cadence_plan(True, True), "Concurrent matrix changed")
    base.require(value.get("preparation_concurrency") == PREPARATION_CONCURRENCY,
                 "Preparation concurrency changed; use a new frozen plan")
    stop_on_failed_window = value.get("stop_on_failed_window", False)
    base.require(type(stop_on_failed_window) is bool, "Invalid frozen failed-window policy")
    base.require(args.stop_on_failed_window is None or args.stop_on_failed_window == stop_on_failed_window,
                 "Failed-window policy cannot change at probe time")
    for source, digest in value["source_sha256"].items():
        base.require(base.sha(source) == digest, "Frozen concurrent UI source changed")
    contract = value.get("measurement_contract", {})
    base.require(contract.get("path") == str(PERFORMANCE) and contract.get("sha256") == base.sha(PERFORMANCE)
                 and contract.get("ui_measurement_contract") == base.read_json(PERFORMANCE)["measurement_policy"]["ui_measurement_contract"],
                 "Explicit UI/business measurement contract changed")
    base.require(base.sha(value["account_path"]) == value["account_sha256"]
                 and base.account_config(value["account_path"]) == value["accounts"], "Account references changed")
    background_input = background_module.validate_probe(base, value, args.background)
    base.validate_resources(value["resources"])
    cpus = set(value["resources"]["cpus"])
    base.require(cpus <= os.sched_getaffinity(0), "Declared CPUs are unavailable")
    os.sched_setaffinity(0, cpus)
    import re
    available = int(re.search(r"(?m)^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text())[1]) / 1024
    base.require(available >= value["resources"]["rss_limit_mib"] + value["resources"]["reserve_mib"], "Insufficient headroom")
    for name in ("node", "chromium"):
        base.require(base.sha(value["runtime"][name]) == value["runtime"][name + "_sha256"], "Browser runtime changed")
    base.require(base.read_json(Path(value["runtime"]["playwright"]) / "package.json").get("version") == "1.63.0",
                 "Playwright version differs")
    accounts = []
    for reference in value["accounts"]:
        base.require(reference["password_env"] in os.environ, "Explicit credential environment is missing")
        secret = os.environ[reference["password_env"]]
        base.require(len(secret) <= 1024 and all(32 <= ord(char) < 127 for char in secret), "Invalid synthetic credential")
        accounts.append(dict(reference, password=secret))
    guard = base.Guard(value)
    report = {"status": "RUNNING", "started_at_utc": base.utc(), "plan_sha256": base.sha(path),
              "actual_fe_jar_sha256": guard.jar_sha256, "windows": [],
              "stop_on_failed_window": stop_on_failed_window, "planned_windows": len(value["cells"]), **flags()}
    base.save(output / "report.json", report)
    end = time.monotonic() + value["resources"]["whole_timeout_seconds"]
    def interrupted(_signum, _frame):
        raise InterruptedError("Concurrent UI interrupted")
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        expected = base.preflight(guard, accounts, end)
        report["preflight"] = expected
        execute_windows(value, guard, accounts, expected, end, background_input, report, output)
        report["status"] = "FUNCTIONAL_CONCURRENCY_PASS" if all(window["status"] == "PASS" for window in report["windows"]) else "PARTIAL_OR_FAILED"
    except BaseException as error:
        report["status"], report["failure_class"] = "FAIL", type(error).__name__
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        report["windows_not_executed"] = [cell["id"] for cell in value["cells"]
                                          if cell["id"] not in {window["cell"]["id"] for window in report["windows"]}]
        report["finished_at_utc"] = base.utc()
        base.save(output / "report.json", report)
    return {"status": report["status"], "report": str(output / "report.json"), **flags()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "probe"), default="plan")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--cluster-record", type=Path)
    parser.add_argument("--cluster-plan", type=Path)
    parser.add_argument("--accounts", type=Path)
    parser.add_argument("--background", type=Path)
    parser.add_argument("--node", type=Path)
    parser.add_argument("--chromium", type=Path)
    parser.add_argument("--cpus")
    parser.add_argument("--rss-limit-mib", type=int, default=6144)
    parser.add_argument("--reserve-mib", type=int, default=2048)
    parser.add_argument("--cell-timeout-seconds", type=int, default=600)
    parser.add_argument("--whole-timeout-seconds", type=int, default=86400)
    parser.add_argument("--allow-no-browser-sandbox", action="store_true")
    parser.add_argument("--stop-on-failed-window", action="store_true", default=None,
                        help="Freeze stopping after a failed window has finished and its cleanup is verified")
    args = parser.parse_args(argv)
    try:
        base.require(args.plan if args.mode == "probe" else args.output, "Missing plan or output")
        result = probe(args) if args.mode == "probe" else plan(args)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["status"] in ("PLANNED_NOT_RUN", "FUNCTIONAL_CONCURRENCY_PASS") else 2
    except Exception as error:
        print(json.dumps({"status": "FAIL", "failure_class": type(error).__name__, **flags()}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
