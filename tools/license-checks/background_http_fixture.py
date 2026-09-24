#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Plan, or explicitly probe, LP026 original-A maintenance and recorded FE HTTP paths."""

import argparse
import base64
from decimal import Decimal, InvalidOperation
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import threading
import time
from urllib.parse import unquote, urlencode, urlsplit
import uuid

import background_http_resources as resources_module
import stream_load_fixture as fixture


ROOT = fixture.ROOT
SOURCE = Path(__file__).resolve()
SQL_SOURCE = SOURCE.with_name("LicenseFixtureSql.java")
BROKER_SOURCE = SOURCE.with_name("LicenseReadOnlyBrokerFixture.java")
INPUT_SOURCE = SOURCE.with_name("LicenseReadOnlyBrokerInputs.java")
RESOURCE_SOURCE = SOURCE.with_name("background_http_resources.py")
MAX_RESPONSE = 2 * 1024 * 1024
CSV_BYTES = b"1,lp026-a\n2,lp026-b\n"
FILE_URIS = {"CSV": "lp026://fixture/rows.csv", "PARQUET": "lp026://fixture/rows.parquet"}
SEARCH_BODY = {"query": {"match_all": {}}, "size": 2}
PHASES = ("dictionary", "mv", "statistics", "es", "file_review_csv", "file_review_parquet")
SUCCESS_STATUSES = ("ORIGINAL_FUNCTIONAL_PREREQUISITES_PASS", "ORIGINAL_FUNCTIONAL_SUBSET_COMPLETE")
SETTINGS = ("SET enable_sql_cache=false", "SET enable_query_cache=false",
            "SET enable_short_circuit_query=false", "SET query_timeout=45", "SET insert_timeout=45")


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def save(path, value):
    """Publish a complete evidence document, never a partly written JSON object."""
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def safe_error(error):
    # Connection/library exceptions may contain credentials or arbitrary server text.
    return {"class": type(error).__name__, "message": str(error) if isinstance(error, ValueError) else None}


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value), "Unsafe fixture identifier")
    return value


def integer(value):
    require(isinstance(value, str) and re.fullmatch(r"\d+", value), "Expected an exact nonnegative integer")
    return int(value)


def rows(result):
    require(result.get("success") is True, "SQL did not succeed")
    names = [item.get("name") for item in result.get("columns", [])]
    result_rows = result.get("rows")
    require(names and len(names) == len(set(names)) and isinstance(result_rows, list), "Missing/duplicate SQL columns")
    require(all(isinstance(row, dict) and set(row) == set(names) for row in result_rows), "SQL row shape mismatch")
    return result_rows


def exact_rows(result, expected):
    require(rows(result) == expected, "Complete SQL result differs from the independent model")
    return {"rows": expected, "sha256": sha(canonical(expected))}


def selected_phases(args):
    requested = list(getattr(args, "phases", PHASES))
    require(requested and len(requested) == len(set(requested)) and set(requested) <= set(PHASES),
            "Select a nonempty, nonduplicate set of known fixture phases")
    return tuple(name for name in PHASES if name in requested)


def successful_scope_status(args):
    return SUCCESS_STATUSES[0] if selected_phases(args) == PHASES else SUCCESS_STATUSES[1]


def plan(args):
    return {"schema_version": 1, "case_id": "LP-026", "status": "PLANNED",
            "scope": "Original A bounded functional prerequisites; no license or performance qualification",
            "phases": {name: "not_run" for name in PHASES},
            "selected_phases": list(selected_phases(args)), "same_run_full_phase_scope": selected_phases(args) == PHASES,
            "successful_scope_status": successful_scope_status(args), "historical_results_combined": False,
            "dictionary_lifetime_seconds": 600, "dictionary_timeout_seconds": args.dictionary_timeout,
            "statistics_timeout_seconds": args.statistics_timeout, "mv_timeout_seconds": args.mv_timeout,
            "statistics_method_binding": {"expected": "SAMPLE", "required_global_huge_table_lower_bound_size_in_bytes": 0,
                                          "unpartitioned_owned_table": True, "FULL_algorithm_proven": False},
            "total_work_timeout_seconds": args.timeout, "cleanup_timeout_seconds": 180,
            "cleanup_timeout_scope": "controlled cleanup work; bounded local shutdown grace is additional",
            "local_shutdown_grace_seconds": {"child_term": 3, "child_kill": 3, "broker_exit": 10,
                                               "es_handlers_total": 5, "observer_join": 3, "output_join": 2},
            "resource_limits": dict(resources_module.LIMITS), "resource_limits_are_sampled": True,
            "poll_seconds": args.poll_seconds,
            "full_contract_retained": {"dataset": "bench_small_plus_write_target", "concurrency": [1, 8, 32],
                                       "warmup_seconds": 180, "window_seconds": 600, "required_pairs": 5,
                                       "phases": ["valid_equivalent_workload", "expired_allowed_background",
                                                  "expired_denial_semantics"]},
            "small_inputs_only_functional": True, "LP026_complete": False, "release_performance_pass": False,
            "runtime_license_enforcement_proven": False, "tool_tests_executed": False,
            "pending": ["Compile and test current helpers after the active benchmark",
                        "Real original-A probes and exact source/package compatibility",
                        "Verify sampled RSS budgets, CPU/IO/namespace-network telemetry and bounded output",
                        "Full load/connection/state matrices and frozen precision criteria",
                        "Candidate FE admission and zero-business-outbound denial assertions"]}


def process_ticks(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    return text[text.rfind(")") + 2:].split()[19]


def is_owned_benchmark(argv, cwd):
    classes = {"LicensePrimitiveCostProbe", "LicenseJdbcBaseline", "LicenseKafkaBaseline", "LicenseKafkaFixture"}
    scripts = {"measure_license_primitives.py", "run_performance_baseline.py", "calibrate_read_capacity.py",
               "stream_load_baseline.py", "complex_planning_fixture.py", "ui_baseline_fixture.py",
               "ui_concurrent_fixture.py", "background_http_fixture.py", "kafka_routine_fixture.py",
               "kafka_routine_baseline.py", "review_public_trust.py"}
    node_scripts = {"LicenseUiConcurrentFixture.cjs", "LicenseUiBaselineFixture.cjs"}
    if not argv:
        return False
    cwd = Path(cwd).resolve()
    executable = Path(argv[0]).name
    script = None
    accepted_scripts = scripts | node_scripts
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable):
        accepted_scripts = scripts
        arguments = iter(argv[1:])
        for argument in arguments:
            if argument == "--":
                script = next(arguments, None)
                break
            if argument in ("-W", "-X"):
                next(arguments, None)
                continue
            if argument.startswith(("-c", "-m")):
                # A module, command string or its arguments is not the controller script.
                return False
            if argument.startswith("-"):
                continue
            script = argument
            break
    elif executable in ("node", "nodejs"):
        accepted_scripts = node_scripts
        arguments = iter(argv[1:])
        for argument in arguments:
            if argument == "--":
                script = next(arguments, None)
                break
            if argument in ("-r", "--require", "--import"):
                next(arguments, None)
                continue
            if argument in ("-e", "--eval", "-p", "--print", "-c", "--check", "--test") \
                    or argument.startswith(("--eval=", "--print=", "--test=")):
                return False
            if argument.startswith("-"):
                continue
            script = argument
            break
    elif executable in scripts | node_scripts:
        script = argv[0]
    if script is not None:
        candidate = Path(script)
        if candidate.name not in accepted_scripts:
            return False
        resolved = (candidate if candidate.is_absolute() else cwd / candidate).resolve()
        return resolved == SOURCE.parent / candidate.name
    if executable != "java" or not any(argument in classes for argument in argv):
        return False
    owner = cwd == ROOT or ROOT in cwd.parents
    absolute_input = any(arg == str(ROOT) or arg.startswith(str(ROOT) + os.sep) for arg in argv)
    return owner or absolute_input


def no_active_benchmark():
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal() or int(entry.name) == os.getpid():
            continue
        try:
            argv = [arg.decode("utf-8", "replace") for arg in (entry / "cmdline").read_bytes().split(b"\0") if arg]
            cwd = os.readlink(entry / "cwd")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if is_owned_benchmark(argv, cwd):
            raise ValueError("An owned timed workload is active; functional probes must wait")


def validate_jdk_release(release, expected_runtime):
    require(release.get("JAVA_VERSION") == "17.0.4", "The fixture requires actual JDK 17.0.4")
    builds = [release[key] for key in ("JAVA_RUNTIME_VERSION", "FULL_VERSION") if key in release]
    require(builds and all(value == expected_runtime for value in builds),
            "Exact JDK runtime build differs from the declared input")


def cluster_identity(args):
    state, _ = fixture.validate_cluster(args.cluster_record)
    installation = fixture.owned(state["installation"])
    package = Path(state["package"]).resolve(strict=True)
    require(ROOT in package.parents, "Original package must belong to this checkout")
    for name in ("query_port", "http_port"):
        values = re.findall(r"(?m)^" + name + r"\s*=\s*(\d+)\s*$",
                            (installation / "fe/conf/fe.conf").read_text())
        require(len(values) == 1 and int(values[0]) == state[name], "Owned FE " + name + " mismatch")
    for name, relative, expected in (("fe_jar_sha256", "fe/lib/doris-fe.jar", args.expected_fe_sha256),
                                     ("be_binary_sha256", "be/lib/doris_be", args.expected_be_sha256)):
        require(re.fullmatch(r"[a-f0-9]{64}", expected or ""), "Explicit original artifact SHA256 is required")
        require(state[name] == expected and fixture.digest(package / relative) == expected,
                "Original package artifact differs from its explicit frozen identity")
    java_home = Path(state["java_home"]).resolve(strict=True)
    release = dict(re.findall(r'^([A-Z_]+)="([^"]*)"$', (java_home / "release").read_text(), re.M))
    validate_jdk_release(release, args.jdk_runtime_version)
    services = {}
    for component in ("fe", "be"):
        pid = int((installation / component / "bin" / (component + ".pid")).read_text())
        ticks = process_ticks(pid)
        executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        expected_executable = java_home / "bin/java" if component == "fe" else package / "be/lib/doris_be"
        require(executable == expected_executable.resolve(strict=True), "Live service executable differs from binding")
        require(process_ticks(pid) == ticks, "Service identity changed during validation")
        services[component] = {"pid": pid, "start_ticks": ticks, "executable": str(executable)}
    supervisor = int(state["supervisor_pid"])
    require(supervisor > 1 and os.readlink(f"/proc/{supervisor}/ns/net") == state["namespace"],
            "Owned namespace supervisor is not live")
    state = dict(state)
    state["verified_identity"] = {"services": services, "supervisor_pid": supervisor,
                                  "supervisor_start_ticks": process_ticks(supervisor), "jdk_release": release,
                                  "cluster_record_sha256": fixture.digest(args.cluster_record)}
    validate_live_identity(state)
    return state


def validate_live_identity(state):
    """Recheck the originally pinned processes before and after every controlled request."""
    identity, namespace = state["verified_identity"], state["namespace"]
    require(namespace != state["host_namespace"] and os.readlink("/proc/self/ns/net") == namespace,
            "Controller left the original private namespace")
    supervisor = identity["supervisor_pid"]
    require(process_ticks(supervisor) == identity["supervisor_start_ticks"]
            and os.readlink(f"/proc/{supervisor}/ns/net") == namespace,
            "Original namespace supervisor identity changed")
    for component, pinned in identity["services"].items():
        pid = pinned["pid"]
        pid_file = Path(state["installation"]) / component / "bin" / (component + ".pid")
        require(int(pid_file.read_text()) == pid and process_ticks(pid) == pinned["start_ticks"]
                and os.readlink(f"/proc/{pid}/ns/net") == namespace
                and str(Path(f"/proc/{pid}/exe").resolve(strict=True)) == pinned["executable"],
                "Original " + component + " identity changed; refuse SQL/HTTP against a replacement")
    return True


class Cancelled(RuntimeError):
    pass


class Budget:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds
        self.cancelled = False
        self.cleanup = False
        self.resources = None
        self.resource_failure = None

    def checkpoint(self):
        if not self.cleanup:
            if self.resources:
                self.resources.check()
            require(self.resource_failure is None, "Background helper output resource failure")
        if self.cancelled and not self.cleanup:
            raise Cancelled("Fixture cancelled")
        require(time.monotonic() < self.deadline, "Fixture time budget expired")

    def seconds(self, cap):
        self.checkpoint()
        return max(0.001, min(cap, self.deadline - time.monotonic()))

    def begin_cleanup(self):
        self.cleanup = True
        self.deadline = time.monotonic() + 180
        if self.resources:
            self.resources.begin_cleanup()

    def abort_requested(self):
        return not self.cleanup and (self.cancelled or self.resource_failure is not None
                                     or bool(self.resources and self.resources.failed.is_set()))

    def pause(self, seconds):
        deadline = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < deadline:
            self.checkpoint()
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        self.checkpoint()


class Processes:
    def __init__(self, budget, output, namespace, resources=None):
        self.budget, self.output, self.namespace = budget, output, namespace
        self.children = []
        self.resources, self.outputs = resources, {}

    def await_exec_identity(self, process, record):
        """Bound the initial /proc exec transition before registering an immutable helper pin."""
        deadline = min(self.budget.deadline, time.monotonic() + 2)
        expected_executable = str(Path(record["expected_executable"]).resolve(strict=True))
        attempts = 0
        record["exec_identity_observations"] = []
        while True:
            self.budget.checkpoint()
            require(process.poll() is None, "Helper exited before exact exec identity was available")
            require(time.monotonic() < deadline, "Helper exec identity did not settle within two seconds")
            attempts += 1
            try:
                pin = resources_module.process_identity(process.pid)
                reason = "exact" if (pin["executable"] == expected_executable
                                     and pin["command_sha256"] == record["launch_command_sha256"]) else "exec_mismatch"
            except (FileNotFoundError, ProcessLookupError, ValueError) as error:
                # exec can temporarily expose an empty cmdline or unavailable executable.
                # No identity from this incomplete observation is accepted or registered.
                pin = None
                reason = "incomplete_proc_" + type(error).__name__
            if len(record["exec_identity_observations"]) < 16:
                record["exec_identity_observations"].append({"attempt": attempts, "reason": reason,
                    "observed_command_sha256": pin["command_sha256"] if pin else None})
            require(process_ticks(process.pid) == record["start_ticks"]
                    and os.readlink(f"/proc/{process.pid}/ns/net") == self.namespace,
                    "Helper identity changed while awaiting exec")
            if pin and pin["executable"] == expected_executable \
                    and pin["command_sha256"] == record["launch_command_sha256"]:
                require(str(pin["start_ticks"]) == str(record["start_ticks"])
                        and pin["namespace"] == self.namespace, "Helper exec pin differs from original child")
                record["exec_identity_attempts"] = attempts
                record["exec_identity"] = pin
                return
            self.budget.pause(min(0.01, max(0, deadline - time.monotonic())))

    def start(self, command, name, background=False):
        self.budget.checkpoint()
        require(not any(os.environ.get(key) for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH")),
                "Ambient JVM/classpath injection is outside the frozen helper identity")
        process = subprocess.Popen([str(value) for value in command], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        record = {"name": name, "pid": process.pid, "start_ticks": None, "namespace": None, "stopped": False,
                  "launch_command_sha256": sha(b"\0".join(os.fsencode(str(arg)) for arg in command) + b"\0"),
                  "expected_executable": str(command[0])}
        self.children.append((process, record))
        try:
            record["start_ticks"] = process_ticks(process.pid)
            record["namespace"] = os.readlink(f"/proc/{process.pid}/ns/net")
            require(record["namespace"] == self.namespace, "Helper escaped the owned network namespace")
            self.await_exec_identity(process, record)
            if self.resources:
                self.resources.register_child(process, record, command)
            if background:
                if self.resources:
                    capture = self.resources.attach_output(process, name)
                else:
                    def failed(scope, kind):
                        self.budget.resource_failure = (scope, kind)
                    capture = resources_module.BoundedOutput(process, self.output, name, failed)
                    capture.start()
                self.outputs[process.pid] = capture
            self.budget.checkpoint()
        except BaseException:
            try:
                self.stop(process)
            finally:
                if process.pid not in self.outputs:
                    for stream in (process.stdout, process.stderr):
                        if stream:
                            stream.close()
            raise
        return process

    def signal_if_live(self, process, record, signum):
        if process.poll() is not None:
            return
        try:
            ticks = process_ticks(process.pid)
            require(ticks == record["start_ticks"], "Refuse to signal a replaced or foreign helper")
            namespace = os.readlink(f"/proc/{process.pid}/ns/net")
        except (FileNotFoundError, ProcessLookupError):
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                raise ValueError("Helper identity unavailable while the owned child remains live") from None
            return
        require(ticks == record["start_ticks"] and namespace == self.namespace,
                "Refuse to signal a replaced or foreign helper")
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                raise ValueError("Helper process group vanished without an owned child exit receipt") from None

    def stop(self, process):
        record = next(item for child, item in self.children if child is process)
        if record.get("stopped"):
            return record
        if process.poll() is None:
            self.signal_if_live(process, record, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.signal_if_live(process, record, signal.SIGKILL)
                process.wait(timeout=3)
        record.update(stopped=True, exit_code=process.returncode)
        if process.pid in self.outputs:
            self.outputs[process.pid].stop()
            record["output"] = self.outputs[process.pid].summary()
        else:
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()
        if self.resources:
            self.resources.retire_child(record, process.returncode)
        return record

    def run(self, command, name, timeout=75):
        process = self.start(command, name)
        primary_error = None
        try:
            stdout, stderr = read_process_output(process, self.budget, timeout)
            save(self.output / (name + "-process.json"),
                 {"exit_code": process.returncode, "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                  "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)})
            return process.returncode, stdout
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_errors = []
            try:
                self.stop(process)
            except BaseException as error:
                cleanup_errors.append(error)
            finally:
                for stream in (process.stdout, process.stderr):
                    if stream:
                        try:
                            stream.close()
                        except BaseException as error:
                            cleanup_errors.append(error)
            if cleanup_errors:
                record = next((item for child, item in self.children if child is process), None)
                if record is not None:
                    record["initial_cleanup_errors"] = [safe_error(error) for error in cleanup_errors]
                self.budget.resource_failure = (name, "helper_cleanup_error")
                # Keep the operation's original failure; partial cleanup gets its own evidence and final retry.
                if primary_error is None:
                    raise cleanup_errors[0]

    def stop_all(self):
        receipts = []
        for process, record in reversed(self.children):
            try:
                receipts.append(self.stop(process))
            except BaseException as error:
                receipts.append({**record, "cleanup_error": safe_error(error)})
        return receipts


def read_process_output(process, budget, timeout):
    """Drain both pipes while limiting memory and elapsed time, including silent children."""
    deadline = min(budget.deadline, time.monotonic() + timeout)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    with selectors.DefaultSelector() as selected:
        for name in buffers:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selected.register(stream, selectors.EVENT_READ, name)
        while selected.get_map():
            budget.checkpoint()
            remaining = deadline - time.monotonic()
            require(remaining > 0, "Helper absolute deadline expired")
            for key, _ in selected.select(min(0.2, remaining)):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selected.unregister(key.fileobj)
                    continue
                require(len(buffers[key.data]) + len(chunk) <= MAX_RESPONSE, "Helper output exceeds bound")
                buffers[key.data].extend(chunk)
        budget.checkpoint()
        remaining = deadline - time.monotonic()
        require(remaining > 0, "Helper absolute deadline expired")
        while process.poll() is None:
            budget.checkpoint()
            remaining = deadline - time.monotonic()
            require(remaining > 0, "Helper absolute deadline expired")
            try:
                process.wait(timeout=min(0.2, remaining))
            except subprocess.TimeoutExpired:
                pass
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


class Sql:
    def __init__(self, args, state, output, processes, classpath):
        self.args, self.state, self.output, self.processes = args, state, output, processes
        self.classpath, self.sequence = classpath, 0
        self.database = None

    def execute(self, statements, continue_on_error=False):
        self.processes.budget.checkpoint()
        validate_live_identity(self.state)
        self.sequence += 1
        prefix = list(SETTINGS)
        if self.database:
            prefix.append("USE " + identifier(self.database))
        requested = prefix + list(statements)
        config = self.output / f"sql-{self.sequence:04d}.json"
        save(config, {"query_port": self.state["query_port"], "user": self.args.user,
                      "password_env": self.args.password_env, "sql": requested,
                      "continue_on_error": continue_on_error})
        code, raw = self.processes.run([Path(self.state["java_home"]) / "bin/java", "-Xmx256m", "-cp",
                                       self.classpath, "LicenseFixtureSql", config], config.stem)
        validate_live_identity(self.state)
        secret = os.environ.get(self.args.password_env, "")
        require(not secret or secret.encode() not in raw, "Refuse to archive echoed credentials")
        value = json.loads(raw)
        save(config.with_suffix(".result.json"), value)
        actual = value.get("statements", [])
        require(not value.get("connection_error") and len(actual) == len(requested), "Incomplete SQL execution")
        require(all(item.get("sql") == requested[index] for index, item in enumerate(actual)), "SQL receipt mismatch")
        require(all(item.get("success") is True for item in actual[:len(prefix)]), "SQL session setup failed")
        require(continue_on_error or (code == 0 and value.get("success") is True),
                "SQL fixture failed; see the structured receipt")
        return actual[len(prefix):]

    def one(self, statement):
        return self.execute([statement])[0]


def helper_dependencies(package):
    dependencies = sorted((Path(package) / "fe/lib").glob("*.jar"))
    # fe-common supplies the generated broker types and an older Parquet format copy.
    # The installed Parquet writer/reader must resolve their matching format types first.
    formats = [path for path in dependencies
               if re.fullmatch(r"parquet-format-structures-\d[^/]*\.jar", path.name)]
    require(len(formats) == 1, "Expected one installed Parquet format dependency")
    return [formats[0], *[path for path in dependencies if path != formats[0]]]


def compile_helpers(state, output, processes):
    classes = output / "classes"
    classes.mkdir()
    dependencies = helper_dependencies(state["package"])
    classpath = os.pathsep.join(map(str, [classes, *dependencies]))
    sources = (SQL_SOURCE, BROKER_SOURCE, INPUT_SOURCE)
    require(all(path.is_file() for path in sources), "LP026 helper source is missing")
    frozen = {str(path): fixture.digest(path) for path in [*sources, *dependencies]}
    code, _ = processes.run([Path(state["java_home"]) / "bin/javac", "-J-Xmx256m", "--release", "17", "-proc:none", "-encoding", "UTF-8",
                             "-cp", classpath, "-d", classes, *sources], "compile-helpers", 120)
    require(code == 0, "Fixture helper compilation failed")
    require(all(fixture.digest(Path(path)) == checksum for path, checksum in frozen.items()),
            "Sources or packaged dependencies changed during helper compilation")
    compiled = {str(path.relative_to(classes)): fixture.digest(path) for path in sorted(classes.rglob("*.class"))}
    require(all(name + ".class" in compiled for name in
                ("LicenseFixtureSql", "LicenseReadOnlyBrokerFixture", "LicenseReadOnlyBrokerInputs")),
            "Expected helper classes were not compiled")
    save(output / "helper-identity.json", {"inputs": frozen, "classes": compiled,
                                         "java_home": state["java_home"], "classpath": classpath})
    return classpath


def wait_for(budget, seconds, interval, operation, accepted):
    deadline = min(budget.deadline, time.monotonic() + seconds)
    while True:
        budget.checkpoint()
        value = operation()
        if accepted(value):
            return value
        require(time.monotonic() < deadline, "Bounded fixture state wait expired")
        budget.pause(min(interval, max(0, deadline - time.monotonic())))


def dictionary_state(result, name, previous=-1, backends=None):
    matching = [row for row in rows(result) if row.get("DictionaryName") == name]
    require(len(matching) == 1, "Expected exactly one owned dictionary; empty results are not readiness")
    row = matching[0]
    require(row.get("Status") in ("NORMAL", "LOADING", "OUT_OF_DATE"), "Unexpected dictionary status")
    if row["Status"] != "NORMAL" or integer(row["Version"]) <= previous:
        return False
    update_result = re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}: succeed(?: fix version (\d+))?",
                                 str(row.get("LastUpdateResult", "")))
    require(update_result and (update_result.group(1) is None or update_result.group(1) == row["Version"])
            and row.get("DataDistribution") not in (None, "", "[]", "{}"), "Dictionary has no successful distribution")
    if backends:
        distributions = re.findall(r"(127\.0\.0\.1:\d+) ver=(\d+) memory=(\d+)", row["DataDistribution"])
        require(len(distributions) == len(backends) and {item[0] for item in distributions} == set(backends)
                and all(int(item[1]) == integer(row["Version"]) and int(item[2]) > 0 for item in distributions),
                "Dictionary distribution does not match all owned live backends/current version")
    return True


class DictionaryLog:
    def __init__(self, state, name):
        self.path = fixture.owned(Path(state["installation"]) / "fe/log/fe.log")
        self.stream = self.path.open("rb")
        self.start = self.stream.seek(0, os.SEEK_END)
        self.inode = os.fstat(self.stream.fileno()).st_ino
        self.name = name

    def finish(self):
        try:
            raw = self.stream.read(16 * 1024 * 1024 + 1)
            require(len(raw) <= 16 * 1024 * 1024, "Dictionary log evidence exceeded its bound")
            lines = [line for line in raw.decode("utf-8", "replace").splitlines()
                     if re.search(r"\bdictionary " + re.escape(self.name) + r"\b", line, re.I)]
            require(any("Submit dictionary " + self.name + " refresh task" in line for line in lines),
                    "No server scheduler submission evidence for this dictionary refresh")
            require(any("Dictionary " + self.name + " refresh succeed" in line for line in lines),
                    "No completed server dictionary refresh evidence")
            return {"path": str(self.path), "inode": self.inode, "start_offset": self.start,
                    "bytes_read": len(raw), "range_sha256": sha(raw), "matching_lines": lines}
        finally:
            self.stream.close()


def probe_dictionary(context):
    sql, budget, args = context.sql, context.budget, context.args
    name = context.names["dictionary"]
    backend_rows = rows(sql.one("SHOW BACKENDS"))
    require(backend_rows and all(row.get("Alive") == "true" and row.get("Host") == "127.0.0.1" for row in backend_rows),
            "Dictionary fixture requires all owned loopback backends alive")
    backends = [row["Host"] + ":" + str(integer(row["BePort"])) for row in backend_rows]
    sql.execute(["CREATE TABLE dict_source(k0 INT NOT NULL,payload VARCHAR(64) NOT NULL) "
                 "DUPLICATE KEY(k0) DISTRIBUTED BY HASH(k0) BUCKETS 1 PROPERTIES('replication_num'='1')",
                 "INSERT INTO dict_source VALUES(1,'lp026-a'),(2,'lp026-b')"])
    context.created["dictionary"] = True  # Includes the uncertain-ACK case; name is unique to this run.
    sql.one(f"CREATE DICTIONARY {name} USING dict_source(k0 KEY,payload VALUE) "
            "LAYOUT(HASH_MAP) PROPERTIES('data_lifetime'='600')")
    initial = wait_for(budget, 120, args.poll_seconds, lambda: sql.one("SHOW DICTIONARIES"),
                       lambda result: dictionary_state(result, name, backends=backends))
    initial_row = next(row for row in rows(initial) if row["DictionaryName"] == name)
    version = integer(initial_row["Version"])
    context.dictionary_id = integer(initial_row["DictionaryId"])
    select = lambda keys: "SELECT " + ",".join(
        f"dict_get('{context.names['database']}.{name}','payload',{key}) AS v{key}" for key in keys)
    exact_rows(sql.one(select((1, 2))), [{"v1": "lp026-a", "v2": "lp026-b"}])
    log = DictionaryLog(context.state, name)
    try:
        sql.one("INSERT INTO dict_source VALUES(3,'lp026-c')")
        final = wait_for(budget, args.dictionary_timeout, args.poll_seconds, lambda: sql.one("SHOW DICTIONARIES"),
                         lambda result: dictionary_state(result, name, version, backends))
        oracle = exact_rows(sql.one(select((1, 2, 3))), [{"v1": "lp026-a", "v2": "lp026-b", "v3": "lp026-c"}])
        source = exact_rows(sql.one("SELECT k0,payload FROM dict_source ORDER BY k0"),
                            [{"k0": str(key), "payload": "lp026-" + chr(96 + key)} for key in range(1, 4)])
        evidence = log.finish()
    finally:
        log.stream.close()
    return {"initial": initial_row, "final": rows(final), "dictionary_oracle": oracle,
            "source_oracle": source, "automatic_scheduler_evidence": evidence,
            "explicit_refresh_commands": 0}


def mv_task_ready(result, job_name, old_ids):
    found = [row for row in rows(result) if row.get("JobName") == job_name and row.get("TaskId") not in old_ids]
    require(all(row.get("Status") in ("PENDING", "RUNNING", "SUCCESS") for row in found),
            "Owned MV task failed/cancelled")
    return bool(found) and all(row["Status"] == "SUCCESS" for row in found)


def probe_mv(context):
    sql, name = context.sql, context.names["mv"]
    sql.execute(["CREATE TABLE mv_source(user_id INT NOT NULL,num SMALLINT SUM NOT NULL) "
                 "AGGREGATE KEY(user_id) DISTRIBUTED BY HASH(user_id) BUCKETS 2 PROPERTIES('replication_num'='1')",
                 "INSERT INTO mv_source VALUES(1,1),(1,2),(2,4)"])
    context.created["mv"] = True
    sql.one(f"CREATE MATERIALIZED VIEW {name} BUILD DEFERRED REFRESH AUTO ON MANUAL "
            "DISTRIBUTED BY RANDOM BUCKETS 2 PROPERTIES('replication_num'='1') AS SELECT * FROM mv_source")
    info = rows(sql.one(f"SELECT JobName FROM mv_infos('database'='{context.names['database']}') WHERE Name='{name}'"))
    require(len(info) == 1 and re.fullmatch(r"[A-Za-z0-9_]+", info[0].get("JobName", "")), "Invalid owned MV job identity")
    job = info[0]["JobName"]
    task_sql = ("SELECT TaskId,JobId,JobName,MvId,Status,MvName,MvDatabaseName,ErrorMsg "
                f"FROM tasks('type'='mv') WHERE JobName='{job}' ORDER BY CreateTime ASC")
    context.mv_task_sql = task_sql
    stages, old_ids = [], set()
    for round_number, second_value in ((1, 4), (2, 9)):
        if round_number == 2:
            sql.one("INSERT INTO mv_source VALUES(2,5)")
        before = rows(sql.one(task_sql))
        old_ids.update(row["TaskId"] for row in before)
        sql.one(f"REFRESH MATERIALIZED VIEW {name} AUTO")
        tasks = wait_for(context.budget, context.args.mv_timeout, context.args.poll_seconds,
                         lambda: sql.one(task_sql), lambda result: mv_task_ready(result, job, old_ids))
        new_tasks = [row for row in rows(tasks) if row["TaskId"] not in old_ids]
        require(all(row["MvName"] == name and row["MvDatabaseName"] == context.names["database"] for row in new_tasks),
                "MV task belongs to a different target")
        expected = [{"user_id": "1", "num": "3"}, {"user_id": "2", "num": str(second_value)}]
        oracle = exact_rows(sql.one(f"SELECT user_id,num FROM {name} ORDER BY user_id"), expected)
        exact_rows(sql.one("SELECT user_id,num FROM mv_source ORDER BY user_id"), expected)
        stages.append({"round": round_number, "tasks": new_tasks, "oracle": oracle})
    return {"job_name": job, "rounds": stages, "kind": "manual_submission_real_background_job",
            "synchronous_analyze_executed": False}


def stats_job_ready(result, database):
    result_rows = rows(result)
    require(all(row.get("db_name") == database and row.get("tbl_name") == "stats_source" for row in result_rows),
            "Statistics job belongs to a foreign table")
    require(all(row.get("state") in ("PENDING", "RUNNING", "FINISHED") for row in result_rows),
            "Automatic statistics job failed")
    if not result_rows or not all(row["state"] == "FINISHED" for row in result_rows):
        return False
    require(all(row.get("job_type") == "SYSTEM" and row.get("schedule_type") == "AUTOMATIC" for row in result_rows),
            "Statistics was not a SYSTEM/AUTOMATIC job")
    return True


def check_column_stats(result):
    values = rows(result)
    require(len(values) == 2 and {row.get("column_name") for row in values} == {"k0", "v"},
            "Statistics columns are missing or duplicated")
    for row in values:
        low, high = (1, 3) if row["column_name"] == "k0" else (10, 30)
        require(row.get("method") == "SAMPLE" and row.get("trigger") == "SYSTEM",
                "Expected original zero-threshold SAMPLE system column statistics")
        wanted = {"count": 3, "ndv": 3, "num_null": 0, "min": low, "max": high}
        try:
            require(all(Decimal(row.get(key, "NaN")) == value for key, value in wanted.items()),
                    "Column statistics differs from the independent three-row model")
        except (InvalidOperation, TypeError):
            raise ValueError("Non-numeric column statistics") from None
    return {"expected": {"rows": 3, "ndv": 3, "nulls": 0, "k0": [1, 3], "v": [10, 30]}, "actual": values,
            "analysis_method": "SAMPLE", "FULL_algorithm_proven": False}


def probe_statistics(context):
    sql = context.sql
    settings = {}
    for name in ("enable_auto_analyze", "enable_auto_analyze_internal_catalog", "enable_stats",
                 "auto_analyze_start_time", "auto_analyze_end_time", "huge_table_lower_bound_size_in_bytes"):
        result = rows(sql.one(f"SHOW GLOBAL VARIABLES LIKE '{name}'"))
        require(len(result) == 1 and result[0].get("Variable_name") == name, "Missing global statistics setting")
        settings[name] = result[0].get("Value")
    require(all(str(settings[name]).lower() == "true" for name in
                ("enable_auto_analyze", "enable_auto_analyze_internal_catalog", "enable_stats")),
            "Original global automatic statistics must already be enabled; the fixture does not alter globals")
    require(settings["huge_table_lower_bound_size_in_bytes"] == "0",
            "This frozen natural-statistics input requires the original global zero threshold; do not alter globals")
    sql.execute(["CREATE TABLE stats_source(k0 INT NOT NULL,v INT NOT NULL) DUPLICATE KEY(k0) "
                 "DISTRIBUTED BY HASH(k0) BUCKETS 1 PROPERTIES('replication_num'='1')",
                 "ALTER TABLE stats_source SET ('auto_analyze_policy'='enable')",
                 "INSERT INTO stats_source VALUES(1,10),(2,20),(3,30)"])
    expected = [{"k0": str(key), "v": str(key * 10)} for key in range(1, 4)]
    oracle = exact_rows(sql.one("SELECT k0,v FROM stats_source ORDER BY k0"), expected)
    # No ANALYZE command is issued: the new owned table and real query feed the existing background scheduler.
    jobs = wait_for(context.budget, context.args.statistics_timeout, context.args.poll_seconds,
                    lambda: sql.one("SHOW AUTO ANALYZE stats_source"),
                    lambda result: stats_job_ready(result, context.names["database"]))
    tasks = []
    for job in rows(jobs):
        task_rows = rows(sql.one("SHOW ANALYZE TASK STATUS " + str(integer(job["job_id"]))))
        require(task_rows and all(row.get("state") == "FINISHED" for row in task_rows),
                "Automatic statistics tasks did not all finish")
        tasks.append({"job_id": job["job_id"], "tasks": task_rows})
    stats = check_column_stats(sql.one("SHOW COLUMN STATS stats_source"))
    exact_rows(sql.one("SELECT k0,v FROM stats_source ORDER BY k0"), expected)
    return {"global_settings": settings, "jobs": rows(jobs), "tasks": tasks, "column_stats": stats,
            "source_oracle": oracle, "explicit_analyze_commands": 0,
            "index_stats": sql.one("SHOW INDEX STATS stats_source stats_source")}


def es_payload(method, path, body):
    if method == "GET" and path == "/" and body == b"":
        return {"name": "lp026-fixture", "version": {"number": "7.17.0"}}
    if method == "GET" and path == "/lp026_rows/_mapping" and body == b"":
        return {"lp026_rows": {"mappings": {"properties": {"id": {"type": "integer"},
                                                                   "payload": {"type": "keyword"}}}}}
    if method == "POST" and path == "/lp026_rows/_search":
        require(json.loads(body) == {"query": {"match_all": {}}, "size": 2}, "Unexpected ES search body")
        return {"took": 1, "timed_out": False, "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {"total": {"value": 2, "relation": "eq"}, "max_score": 1.0,
                         "hits": [{"_index": "lp026_rows", "_id": "1", "_score": 1.0,
                                   "_source": {"id": 1, "payload": "lp026-a"}},
                                  {"_index": "lp026_rows", "_id": "2", "_score": 1.0,
                                   "_source": {"id": 2, "payload": "lp026-b"}}]}}
    raise ValueError("Unexpected ES mock route")


class EsRecorder:
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()
        self.write_lock = threading.Lock()
        self.phase, self.events, self.active, self.errors = "setup", [], 0, []
        self.request_count = self.error_count = 0

    def record_error(self, kind):
        with self.lock:
            self.error_count += 1
            if len(self.errors) < 32:
                self.errors.append(kind)

    def respond(self, method, path, body):
        with self.lock:
            require(self.request_count < 128, "ES request budget exceeded")
            self.request_count += 1
            request_id = self.request_count
            phase = self.phase
        status = 200
        try:
            value = es_payload(method, path, body)
        except (ValueError, UnicodeError) as error:
            status, value = 400, {"error": "fixture_request_rejected"}
            self.record_error(type(error).__name__)
        raw = canonical(value)
        event = {"request_id": request_id, "phase": phase, "method": method,
                 "path": path if path in ("/", "/lp026_rows/_mapping", "/lp026_rows/_search") else "<unexpected>",
                 "path_sha256": sha(path.encode()), "request_sha256": sha(body), "request_bytes": len(body),
                 "status": status, "response_sha256": sha(raw), "response_bytes": len(raw),
                 "at_utc": fixture.utc(), "monotonic_ns": time.monotonic_ns()}
        with self.lock:
            self.events.append(event)
        with self.write_lock:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, sort_keys=True) + "\n")
        return status, raw

    def set_phase(self, phase):
        deadline = time.monotonic() + 5
        while True:
            with self.lock:
                if self.active == 0:
                    self.phase = phase
                    return
            require(time.monotonic() < deadline, "Cannot change ES phase with active requests")
            time.sleep(0.01)


class EsHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)
        with self.server.recorder.lock:
            self.server.recorder.active += 1

    def finish(self):
        try:
            super().finish()
        finally:
            with self.server.recorder.lock:
                self.server.recorder.active -= 1

    def do_GET(self):
        self.handle_fixed()

    def do_POST(self):
        self.handle_fixed()

    do_PUT = do_POST
    do_DELETE = do_POST
    do_HEAD = do_POST

    def handle_fixed(self):
        try:
            require(not self.headers.get("Transfer-Encoding"), "Chunked ES input is not supported")
            length = int(self.headers.get("Content-Length", "0"))
            require(0 <= length <= 4096 and len(self.path) <= 256, "ES request exceeds its bound")
            body = self.rfile.read(length)
            require(len(body) == length, "Truncated ES input")
            status, raw = self.server.recorder.respond(self.command, self.path, body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
        except (ValueError, OSError):
            self.server.recorder.record_error("transport_or_bounds")
            self.close_connection = True


class EsServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, recorder):
        self.capacity = threading.BoundedSemaphore(8)
        self.connection_lock = threading.Lock()
        self.connections, self.workers = set(), set()
        super().__init__(("127.0.0.1", 0), EsHandler)
        self.recorder = recorder

    def process_request(self, request, client_address):
        if not self.capacity.acquire(blocking=False):
            self.recorder.record_error("concurrent_connection_bound")
            request.close()
            return
        with self.connection_lock:
            self.connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.connection_lock:
                self.connections.discard(request)
            self.capacity.release()
            request.close()
            raise

    def process_request_thread(self, request, client_address):
        worker = threading.current_thread()
        worker.name = "lp026-es-handler"
        with self.connection_lock:
            self.workers.add(worker)
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.connection_lock:
                self.connections.discard(request)
                self.workers.discard(worker)
            self.capacity.release()

    def stop_requests(self):
        with self.connection_lock:
            connections, workers = list(self.connections), list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        deadline = time.monotonic() + 5
        for worker in workers:
            worker.join(timeout=max(0, deadline - time.monotonic()))
        with self.connection_lock:
            require(not self.connections and not self.workers, "ES handlers did not stop within cleanup bound")
        return {"connections_interrupted": len(connections), "handlers_stopped": True}


def http_request(context, method, path, payload=None):
    require(method in ("GET", "POST") and path.startswith("/rest/v2/api/"), "Unexpected FE HTTP request")
    validate_live_identity(context.state)
    context.budget.checkpoint()
    deadline = min(context.budget.deadline, time.monotonic() + 30)
    secret = os.environ.get(context.args.password_env, "")
    token = base64.b64encode((context.args.user + ":" + secret).encode()).decode()
    headers = {"Authorization": "Basic " + token, "Content-Type": "application/json"}
    request = None if payload is None else canonical(payload)
    connection = http.client.HTTPConnection("127.0.0.1", context.state["http_port"],
                                            timeout=context.budget.seconds(30))
    started = time.monotonic_ns()
    response = watchdog = None
    watchdog_stop = threading.Event()
    try:
        connection.connect()
        transport = connection.sock
        require(transport is not None, "FE HTTP transport was not connected")
        remaining = deadline - time.monotonic()
        require(remaining > 0, "FE HTTP absolute deadline expired")
        # Retain the actual socket: getresponse() may set connection.sock=None for Connection: close.
        def interrupt_transport():
            while not watchdog_stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or context.budget.abort_requested():
                    try:
                        transport.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                watchdog_stop.wait(min(0.1, remaining))
        watchdog = threading.Thread(target=interrupt_transport, name="lp026-http-deadline", daemon=True)
        watchdog.start()
        connection.request(method, path, body=request, headers=headers)
        response = connection.getresponse()
        raw = read_http_body(response, transport, context.budget, deadline)
        validate_live_identity(context.state)
        require(token.encode() not in raw and (not secret or secret.encode() not in raw), "Echoed HTTP credentials")
        content_type = response.getheader("Content-Type", "")
        require(content_type.split(";", 1)[0].lower() == "application/json", "Expected FE JSON content type")
        body = json.loads(raw)
        record = {"method": method, "path": path, "request_body": payload, "http_status": response.status,
                  "content_type": content_type, "body": body, "elapsed_ns": time.monotonic_ns() - started,
                  "credentials_recorded": False, "followed_redirect": False}
        context.http_sequence += 1
        save(context.output / f"http-{context.http_sequence:03d}.json", record)
        require(response.status == 200 and isinstance(body, dict) and type(body.get("code")) is int
                and body["code"] == 0 and body.get("msg") == "success", "FE HTTP transport/business failure")
        return body.get("data")
    finally:
        if watchdog:
            watchdog_stop.set()
            watchdog.join(timeout=1)
        if response:
            response.close()
        connection.close()


def read_http_body(response, transport, budget, deadline):
    raw = bytearray()
    while True:
        budget.checkpoint()
        remaining = deadline - time.monotonic()
        require(remaining > 0, "FE HTTP absolute deadline expired")
        transport.settimeout(remaining)
        chunk = response.read1(min(65536, MAX_RESPONSE + 1 - len(raw)))
        budget.checkpoint()
        require(time.monotonic() < deadline, "FE HTTP absolute deadline expired")
        if not chunk:
            return bytes(raw)
        require(len(raw) + len(chunk) <= MAX_RESPONSE, "FE HTTP response exceeded its bound")
        raw.extend(chunk)
        if response.isclosed():
            return bytes(raw)


def check_es_response(data, catalog, operation):
    require(isinstance(data, dict) and set(data) == {"catalog", "table", "result"}
            and data["catalog"] == catalog and data["table"] == "lp026_rows", "ES FE envelope mismatch")
    result = data["result"]
    if operation == "mapping":
        require(result == {"lp026_rows": {"mappings": {"properties": {"id": {"type": "integer"},
                                                                                  "payload": {"type": "keyword"}}}}},
                "Mapping structure differs from the fixed model")
    else:
        require(result.get("timed_out") is False and result.get("hits", {}).get("total") == {"value": 2, "relation": "eq"},
                "ES search count/timeout mismatch")
        hits = result["hits"].get("hits")
        require(isinstance(hits, list) and len(hits) == 2 and [row.get("_source") for row in hits]
                == [{"id": 1, "payload": "lp026-a"}, {"id": 2, "payload": "lp026-b"}], "ES business values differ")


def probe_es(context):
    recorder = EsRecorder(context.output / "es-requests.jsonl")
    server = EsServer(recorder)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1},
                              name="lp026-es-listener", daemon=True)
    context.es = (server, thread, recorder)
    thread.start()
    catalog = context.names["catalog"]
    require(not any(catalog in row.values() for row in rows(context.sql.one("SHOW CATALOGS"))),
            "Refuse to adopt an existing catalog")
    context.created["catalog"] = True
    context.sql.one(f"CREATE CATALOG {catalog} PROPERTIES('type'='es','hosts'='http://127.0.0.1:{server.server_port}')")
    query = urlencode({"catalog": catalog, "table": "lp026_rows"})
    recorder.set_phase("mapping")
    mapping = http_request(context, "GET", "/rest/v2/api/es_catalog/get_mapping?" + query)
    check_es_response(mapping, catalog, "mapping")
    require(not any(row["path"] == "/lp026_rows/_search" for row in recorder.events), "Mapping caused business search")
    recorder.set_phase("search")
    search = http_request(context, "POST", "/rest/v2/api/es_catalog/search?" + query, SEARCH_BODY)
    check_es_response(search, catalog, "search")
    require(not recorder.errors and any(row["path"] == "/" for row in recorder.events)
            and any(row["path"] == "/lp026_rows/_mapping" for row in recorder.events)
            and any(row["phase"] == "search" and row["path"] == "/lp026_rows/_search" for row in recorder.events),
            "ES required exchange evidence missing or unexpected route occurred")
    return {"mapping": mapping, "search": search, "events": list(recorder.events), "mock_real_es_version": False}


def validate_input_manifest(path, directory):
    directory = fixture.owned(directory)
    manifest = json.loads(path.read_text())
    require(manifest.get("schema_version") == 1 and isinstance(manifest.get("files"), list)
            and len(manifest["files"]) == 2, "Unexpected broker input manifest")
    entries = {}
    for entry in manifest["files"]:
        format_name = entry.get("format")
        require(format_name in FILE_URIS and format_name not in entries and entry.get("uri") == FILE_URIS[format_name],
                "Unexpected or duplicate broker fixture URI")
        file = fixture.owned(entry["path"])
        require(directory in file.parents and not Path(entry["path"]).is_symlink(), "Broker input escaped its owner")
        require(type(entry.get("size")) is int and 0 < entry["size"] <= 8 * 1024 * 1024
                and file.stat().st_size == entry["size"] and fixture.digest(file) == entry.get("sha256"),
                "Broker input content differs from manifest")
        if format_name == "CSV":
            require(file.read_bytes() == CSV_BYTES, "CSV differs from the independent fixed two-row model")
        else:
            with file.open("rb") as stream:
                first = stream.read(4)
                stream.seek(-4, os.SEEK_END)
                require(first == b"PAR1" and stream.read(4) == b"PAR1", "Invalid Parquet boundaries")
        entries[format_name] = entry
    return entries


def validate_loaded_origins(origins, package):
    expected = {"org.apache.parquet.avro.AvroParquetWriter", "org.apache.parquet.hadoop.ParquetFileReader",
                "org.apache.parquet.example.data.simple.convert.GroupRecordConverter", "org.apache.avro.Schema",
                "org.apache.hadoop.conf.Configuration", "org.apache.parquet.format.PageHeader"}
    require(isinstance(origins, dict) and set(origins) == expected, "Missing input helper dependency origins")
    library = (Path(package) / "fe/lib").resolve()
    for name, origin in origins.items():
        require(isinstance(origin, str), "Invalid dependency origin")
        parsed = urlsplit(origin)
        require(parsed.scheme == "file" and parsed.netloc == "" and not parsed.query and not parsed.fragment,
                "Input helper used a nonlocal dependency")
        path = Path(unquote(parsed.path)).resolve()
        require(path.parent == library and path.suffix == ".jar", "Input helper loaded a foreign dependency")
        if name == "org.apache.parquet.format.PageHeader":
            require(re.fullmatch(r"parquet-format-structures-\d[^/]*\.jar", path.name),
                    "Input helper loaded shadowed Parquet format classes")


def check_preview(data, entry, format_name):
    require(isinstance(data, dict) and isinstance(data.get("reviewStatistic"), dict), "Missing preview statistics")
    require(data["reviewStatistic"] == {"fileNumber": 1, "fileSize": entry["size"]}, "Preview file count/size differs")
    sample = data.get("fileSample")
    require(isinstance(sample, dict) and sample.get("sampleFileName") == entry["uri"]
            and sample.get("fileLineNumber") == 2 and sample.get("maxColumnSize") == 2
            and sample.get("sampleFileLines") == [["1", "lp026-a"], ["2", "lp026-b"]],
            "Preview returned incorrect full sample values")
    if format_name == "PARQUET":
        require(sample.get("colNames") == ["id", "payload"], "Parquet schema columns differ")
    else:
        require(sample.get("colNames") in (None, []), "CSV unexpectedly supplied a schema")


def prepare_broker(context):
    directory = context.output / "broker"
    directory.mkdir()
    context.broker_directory = directory
    java = Path(context.state["java_home"]) / "bin/java"
    code, _ = context.processes.run([java, "-Xmx256m", "-cp", context.classpath,
                                    "LicenseReadOnlyBrokerInputs", directory], "broker-inputs", 90)
    require(code == 0, "Independent broker inputs preparation failed")
    manifest_path = directory / "input-manifest.json"
    entries = validate_input_manifest(manifest_path, directory)
    validation = json.loads((directory / "input-validation.json").read_text())
    context.report["broker_input_validation"] = validation
    # Exact independent-reader validation schema is checked in validate_broker_input_validation.
    validate_broker_input_validation(validation, entries)
    validate_loaded_origins(validation.get("loaded_origins"), context.state["package"])
    config = {"namespace": context.state["namespace"], "host_namespace": context.state["host_namespace"],
              "output_directory": str(directory), "input_manifest": str(manifest_path),
              "ready_file": str(directory / "ready.json"), "requests_file": str(directory / "requests.jsonl"),
              "summary_file": str(directory / "summary.json"), "stop_file": str(directory / "stop"),
              "timeout_seconds": 300, "port": 0}
    path = directory / "broker-config.json"
    save(path, config)
    process = context.processes.start([java, "-Xmx256m", "-cp", context.classpath,
                                       "LicenseReadOnlyBrokerFixture", path], "read-only-broker", background=True)
    context.broker_process = process
    ready_path = directory / "ready.json"
    wait_for(context.budget, 20, 0.1, lambda: (process.poll(), ready_path.exists()),
             lambda value: broker_ready_file(value))
    ready = json.loads(ready_path.read_text())
    require(ready.get("schema_version") == 1 and ready.get("bind_address") == "127.0.0.1"
            and ready.get("pid") == process.pid and ready.get("namespace") == context.state["namespace"]
            and str(ready.get("start_ticks")) == process_ticks(process.pid)
            and ready.get("input_manifest_sha256") == fixture.digest(manifest_path)
            and type(ready.get("port")) is int and 1024 <= ready["port"] <= 65535, "Broker readiness identity mismatch")
    context.broker_port = ready["port"]
    context.report["broker_ready"] = ready
    name = context.names["broker"]
    require(not any(row.get("Name") == name for row in rows(context.sql.one("SHOW BROKER"))),
            "Refuse to adopt an existing broker")
    context.created["broker"] = True
    context.sql.one(f'ALTER SYSTEM ADD BROKER {name} "127.0.0.1:{ready["port"]}"')
    wait_for(context.budget, 45, context.args.poll_seconds, lambda: context.sql.one("SHOW BROKER"),
             lambda result: broker_alive(result, name, ready["port"]))
    return entries


def broker_ready_file(value):
    code, exists = value
    require(code is None, "Broker exited before readiness")
    return exists


def broker_alive(result, name, port):
    found = [row for row in rows(result) if row.get("Name") == name]
    require(len(found) == 1 and found[0].get("Host") == "127.0.0.1" and found[0].get("Port") == str(port),
            "Registered broker identity mismatch")
    require(found[0].get("Alive") in ("true", "false"), "Unexpected broker liveness value")
    return found[0]["Alive"] == "true"


def validate_broker_input_validation(value, entries):
    # This exact interface is shared with LicenseReadOnlyBrokerInputs, never inferred from HTTP results.
    expected = [{"id": 1, "payload": "lp026-a"}, {"id": 2, "payload": "lp026-b"}]
    require(value.get("schema_version") == 1 and value.get("schema_valid") is True
            and value.get("independent_reader") == "ParquetFileReader+GroupRecordConverter"
            and value.get("rows_match_model") is True
            and value.get("csv_rows") == expected and value.get("parquet_rows") == expected
            and value.get("csv_sha256") == entries["CSV"]["sha256"]
            and value.get("parquet_sha256") == entries["PARQUET"]["sha256"]
            and value.get("parquet_size") == entries["PARQUET"]["size"],
            "Broker independent input validation is incomplete")


def broker_events(directory):
    path = directory / "requests.jsonl"
    require(path.is_file() and path.stat().st_size <= 8 * 1024 * 1024, "Missing/oversized broker request evidence")
    data = path.read_text()
    # A simultaneous heartbeat may be appending a final line. Completed file-read events are flushed before replies.
    complete = data[:data.rfind("\n") + 1]
    return [json.loads(line) for line in complete.splitlines()]


def check_broker_phase(events, uri, baseline_count):
    observed = events[baseline_count:]
    require(all(row.get("status_name") in ("OK", "END_OF_FILE") for row in observed), "Broker protocol error")
    require(all(row.get("allowed_uri") == uri or row.get("method") == "ping" for row in observed),
            "Preview accessed a different broker input")
    matching = [row for row in observed if row.get("allowed_uri") == uri]
    methods = {row.get("method") for row in matching}
    require({"listPath", "openReader", "pread"} <= methods, "Preview did not exercise real broker listing/open/read")
    require(any(row.get("method") == "pread" and row.get("returned_bytes", 0) > 0 for row in matching),
            "Preview has no actual file bytes")
    return {"uri": uri, "events": matching, "open_count": sum(row.get("method") == "openReader" for row in matching),
            "close_count": sum(row.get("method") == "closeReader" for row in matching)}


def check_broker_summary(value, ready, events):
    require(value.get("schema_version") == 1 and value.get("pid") == ready.get("pid")
            and value.get("namespace") == ready.get("namespace")
            and value.get("input_manifest_sha256") == ready.get("input_manifest_sha256"),
            "Final broker identity differs from readiness")
    require(value.get("stop_reason") == "stop_file" and value.get("protocol_errors") == 0
            and value.get("active_readers") == 0 and value.get("worker_threads_terminated") is True
            and value.get("evidence_error") is False, "Broker cleanup or evidence remained incomplete")
    require(value.get("active_readers_before_cleanup") == 0 and value.get("cleanup_closed_readers") == 0,
            "Original FE left broker readers open; forced cleanup is not client cleanup")
    counts, statuses = {}, {}
    for index, event in enumerate(events, 1):
        require(event.get("schema_version") == 1 and event.get("request_id") == index,
                "Broker request evidence is missing or reordered")
        require(event.get("status_name") in ("OK", "END_OF_FILE"), "Broker request failed")
        method, status = event.get("method"), event["status_name"]
        counts[method] = counts.get(method, 0) + 1
        statuses[status] = statuses.get(status, 0) + 1
    require(value.get("requests") == len(events) and value.get("counts") == counts
            and value.get("status_counts") == statuses
            and value.get("returned_bytes") == sum(event["returned_bytes"] for event in events),
            "Broker summary does not reconcile with complete request evidence")
    return value


class Context:
    def __init__(self, args, output, report, state, budget, processes, classpath):
        self.args, self.output, self.report, self.state = args, output, report, state
        self.budget, self.processes, self.classpath = budget, processes, classpath
        token = uuid.uuid4().hex
        self.names = {"database": "lp026_" + token, "dictionary": "dict_" + token,
                      "mv": "mv_" + token, "catalog": "lp026_es_" + token, "broker": "lp026_broker_" + token}
        self.sql = Sql(args, state, output, processes, classpath)
        self.created, self.http_sequence = {}, 0
        self.es = self.broker_process = self.broker_directory = self.broker_port = self.mv_task_sql = None
        self.dictionary_id = None

    def stage(self, name, action):
        self.budget.checkpoint()
        no_active_benchmark()
        validate_live_identity(self.state)
        self.report["phases"][name] = {"status": "RUNNING", "started_at_utc": fixture.utc()}
        save(self.output / "report.json", self.report)
        result = action()
        validate_live_identity(self.state)
        self.report["phases"][name].update(status="FUNCTIONAL_PREREQUISITE_PASS", result=result,
                                          finished_at_utc=fixture.utc())
        save(self.output / "report.json", self.report)


def cleanup(context):
    """Try every independent cleanup even if earlier SQL or evidence publication fails."""
    result = {"steps": [], "errors": []}
    urgent = context.budget.abort_requested()
    context.budget.begin_cleanup()

    def attempt(name, action):
        try:
            value = action()
            if isinstance(value, list):
                require(all(not isinstance(item, dict) or "sql" not in item or item.get("success") is True
                            for item in value), "A cleanup SQL operation failed")
            result["steps"].append({"name": name, "result": value})
        except BaseException as error:
            result["errors"].append({"name": name, **safe_error(error)})

    local_stopped = False
    def stop_local():
        nonlocal local_stopped
        if local_stopped:
            return
        local_stopped = True
        if context.es:
            server, thread, recorder = context.es
            if thread.is_alive():
                attempt("es_shutdown", server.shutdown)
            attempt("es_close", server.server_close)
            attempt("es_stop_active_requests", server.stop_requests)
            attempt("es_thread_join", lambda: thread.join(timeout=5))
            if thread.is_alive() or recorder.active:
                result["errors"].append({"name": "es_shutdown", "message": "ES thread/request remains active"})
            if getattr(recorder, "errors", []):
                result["errors"].append({"name": "es_recorder", "errors": list(recorder.errors),
                                         "error_count": recorder.error_count})
        if context.broker_directory:
            attempt("broker_stop_marker", lambda: (context.broker_directory / "stop").touch(exist_ok=False))
        if context.broker_process:
            attempt("broker_graceful_exit", lambda: context.broker_process.wait(timeout=10))
        result["processes"] = context.processes.stop_all()

    if urgent:
        # Resource failures/cancellation release local pressure before any potentially slow cleanup SQL.
        stop_local()
    sql, names = context.sql, context.names
    if context.created.get("database"):
        if context.created.get("mv"):
            def cancel_mv():
                if not context.mv_task_sql:
                    return []
                tasks = rows(sql.one(context.mv_task_sql))
                pending = [row for row in tasks if row.get("Status") in ("PENDING", "RUNNING")]
                return sql.execute([f"CANCEL MATERIALIZED VIEW TASK {integer(row['TaskId'])} ON {names['mv']}"
                                    for row in pending], continue_on_error=True) if pending else []
            attempt("cancel_owned_mv_tasks", cancel_mv)
        def cancel_stats():
            existing = rows(sql.one("SHOW TABLES"))
            if not any("stats_source" in row.values() for row in existing):
                return []
            jobs = rows(sql.one("SHOW AUTO ANALYZE stats_source"))
            pending = [row for row in jobs if row.get("state") in ("PENDING", "RUNNING")]
            return sql.execute(["KILL ANALYZE " + str(integer(row["job_id"])) for row in pending],
                               continue_on_error=True) if pending else []
        attempt("cancel_owned_statistics", cancel_stats)
        if context.created.get("dictionary"):
            def drop_dictionary():
                path = fixture.owned(Path(context.state["installation"]) / "fe/log/fe.log")
                with path.open("rb") as stream:
                    start = stream.seek(0, os.SEEK_END)
                    present = [row for row in rows(sql.one("SHOW DICTIONARIES"))
                               if row.get("DictionaryName") == names["dictionary"]]
                    require(len(present) <= 1, "Ambiguous owned dictionary during cleanup")
                    if present:
                        context.dictionary_id = integer(present[0]["DictionaryId"])
                    receipt = sql.one(f"DROP DICTIONARY IF EXISTS {names['dictionary']}")
                    require(not any(row.get("DictionaryName") == names["dictionary"]
                                    for row in rows(sql.one("SHOW DICTIONARIES"))), "Dictionary metadata remains")
                    if context.dictionary_id is None:
                        return {"receipt": receipt, "dictionary_absent_before_and_after_drop": True}
                    observed = bytearray()
                    marker = f"Unload data of dictionary {context.dictionary_id} succeed".encode()
                    def unloaded():
                        observed.extend(stream.read(65536))
                        require(len(observed) <= 16 * 1024 * 1024, "Dictionary unload log bound exceeded")
                        return marker in observed
                    wait_for(context.budget, 30, 1, unloaded, bool)
                    return {"receipt": receipt, "dictionary_id": context.dictionary_id, "unload_log_start": start,
                            "unload_log_range_sha256": sha(observed), "server_unload_success": True}
            attempt("drop_dictionary_and_observe_unload", drop_dictionary)
        if context.created.get("mv"):
            attempt("drop_mv", lambda: sql.execute([f"DROP MATERIALIZED VIEW IF EXISTS {names['mv']}"],
                                                    continue_on_error=True))
        sql.database = None
        attempt("drop_database", lambda: sql.one("DROP DATABASE IF EXISTS " + names["database"]))
        def database_absent():
            remaining = rows(sql.one("SHOW DATABASES"))
            require(not any(names["database"] in row.values() for row in remaining), "Owned database remains")
            return True
        attempt("database_absent", database_absent)
    if context.created.get("catalog"):
        attempt("drop_catalog", lambda: sql.one("DROP CATALOG IF EXISTS " + names["catalog"]))
        def catalog_absent():
            require(not any(names["catalog"] in row.values() for row in rows(sql.one("SHOW CATALOGS"))), "Owned catalog remains")
            return True
        attempt("catalog_absent", catalog_absent)
    if context.created.get("broker"):
        attempt("drop_broker", lambda: sql.one(f'ALTER SYSTEM DROP BROKER {names["broker"]} "127.0.0.1:{context.broker_port}"'))
        def broker_absent():
            require(not any(row.get("Name") == names["broker"] for row in rows(sql.one("SHOW BROKER"))), "Owned broker remains")
            return True
        attempt("broker_absent", broker_absent)
    # Process shutdown never depends on successful parsing or writing of auxiliary evidence.
    stop_local()
    if urgent:
        result["processes"] = context.processes.stop_all()
    if context.broker_directory and (context.broker_directory / "summary.json").exists():
        def summary():
            value = json.loads((context.broker_directory / "summary.json").read_text())
            context.report["broker_final_summary"] = value
            events_path = context.broker_directory / "requests.jsonl"
            events = broker_events(context.broker_directory)
            require(events_path.read_bytes().endswith(b"\n"), "Broker left incomplete request evidence")
            return check_broker_summary(value, context.report["broker_ready"], events)
        attempt("broker_summary", summary)
    elif context.broker_process:
        result["errors"].append({"name": "broker_summary", "message": "Missing final broker shutdown summary"})
    result["complete"] = not result["errors"] and all(item.get("stopped") and not item.get("cleanup_error")
                                                      for item in result["processes"])
    return result


def probe(args, output, report):
    no_active_benchmark()
    state = cluster_identity(args)
    require(args.cpu in os.sched_getaffinity(0), "Requested fixture CPU is unavailable")
    os.sched_setaffinity(0, {args.cpu})
    report.update(status="RUNNING", started_at_utc=fixture.utc(), actual_cpu_affinity=sorted(os.sched_getaffinity(0)),
                  original_identity=state["verified_identity"], namespace=state["namespace"],
                  source_sha256={str(path): fixture.digest(path)
                                 for path in (SOURCE, RESOURCE_SOURCE, SQL_SOURCE, BROKER_SOURCE, INPUT_SOURCE)})
    budget = Budget(args.timeout)
    resources = resources_module.ResourceGuard(output, state)
    budget.resources = resources
    processes = Processes(budget, output, state["namespace"], resources=resources)
    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}

    def cancelled(signum, frame):
        budget.cancelled = True
        # The bounded pipe reader/HTTP deadline releases the active operation before independent cleanup.

    for signum in previous:
        signal.signal(signum, cancelled)
    context = None
    try:
        resources.start()
        classpath = compile_helpers(state, output, processes)
        context = Context(args, output, report, state, budget, processes, classpath)
        report["owned_names"] = context.names
        require(not any(context.names["database"] in row.values() for row in rows(context.sql.one("SHOW DATABASES"))),
                "Refuse to adopt an existing database")
        context.created["database"] = True
        context.sql.one("CREATE DATABASE " + context.names["database"])
        context.sql.database = context.names["database"]
        report["original_http_auth"] = context.sql.one("ADMIN SHOW FRONTEND CONFIG LIKE '%enable_all_http_auth'")
        selected = selected_phases(args)
        for name, action in (("dictionary", probe_dictionary), ("mv", probe_mv),
                             ("statistics", probe_statistics), ("es", probe_es)):
            if name in selected:
                context.stage(name, lambda action=action: action(context))
        entries = prepare_broker(context) if any(name.startswith("file_review_") for name in selected) else {}
        for format_name, phase in (("CSV", "file_review_csv"), ("PARQUET", "file_review_parquet")):
            if phase not in selected:
                continue
            def preview(format_name=format_name):
                before = len(broker_events(context.broker_directory))
                entry = entries[format_name]
                payload = {"fileInfo": {"columnSeparator": ",", "fileUrl": entry["uri"], "format": format_name},
                           "connectInfo": {"brokerName": context.names["broker"],
                                           "brokerProps": {"broker.name": context.names["broker"]}}}
                data = http_request(context, "POST", "/rest/v2/api/import/file_review", payload)
                check_preview(data, entry, format_name)
                evidence = check_broker_phase(broker_events(context.broker_directory), entry["uri"], before)
                require(evidence["open_count"] == evidence["close_count"],
                        "Original preview left a broker reader open; preserve failure and stop bounded helper")
                return {"response": data, "broker": evidence}
            context.stage(phase, preview)
        validate_live_identity(state)
        budget.checkpoint()
        report["status"] = successful_scope_status(args)
    except BaseException as error:
        report["status"], report["error"] = "FAILED", safe_error(error)
        for value in report["phases"].values():
            if isinstance(value, dict) and value.get("status") == "RUNNING":
                value.update(status="FAILED", error=safe_error(error))
        raise
    finally:
        try:
            if context:
                report["cleanup"] = cleanup(context)
                if not report["cleanup"]["complete"]:
                    report["status"] = "FAILED"
                elif report["status"] in SUCCESS_STATUSES:
                    try:
                        validate_live_identity(state)
                        report["original_identity_rechecked_after_cleanup"] = True
                    except BaseException as error:
                        report["status"], report["error"] = "FAILED", safe_error(error)
            else:
                report["cleanup"] = {"processes": processes.stop_all()}
        finally:
            # These fallbacks run even if SQL cleanup or auxiliary evidence handling itself failed.
            try:
                report["final_process_cleanup"] = processes.stop_all()
            finally:
                try:
                    report["resources"] = resources.stop()
                    if not report["resources"]["complete"]:
                        report["status"] = "FAILED"
                except BaseException as error:
                    report["status"], report["resource_cleanup_error"] = "FAILED", safe_error(error)
                finally:
                    for signum, handler in previous.items():
                        signal.signal(signum, handler)
                    report["finished_at_utc"] = fixture.utc()
                    save(output / "report.json", report)
    require(report["status"] in SUCCESS_STATUSES, "Fixture cleanup was incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "probe"), default="plan")
    parser.add_argument("--phases", nargs="+", choices=PHASES, default=list(PHASES),
                        help="Run selected phases in canonical order; default is all six; omitted phases stay not_run")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cluster-record", type=Path)
    parser.add_argument("--expected-fe-sha256")
    parser.add_argument("--expected-be-sha256")
    parser.add_argument("--jdk-runtime-version", default="17.0.4+8")
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_BASELINE_PASSWORD")
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=2400)
    parser.add_argument("--dictionary-timeout", type=int, default=750)
    parser.add_argument("--statistics-timeout", type=int, default=300)
    parser.add_argument("--mv-timeout", type=int, default=120)
    parser.add_argument("--poll-seconds", type=float, default=5)
    args = parser.parse_args()
    require(1800 <= args.timeout <= 3600 and 610 <= args.dictionary_timeout <= 900
            and 120 <= args.statistics_timeout <= 600 and 60 <= args.mv_timeout <= 300
            and 1 <= args.poll_seconds <= 15, "Fixture bounds are outside their declared ranges")
    require(re.fullmatch(r"[A-Z][A-Z0-9_]*", args.password_env), "Invalid password environment name")
    require(re.fullmatch(r"[A-Za-z0-9_]+", args.user), "Use a simple explicitly selected test account")
    if args.mode == "probe":
        require(args.cluster_record is not None and args.expected_fe_sha256 and args.expected_be_sha256,
                "probe requires an owned cluster record and explicit original FE/BE hashes")
    output = fixture.owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    report = plan(args)
    save(output / "plan.json", report)
    try:
        if args.mode == "probe":
            probe(args, output, report)
    except BaseException as error:
        report["status"] = "FAILED"
        report.setdefault("error", safe_error(error))
        raise
    finally:
        save(output / "report.json", report)
    print(json.dumps({"status": report["status"], "report": str(output / "report.json"),
                      "LP026_complete": False, "release_performance_pass": False}), flush=True)


if __name__ == "__main__":
    main()
