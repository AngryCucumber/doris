#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Plan an owned 3-voter FE / 4-BE topology; launching requires an explicit frozen resource profile."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve()
SQL_SOURCE = SOURCE.with_name("LicenseFixtureSql.java")
NAMES = ("fe1", "fe2", "fe3", "be1", "be2", "be3", "be4")
FE_PORTS = {"http_port": 28030, "query_port": 29030, "rpc_port": 29020,
            "edit_log_port": 29010, "arrow_flight_sql_port": 28070}
BE_PORTS = {"be_port": 29060, "heartbeat_service_port": 29050, "brpc_port": 28060,
            "webserver_port": 28040, "arrow_flight_sql_port": 28050}


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def read(path):
    return json.loads(Path(path).read_text())


def cleanup_save(path, state):
    """Archival failures must not skip process cleanup or result in a clean exit code."""
    try:
        save(path, state)
    except (OSError, ValueError, TypeError) as error:
        state.setdefault("archive_errors", []).append(type(error).__name__ + ": " + str(error))
        state["status"] = "CLEANUP_FAILED"
        print("Cleanup evidence could not be saved: " + str(path), file=sys.stderr, flush=True)


def owned(path, parent):
    resolved = Path(path).resolve()
    if Path(parent).resolve() not in resolved.parents:
        raise ValueError("Path must be a child of " + str(parent))
    # Original launcher scripts evaluate uppercase config values; exclude shell syntax in local paths.
    if not re.fullmatch(r"[/A-Za-z0-9_.+\-]+", str(resolved)):
        raise ValueError("Launcher paths must contain only simple filename characters")
    return resolved


def resources(profile, available_cpus):
    if set(profile) != {"nodes", "reserve_mib", "allow_existing_host_limits"} or set(profile["nodes"]) != set(NAMES):
        raise ValueError("Explicit resource profile must contain all seven nodes and reserve/host-limit choices")
    if type(profile["reserve_mib"]) is not int or not 2048 <= profile["reserve_mib"] <= 65536:
        raise ValueError("Reserve must be an explicit integer >= 2048 MiB; native overhead is not a heap reservation")
    if type(profile["allow_existing_host_limits"]) is not bool:
        raise ValueError("Existing host-limit exception must be an explicit boolean")
    for name, node in profile["nodes"].items():
        fields = {"cpus", "heap_mib"} if name.startswith("fe") else {"cpus", "jvm_heap_mib", "memory_mib"}
        if set(node) != fields or not isinstance(node["cpus"], list) or not node["cpus"]:
            raise ValueError("Unexpected/missing per-node resource fields: " + name)
        if (any(type(cpu) is not int or cpu < 0 for cpu in node["cpus"])
                or sorted(set(node["cpus"])) != node["cpus"] or not set(node["cpus"]) <= available_cpus):
            raise ValueError("Node CPUs must be unique, sorted and currently available: " + name)
        for key in fields - {"cpus"}:
            minimum = 1024 if key in ("heap_mib", "memory_mib") else 256
            if type(node[key]) is not int or not minimum <= node[key] <= 65536:
                raise ValueError("Invalid explicit memory profile: " + name + "/" + key)
    return profile


def configuration(original, values, heap_mib):
    text = re.sub(r"-Xm([xs])\d+[mMgG]", lambda match: "-Xm" + match[1] + str(heap_mib) + "m", original)
    if not re.search(r"(?m)^JAVA_OPTS_FOR_JDK_17=.*-Xmx" + str(heap_mib) + "m", text):
        raise ValueError("Original launcher has no recognized JDK 17 heap option")
    for key, value in values.items():
        text = re.sub(r"(?m)^" + re.escape(key) + r"\s*=.*\n?", "", text)
        text += "\n" + key + " = " + str(value) + "\n"
    return text


def memory_available_mib():
    values = dict((line.split(":", 1)[0], line.split(":", 1)[1].strip())
                  for line in Path("/proc/meminfo").read_text().splitlines())
    return int(values["MemAvailable"].split()[0]) // 1024


def planned_memory_mib(profile):
    return sum(node.get("heap_mib", node.get("memory_mib", 0) + node.get("jvm_heap_mib", 0))
               for node in profile["nodes"].values()) + profile["reserve_mib"]


def package_files(package):
    result = []
    for directory, folders, files in os.walk(package, followlinks=True):
        for name in folders + files:
            path = Path(directory) / name
            if package not in path.resolve().parents:
                raise ValueError("Package path escapes the selected original distribution")
            if path.is_symlink() and path.resolve().is_dir():
                # Do not traverse cycles/alternate directory trees without a complete canonical inventory.
                raise ValueError("Directory symlinks in a package require an explicit separate inventory")
        result.extend(Path(directory) / name for name in files if (Path(directory) / name).is_file())
    return sorted(result)


def plan_cluster(package, workdir, java_home, profile_path):
    package, workdir = owned(package, ROOT), owned(workdir, ROOT / ".build-records")
    java_home = owned(java_home, ROOT / ".build-records")
    profile = resources(read(profile_path), os.sched_getaffinity(0))
    if workdir.exists():
        raise ValueError("Use a new workdir; no installation, metadata or evidence is overwritten")
    for path in (package / "fe/lib/doris-fe.jar", package / "be/lib/doris_be", java_home / "bin/java",
                 java_home / "bin/javac", java_home / "lib/modules"):
        if not path.is_file():
            raise ValueError("Missing original package/JDK file: " + str(path))
    workdir.mkdir(parents=True, mode=0o700, exist_ok=False)
    plan = {"schema": 1, "tool": str(SOURCE), "run_id": uuid.uuid4().hex,
            "status": "PLANNED", "workdir": str(workdir), "package": str(package),
            "java_home": str(java_home), "host_namespace": os.readlink("/proc/self/ns/net"),
            "resource_profile": profile, "planned_memory_with_reserve_mib": planned_memory_mib(profile),
            "mem_available_at_plan_mib": memory_available_mib(), "nodes": [], "bindings": {},
            "topology": "Private outer namespace bridge, seven private node namespaces; no host links/default route",
            "LP009_complete": False, "release_performance_pass": False,
            "scope": "Original distribution membership prerequisite; no fanout/data/performance qualification"}
    paths = {"tool": SOURCE, "sql_helper": SQL_SOURCE, "java": java_home / "bin/java",
             "javac": java_home / "bin/javac", "jdk_modules": java_home / "lib/modules"}
    # Bind the actual unchanged distribution, including launcher dependencies, not only its two main binaries.
    for path in package_files(package):
        paths["package/" + str(path.relative_to(package))] = path
    for index, name in enumerate(NAMES):
        component = name[:2]
        installation = workdir / name / component
        original = package / component
        installation.mkdir(parents=True)
        for folder in ("bin", "conf"):
            shutil.copytree(original / folder, installation / folder)
        for folder in ("lib", "webroot", "www", "plugins"):
            if (original / folder).exists():
                (installation / folder).symlink_to(original / folder, target_is_directory=True)
        for folder in ("log", "meta", "storage"):
            (installation / folder).mkdir()
        ip = "10.254.23." + str(11 + index)
        node = {"name": name, "component": component, "ip": ip, "installation": str(installation),
                "resources": profile["nodes"][name], "ports": FE_PORTS if component == "fe" else BE_PORTS,
                "state_path": str(workdir / name / "node.json"), "bridge_peer": "lpv" + str(index)}
        values = {"JAVA_HOME": str(java_home), "priority_networks": ip + "/32", **node["ports"]}
        if component == "fe":
            values.update(meta_dir=str(installation / "meta"), thrift_server_max_worker_threads=64,
                          mysql_service_io_threads_num=2)
            heap = node["resources"]["heap_mib"]
        else:
            values.update(storage_root_path=str(installation / "storage"),
                          mem_limit=node["resources"]["memory_mib"] * 1024 * 1024,
                          num_cores=len(node["resources"]["cpus"]), webserver_num_workers=8,
                          pipeline_executor_size=len(node["resources"]["cpus"]),
                          doris_scanner_thread_pool_thread_num=8)
            heap = node["resources"]["jvm_heap_mib"]
            if profile["allow_existing_host_limits"]:
                values["SKIP_CHECK_ULIMIT"] = "true"
        config = installation / "conf" / (component + ".conf")
        config.write_text(configuration(config.read_text(), values, heap))
        for path in sorted(installation.rglob("*")):
            if path.is_file() and installation in path.resolve().parents:
                paths[name + "/" + str(path.relative_to(installation))] = path
        plan["nodes"].append(node)
    plan["bindings"] = {name: {"path": str(path), "sha256": digest(path)} for name, path in paths.items()}
    save(workdir / "plan.json", plan)
    return plan


def check_bindings(plan):
    for name, binding in plan["bindings"].items():
        if digest(binding["path"]) != binding["sha256"]:
            raise ValueError("Frozen input changed: " + name)


def validate_plan(plan, plan_path):
    workdir = owned(plan["workdir"], ROOT / ".build-records")
    if (plan.get("schema") != 1 or plan.get("tool") != str(SOURCE) or workdir / "plan.json" != plan_path
            or not re.fullmatch(r"[0-9a-f]{32}", plan.get("run_id", ""))
            or plan.get("LP009_complete") is not False or plan.get("release_performance_pass") is not False):
        raise ValueError("Not a complete owned plan from this tool")
    owned(plan["package"], ROOT)
    owned(plan["java_home"], ROOT / ".build-records")
    if not re.fullmatch(r"net:\[\d+\]", plan["host_namespace"]):
        raise ValueError("Invalid parent namespace identity")
    # Stopping must remain possible if CPU availability has changed since planning.
    profile_cpus = {cpu for node in plan["resource_profile"]["nodes"].values() for cpu in node["cpus"]}
    resources(plan["resource_profile"], profile_cpus)
    if planned_memory_mib(plan["resource_profile"]) != plan["planned_memory_with_reserve_mib"]:
        raise ValueError("Resource budget differs from the explicit profile")
    if not isinstance(plan.get("nodes"), list) or len(plan["nodes"]) != len(NAMES):
        raise ValueError("Expected exactly seven frozen nodes")
    for index, (node, name) in enumerate(zip(plan["nodes"], NAMES)):
        component = name[:2]
        expected = {"name": name, "component": component, "ip": "10.254.23." + str(11 + index),
                    "installation": str(workdir / name / component), "state_path": str(workdir / name / "node.json"),
                    "ports": FE_PORTS if component == "fe" else BE_PORTS, "bridge_peer": "lpv" + str(index),
                    "resources": plan["resource_profile"]["nodes"][name]}
        if node != expected:
            raise ValueError("Node paths/topology/resources differ from the owned plan shape: " + name)
        owned(node["installation"], workdir)
        owned(node["state_path"], workdir)
    for key, path in (("tool", SOURCE), ("sql_helper", SQL_SOURCE),
                      ("java", Path(plan["java_home"]) / "bin/java")):
        if plan["bindings"][key]["path"] != str(path):
            raise ValueError("Frozen source/runtime path does not match the plan")
    return plan


def proc_data(pid):
    root = Path("/proc") / str(pid)
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "start_ticks": int(fields[19]), "state": fields[0],
            "namespace": os.readlink(root / "ns/net"), "exe": os.readlink(root / "exe"),
            "cwd": os.readlink(root / "cwd"), "command_sha256": digest(root / "cmdline")}


def pin_process(pid, kind, installation, namespace, node_name=None):
    data = proc_data(pid)
    if pid <= 1 or data["namespace"] != namespace or data["state"] in ("Z", "X"):
        raise ValueError("Process is not live in its owned namespace")
    command = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
    if kind in ("fe", "be"):
        env = (Path("/proc") / str(pid) / "environ").read_bytes().split(b"\0")
        if (b"DORIS_HOME=" + str(installation).encode() not in env or data["cwd"] != str(installation)
                or (kind == "fe" and b"org.apache.doris.DorisFE" not in command)
                or (kind == "be" and Path(data["exe"]).name != "doris_be")):
            raise ValueError("Service does not belong to this exact fresh installation")
    elif kind == "launcher":
        script = installation / "bin" / ("start_" + installation.name + ".sh")
        if str(script).encode() not in command or data["cwd"] != str(installation):
            raise ValueError("Launcher does not identify the exact owned installation")
    elif str(SOURCE).encode() not in command or str(installation).encode() not in command:
        raise ValueError("Keeper/supervisor command does not identify this tool and plan")
    if kind == "keeper":
        if (not node_name or b"--node" not in command or command.index(b"--node") + 1 >= len(command)
                or command[command.index(b"--node") + 1] != node_name.encode()):
            raise ValueError("Keeper does not identify its exact node")
    data.update(kind=kind, installation=str(installation))
    if node_name:
        data["node_name"] = node_name
    return data


def same_process(pin):
    try:
        now = proc_data(pin["pid"])
    except (FileNotFoundError, ProcessLookupError):
        return False
    if now["state"] in ("Z", "X"):
        return False
    for key in ("pid", "start_ticks", "namespace", "exe", "cwd", "command_sha256"):
        if now[key] != pin[key]:
            raise ValueError("Refuse to signal changed process identity: " + str(pin["pid"]))
    pin_process(pin["pid"], pin["kind"], Path(pin["installation"]), pin["namespace"], pin.get("node_name"))
    return True


def stop_pins(pins, grace=20):
    results = []
    for pin in pins:
        record = {"identity": pin, "term_sent": False, "kill_sent": False, "exited": False}
        results.append(record)
        try:
            if same_process(pin):
                os.kill(pin["pid"], signal.SIGTERM)
                record["term_sent"] = True
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            record["error"] = str(error)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        live = []
        for record in results:
            if "error" in record:
                continue
            try:
                if same_process(record["identity"]):
                    live.append(record)
                else:
                    record["exited"] = True
            except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
                record["error"] = str(error)
        if not live:
            break
        time.sleep(.1)
    for record in results:
        if record["exited"] or "error" in record:
            continue
        try:
            if same_process(record["identity"]):
                os.kill(record["identity"]["pid"], signal.SIGKILL)
                record["kill_sent"] = True
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            record["error"] = str(error)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        for record in results:
            if "error" not in record and not record["exited"]:
                try:
                    record["exited"] = not same_process(record["identity"])
                except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
                    record["error"] = str(error)
        if all(record["exited"] or "error" in record for record in results):
            break
        time.sleep(.1)
    return results


def discover_services(node, namespace):
    pins = []
    for proc in Path("/proc").iterdir():
        if proc.name.isdigit():
            try:
                pins.append(pin_process(int(proc.name), node["component"], Path(node["installation"]), namespace))
            except (OSError, ValueError):
                pass
    return pins


def merge_pins(*groups):
    result = []
    for pin in (pin for group in groups for pin in group if pin):
        # A later discovery must never replace an older identity for the same PID and evade its refusal.
        if not any(prior["pid"] == pin["pid"] for prior in result):
            result.append(pin)
    return result


def validate_node_record(plan, node, record):
    namespace = record["namespace"]
    if (record["name"] != node["name"] or namespace == plan["host_namespace"]
            or not re.fullmatch(r"net:\[\d+\]", namespace)):
        raise ValueError("Node state belongs to a different node/namespace")
    for name, kind, installation in (("keeper", "keeper", str(Path(plan["workdir"]) / "plan.json")),
                                      ("service", node["component"], node["installation"]),
                                      ("launcher", "launcher", node["installation"])):
        pin = record.get(name)
        if pin is None and name != "keeper":
            continue
        if (pin["kind"] != kind or pin["installation"] != installation or pin["namespace"] != namespace
                or type(pin["pid"]) is not int or pin["pid"] <= 1
                or type(pin["start_ticks"]) is not int or pin["start_ticks"] < 0
                or (name == "keeper" and pin.get("node_name") != node["name"])):
            raise ValueError("Recorded process does not belong to this exact node/plan")
        if (not all(isinstance(pin.get(field), str) and pin[field] for field in ("exe", "cwd", "command_sha256"))
                or not re.fullmatch(r"[0-9a-f]{64}", pin["command_sha256"])):
            raise ValueError("Recorded process identity is incomplete")
    return record


def live_namespace_processes(namespace):
    found = []
    for path in Path("/proc").iterdir():
        if path.name.isdigit():
            try:
                if os.readlink(path / "ns/net") == namespace:
                    value = proc_data(int(path.name))
                    if value["state"] not in ("Z", "X"):
                        found.append(value)
            except (FileNotFoundError, ProcessLookupError):
                pass
    return found


def cleanup_nodes(plan, known):
    """Continue across bad/missing state files, retaining every previously observed process pin."""
    result = {"errors": [], "keepers": [], "launchers": [], "services": [], "remaining_namespace_processes": []}
    records = {}
    service_pins = []
    for node in reversed(plan["nodes"]):
        name = node["name"]
        old = known.get(name)
        try:
            if old:
                records[name] = validate_node_record(plan, node, old)
                service_pins = merge_pins(service_pins, [old.get("service")])
            if Path(node["state_path"]).exists():
                latest = validate_node_record(plan, node, read(node["state_path"]))
                if old and latest["keeper"] != old["keeper"]:
                    raise ValueError("Node keeper identity changed since its creation")
                records[name] = latest
                service_pins = merge_pins(service_pins, [latest.get("service")])
        except (OSError, ValueError, KeyError, TypeError) as error:
            result["errors"].append(name + ": " + type(error).__name__ + ": " + str(error))
    result["keepers"] = stop_pins([record["keeper"] for record in records.values()], 30)
    launchers = []
    for node in reversed(plan["nodes"]):
        name = node["name"]
        old = records.get(name)
        if not old:
            continue
        if old.get("launcher_running") and old.get("launcher"):
            launchers = merge_pins(launchers, [old["launcher"]])
        try:
            latest = validate_node_record(plan, node, read(node["state_path"]))
            if latest["keeper"] != old["keeper"]:
                raise ValueError("Node keeper identity changed during cleanup")
            service_pins = merge_pins(service_pins, [latest.get("service")])
            if latest.get("launcher_running") and latest.get("launcher"):
                launchers = merge_pins(launchers, [latest["launcher"]])
        except (OSError, ValueError, KeyError, TypeError) as error:
            result["errors"].append(name + ": " + type(error).__name__ + ": " + str(error))
    result["launchers"] = stop_pins(launchers)
    for node in reversed(plan["nodes"]):
        record = records.get(node["name"])
        if not record:
            continue
        try:
            service_pins = merge_pins(service_pins, discover_services(node, record["namespace"]))
        except (OSError, ValueError) as error:
            result["errors"].append(node["name"] + ": discovery: " + str(error))
    result["services"] = stop_pins(service_pins)
    # A daemon may be between fork and exec. Unknown occupants are never silently treated as clean or signalled.
    for node in reversed(plan["nodes"]):
        record = records.get(node["name"])
        if not record:
            continue
        try:
            result["remaining_namespace_processes"].extend(live_namespace_processes(record["namespace"]))
        except OSError as error:
            result["errors"].append(node["name"] + ": namespace inventory: " + str(error))
    result["complete"] = (not result["errors"] and not result["remaining_namespace_processes"]
                          and all(entry["exited"] for entry in result["keepers"] + result["launchers"] + result["services"]))
    return result


class Stop:
    def __init__(self):
        self.requested = False
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, self.receive)

    def receive(self, _number, _frame):
        self.requested = True

    def check(self):
        if self.requested:
            raise InterruptedError("Owned cluster stop requested")


def command(argv, timeout=30, **kwargs):
    return subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout, check=True, **kwargs).stdout


def wait_until(test, stop, seconds=180):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        stop.check()
        try:
            value = test()
            if value:
                return value
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            last = type(error).__name__ + ": " + str(error)
        time.sleep(1)
    raise TimeoutError("Bounded readiness failed: " + str(last))


def verify_resources(node, pin, stop):
    actual = {"cpus": sorted(os.sched_getaffinity(pin["pid"])),
              "cgroup_membership": (Path("/proc") / str(pin["pid"]) / "cgroup").read_text()}
    if actual["cpus"] != node["resources"]["cpus"]:
        raise ValueError("Actual service affinity differs from the node profile")
    if node["component"] == "fe":
        options = (Path("/proc") / str(pin["pid"]) / "cmdline").read_bytes().decode().split("\0")
        expected_heap = node["resources"]["heap_mib"]
    else:
        entries = (Path("/proc") / str(pin["pid"]) / "environ").read_bytes().split(b"\0")
        java = [entry[len(b"JAVA_OPTS="):].decode() for entry in entries if entry.startswith(b"JAVA_OPTS=")]
        if len(java) != 1:
            raise ValueError("BE embedded JVM options are not observable")
        options = java[0].split()
        expected_heap = node["resources"]["jvm_heap_mib"]
        def memory_limit():
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open("http://127.0.0.1:28040/api/show_config?conf_item=mem_limit", timeout=5) as response:
                if response.status != 200:
                    raise ValueError("Original BE config endpoint did not return HTTP 200")
                rows = json.loads(response.read(65536))
            if len(rows) != 1 or rows[0][0] != "mem_limit" or int(rows[0][2]) != node["resources"]["memory_mib"] * 1048576:
                raise ValueError("Original BE runtime memory limit differs from the explicit profile")
            return rows
        actual["be_runtime_mem_limit_response"] = wait_until(memory_limit, stop, 90)
    actual["jvm_heap_options"] = [option for option in options if re.fullmatch(r"-Xm[xs]\d+[mMgG]", option)]
    if [option for option in actual["jvm_heap_options"] if option.startswith("-Xmx")] != ["-Xmx%dm" % expected_heap]:
        raise ValueError("Actual launcher JVM heap differs from the explicit node profile")
    return actual


def node_worker(plan_path, name):
    plan = validate_plan(read(plan_path), plan_path)
    node = next(node for node in plan["nodes"] if node["name"] == name)
    top = read(Path(plan["workdir"]) / "cluster.json")
    namespace = os.readlink("/proc/self/ns/net")
    if (namespace in (plan["host_namespace"], top["namespace"])
            or os.getppid() != top["supervisor"]["pid"] or not same_process(top["supervisor"])):
        raise ValueError("Node keeper must be a direct owned child in its new namespace")
    os.sched_setaffinity(0, node["resources"]["cpus"])
    if os.sched_getaffinity(0) != set(node["resources"]["cpus"]):
        raise ValueError("Actual node CPU affinity differs from its frozen resource profile")
    state_path = Path(node["state_path"])
    state = {"name": name, "status": "NETWORK_PENDING", "namespace": namespace,
             "keeper": pin_process(os.getpid(), "keeper", plan_path, namespace, name), "service": None,
             "launcher": None, "launcher_running": False}
    stop = Stop()
    save(state_path, state)
    installation = Path(node["installation"])
    launcher = None
    try:
        wait_until(lambda: (state_path.parent / "start.json").is_file(), stop, 900)
        start = read(state_path.parent / "start.json")
        if start.get("run_id") != plan["run_id"]:
            raise ValueError("Start instruction belongs to a different plan")
        route = json.loads(command(["ip", "-j", "route", "show"]))
        if any(entry.get("dst") == "default" for entry in route):
            raise ValueError("Node has an unexpected default route")
        state["network"] = {"addresses": json.loads(command(["ip", "-j", "address", "show"])), "routes": route}
        args = ["bash", installation / "bin" / ("start_" + node["component"] + ".sh"), "--daemon"]
        if name in ("fe2", "fe3"):
            args += ["--helper", plan["nodes"][0]["ip"] + ":" + str(FE_PORTS["edit_log_port"])]
        with (state_path.parent / "launcher.log").open("w") as log:
            launcher = subprocess.Popen(list(map(str, args)), cwd=installation, stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=subprocess.STDOUT)
            state["launcher_running"] = True
            state["launcher"] = pin_process(launcher.pid, "launcher", installation, namespace)
            save(state_path, state)
            deadline = time.monotonic() + 60
            while launcher.poll() is None:
                stop.check()
                if time.monotonic() >= deadline:
                    raise TimeoutError("Original launcher exceeded its 60-second budget")
                time.sleep(.1)
            state["launcher_running"] = False
            state["launcher_exit_code"] = launcher.returncode
            save(state_path, state)
            if launcher.returncode:
                raise RuntimeError("Original launcher failed; output preserved")
        pidfile = installation / "bin" / (node["component"] + ".pid")
        state["service"] = wait_until(lambda: pin_process(int(pidfile.read_text().strip()), node["component"],
                                                          installation, namespace), stop, 30)
        save(state_path, state)
        state["actual_resource_profile"] = verify_resources(node, state["service"], stop)
        state["status"] = "SERVICE_STARTED"
        save(state_path, state)
        while not stop.requested:
            if not same_process(state["service"]):
                raise RuntimeError("Owned service exited")
            time.sleep(1)
    except Exception as error:
        state.update(status="FAILED", error=type(error).__name__ + ": " + str(error))
    finally:
        cleanup_errors = []
        if launcher is not None and launcher.poll() is None and not state["launcher"]:
            try:
                state["launcher"] = pin_process(launcher.pid, "launcher", installation, namespace)
            except (OSError, ValueError) as error:
                cleanup_errors.append("Unidentified owned launcher: " + str(error))
        state["launcher_cleanup"] = stop_pins([state["launcher"]]) if state["launcher_running"] and state["launcher"] else []
        # A daemon can start just before its launcher fails. Pin only exact namespace/installation matches.
        pins = [state["service"]] if state["service"] else []
        try:
            pins = merge_pins(pins, discover_services(node, namespace))
        except (OSError, ValueError) as error:
            cleanup_errors.append("Service discovery: " + str(error))
        state["cleanup_service_identities"] = pins
        cleanup_save(state_path, state)
        state["cleanup"] = stop_pins(pins)
        if launcher is not None:
            try:
                launcher.wait(timeout=2)
            except subprocess.TimeoutExpired:
                cleanup_errors.append("Owned launcher did not exit")
        try:
            state["unclassified_live_processes"] = [value for value in live_namespace_processes(namespace)
                                                    if value["pid"] != os.getpid()]
        except OSError as error:
            cleanup_errors.append("Namespace inventory: " + str(error))
        state["cleanup_errors"] = cleanup_errors
        clean = (not cleanup_errors and not state.get("archive_errors") and not state.get("unclassified_live_processes")
                 and all(record["exited"] for record in state["cleanup"] + state["launcher_cleanup"]))
        state["status"] = ("FAILED_CLEANED" if "error" in state else "STOPPED") if clean else "CLEANUP_FAILED"
        cleanup_save(state_path, state)
    return 0 if state["status"] == "STOPPED" and "error" not in state else 2


class Sql:
    def __init__(self, plan):
        self.plan = plan
        self.output = Path(plan["workdir"]) / "oracle"
        self.output.mkdir()
        lib = Path(plan["package"]) / "fe/lib"
        dependencies = []
        for prefix in ("mariadb-java-client", "jackson-core", "jackson-databind", "jackson-annotations"):
            paths = list(lib.glob(prefix + "-*.jar"))
            if len(paths) != 1:
                raise ValueError("Expected one original JDBC dependency: " + prefix)
            dependencies.append(paths[0])
        self.classpath = os.pathsep.join(map(str, [self.output, *dependencies]))
        self.java = Path(plan["java_home"]) / "bin/java"
        output = command([self.java.with_name("javac"), "--release", "8", "-encoding", "UTF-8", "-cp",
                          self.classpath, "-d", self.output, SQL_SOURCE], timeout=60)
        save(self.output / "compile.json", {"output": output, "source_sha256": digest(SQL_SOURCE),
             "class_sha256": digest(self.output / "LicenseFixtureSql.class")})
        self.sequence = 0

    def execute(self, keeper, statements):
        if not same_process(keeper):
            raise ValueError("SQL node keeper is no longer owned/live")
        self.sequence += 1
        config = self.output / ("sql-%04d.json" % self.sequence)
        env_name = "MASSDB_MULTINODE_EMPTY_ROOT_" + self.plan["run_id"]
        save(config, {"query_port": FE_PORTS["query_port"], "user": "root", "password_env": env_name,
                      "sql": statements})
        env = dict(os.environ)
        env.pop(env_name, None)
        response = subprocess.run(["nsenter", "-t", str(keeper["pid"]), "-n", str(self.java), "-cp",
                                   self.classpath, "LicenseFixtureSql", str(config)], env=env,
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=40)
        try:
            result = json.loads(response.stdout)
        except ValueError:
            save(config.with_suffix(".result.json"), {"exit_code": response.returncode,
                 "error": "SQL helper did not return structured JSON"})
            raise RuntimeError("SQL readiness helper not yet available") from None
        save(config.with_suffix(".result.json"), result)
        if response.returncode or result.get("success") is not True:
            raise RuntimeError("SQL failed; original structured errno/state retained")
        return result["statements"]


def bootstrap_ready(sql, keeper, node):
    # Constant SELECT is planned on a BE in the original package. Before registering
    # any BE, use local FE metadata; the complete remote heartbeat oracle runs later.
    response = sql.execute(keeper, ["SET forward_to_master=false", "SHOW FRONTENDS"])
    rows = response[1]["rows"]
    connected = [row for row in rows if row["CurrentConnected"] == "Yes"]
    if (len(connected) != 1 or connected[0]["Host"] != node["ip"]
            or connected[0]["Role"] != "FOLLOWER"
            or connected[0]["Join"].lower() != "true"
            or int(connected[0]["QueryPort"]) != FE_PORTS["query_port"]
            or int(connected[0]["EditLogPort"]) != FE_PORTS["edit_log_port"]):
        raise ValueError("Bootstrap metadata did not identify the intended joined FE")
    return True


def check_membership(frontends, backends, nodes, minimum_journal=0, connected_ip=None):
    expected_fe = {node["ip"] for node in nodes if node["component"] == "fe"}
    expected_be = {node["ip"] for node in nodes if node["component"] == "be"}
    if len(frontends) != 3 or {row["Host"] for row in frontends} != expected_fe:
        raise ValueError("FE membership is not the exact three distinct owned hosts")
    if (sum(row["IsMaster"].lower() == "true" for row in frontends) != 1
            or len({row["ClusterId"] for row in frontends}) != 1):
        raise ValueError("Expected one elected master and one common cluster ID")
    for row in frontends:
        if (row["Role"] != "FOLLOWER" or row["Join"].lower() != "true" or row["Alive"].lower() != "true"
                or int(row["ReplayedJournalId"]) < minimum_journal or row["ErrMsg"]
                or int(row["EditLogPort"]) != FE_PORTS["edit_log_port"]
                or int(row["RpcPort"]) != FE_PORTS["rpc_port"]
                or int(row["QueryPort"]) != FE_PORTS["query_port"]
                or int(row["HttpPort"]) != FE_PORTS["http_port"]
                or row["LastHeartbeat"] in ("", "NULL", "1970-01-01 00:00:00")):
            raise ValueError("FE role, BDB join, remote heartbeat or replay watermark is not ready")
    if connected_ip and [row["Host"] for row in frontends if row["CurrentConnected"] == "Yes"] != [connected_ip]:
        raise ValueError("Oracle did not reach the intended distinct FE")
    if len(backends) != 4 or {row["Host"] for row in backends} != expected_be:
        raise ValueError("BE membership is not the exact four distinct owned hosts")
    for row in backends:
        if (row["Alive"].lower() != "true" or row["SystemDecommissioned"].lower() != "false"
                or int(row["HeartbeatPort"]) != BE_PORTS["heartbeat_service_port"]
                or int(row["BePort"]) != BE_PORTS["be_port"]
                or int(row["HttpPort"]) != BE_PORTS["webserver_port"]
                or int(row["BrpcPort"]) != BE_PORTS["brpc_port"] or row["ErrMsg"]
                or row["LastHeartbeat"] in ("", "NULL", "1970-01-01 00:00:00")):
            raise ValueError("BE heartbeat/ports are not ready")
    return True


def supervise(plan_path):
    plan = validate_plan(read(plan_path), plan_path)
    workdir = Path(plan["workdir"])
    namespace = os.readlink("/proc/self/ns/net")
    if namespace in (plan["host_namespace"], os.readlink("/proc/1/ns/net")):
        raise ValueError("Refuse topology creation in the host namespace")
    if (workdir / "cluster.json").exists():
        raise ValueError("A plan cannot be relaunched or overwrite prior cluster evidence")
    resources(plan["resource_profile"], os.sched_getaffinity(0))
    if memory_available_mib() < plan["planned_memory_with_reserve_mib"]:
        raise ValueError("Launch memory profile plus reserve no longer fits MemAvailable")
    if {link["ifname"] for link in json.loads(command(["ip", "-j", "link", "show"]))} != {"lo"}:
        raise ValueError("Expected a new empty outer network namespace")
    state_path = workdir / "cluster.json"
    state = {"status": "STARTING", "plan_sha256": digest(plan_path), "namespace": namespace,
             "host_namespace": plan["host_namespace"], "nodes": {}, "LP009_complete": False,
             "release_performance_pass": False, "supervisor": pin_process(os.getpid(), "supervisor", plan_path, namespace),
             "host_max_map_count": Path("/proc/sys/vm/max_map_count").read_text().strip(),
             "host_swaps": Path("/proc/swaps").read_text(), "mem_available_at_launch_mib": memory_available_mib()}
    save(state_path, state)
    stop = Stop()
    children = []
    try:
        check_bindings(plan)
        command(["ip", "link", "set", "lo", "up"])
        command(["ip", "link", "add", "lpbr0", "type", "bridge"])
        command(["ip", "link", "set", "lpbr0", "up"])
        for node in plan["nodes"]:
            stop.check()
            log = (workdir / node["name"] / "keeper.log").open("w")
            child = subprocess.Popen(["unshare", "--net", sys.executable, str(SOURCE), "--mode", "node-worker",
                                      "--plan", str(plan_path), "--node", node["name"]],
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            log.close()
            child_entry = {"process": child, "name": node["name"], "birth_ticks": None}
            children.append(child_entry)
            child_entry["birth_ticks"] = int((Path("/proc") / str(child.pid) / "stat").read_text().rsplit(")", 1)[1].split()[19])
            record = wait_until(lambda: read(node["state_path"]) if Path(node["state_path"]).exists() else None,
                                stop, 30)
            validate_node_record(plan, node, record)
            keeper = record["keeper"]
            if keeper["pid"] != child.pid or keeper["namespace"] in {namespace, plan["host_namespace"]} \
                    or not same_process(keeper):
                raise ValueError("Node namespace/keeper ownership mismatch")
            if keeper["namespace"] in {entry["keeper"]["namespace"] for entry in state["nodes"].values()}:
                raise ValueError("Two nodes unexpectedly share a network namespace")
            state["nodes"][node["name"]] = record
            save(state_path, state)
            peer = node["bridge_peer"]
            command(["ip", "link", "add", peer, "type", "veth", "peer", "name", "lpchild0"])
            command(["ip", "link", "set", "lpchild0", "netns", keeper["pid"]])
            command(["ip", "link", "set", peer, "master", "lpbr0"])
            command(["ip", "link", "set", peer, "up"])
            prefix = ["nsenter", "-t", keeper["pid"], "-n", "ip"]
            command(prefix + ["link", "set", "lo", "up"])
            command(prefix + ["link", "set", "lpchild0", "name", "eth0"])
            command(prefix + ["address", "add", node["ip"] + "/24", "dev", "eth0"])
            command(prefix + ["link", "set", "eth0", "up"])
        state["outer_network"] = {"links": json.loads(command(["ip", "-j", "link", "show"])),
                                  "routes": json.loads(command(["ip", "-j", "route", "show"]))}
        if state["outer_network"]["routes"]:
            raise ValueError("Outer bridge namespace must not have IP routes")
        sql = Sql(plan)

        def start_node(node):
            save(Path(node["state_path"]).parent / "start.json", {"run_id": plan["run_id"]})
            def started():
                record = read(node["state_path"])
                if record["status"] in ("STOPPED", "FAILED_CLEANED", "CLEANUP_FAILED", "FAILED"):
                    raise RuntimeError("Node startup failed: " + node["name"])
                return record if record["status"] == "SERVICE_STARTED" else None
            record = wait_until(started, stop, 180)
            state["nodes"][node["name"]] = record
            save(state_path, state)
            return record["keeper"]

        first = start_node(plan["nodes"][0])
        wait_until(lambda: bootstrap_ready(sql, first, plan["nodes"][0]), stop)
        for node in plan["nodes"][1:3]:
            sql.execute(first, ['ALTER SYSTEM ADD FOLLOWER "' + node["ip"] + ':29010"'])
            keeper = start_node(node)
            wait_until(lambda: bootstrap_ready(sql, keeper, node), stop)
        for node in plan["nodes"][3:]:
            start_node(node)
            sql.execute(first, ['ALTER SYSTEM ADD BACKEND "' + node["ip"] + ':29050"'])
        marker = "mn_replay_" + plan["run_id"][:12]
        sql.execute(first, ["CREATE DATABASE " + marker])
        initial = sql.execute(first, ["SHOW FRONTENDS"])[0]["rows"]
        watermark = max(int(row["ReplayedJournalId"]) for row in initial if row["IsMaster"].lower() == "true")
        state["replay_marker"] = {"database": marker, "minimum_journal": watermark}
        snapshots = []
        for node in plan["nodes"][:3]:
            keeper = state["nodes"][node["name"]]["keeper"]
            def ready():
                response = sql.execute(keeper, ["SHOW FRONTENDS", "SHOW BACKENDS"])
                check_membership(response[0]["rows"], response[1]["rows"], plan["nodes"], watermark, node["ip"])
                return {"connected_node": node["name"], "view_scope": "master-reported membership; SHOW may forward",
                        "frontends": response[0]["rows"], "backends": response[1]["rows"]}
            snapshots.append(wait_until(ready, stop))
        sql.execute(first, ["DROP DATABASE " + marker])
        check_bindings(plan)
        state.update(status="MEMBERSHIP_READY", membership_oracle=snapshots, replay_marker_removed=True)
        save(state_path, state)
        print(json.dumps({"status": state["status"], "record": str(state_path), "supervisor_pid": os.getpid(),
                          "LP009_complete": False, "release_performance_pass": False}), flush=True)
        while not stop.requested:
            for node in plan["nodes"]:
                record = read(node["state_path"])
                if record["status"] != "SERVICE_STARTED" or not same_process(record["service"]):
                    raise RuntimeError("Previously ready node exited: " + node["name"])
            time.sleep(1)
    except Exception as error:
        state.update(status="FAILED", error=type(error).__name__ + ": " + str(error))
    finally:
        state["node_cleanup"] = cleanup_nodes(plan, state["nodes"])
        unrecorded = []
        known = {record["identity"]["pid"] for record in state["node_cleanup"]["keepers"]}
        for child_entry in children:
            child, birth_ticks = child_entry["process"], child_entry["birth_ticks"]
            if child.pid not in known and child.poll() is None:
                try:
                    current = proc_data(child.pid)
                    if ((birth_ticks is not None and current["start_ticks"] != birth_ticks)
                            or current["namespace"] == plan["host_namespace"]):
                        raise ValueError("Unrecorded child identity changed")
                    pin = pin_process(child.pid, "keeper", plan_path, current["namespace"], child_entry["name"])
                    unrecorded.extend(stop_pins([pin]))
                except (OSError, ValueError) as error:
                    unrecorded.append({"pid": child.pid, "exited": False, "error": str(error)})
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass  # Only validated identities may be signalled; preserve any unresolved cleanup.
        state["unrecorded_child_cleanup"] = unrecorded
        clean = state["node_cleanup"]["complete"] and all(entry["exited"] for entry in unrecorded)
        state["status"] = ("FAILED_CLEANED" if "error" in state else "STOPPED") if clean else "CLEANUP_FAILED"
        cleanup_save(state_path, state)
    return 0 if state["status"] == "STOPPED" and "error" not in state else 2


def stop_cluster(plan_path):
    plan = validate_plan(read(plan_path), plan_path)
    workdir = owned(plan["workdir"], ROOT / ".build-records")
    state_path = workdir / "cluster.json"
    state = read(state_path)
    if state["plan_sha256"] != digest(plan_path):
        raise ValueError("Plan identity changed; refusing to signal its recorded processes")
    supervisor = state["supervisor"]
    if (supervisor["kind"] != "supervisor" or supervisor["installation"] != str(plan_path)
            or supervisor["namespace"] != state["namespace"] or supervisor["namespace"] == plan["host_namespace"]):
        raise ValueError("Supervisor identity does not belong to this plan")
    cleanup = {"supervisor": stop_pins([supervisor], 90)}
    # An interrupted supervisor may not reach finally. Independently validate every saved node identity.
    cleanup["nodes"] = cleanup_nodes(plan, state["nodes"])
    cleanup["complete"] = cleanup["nodes"]["complete"] and all(entry["exited"] for entry in cleanup["supervisor"])
    save(workdir / ("stop-" + uuid.uuid4().hex[:8] + ".json"), cleanup)
    return 0 if cleanup["complete"] else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "launch", "stop", "supervise", "node-worker"), default="plan")
    parser.add_argument("--package", type=Path)
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--java-home", type=Path)
    parser.add_argument("--resources", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--node", choices=NAMES, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.mode == "plan":
        if not all((args.package, args.workdir, args.java_home, args.resources)) or args.plan or args.node:
            parser.error("Plan requires package, new workdir, java-home and explicit resources JSON")
        plan = plan_cluster(args.package, args.workdir, args.java_home, args.resources)
        print(json.dumps({"status": "PLANNED", "plan": str(Path(plan["workdir"]) / "plan.json"),
                          "started_processes": 0, "memory_with_reserve_mib": plan["planned_memory_with_reserve_mib"],
                          "resource_adequacy_proven": False, "release_performance_pass": False}))
        return 0
    if not args.plan or any((args.package, args.workdir, args.java_home, args.resources)):
        parser.error("Use only a previously generated --plan for launch/stop/internal modes")
    plan_path = owned(args.plan, ROOT / ".build-records")
    plan = validate_plan(read(plan_path), plan_path)
    if args.mode == "launch":
        if (plan_path.parent / "cluster.json").exists():
            parser.error("A plan can be launched only once; create a fresh plan/workdir")
        if os.readlink("/proc/self/ns/net") != plan["host_namespace"]:
            parser.error("Launch must originate from the recorded parent namespace")
        resources(plan["resource_profile"], os.sched_getaffinity(0))
        if memory_available_mib() < plan["planned_memory_with_reserve_mib"]:
            parser.error("Current MemAvailable is below the explicit profile plus reserve; no service started")
        check_bindings(plan)
        os.execvp("unshare", ["unshare", "--net", sys.executable, str(SOURCE), "--mode", "supervise",
                              "--plan", str(plan_path)])
    if args.mode == "stop":
        return stop_cluster(plan_path)
    if args.mode == "node-worker":
        if not args.node:
            parser.error("Internal node keeper requires a node name")
        return node_worker(plan_path, args.node)
    return supervise(plan_path)


if __name__ == "__main__":
    sys.exit(main())
