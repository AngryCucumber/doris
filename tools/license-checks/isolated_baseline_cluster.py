#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Run an unchanged distribution in a private Linux network namespace for P0 measurements."""

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


ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def configuration(source, updates, heap):
    text = source.read_text()
    text = re.sub(r"-Xm[xs]\d+[mg]", lambda m: "-Xm" + m[0][3] + heap, text)
    for key, value in updates.items():
        text = re.sub(r"(?m)^" + re.escape(key) + r"\s*=.*\n?", "", text)
        text += "\n" + key + " = " + str(value) + "\n"
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--cpus", default="6,7,8,9")
    parser.add_argument("--be-memory-mib", type=int, default=2048,
                        help="Explicit BE process memory profile; changing it requires a separate baseline")
    parser.add_argument("--allow-host-resource-profile", action="store_true",
                        help="Record existing host mmap/swap limits instead of changing global kernel settings")
    parser.add_argument("--parent-netns", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1024 <= args.be_memory_mib <= 65536:
        parser.error("BE memory profile must be between 1024 and 65536 MiB")
    package, workdir = args.package.resolve(), args.workdir.resolve()
    records = ROOT / ".build-records"
    if records not in workdir.parents or ROOT not in package.parents:
        parser.error("Package and new test installation must belong to this checkout")
    if not args.parent_netns:
        if workdir.exists():
            parser.error("Use a new workdir; existing test data and services are never overwritten")
        command = ["unshare", "--net", "--fork", "--kill-child", sys.executable, str(Path(__file__).resolve()),
                   *sys.argv[1:], "--parent-netns", os.readlink("/proc/self/ns/net")]
        os.execvp(command[0], command)
    namespace = os.readlink("/proc/self/ns/net")
    if namespace == args.parent_netns:
        parser.error("Private network namespace was not established")
    cpus = {int(value) for value in args.cpus.split(",")}
    if not cpus or not cpus <= os.sched_getaffinity(0):
        parser.error("Requested CPUs are unavailable")
    os.sched_setaffinity(0, cpus)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    workdir.mkdir(parents=True, exist_ok=False)
    installation = workdir / "installation"
    configurations = {}
    for component in ("fe", "be"):
        target, original = installation / component, package / component
        target.mkdir(parents=True)
        shutil.copytree(original / "bin", target / "bin")
        shutil.copytree(original / "conf", target / "conf")
        for name in ("lib", "webroot", "www", "plugins"):
            if (original / name).exists():
                (target / name).symlink_to(original / name, target_is_directory=True)
        for name in ("log", "meta", "storage"):
            (target / name).mkdir()
        updates = {"JAVA_HOME": str(args.java_home.resolve()), "priority_networks": "127.0.0.0/8"}
        if component == "fe":
            updates.update(http_port=28030, query_port=29030, rpc_port=29020, edit_log_port=29010,
                           arrow_flight_sql_port=28070, meta_dir=str(target / "meta"),
                           thrift_server_max_worker_threads=128, mysql_service_io_threads_num=4)
            heap = "2048m"
        else:
            updates.update(be_port=29060, heartbeat_service_port=29050, brpc_port=28060,
                           webserver_port=28040, arrow_flight_sql_port=28050,
                           storage_root_path=str(target / "storage"), mem_limit=args.be_memory_mib * 1024 * 1024,
                           num_cores=len(cpus),
                           webserver_num_workers=16, pipeline_executor_size=len(cpus),
                           doris_scanner_thread_pool_thread_num=16)
            heap = "512m"
            if args.allow_host_resource_profile:
                updates["SKIP_CHECK_ULIMIT"] = "true"
        config = target / "conf" / (component + ".conf")
        config.write_text(configuration(config, updates, heap))
        configurations[component] = digest(config)
    state = {"supervisor_pid": os.getpid(), "namespace": namespace, "host_namespace": args.parent_netns,
             "package": str(package), "installation": str(installation), "cpus": sorted(cpus),
             "java_home": str(args.java_home.resolve()), "query_port": 29030, "http_port": 28030,
             "be_process_memory_limit_bytes": args.be_memory_mib * 1024 * 1024,
             "be_heartbeat_port": 29050, "config_sha256": configurations,
             "fe_jar_sha256": digest(package / "fe/lib/doris-fe.jar"),
             "be_binary_sha256": digest(package / "be/lib/doris_be"), "status": "starting",
             "host_resource_profile_override": args.allow_host_resource_profile,
             "host_max_map_count": Path("/proc/sys/vm/max_map_count").read_text().strip(),
             "host_swaps": Path("/proc/swaps").read_text(),
             "scope": "Local isolated baseline; not target production qualification or a B performance pass"}
    state_path = workdir / "cluster.json"

    def save():
        state_path.write_text(json.dumps(state, indent=2) + "\n")

    save()
    stopping = False

    def stop(_signal, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for component in ("fe", "be"):
            log = workdir / (component + "-launcher.log")
            with log.open("wb") as stream:
                subprocess.run(["bash", str(installation / component / "bin" / ("start_" + component + ".sh")),
                                "--daemon"], stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=60)
        state["status"] = "launched_readiness_pending"
        save()
        print(json.dumps({"supervisor_pid": os.getpid(), "namespace": namespace,
                          "query_port": 29030, "workdir": str(workdir)}), flush=True)
        while not stopping:
            time.sleep(1)
    finally:
        # Only stop recorded processes whose network namespace is this private test namespace.
        for component in ("be", "fe"):
            for pidfile in (installation / component / "bin").glob("*.pid"):
                try:
                    pid = int(pidfile.read_text().strip())
                    if pid > 1 and os.readlink("/proc/" + str(pid) + "/ns/net") == namespace:
                        os.kill(pid, signal.SIGTERM)
                except (OSError, ValueError):
                    pass
        state["status"] = "stop_requested"
        save()


if __name__ == "__main__":
    main()
