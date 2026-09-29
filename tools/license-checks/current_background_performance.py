#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""One G5/G6/G7 allowed-business participant; outer controller owns state/UI events.

No API Guard that assumes original A, no service start, no license import, no clock
change. An optional Java handshake must be installed explicitly before live use.
"""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sys
import time

import calibrate_read_capacity as capacity
import p4_jdbc_evidence as clocks
import p4_jdbc_lifecycle as lifecycle
import p4_statistics as statistics
import ui_background_fixture as background
import ui_baseline_fixture as api

SOURCE = Path(__file__).resolve()
require, read_json = statistics.require, statistics.read_json
reference, verify_reference, publish = statistics.reference, statistics.verify_reference, lifecycle.publish
MODE = "reuse_per_worker_no_replay"
SOURCES = {"adapter": SOURCE, "helper": background.JAVA_SOURCE, "background": Path(background.__file__),
           "api": Path(api.__file__), "capacity": Path(capacity.__file__), "clock": Path(clocks.__file__),
           "lifecycle": Path(lifecycle.__file__), "statistics": Path(statistics.__file__)}
IDENTITIES = {"fe_artifact": "fe_sha256", "be_artifact": "be_sha256", "environment": "environment_sha256",
              "configuration": "configuration_sha256", "fixture": "fixture_sha256", "client": "client_sha256"}
JARS = {"mariadb-java-client-3.0.9.jar", "jackson-annotations-2.16.0.jar", "jackson-core-2.16.0.jar",
        "jackson-databind-2.16.0.jar"}
PIN_KEYS = ("pid", "start_ticks", "namespace", "exe", "command_sha256")


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def stamp(path):
    value = Path(path).stat()
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def pin(pid):
    value = api.proc(pid)
    require(value["state"] not in ("Z", "X"), "Background process is not alive")
    return {key: value[key] for key in PIN_KEYS}


def plan(profile):
    background.validate_current_config(profile)
    offsets = background.current_arrivals(profile["rate_per_second"], profile["duration_seconds"])
    count = len(offsets) // 2
    require(count >= 8, "Each of sixteen persistent workers needs actual scheduled work")
    formal = profile["qualification"] == "formal"
    require(not formal or count >= 10000, "Each metadata/write stream requires 10000 operations; mixed total is insufficient")
    text = "sequence\toffset_ns\n" + "".join(f"{i}\t{offset}\n" for i, offset in enumerate(offsets))
    return {"generated_requests": len(offsets), "scheduled_requests": count * 2,
            "requests_per_stream": count, "discarded_odd_tail": len(offsets) % 2,
            "reference_schedule_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "schedule_hash_scope": "Python reference only; formal execution binds actual Java plan-only TSV",
            "offsets": offsets, "warmup_seconds": 0, "formal_performance_pass": False}


def actual_schedule(profile, binding):
    path = verify_reference(binding); expected = plan(profile)["offsets"]
    require(path.stat().st_size <= 64*1024**2, "Frozen schedule exceeds bound")
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        require(reader.fieldnames == ["sequence", "offset_ns"], "Frozen schedule columns differ")
        seen = 0
        for index, row in enumerate(reader):
            require(index < len(expected) and re.fullmatch(r"[0-9]+", row["sequence"])
                    and re.fullmatch(r"[0-9]+", row["offset_ns"])
                    and int(row["sequence"]) == index and abs(int(row["offset_ns"])-expected[index]) <= 1,
                    "Frozen actual Java schedule differs from independent seed model")
            seen += 1
    require(seen == len(expected), "Frozen schedule is incomplete")
    return binding["sha256"]


def business_binding(profile):
    background.validate_current_config(profile)
    fields = {key: value for key, value in profile.items()
              if key not in {"group", "qualification", "duration_seconds", "rate_per_second", "rate_basis"}}
    fields.update(profile=background.CURRENT_PROFILE, connection_mode=MODE,
                  source="license_perf.point_rows", source_rows=1000000, oracle="full_4_column_md5_and_exact_id_domains",
                  mix="alternating_write_then_metadata_even_prefix", source_target_oracle="outside_measurement",
                  cpu_denominator="all_successful_business_operations_no_stream_allocation",
                  timeout_contract="connect10s_socketIdleConfigured_SQLConfigured_queue_in_E2E_no_total_request_deadline",
                  metadata_round_robin=list(background.CURRENT_METADATA_SQL))
    return {"fields": fields, "sha256": canonical(fields)}


def runtime(spec):
    require(set(spec) == {"java_home", "jars"}, "Explicit JDK/JAR runtime required")
    home = api.owned(spec["java_home"]).resolve(strict=True)
    require('JAVA_VERSION="17.0.4"' in (home / "release").read_text(), "Requires actual JDK 17.0.4")
    jars = [Path(item).resolve(strict=True) for item in spec["jars"]]
    require(all(SOURCE.parents[2] in path.parents for path in jars), "JDBC/JSON jars must belong to this checkout")
    require(len(jars) == 4 and {item.name for item in jars} == JARS, "Use exactly the four declared JDBC/JSON jars")
    return {"java_home": str(home), "jdk_runtime": {name: api.sha(home / name) for name in
            ("bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so", "release")},
            "dependencies_sha256": {str(item): api.sha(item) for item in sorted(jars)}}


def dependencies(context):
    result = [context["workload"], *context["bindings"].values(), *context["service_configs"].values()]
    if "arrival_schedule" in context: result.append(context["arrival_schedule"])
    if context["phase"] == "AB": result += [context["freeze"], context["publication"]]
    for item in result: verify_reference(item)
    return result


def validate_context(context, profile, live=False):
    plan(profile)
    require(context["schema_version"] == 1 and context["phase"] in ("DIAGNOSTIC", "CAPACITY", "AA", "AB")
            and context["variant"] in ("A", "B"), "Invalid actual phase/variant")
    require(context["phase"] not in ("AA", "CAPACITY") or context["variant"] == "A", "A-only phase cannot run B")
    require(context["group"] == profile["group"] and context["group"] in ("G5", "G6", "G7"), "Group differs")
    require(isinstance(context["window_id"], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", context["window_id"])
            and type(context["pair_id"]) is int and context["pair_id"] >= 0, "Invalid window identity")
    statistics.validate_identity(context["identity"])
    require(set(context["bindings"]) == set(SOURCES) | set(IDENTITIES), "Incomplete actual source/identity binding")
    for key, source in SOURCES.items(): require(context["bindings"][key] == reference(source), "Source differs: " + key)
    for key, field in IDENTITIES.items():
        require(verify_reference(context["bindings"][key]) and context["bindings"][key]["sha256"] == context["identity"][field],
                "Identity differs: " + key)
    require(read_json(verify_reference(context["workload"])) == profile, "Actual workload differs")
    require(set(context["services"]) == {"fe", "be"} and set(context["service_configs"]) == {"fe", "be"}, "Service roles missing")
    require(context["services"]["fe"]["pid"] != context["services"]["be"]["pid"], "FE/BE service roles alias")
    require(all(set(item) == set(PIN_KEYS) for item in context["services"].values()), "Actual lifetime pins incomplete")
    require(set(context["target"]) == {"name", "host", "query_port"} and context["target"]["host"] == "127.0.0.1",
            "Only the private local FE endpoint is allowed")
    require(type(context["target"]["query_port"]) is int and 1023 < context["target"]["query_port"] < 65536,
            "Invalid FE query endpoint")
    config = verify_reference(context["service_configs"]["fe"]).read_text()
    require(re.findall(r"(?m)^query_port\s*=\s*(\d+)\s*$", config) == [str(context["target"]["query_port"])],
            "Query port differs from actual FE configuration")
    admin = context["admin_account"]
    require(set(admin) == background.ACCOUNT_KEYS and re.fullmatch(r"[A-Za-z0-9_@.:-]{1,128}", admin["username"])
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", admin["password_env"]), "Admin credential reference invalid")
    bound_runtime = runtime(context["runtime"])
    require(context["license_scenario"] in ("VALID", "EXPIRED", "EVENTS"), "Declare target license scenario")
    resources = context["resources"]
    require(set(resources) == {"cpus", "rss_limit_mib", "cell_timeout_seconds", "whole_timeout_seconds"}
            and resources["cpus"] and all(type(v) is int and v >= 0 for v in resources["cpus"])
            and 512 <= resources["rss_limit_mib"] <= 8192, "Resource bounds invalid")
    minimum = sum(profile[key] for key in ("duration_seconds", "drain_seconds", "prepare_timeout_seconds",
                                         "verify_timeout_seconds", "cleanup_timeout_seconds")) + 120
    require(all(type(resources[key]) is int and minimum <= resources[key] <= 14400
                for key in ("cell_timeout_seconds", "whole_timeout_seconds")), "Whole lifecycle deadline insufficient")
    for key, limit in (("coordination_seconds", 300), ("max_clock_uncertainty_ns", 1000000000)):
        require(type(context[key]) is int and 0 < context[key] <= limit, "Invalid handshake bound")
    require(type(context["context_deadline_monotonic_ns"]) is int, "Missing fresh launch deadline")
    client = read_json(verify_reference(context["bindings"]["client"]))
    require(client.get("runtime") == bound_runtime and client.get("resources") == resources
            and client.get("connection_mode") == MODE and client.get("admin_account") == admin
            and all(client.get(key) == profile[key] for key in ("read_account", "write_account")),
            "Frozen client does not bind actual runtime/resources/accounts")
    fixture = read_json(verify_reference(context["bindings"]["fixture"]))
    require(fixture.get("business_workload_sha256") == business_binding(profile)["sha256"], "Fixture does not bind exact workload")
    environment = read_json(verify_reference(context["bindings"]["environment"]))
    require(environment.get("runtime_policy") == {"client_cpus": resources["cpus"], "jvm_heap_mib": 512},
            "Environment does not bind current client policy")
    configuration = read_json(verify_reference(context["bindings"]["configuration"]))
    require(configuration.get("service_configs") == context["service_configs"], "Configuration identity differs")
    dependencies(context)
    formal = profile["qualification"] == "formal" and context["phase"] != "DIAGNOSTIC"
    require(not formal or "arrival_schedule" in context, "Formal window needs a frozen actual Java plan-only schedule")
    schedule_sha = actual_schedule(profile, context["arrival_schedule"]) if "arrival_schedule" in context else None
    if context["phase"] == "AB":
        frozen = read_json(verify_reference(context["freeze"])); publication = read_json(verify_reference(context["publication"]))
        require(frozen["status"] == "FROZEN_ELIGIBLE" and frozen["identities"][context["variant"]] == context["identity"],
                "A/B identity was not frozen")
        cell = frozen["cell"]; planned = plan(profile)
        require(cell["group"] == context["group"] and cell["workload_sha256"] == business_binding(profile)["sha256"]
                and cell["rate"] == profile["rate_per_second"] and cell["duration_seconds"] == profile["duration_seconds"]
                and cell["warmup_seconds"] == 0 and cell["concurrency"] == 16 and cell["connection_mode"] == MODE
                and cell["request_count"] == planned["scheduled_requests"]
                and schedule_sha is not None and cell["arrival_schedule_sha256"] == schedule_sha, "A/B frozen cell differs")
        require(publication["freeze"] == context["freeze"] and publication["boot_id"] == statistics.boot_id(), "Wrong freeze publication")
        require(publication["published_monotonic_ns"] <= context.get("created_monotonic_ns", time.monotonic_ns()),
                "Freeze publication must precede launch")
    else: require("freeze" not in context and "publication" not in context, "Only AB consumes publication")
    if live:
        now = time.monotonic_ns()
        require(now < context["context_deadline_monotonic_ns"] <= now + 300*10**9, "Expired/unbounded launch context")
        require(not any(os.environ.get(key) for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH")),
                "Hidden JVM options/classpath forbidden")
        require(set(os.sched_getaffinity(0)) == set(resources["cpus"]), "Actual client CPU policy differs")
        OwnedGuard(context).check()
    return bound_runtime


def installed_slots(context):
    """Read only the live DORIS_HOME/CLASSPATH fields; never archive full environments."""
    root = SOURCE.parents[2]; installation = {}; selected_env = {}; files = []
    for role in ("fe", "be"):
        config = verify_reference(context["service_configs"][role])
        require(root / ".build-records" in config.parents and config.name == role + ".conf"
                and config.parent.name == "conf" and config.parent.parent.name == role,
                "Service config is not this checkout's installed conf slot")
        installation[role] = config.parent.parent
        raw = Path('/proc', str(context["services"][role]["pid"]), 'environ').read_bytes()
        homes = [part.partition(b'=')[2].decode() for part in raw.split(b'\0') if part.startswith(b'DORIS_HOME=')]
        require(len(homes) == 1 and Path(homes[0]).samefile(installation[role]), "Bound config is not the actual process DORIS_HOME slot")
        selected_env[role] = {"DORIS_HOME": homes[0]}
        pid_file = installation[role] / 'bin' / (role + '.pid')
        require(int(pid_file.read_text()) == context["services"][role]["pid"], "Installed service PID differs")
        slot = installation[role] / 'lib' / ('doris-fe.jar' if role == 'fe' else 'doris_be')
        require(slot.samefile(verify_reference(context["bindings"][role+'_artifact'])), "Installed artifact slot differs")
        files += [str(config), str(pid_file), str(slot)]
    require(installation['fe'].parent == installation['be'].parent, "FE/BE are not the same owned installation")
    require(context['services']['be']['exe'] == str(verify_reference(context['bindings']['be_artifact']))
            and context['services']['fe']['exe'] == str(Path(context['runtime']['java_home'], 'bin/java').resolve()),
            "Actual service executable/JDK differs")
    fe_pid = context['services']['fe']['pid']
    argv = Path('/proc', str(fe_pid), 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    require('org.apache.doris.DorisFE' in argv, "Actual FE entrypoint differs")
    cp = [argv[i+1] for i, entry in enumerate(argv[:-1]) if entry in ('-cp', '-classpath', '--class-path')]
    if not cp:
        cp = [part.partition(b'=')[2].decode() for part in Path('/proc', str(fe_pid), 'environ').read_bytes().split(b'\0')
              if part.startswith(b'CLASSPATH=')]
    require(len(cp) == 1, "Actual FE classpath missing/ambiguous")
    slots = [Path(entry) for entry in cp[0].split(os.pathsep) if Path(entry).name == 'doris-fe.jar']
    require(len(slots) == 1 and slots[0].samefile(installation['fe'] / 'lib/doris-fe.jar'), "Actual FE loaded JAR differs from installed lib slot")
    return {"installation": {key: str(value) for key,value in installation.items()}, "selected_environment": selected_env,
            "classpath_sha256": hashlib.sha256(cp[0].encode()).hexdigest(), "classpath_fe_slot": str(slots[0]),
            "checked_files": files, "observed_monotonic_ns": time.monotonic_ns()}


class OwnedGuard:
    """Actual private FE/BE deployment check; accepts either explicitly bound FE artifact."""
    def __init__(self, context):
        self.context = context; self.pins = list(context["services"].values())
        self.targets = [context["target"]]; self.jar = verify_reference(context["bindings"]["fe_artifact"])
        self.deployment = None; self.stamps = {}

    def check(self):
        value = self.context; namespace = os.readlink("/proc/self/ns/net")
        require(value["host_namespace"] == os.readlink('/proc/1/ns/net') and namespace != value["host_namespace"]
                and all(pin(item["pid"]) == item and item["namespace"] == namespace for item in self.pins),
                "Private service lifetime/actual host namespace changed")
        if self.deployment is None:
            self.deployment = installed_slots(value)
            paths = [*self.deployment["checked_files"], *(value["bindings"][role+"_artifact"]["path"] for role in ("fe", "be"))]
            self.stamps = {path: stamp(path) for path in paths}
        else:
            require(all(stamp(path) == observed for path,observed in self.stamps.items()), "Service artifact/config/slot changed")


class Clock:
    def __init__(self, output, launch_ref, process_pin):
        self.output = Path(output); self.launch_ref = launch_ref; self.launch = read_json(verify_reference(launch_ref))
        self.pin = process_pin; self.request = None; self.bridge = None; self.mapping = None

    def receipt(self, value):
        expected = {"schema_version": 1, "launch_token": self.launch["launch_token"], "launch_sha256": self.launch_ref["sha256"],
                    "boot_id": self.launch["boot_id"], "helper_pid": self.pin["pid"], "helper_start_ticks": self.pin["start_ticks"],
                    "namespace": self.pin["namespace"]}
        require(all(value.get(key) == item for key, item in expected.items()), "Clock receipt from another helper/launch")

    def poll(self):
        if self.bridge is not None: return
        require(time.monotonic_ns() < self.launch["context_deadline_monotonic_ns"], "Context expired before clock/release")
        if self.request is None:
            ready_path = self.output / "p4-clock-ready.json"
            if not ready_path.exists(): return
            ready = read_json(ready_path); self.receipt(ready)
            require(isinstance(ready.get("ready_nonce"), str) and len(ready["ready_nonce"]) >= 16, "Missing fresh helper nonce")
            self.request = {"launch_token": self.launch["launch_token"], "launch_sha256": self.launch_ref["sha256"],
                            "boot_id": self.launch["boot_id"], "nonce": secrets.token_hex(32), "ready_nonce": ready["ready_nonce"]}
            self.before = time.monotonic_ns(); publish(self.output / "clock-request.json", self.request); return
        require(time.monotonic_ns() - self.before <= self.launch["coordination_seconds"]*10**9, "Clock request expired")
        path = self.output / "p4-helper-clock.json"
        if not path.exists(): return
        reply = read_json(path); after = time.monotonic_ns(); self.receipt(reply)
        require(reply["nonce"] == self.request["nonce"], "Clock nonce mismatch")
        bridge = {"schema_version": 1, "launch_token": self.launch["launch_token"], "launch_sha256": self.launch_ref["sha256"],
                  "boot_id": self.launch["boot_id"], "nonce": reply["nonce"], "controller_before_ns": self.before,
                  "controller_after_ns": after, "helper_clock": reference(path)}
        self.mapping = clocks.clock_bridge(self.launch, self.launch_ref, bridge, reply)
        for item in dependencies(self.launch): verify_reference(item)
        require(pin(self.pin["pid"]) == self.pin, "Clock helper lifetime changed")
        require(time.monotonic_ns() < self.launch["context_deadline_monotonic_ns"], "Context expired before clock ack")
        publish(self.output / "p4-clock-bridge.json", bridge); self.bridge = reference(self.output / "p4-clock-bridge.json")
        publish(self.output / "clock-ack.json", {**self.request, "helper_clock_sha256": bridge["helper_clock"]["sha256"],
                                               "bridge_sha256": self.bridge["sha256"]})


class Participant(background.CurrentBackground):
    def __init__(self, plan_value, guard, context, deadline, launch_ref):
        self.clock = None; self.adapter_context = context; self.launch_ref = launch_ref
        super().__init__(api, plan_value, guard, context["target"], {"id": "business"}, context["admin_account"],
                         deadline, context["services"])
        self.config.update(p4_launch=launch_ref, p4_coordination_seconds=context["coordination_seconds"])
        api.save(self.config_path, self.config)

    def check(self, phase_deadline=None):
        if not self.finished and getattr(self, "stop_file", None) is not None:
            require(not self.stop_file.exists(), "Background stop requested before release/completion")
        value = super().check(phase_deadline)
        if not self.finished and self.work_pin is not None and self.process.poll() is None:
            if self.clock is None:
                self.clock = Clock(self.output, self.launch_ref, {key: self.work_pin[key] for key in PIN_KEYS})
            self.clock.poll()
        return value


def freeze_inputs(context, profile, bound_runtime):
    return {"input_path": context["workload"]["path"], "input_sha256": context["workload"]["sha256"], "config": profile,
            **bound_runtime, "source_sha256": {str(path): api.sha(path) for path in
            (background.SOURCE, background.JAVA_SOURCE, *background.FROZEN_REFERENCES)},
            "connection_mode": MODE, "point_mode": "metadata_text_statement",
            "schedule": "java.util.Random_poisson_StrictMath_log_frozen_before_SQL",
            "scope": "P4 allowed-business participant; external lifecycle/state controller"}


def barrier(ref, stage, launch_ref, variant):
    value = read_json(verify_reference(ref)); launch = read_json(launch_ref["path"])
    require(value.get("status") == "VERIFIED" and value.get("stage") == stage
            and value.get("launch_sha256") == launch_ref["sha256"] and value.get("boot_id") == launch["boot_id"],
            "Missing actual barrier identity/state proof")
    require(value.get("raw_artifacts") and isinstance(value.get("observed_monotonic_ns"), int), "Barrier lacks original state evidence")
    for item in [value["auditor"], *value["raw_artifacts"]]: verify_reference(item)
    if variant == "A": require(value.get("observed_license_state") == "ORIGINAL_A_NO_LICENSE", "A has no license API")
    elif stage == "READY_FOR_VERIFICATION":
        require(value.get("observed_license_state") in ("VALID", "EXPIRING"), "Full source oracle requires usable post-window state")
    elif launch["license_scenario"] != "EVENTS":
        allowed = ("VALID", "EXPIRING") if launch["license_scenario"] == "VALID" else ("EXPIRED",)
        require(value.get("observed_license_state") in allowed, "Actual measurement state differs")
    else: require(value.get("observed_license_state") in ("VALID", "EXPIRING", "EXPIRED", "PENDING"), "Missing event initial state")
    return value


class Window:
    """Explicit start -> release -> await_quiescence -> finish. Caller owns real event barriers."""
    def __init__(self, context, output, stop_file=None):
        self.context = json.loads(json.dumps(context)); self.profile = read_json(verify_reference(context["workload"]))
        bound_runtime = validate_context(self.context, self.profile, live=True)
        require("P4_CLOCK_ONLY_EXPLICIT_LAUNCH" in background.JAVA_SOURCE.read_text(), "Optional Java P4 handshake patch not installed")
        self.output = api.owned(output); self.output.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.stop_file = Path(stop_file) if stop_file else self.output / "stop"
        self.dependency_stamps = {item["path"]: stamp(item["path"]) for item in dependencies(context)}
        self.guard = OwnedGuard(self.context); self.guard.check(); self.active = None; self.closed = False; self.released = False; self.quiescent = False
        self.started = time.monotonic_ns(); self.deadline = time.monotonic() + context["resources"]["whole_timeout_seconds"]
        self.launch = {**self.context, "schema_version": 1, "created_monotonic_ns": self.started,
                       "boot_id": statistics.boot_id(), "utc_anchor": lifecycle.anchor(), "launch_token": secrets.token_hex(32),
                       "actual_namespace": os.readlink("/proc/self/ns/net"), "bound_runtime": bound_runtime,
                       "installed_slots": self.guard.deployment}
        publish(self.output / "p4-launch.json", self.launch); self.launch_ref = reference(self.output / "p4-launch.json")
        frozen = freeze_inputs(self.context, self.profile, bound_runtime); publish(self.output / "frozen.json", frozen)
        self.active = Participant({"background": frozen, "output": str(self.output), "resources": context["resources"]},
                                  self.guard, self.context, self.deadline, self.launch_ref)
        self.active.stop_file = self.stop_file

    def checkpoint(self):
        require(not self.stop_file.exists() and time.monotonic() < self.deadline, "Window stop/deadline")
        require(all(stamp(path) == previous for path, previous in self.dependency_stamps.items()), "Executing input/source changed")
        self.guard.check()
        if self.active is not None and not self.active.finished: self.active.check()

    def start(self):
        self.active.start(); self.checkpoint()
        require(self.active.clock and self.active.clock.bridge, "Background readiness lacks completed clock handshake")
        publish(self.output / "ready-observation.json", {"observed_monotonic_ns": time.monotonic_ns(), "ready": reference(self.active.output / "ready.json")})
        return self

    def release(self, state_evidence):
        self.checkpoint(); require(not self.released, "Window already released")
        value = barrier(state_evidence, "READY_FOR_MEASUREMENT", self.launch_ref, self.context["variant"])
        ready = read_json(self.output / "ready-observation.json")
        require(ready["observed_monotonic_ns"] <= value["observed_monotonic_ns"] <= time.monotonic_ns(), "State proof predates readiness")
        require(time.monotonic_ns() < self.launch["context_deadline_monotonic_ns"], "Context expired before actual release")
        publish(self.output / "release-barrier.json", {"evidence": state_evidence, "before_monotonic_ns": time.monotonic_ns()})
        self.active.release(); self.released = True

    def await_quiescence(self, checkpoint=None):
        require(self.released, "Window not released")
        while True:
            self.checkpoint()
            if checkpoint is not None: checkpoint(self)
            marker = self.active.output / "verification-ready.json"
            if marker.exists(): break
            if self.active.process.poll() is not None:
                require(marker.exists(), "Helper exited before quiescence receipt"); break
            time.sleep(.02)
        value = read_json(marker); self.active._identity_receipt(value)
        require(value.get("workers_closed") is True and value.get("business_window_finished") is True,
                "Business worker cleanup is incomplete")
        self.quiescent = True
        publish(self.output / "quiescence-observation.json", {"observed_monotonic_ns": time.monotonic_ns(), "receipt": reference(marker)})
        return reference(marker)

    def finish(self, state_evidence=None, failure=None):
        require(not self.closed, "Window completion already recorded"); self.closed = True
        errors = []; result = None
        try:
            if failure is not None: errors.append(type(failure).__name__)
            if failure is None:
                require(self.quiescent and state_evidence is not None, "Explicit post-window state barrier required")
                value = barrier(state_evidence, "READY_FOR_VERIFICATION", self.launch_ref, self.context["variant"])
                seen = read_json(self.output / "quiescence-observation.json")["observed_monotonic_ns"]
                require(seen <= value["observed_monotonic_ns"] <= time.monotonic_ns(), "Post state proof predates quiescence")
                publish(self.output / "verification-barrier.json", {"evidence": state_evidence, "before_monotonic_ns": time.monotonic_ns()})
                self.active.allow_verification()
        except BaseException as error: errors.append(type(error).__name__)
        finally:
            # Never condition own child cleanup on clock, source, or state evidence remaining valid.
            try: result = self.active.finish()
            except BaseException as error: errors.append(type(error).__name__)
            with capacity.shield_cleanup_signals():
                if self.active.process is not None:
                    try:
                        if self.active.process.poll() is None: capacity.terminate_client(self.active.process)
                        self.active.process.wait(timeout=5)
                    except BaseException as error: errors.append(type(error).__name__)
        try: dependencies(self.launch)
        except (ValueError, OSError) as error: errors.append(type(error).__name__)
        pin_value = self.active.work_pin; helper_process = read_json(self.active.output / "background-process.json") if pin_value else None
        life_path = self.active.output / "process-lifecycle.json"
        events = read_json(life_path) if life_path.exists() else []
        waited = [event for event in events if event.get("pid") == (pin_value or {}).get("pid")
                  and event.get("parent_wait_complete") is True]
        remaining = capacity.live_group_members(pin_value["pid"]) if pin_value else []
        if not result or result.get("status") != "PASS" or not waited or remaining: errors.append("IncompleteLifecycle")
        clock = self.active.clock
        if not clock or not clock.bridge: errors.append("MissingClock")
        if clock and clock.bridge and (self.active.output / "summary.json").exists():
            try:
                upper = read_json(self.active.output / "summary.json")["cleanup_end_java_ns"] + clock.mapping["offset_upper_ns"]
                delay = upper - time.monotonic_ns()
                require(delay <= 2*self.context["max_clock_uncertainty_ns"], "Invalid cleanup clock bound")
                if delay > 0: time.sleep(delay/1e9)
            except (KeyError, ValueError, OSError): errors.append("InvalidCleanupClock")
        completion = {"schema_version": 1, "launch_token": self.launch["launch_token"], "launch_sha256": self.launch_ref["sha256"],
            "boot_id": statistics.boot_id(), "helper_pid": (pin_value or {}).get("pid"), "helper_start_ticks": (pin_value or {}).get("start_ticks"),
            "exit_code": waited[-1].get("exit_code") if waited else None, "parent_wait_complete": bool(waited),
            "remaining_live_pids": remaining, "controller_errors": errors, "bridge": clock.bridge if clock else None,
            "completed_monotonic_ns": time.monotonic_ns(), "utc_anchor": lifecycle.anchor(),
            "actual_launch": reference(self.active.output / "background-process.json") if helper_process else None,
            "actual_wait_events": reference(life_path) if events else None, "result": reference(self.active.output / "controller.json") if result else None}
        publish(self.output / "p4-completion.json", completion)
        return {"status": "RAW_WINDOW_COMPLETE" if not errors and completion["exit_code"] == 0 else "INVALID_WINDOW",
                "window_directory": str(self.output), "launch": self.launch_ref, "completion": reference(self.output / "p4-completion.json"),
                "formal_performance_pass": False}


def run_window(context, output, on_ready, on_quiescent, checkpoint=None, stop_file=None):
    value = Window(context, output, stop_file)
    try:
        value.start(); value.release(on_ready(value)); value.await_quiescence(checkpoint)
        return value.finish(on_quiescent(value))
    except BaseException as error:
        if not value.closed: value.finish(failure=error)
        raise


def raw_bindings(directory):
    items = []
    for path in sorted(Path(directory).rglob("*")):
        require(not path.is_symlink(), "Raw artifact symlink forbidden")
        if path.is_file(): items.append(reference(path))
    return items


def normalize(manifest):
    directory = Path(manifest["window_directory"]).resolve(); original = raw_bindings(directory)
    launch_ref = manifest["launch"]; launch = read_json(verify_reference(launch_ref))
    require(launch_ref == reference(directory / "p4-launch.json"), "Launch from another window")
    profile = read_json(verify_reference(launch["workload"])); bound_runtime = validate_context(launch, profile)
    require(bound_runtime == launch["bound_runtime"], "Executed runtime differs")
    raw_dir = directory / "business-background"; config = read_json(raw_dir / "config.json")
    require(config["p4_launch"] == launch_ref and config["cpu_services"] == launch["services"]
            and config["target"] == launch["target"] and config["oracle_account"] == launch["admin_account"]
            and config["namespace"] == launch["actual_namespace"] and config["heap_mib"] == 512,
            "Executed helper input differs")
    require(all(config.get(key) == value for key, value in profile.items()), "Executed business profile differs")
    require(read_json(directory / "frozen.json") == freeze_inputs(launch, profile, bound_runtime), "Compiled frozen inputs differ")
    helper_identity = read_json(raw_dir / "helper-identity.json")
    require(helper_identity["dependencies"] == bound_runtime["dependencies_sha256"], "Actual compiled dependencies differ")
    require(helper_identity["frozen"] == read_json(directory / "frozen.json"), "Compiled helper source/input freeze differs")
    for path, digest in helper_identity["classes"].items(): require(api.sha(path) == digest, "Compiled class changed")
    require(str(raw_dir / "classes/LicenseUiBackground.class") in helper_identity["classes"], "Main class not bound")
    require(set(helper_identity["classes"]) == {str(path) for path in (raw_dir / "classes").rglob("*.class")},
            "Unbound compiled class introduced")
    actual = read_json(raw_dir / "background-process.json"); completion = read_json(verify_reference(manifest["completion"]))
    require(completion["actual_launch"] == reference(raw_dir / "background-process.json")
            and completion["actual_wait_events"] == reference(raw_dir / "process-lifecycle.json"), "Wait/launch sources differ")
    expected_command = [str(Path(bound_runtime["java_home"]) / "bin/java"), "-Xmx512m", "-cp",
                        os.pathsep.join([str(raw_dir / "classes"), *sorted(bound_runtime["dependencies_sha256"])]),
                        "LicenseUiBackground", str(raw_dir / "config.json")]
    command_sha = hashlib.sha256(b"\0".join(os.fsencode(value) for value in expected_command)+b"\0").hexdigest()
    require(actual["expected_launch"]["command_sha256"] == actual["pin"]["command_sha256"] == command_sha
            and actual["pin"]["namespace"] == launch["actual_namespace"]
            and actual["pin"]["exe"] == str(Path(expected_command[0]).resolve()), "Actual helper command/namespace changed")
    require(completion["launch_token"] == launch["launch_token"] and completion["launch_sha256"] == launch_ref["sha256"]
            and completion["boot_id"] == launch["boot_id"] == statistics.boot_id()
            and completion["exit_code"] == 0 and completion["parent_wait_complete"] is True
            and not completion["remaining_live_pids"] and not completion["controller_errors"], "Parent wait/exit failed")
    events = read_json(verify_reference(completion["actual_wait_events"]))
    require(any(item.get("pid") == actual["pin"]["pid"] and item.get("parent_wait_complete") is True and item.get("exit_code") == 0
                for item in events), "No actual waited work JVM receipt")
    bridge = read_json(verify_reference(completion["bridge"])); helper = read_json(verify_reference(bridge["helper_clock"]))
    require(helper["helper_pid"] == completion["helper_pid"] == actual["pin"]["pid"]
            and helper["helper_start_ticks"] == completion["helper_start_ticks"] == actual["pin"]["start_ticks"], "Clock/parent process differs")
    mapping = clocks.clock_bridge(launch, launch_ref, bridge, helper); offset = mapping["estimated_offset_ns"]
    ready_clock = read_json(raw_dir / "p4-clock-ready.json")
    request, ack = (read_json(raw_dir/name) for name in ("clock-request.json", "clock-ack.json"))
    require(all(ready_clock.get(key) == helper[key] for key in
                ("launch_token", "launch_sha256", "boot_id", "helper_pid", "helper_start_ticks", "namespace"))
            and isinstance(ready_clock.get("ready_nonce"), str) and len(ready_clock["ready_nonce"]) >= 16,
            "Clock readiness belongs to another helper")
    require(all(request.get(key) == ack.get(key) == helper[key] for key in
                ("launch_token", "launch_sha256", "boot_id", "nonce"))
            and request["ready_nonce"] == ack["ready_nonce"] == ready_clock["ready_nonce"]
            and ack["helper_clock_sha256"] == bridge["helper_clock"]["sha256"]
            and ack["bridge_sha256"] == completion["bridge"]["sha256"], "Clock request/ack is replayed or unbound")
    clocks.utc_anchor(launch["utc_anchor"]); clocks.utc_anchor(completion["utc_anchor"])
    expected = {key: helper[key] for key in ("launch_token", "launch_sha256", "boot_id", "helper_pid", "helper_start_ticks", "namespace")}
    for name in ("ready.json", "summary.json", "measurement-start.json", "measurement-end.json", "window-start.json",
                 "window-end.json", "verification-ready.json", "verification-start.json"):
        value = read_json(raw_dir/name)
        require(all(value.get(key) == item for key, item in expected.items()), "Helper receipt identity differs: " + name)
    summary = read_json(raw_dir / "summary.json"); controller = read_json(raw_dir / "controller.json")
    require(controller["status"] == summary["status"] == "PASS" and controller["cleanup_confirmed"]
            and controller["owned_child_exited"] and not controller["errors"] and summary["workers_closed"]
            and summary["cleanup_confirmed"] and summary["automatic_write_replays"] == 0, "Oracle/cleanup/retry failed")
    requests = background.audit_current_receipts(api, raw_dir, profile, summary)
    models = background.audit_full_models(api, raw_dir, profile, summary)
    require(requests == controller["receipt_audit"] and models == controller["full_model_audit"], "Stored controller audit differs from raw recomputation")
    require(all(value["successful"] == value["scheduled"] and value["unknown"] == value["errors"] == 0
                for value in requests["streams"].values()), "Business errors/unknown outcomes retained")
    connection_ids = set()
    for role in ("read", "write"):
        settings = {"enable_sql_cache": "false", "enable_query_cache": "false", "enable_short_circuit_query": "true",
                    "query_timeout": str(profile["timeout_seconds"]), "insert_timeout": str(profile["timeout_seconds"])}
        if role == "write": settings.update(group_commit="off_mode", enable_insert_strict="true", enable_unique_key_partial_update="false")
        for worker in range(8):
            opened, ended = (read_json(raw_dir/f"{role}-{worker}-p4-{phase}.json") for phase in ("open", "end"))
            require(read_json(raw_dir/f"{role}-{worker}-session.json") == settings, "Actual worker session settings differ")
            require(all(opened.get(key) == ended.get(key) == item for key, item in expected.items())
                    and opened["role"] == ended["role"] == role and opened["worker"] == ended["worker"] == worker
                    and opened["connections_opened"] == 1 and opened["driver_version"] == "3.0.9"
                    and opened["connection_class"] == "org.mariadb.jdbc.Connection"
                    and opened["connection_id"] == ended["connection_id"] and ended["same_client_and_connection"] is True,
                    "Actual persistent worker identity/reuse differs")
            require(opened["connection_id"] not in connection_ids, "Worker connections alias")
            connection_ids.add(opened["connection_id"])
            require(ended["operations"] == (requests["streams"][role]["scheduled"] + 7-worker)//8,
                    "Persistent connection operation count differs")
    start, end, ready, verify = (read_json(raw_dir/name) for name in
        ("window-start.json", "measurement-end.json", "ready.json", "verification-start.json"))
    cpu_start = read_json(raw_dir / "measurement-start.json")
    epoch = start["epoch_java_monotonic_ns"]; last = end["request_interval_end_java_ns"]
    require(helper["jvm_sample_ns"] <= ready["java_monotonic_ns"] <= cpu_start["java_monotonic_ns"] <= epoch
            and epoch + mapping["offset_upper_ns"] <= launch["context_deadline_monotonic_ns"], "Actual measured start exceeds context lifetime")
    lower = min(v["sample_started_java_ns"] for v in cpu_start["cpu"].values()) + mapping["offset_lower_ns"]
    upper = max(end["java_monotonic_ns"], *(v["sample_ended_java_ns"] for v in end["cpu"].values())) + mapping["offset_upper_ns"]
    require(launch["created_monotonic_ns"] <= lower and summary["cleanup_end_java_ns"] >= verify["java_monotonic_ns"] >= end["java_monotonic_ns"]
            and summary["cleanup_end_java_ns"] + mapping["offset_upper_ns"] <= completion["completed_monotonic_ns"], "Launch/cleanup/wait timing invalid")
    extra = []; deps = dependencies(launch)
    for name, stage, boundary in (("release-barrier.json", "READY_FOR_MEASUREMENT", lower),
                                 ("verification-barrier.json", "READY_FOR_VERIFICATION", None)):
        control = read_json(directory/name); value = barrier(control["evidence"], stage, launch_ref, launch["variant"])
        require(value["observed_monotonic_ns"] <= control["before_monotonic_ns"], "Barrier observation order invalid")
        if boundary is not None:
            release = read_json(raw_dir/"release.json")
            require(value["observed_monotonic_ns"] >= read_json(directory/"ready-observation.json")["observed_monotonic_ns"]
                    and release["token"] == config["token"] and control["before_monotonic_ns"] <= release["controller_monotonic_ns"]
                    <= min(v["sample_started_java_ns"] for v in cpu_start["cpu"].values()) + mapping["offset_upper_ns"],
                    "Measurement begins before actual release/state proof")
        else:
            release = read_json(raw_dir/"verify-release.json")
            require(value["observed_monotonic_ns"] >= read_json(directory/"quiescence-observation.json")["observed_monotonic_ns"]
                    and release["token"] == config["token"] and control["before_monotonic_ns"] <= release["controller_monotonic_ns"]
                    <= verify["java_monotonic_ns"] + mapping["offset_upper_ns"], "Verification predates actual restored state")
        extra += [control["evidence"], *value["raw_artifacts"]]; deps += [value["auditor"]]
    formal = profile["qualification"] == "formal" and launch["phase"] != "DIAGNOSTIC"
    if formal or "observer" in manifest:
        observation = read_json(verify_reference(manifest["observer"]))
        require(observation["status"] == "VERIFIED" and observation["launch_sha256"] == launch_ref["sha256"]
                and observation["boot_id"] == launch["boot_id"] and observation["coverage_start_monotonic_ns"] <= lower
                and observation["coverage_end_monotonic_ns"] >= upper and observation["budget_verified"] is True
                and observation["resource_failures"] == [] and observation["raw_artifacts"], "Actual resource/state observation incomplete")
        require(observation["license_scenario"] == launch["license_scenario"]
                and observation["actual_state_timeline_verified"] is True, "Actual state timeline is unproven")
        for role in ("fe", "be"):
            require(observation["services"][role] == {"pin": launch["services"][role], "artifact": launch["bindings"][role+"_artifact"],
                    "configuration": launch["service_configs"][role]}, "Observer deployment differs")
        extra += [manifest["observer"], *observation["raw_artifacts"]]; deps += [observation["auditor"]]
    planned = plan(profile)
    if "arrival_schedule" in launch:
        require(summary["total_schedule_sha256"] == actual_schedule(profile, launch["arrival_schedule"]),
                "Executed schedule differs from frozen actual Java schedule")
    if formal: require(all(value["successful"] >= 10000 for value in requests["streams"].values()), "Each stream needs 10000 successful samples")
    metrics = {key: requests[key] for key in ("success_qps", "p95_ms", "p99_ms")}
    metrics.update({role+"_cpu_seconds_per_success": requests["cpu"][role]["cpu_seconds_per_success"] for role in ("fe", "be")})
    window = {"window_id": launch["window_id"], "pair_id": launch["pair_id"], "variant": launch["variant"], "boot_id": launch["boot_id"],
        "identity": launch["identity"], "workload_sha256": business_binding(profile)["sha256"],
        "arrival_schedule_sha256": summary["total_schedule_sha256"], "rate": profile["rate_per_second"], "warmup_seconds": 0,
        "duration_seconds": profile["duration_seconds"], "warmup_start_monotonic_ns": epoch+offset,
        "warmup_end_monotonic_ns": epoch+offset, "start_monotonic_ns": epoch+offset, "end_monotonic_ns": last+offset,
        "monotonic_clock_domain": "bounded_jvm_mapping", "monotonic_mapping": mapping, "monotonic_mapping_uncertainty_ns": mapping["uncertainty_ns"],
        "effective_duration_seconds": requests["effective_duration_seconds"], "scheduled_requests": requests["scheduled_requests"],
        "observed_requests": requests["scheduled_requests"], "successful_requests": requests["successful_requests"],
        "error_count": 0, "timeout_count": 0, "retry_count": 0, "oracle_verified": True, "cleanup_verified": True,
        "cpu_boundary_verified": True, "metrics": metrics}
    if launch["phase"] == "AB":
        window.update(freeze_sha256=launch["freeze"]["sha256"], freeze_publication_sha256=launch["publication"]["sha256"])
    require(raw_bindings(directory) == original, "Raw changed while independently auditing")
    raw = list({item["path"]: item for item in original + extra}.values()); deps = list({item["path"]: item for item in deps}.values())
    for item in raw + deps: verify_reference(item)
    return {"status": "VERIFIED" if formal else "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED", "window": window,
            "auditor": reference(SOURCE), "raw_artifacts": raw, "dependency_bindings": deps,
            "request_audit": requests, "full_model_audit": models, "formal_shape_met": formal,
            "cpu_scope": "mixed total CPU per successful operation; never allocated to individual streams",
            "business_stream_metrics": {key: {k: v for k,v in item.items() if k != "successful_latency_ms"}
                                        for key,item in requests["streams"].items()},
            "formal_performance_pass": False, "group_event_or_ui_qualification": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "normalize")); parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True); args = parser.parse_args()
    value = read_json(args.input)
    require(not args.output.exists(), "Never overwrite evidence")
    if args.mode == "plan": result = {"plan": plan(value), "business": business_binding(value)}
    else:
        require(Path(value["window_directory"]).resolve() not in args.output.resolve().parents, "Audit must be outside raw window")
        result = normalize(value)
    publish(args.output, result)
    print(json.dumps({"status": result.get("status", "OFFLINE_PLAN"), "formal_performance_pass": False}))
    return 0


if __name__ == "__main__": raise SystemExit(main())
