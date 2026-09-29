#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""One G3 PostgreSQL/JDBC INSERT SELECT window. Import/plan/audit never send SQL."""

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
from types import SimpleNamespace

import dml_performance as dml
import external_read_performance as external
import p4_jdbc_evidence as clocks
import p4_statistics as stats
import ui_background_fixture as lifecycle

SOURCE = Path(__file__).resolve()
JAVA_SOURCE = SOURCE.with_name("LicenseExternalWritePerformance.java")
PROFILE = "g3_external_write_v1"
require, ref, verify, read = stats.require, stats.reference, stats.verify_reference, stats.read_json
BOUNDS = {"warmup_seconds": (1, 7200), "duration_seconds": (1, 604800), "timeout_seconds": (1, 60),
          "drain_seconds": (1, 120), "prepare_timeout_seconds": (120, 3600), "verify_timeout_seconds": (120, 7200),
          "cleanup_timeout_seconds": (30, 120), "coordination_timeout_seconds": (10, 1800),
          "max_requests": (2, 100000), "max_rows": (200, 10000000), "min_disk_free_bytes": (1024**3, 1024**4),
          "max_raw_ledger_bytes": (8 * 1024**2, 2 * 1024**3)}
JARS = {"mariadb-java-client-3.0.9.jar", "postgresql-42.7.8.jar", "jackson-core-2.16.0.jar",
        "jackson-databind-2.16.0.jar", "jackson-annotations-2.16.0.jar"}
SOURCES = {"runner": SOURCE, "java_helper": JAVA_SOURCE, "process_lifecycle": Path(lifecycle.__file__),
           "dml_lifecycle": Path(dml.__file__), "external_environment": Path(external.__file__),
           "clock_adapter": Path(clocks.__file__), "statistics": Path(stats.__file__)}
IDENTITIES = {"fe_artifact": "fe_sha256", "be_artifact": "be_sha256", "environment": "environment_sha256",
              "configuration": "configuration_sha256", "fixture": "fixture_sha256", "client": "client_sha256"}
SCHEMA = [["run_id", "character varying(32)", True], ["request_id", "bigint", True], ["id", "bigint", True],
          ["grp", "integer", True], ["v", "bigint", True], ["payload", "character varying(32)", True]]
PRIMARY_KEY = "PRIMARY KEY (run_id, request_id, id)"


def schema_hash():
    return hashlib.sha256(json.dumps({"columns": SCHEMA, "primary_key": PRIMARY_KEY}, separators=(",", ":")).encode()).hexdigest()


def account(value):
    require(set(value) == {"username", "host", "password_env"}
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value["username"]) and value["host"] == "%"
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value["password_env"]), "Account needs a user and credential environment name")


def validate_config(value):
    require(isinstance(value, dict) and set(value) == set(BOUNDS) | {"schema_version", "profile", "qualification", "license_state",
        "concurrency", "rate_per_second", "seed", "rows_per_operation", "read_account", "write_account", "native_account",
        "storage_paths", "source_data_sha256"}, "External write profile fields differ")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["profile"] == PROFILE and value["seed"] == 20260922
            and type(value["seed"]) is int and value["rows_per_operation"] == 100 and type(value["rows_per_operation"]) is int,
            "External write fixed model/seed differs")
    require(type(value["concurrency"]) is int and value["concurrency"] in (1, 8)
            and value["qualification"] in ("formal", "diagnostic") and value["license_state"] == "VALID", "External write mode differs")
    for key, (low, high) in BOUNDS.items():
        require(type(value[key]) is int and low <= value[key] <= high, "External write bound differs: " + key)
    require(value["qualification"] == "diagnostic" or value["warmup_seconds"] >= 180 and value["duration_seconds"] >= 600,
            "External write formal window too short")
    require(type(value["rate_per_second"]) in (float, int) and math.isfinite(value["rate_per_second"])
            and 0 < value["rate_per_second"] <= 1000, "External write rate invalid")
    require(value["rate_per_second"] * (value["warmup_seconds"] + value["duration_seconds"]) < value["max_requests"] * .95,
            "Expected sink arrivals exceed the frozen resource envelope")
    require(value["max_rows"] >= value["max_requests"] * 100
            and value["min_disk_free_bytes"] >= value["max_rows"] * 512 + value["max_raw_ledger_bytes"] + 1024**3,
            "External write row/disk reservation too small")
    require(value["source_data_sha256"] == external.MODEL_SHA, "Frozen original PG source model changed")
    for key in ("read_account", "write_account"): account(value[key])
    native = value["native_account"]
    require(set(native) == {"host", "port", "database", "user", "password_env"}
            and re.fullmatch(r"10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", native["host"])
            and type(native["port"]) is int and 0 < native["port"] < 65536
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", native["database"]), "Private native PostgreSQL endpoint differs")
    account({"username": native["user"], "host": "%", "password_env": native["password_env"]})
    paths = value["storage_paths"]
    require(isinstance(paths, list) and 1 <= len(paths) <= 8 and len(set(paths)) == len(paths)
            and all(isinstance(path, str) and Path(path).is_absolute() for path in paths), "Explicit owned storage paths required")
    return value


def plan(value):
    validate_config(value); result = {}; base = 0
    for phase, seconds in (("warmup", value["warmup_seconds"]), ("measurement", value["duration_seconds"])):
        arrivals = lifecycle.current_arrivals(value["rate_per_second"], seconds)
        require(arrivals and len(arrivals) + base <= value["max_requests"], "External write arrival bound exceeded")
        text = "sequence\toffset_ns\trequest_id\trows\n" + "".join(
            f"{index}\t{offset}\t{base + index}\t100\n" for index, offset in enumerate(arrivals))
        result[phase] = {"arrivals": arrivals, "first_request": base, "requests": len(arrivals), "tsv": text,
                         "reference_schedule_sha256": hashlib.sha256(text.encode()).hexdigest()}; base += len(arrivals)
    require(value["qualification"] != "formal" or result["measurement"]["requests"] >= 10000,
            "Formal sink needs at least 10000 complete operations, extend the declared duration")
    result.update(total_requests=base, maximum_target_rows=base * 100, formal_performance_pass=False)
    return result


def business_binding(value):
    validate_config(value)
    fields = {key: value[key] for key in ("profile", "seed", "rows_per_operation", "concurrency", "timeout_seconds", "drain_seconds",
        "max_requests", "max_rows", "min_disk_free_bytes", "max_raw_ledger_bytes", "read_account", "write_account", "native_account", "source_data_sha256")}
    fields.update(connection_mode="reuse", source="internal.license_perf.point_rows", source_ids=[0, 99],
                  target="owned_PostgreSQL_run_request_id_primary_key", arrival="java_Random20260922_StrictMath_log_reset_each_phase",
                  jdbc="MariaDB3.0.9_text_no_retry_query_timer0_owned_socket_deadline120s",
                  native_oracle="PostgreSQL42.7.8_all_six_columns_sorted_full_rows_post_window",
                  successful_ack_update_count=0, online_visibility_claim=False,
                  commit_evidence={"server_variable_autocommit": "1",
                                   "driver_getAutoCommit": "recorded_boolean_not_server_commit_proof",
                                   "independent_native_full_model": "required_post_window"})
    return {"fields": fields, "sha256": hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def declared_schedule(launch, profile, directory=None):
    """Freeze actual Java TSV bytes; Python's independent log implementation is a <=1ns reference."""
    required = profile["qualification"] == "formal" or launch["phase"] == "AB"
    if "arrival_schedule" not in launch:
        require(not required, "Formal/AB sink needs predeclared actual Java arrival TSV references")
        return None
    binding = launch["arrival_schedule"]; value = read(verify(binding)); planned = plan(profile)
    require(set(value) == {"schema_version", "workload_sha256", "warmup", "measurement"}
            and value["schema_version"] == 1 and value["workload_sha256"] == launch["workload"]["sha256"],
            "Sink predeclared schedule belongs to another workload")
    for phase in ("warmup", "measurement"):
        path = verify(value[phase]); selected = planned[phase]
        require(path.stat().st_size <= profile["max_requests"] * 128, "Declared sink arrivals exceed bound")
        rows = dml.csv_rows(path)
        require(len(rows) == selected["requests"], "Declared sink arrival count differs")
        for index, (row, offset) in enumerate(zip(rows, selected["arrivals"])):
            require(set(row) == {"sequence", "offset_ns", "request_id", "rows"} and int(row["sequence"]) == index
                    and abs(int(row["offset_ns"]) - offset) <= 1 and int(row["request_id"]) == selected["first_request"] + index
                    and int(row["rows"]) == 100, "Declared sink schedule differs from independent seed/model")
        if directory is not None:
            require(stats.digest(Path(directory) / (phase + "-arrivals.tsv")) == value[phase]["sha256"],
                    "Actual Java sink arrivals differ from the predeclared bytes")
    return value


def freeze(api, path, cluster, resources, postgres_driver):
    path = api.owned(path); profile = validate_config(api.read_json(path)); plan(profile)
    java = Path(cluster["java_home"]).resolve(strict=True); package = Path(cluster["package"]).resolve(strict=True)
    require(api.ROOT in java.parents and api.ROOT in package.parents
            and 'JAVA_VERSION="17.0.4"' in (java / "release").read_text(), "Use actual checkout JDK17.0.4 and package")
    dependencies = [Path(postgres_driver).resolve(strict=True)]
    dependencies += [package / "fe/lib" / name for name in sorted(JARS - {"postgresql-42.7.8.jar"})]
    require({path.name for path in dependencies} == JARS and all(path.is_file() for path in dependencies), "Exact five JDBC/Jackson jars required")
    for name in profile["storage_paths"]:
        actual = api.owned(Path(name)).resolve(strict=True)
        require(actual.is_dir() and str(actual) == name, "Storage path must be an actual owned directory")
    require(resources["rss_limit_mib"] >= 1024 and resources["cpus"], "Own client resource budget missing")
    return {"input_path": str(path), "input_sha256": api.sha(path), "config": profile, "java_home": str(java),
            "jdk_runtime": {name: api.sha(java / name) for name in ("bin/java", "bin/javac", "lib/modules", "release")},
            "dependencies_sha256": {str(path): api.sha(path) for path in dependencies},
            "source_sha256": {str(path): api.sha(path) for path in SOURCES.values()},
            "business_workload_sha256": business_binding(profile)["sha256"], "scope": "G3 independent external sink window"}


def source(context, profile, live=False):
    actual = external.external_source(context, {"source_kind": "catalog", "source_data_sha256": profile["source_data_sha256"]}, live)
    prepared = read(verify(actual["plan"]))
    native = profile["native_account"]
    require(all(native[key] == prepared["postgres"][key if key != "host" else "ip"]
                for key in ("host", "port", "database", "user")), "Native oracle uses another PostgreSQL service/account")
    require({key: prepared["driver"][key] for key in ("path", "sha256")} == context["bindings"]["postgres_driver"],
            "Native driver differs from prepared source driver")
    # Native service data directory must be among the observed/reserved filesystems.
    require(str(Path(prepared["root"]) / "postgres/data") in profile["storage_paths"], "PG data filesystem was not reserved")
    return actual


def validate_launch(value, profile):
    require(value["schema_version"] == 1 and value["phase"] in ("DIAGNOSTIC", "CAPACITY", "AA", "AB")
            and value["variant"] in ("A", "B") and (value["phase"] not in ("AA", "CAPACITY") or value["variant"] == "A"),
            "External write launch phase/variant differs")
    require(re.fullmatch(r"[a-f0-9]{32}", value["launch_token"]) and value["boot_id"] == stats.boot_id()
            and type(value["created_monotonic_ns"]) is int and value["created_monotonic_ns"] >= 0
            and isinstance(value["window_id"], str) and value["window_id"] and type(value["pair_id"]) is int and value["pair_id"] >= 0,
            "Actual external write launch identity missing")
    require(type(value["max_clock_uncertainty_ns"]) is int and 0 < value["max_clock_uncertainty_ns"] <= 10**9, "Clock bound missing")
    clocks.utc_anchor(value["utc_anchor"]); stats.validate_identity(value["identity"])
    require(read(verify(value["workload"])) == profile, "External write workload changed")
    arrival = declared_schedule(value, profile)
    target = value["target"]
    require(set(target) == {"name", "host", "query_port"} and target["host"] == "127.0.0.1"
            and isinstance(target["name"], str) and target["name"] and type(target["query_port"]) is int
            and 0 < target["query_port"] < 65536, "Actual private FE target missing")
    require(set(value["services"]) == set(value["service_configs"]) == {"fe", "be"}
            and value["services"]["fe"]["pid"] != value["services"]["be"]["pid"]
            and all(value["services"][role]["start_ticks"] == value["service_start_ticks"][role] for role in ("fe", "be")),
            "Actual FE/BE launch generation missing")
    for item in value["service_configs"].values(): verify(item)
    ports = re.findall(r"(?m)^\s*query_port\s*=\s*(\d+)\s*(?:#.*)?$", verify(value["service_configs"]["fe"]).read_text())
    require(len(ports) == 1 and int(ports[0]) == target["query_port"], "FE target differs from frozen actual configuration")
    bindings = value["bindings"]
    require(set(bindings) == set(SOURCES) | set(IDENTITIES) | {"jdbc_driver", "postgres_driver"}, "External write bindings incomplete")
    for item in bindings.values(): verify(item)
    for key, path in SOURCES.items(): require(bindings[key] == ref(path), "External write source changed: " + key)
    for key, name in IDENTITIES.items(): require(bindings[key]["sha256"] == value["identity"][name], "External write identity differs: " + key)
    require(Path(bindings["jdbc_driver"]["path"]).name == "mariadb-java-client-3.0.9.jar"
            and Path(bindings["postgres_driver"]["path"]).name == "postgresql-42.7.8.jar", "External write actual drivers differ")
    native = source(value, profile)
    require(read(verify(bindings["environment"]))["external_source"] == value["external_source"], "Environment does not bind actual PG source")
    client = read(verify(bindings["client"]))
    require(all(client[key] == profile[key] for key in ("read_account", "write_account", "native_account"))
            and client["connection_mode"] == "reuse" and client["target"] == target, "Client does not bind actual accounts/protocol/FE")
    require(read(verify(bindings["configuration"]))["service_configs"] == value["service_configs"], "Configuration identity omitted actual FE/BE files")
    fixture = read(verify(bindings["fixture"]))
    require(fixture["external_source"] == value["external_source"] and fixture["source_data_sha256"] == native["source_data_sha256"]
            and fixture["rows_per_operation"] == 100, "Fixture does not bind complete sink model")
    if value["phase"] == "AB":
        frozen, published = (read(verify(value[key])) for key in ("freeze", "publication"))
        require(frozen["status"] == "FROZEN_ELIGIBLE" and frozen["identities"][value["variant"]] == value["identity"]
                and published["freeze"] == value["freeze"] and published["boot_id"] == value["boot_id"]
                and published["published_monotonic_ns"] <= value["created_monotonic_ns"], "A/B was not frozen before launch")
        cell = frozen["cell"]; scheduled = plan(profile)["measurement"]
        expected = {"group": "G3", "workload_sha256": business_binding(profile)["sha256"], "rate": profile["rate_per_second"],
            "concurrency": profile["concurrency"], "connection_mode": "reuse", "seed": 20260922, "license_state": "VALID",
            "warmup_seconds": profile["warmup_seconds"], "duration_seconds": profile["duration_seconds"],
            "request_count": scheduled["requests"], "arrival_schedule_sha256": arrival["measurement"]["sha256"]}
        require(all(cell.get(key) == item for key, item in expected.items()), "External sink A/B cell differs")
    else: require("freeze" not in value and "publication" not in value, "A-only/diagnostic claims A/B freeze")
    return value


class ExternalWrite(lifecycle.Background):
    """Reuse bounded owned process launch/identity/RSS/wait; only sink semantics are new."""
    coordinate = dml.DmlPerformance.coordinate
    release_warmup = dml.DmlPerformance.release_warmup
    release_measurement = dml.DmlPerformance.release_measurement
    allow_verification = dml.DmlPerformance.allow_verification

    def __init__(self, api, plan, guard, target, cell, admin, whole_deadline, cpu_services, launch):
        frozen = plan["external_write"]; profile = validate_config(frozen["config"]); validate_launch(launch, profile)
        require({key: target[key] for key in ("name", "host", "query_port")} == launch["target"] and cpu_services == launch["services"],
                "Actual target or CPU services differs from frozen launch")
        require(set(cpu_services) == {"fe", "be"} and cpu_services["fe"]["pid"] != cpu_services["be"]["pid"]
                and all(api.same(pin) for pin in cpu_services.values()), "CPU services must be distinct actual FE/BE")
        super().__init__(api, {**plan, "background": frozen}, guard, target, cell, admin, whole_deadline)
        for role, pin in cpu_services.items():
            require(any(all(owned.get(key) == pin.get(key) for key in ("pid", "start_ticks", "namespace", "exe", "command_sha256"))
                        for owned in self.config["cluster_pins"]) and pin["start_ticks"] == launch["service_start_ticks"][role],
                    "CPU process not from the owned cluster/launch")
            require(Path(pin["exe"]).name == ("java" if role == "fe" else "doris_be"), "CPU service role differs")
        for key in ("jdbc_driver", "postgres_driver"):
            item = launch["bindings"][key]
            require(frozen["dependencies_sha256"].get(item["path"]) == item["sha256"], "Executed driver differs from source identity")
        external.check_jvm_environment(); native = source(launch, profile, live=True)
        external.check_installed_slots(launch, frozen)
        key = profile["native_account"]["password_env"]
        require(key in os.environ and len(os.environ[key]) <= 1024, "Explicit native PG credential environment missing")
        self.environment[key] = os.environ[key]
        self.token = launch["launch_token"]; self.launch = launch
        api.save(self.output / "p4-launch.json", launch); self.launch_ref = ref(self.output / "p4-launch.json")
        self.config.update(token=self.token, table="public.p4_sink_" + self.token, catalog=native["catalog"], launch=self.launch_ref,
                           cpu_services=cpu_services, clock_ticks_per_second=os.sysconf("SC_CLK_TCK"))
        api.save(self.config_path, self.config)

    def check(self, phase_deadline=None):
        result = super().check(phase_deadline)
        if hasattr(self, "launch"): external.check_external_service(self.launch)
        now = time.monotonic()
        if now - getattr(self, "last_size_check", 0) >= 1:
            self.last_size_check = now
            require(sum(path.stat().st_size for path in self.output.iterdir() if path.is_file()
                        and path.suffix in (".json", ".jsonl", ".tsv")) <= self.profile["max_raw_ledger_bytes"],
                    "Sink raw ledger exceeded frozen disk bound")
        return result

    def start(self):
        lifecycle.verify_frozen(self.api, self.frozen); classes = self.output / "classes"; classes.mkdir()
        self.classpath = os.pathsep.join([str(classes), *sorted(self.frozen["dependencies_sha256"])])
        java = Path(self.frozen["java_home"]) / "bin/java"; deadline = min(self.whole_deadline, time.monotonic() + 120)
        try:
            self._launch([java.with_name("javac"), "-J-Xmx256m", "--release", "17", "-encoding", "UTF-8", "-cp", self.classpath,
                          "-d", classes, JAVA_SOURCE], "compile", deadline)
            self._await(lambda: self.process.poll() is not None, deadline)
            require(self.process.returncode == 0, "External write compilation failed")
        finally: lifecycle.reap_owned(self.api, self.process, self.pin, deadline, self._process_event)
        lifecycle.verify_frozen(self.api, self.frozen)
        compiled = {str(path): self.api.sha(path) for path in classes.rglob("*.class")}
        require(str(classes / "LicenseExternalWritePerformance.class") in compiled, "Compiled sink helper missing")
        self.api.save(self.output / "helper-identity.json", {"classes": compiled, "frozen": self.frozen})
        deadline = min(self.whole_deadline, time.monotonic() + self.profile["prepare_timeout_seconds"])
        self._launch([java, "-Xmx512m", "-cp", self.classpath, "LicenseExternalWritePerformance", self.config_path], "sink", deadline)
        self.work_pin = dict(self.pin); self._await(lambda: (self.output / "ready.json").exists(), deadline)
        ready = read(self.output / "ready.json"); self._identity_receipt(ready)
        require(ready["token"] == self.token and ready["connections"] == self.profile["concurrency"]
                and ready["source_rows_verified"] == 1000000, "External sink readiness incomplete")
        declared_schedule(self.launch, self.profile, self.output)
        self.api.save(self.output / "controller-ready.json", {"observed_monotonic_ns": time.monotonic_ns(), "ready": ready})

    def finish(self):
        if self.finished: return read(self.output / "controller.json")
        self.finished = True; failures = []
        if not (self.output / "verification-ready.json").exists(): self.api.save(self.output / "stop.json", {"token": self.token})
        deadline = min(self.whole_deadline, time.monotonic() + self.profile["verify_timeout_seconds"] + self.profile["cleanup_timeout_seconds"])
        clean = False
        try: self._await(lambda: self.process.poll() is not None, deadline)
        except BaseException as error: failures.append(lifecycle.process_error(error, "sink_wait"))
        finally:
            try: clean = lifecycle.reap_owned(self.api, self.process, self.pin, deadline, self._process_event)
            except BaseException as error: failures.append(lifecycle.process_error(error, "sink_reap"))
        code = self.process.returncode if self.process else None
        completion = {"schema_version": 1, "launch_token": self.token, "launch_sha256": self.launch_ref["sha256"],
            "boot_id": self.launch["boot_id"], "helper_pid": self.work_pin["pid"] if self.work_pin else None,
            "helper_start_ticks": self.work_pin["start_ticks"] if self.work_pin else None, "exit_code": code,
            "completed_monotonic_ns": time.monotonic_ns(), "utc_anchor": dml.utc_anchor(),
            "remaining_live_pids": [] if clean else ["UNPROVEN_EXIT"]}
        if (self.output / "p4-clock-bridge.json").exists(): completion["bridge"] = ref(self.output / "p4-clock-bridge.json")
        self.api.save(self.output / "p4-completion.json", completion)
        summary = read(self.output / "summary.json") if (self.output / "summary.json").exists() else {}
        if summary:
            try: self._identity_receipt(summary)
            except BaseException as error: failures.append(lifecycle.process_error(error, "summary_identity")); summary = {}
        cleanup = summary.get("cleanup_confirmed") is True
        if not cleanup and clean and self.classpath and (self.output / "owner.json").exists():
            # Recovery follows a real parent wait and never adopts a table without its original owner receipt.
            self.recovery_deadline = time.monotonic() + self.profile["cleanup_timeout_seconds"]
            try:
                lifecycle.verify_frozen(self.api, self.frozen); external.check_external_service(self.launch)
                java = Path(self.frozen["java_home"]) / "bin/java"
                self._launch([java, "-Xmx512m", "-cp", self.classpath, "LicenseExternalWritePerformance", self.config_path,
                              "--cleanup-only"], "recovery", self.recovery_deadline)
                self._await(lambda: self.process.poll() is not None, self.recovery_deadline)
                receipt = read(self.output / "recovery-cleanup.json")
                require(self.process.returncode == 0 and receipt["token"] == self.token and receipt["pid"] == self.pin["pid"]
                        and receipt["start_ticks"] == self.pin["start_ticks"] and receipt["namespace"] == self.pin["namespace"],
                        "Native cleanup recovery identity differs")
                cleanup = receipt["cleanup_confirmed"] is True
            except BaseException as error: failures.append(lifecycle.process_error(error, "owned_sink_recovery"))
            finally:
                try: lifecycle.reap_owned(self.api, self.process, self.pin, self.recovery_deadline, self._process_event)
                except BaseException as error: failures.append(lifecycle.process_error(error, "sink_recovery_wait"))
        try: self.guard.check(); lifecycle.verify_frozen(self.api, self.frozen); external.check_external_service(self.launch)
        except BaseException as error: failures.append(lifecycle.process_error(error, "final_inputs"))
        failures.extend(getattr(self, "process_evidence_errors", []))
        report = {"status": "RAW_WINDOW_COMPLETE" if clean and cleanup and not failures
                  and code == 0 and summary.get("status") == "RAW_WINDOW_COMPLETE" else "INVALID_WINDOW",
                  "summary": summary, "cleanup_confirmed": cleanup,
                  "owned_child_exited": clean, "errors": failures, "rss_peak_mib_sampled": self.peak,
                  "resource_samples": self.samples, "formal_performance_pass": False}
        self.api.save(self.output / "controller.json", report); return report


def audit_requests(directory, profile):
    planned = plan(profile); phases = {}; outcomes = [None] * planned["total_requests"]; config = read(directory / "config.json")
    connection_ids = set()
    for worker in range(profile["concurrency"]):
        session = read(directory / f"worker-{worker}-session.json")
        values = session["actual_settings"]
        require(session["worker"] == worker and session["connections_opened"] == 1 and session["driver"] == "3.0.9"
                and type(session["auto_commit"]) is bool and len(values) == 7 and values[6] == "1" and values[0].lower() in ("0", "false")
                and values[1].lower() in ("0", "false") and values[2] == "off_mode"
                and values[3:5] == [str(profile["timeout_seconds"])] * 2
                and values[5].split("@")[0].strip("'") == profile["write_account"]["username"], "Actual sink worker account/session differs")
        require(type(session["server_connection_id"]) is int and session["server_connection_id"] > 0
                and session["server_connection_id"] not in connection_ids, "Sink connections aliased")
        connection_ids.add(session["server_connection_id"])
    for phase in ("warmup", "measurement"):
        selected = planned[phase]; rows = dml.csv_rows(directory / (phase + "-arrivals.tsv"))
        require(len(rows) == selected["requests"], "Sink arrival count differs")
        for index, (row, expected) in enumerate(zip(rows, selected["arrivals"])):
            require(set(row) == {"sequence", "offset_ns", "request_id", "rows"} and int(row["sequence"]) == index
                    and abs(int(row["offset_ns"]) - expected) <= 1 and int(row["request_id"]) == selected["first_request"] + index
                    and int(row["rows"]) == 100, "Sink arrivals/model changed")
        start, end = (read(directory / (phase + "-" + point + ".json")) for point in ("start", "end"))
        epoch = start["epoch_ns"]; last = epoch; seen = set(); latencies = []; service = []; queue = []; errors = 0; timeouts = 0
        for worker in range(profile["concurrency"]):
            session = read(directory / f"worker-{worker}-session.json"); previous = epoch; previous_sequence = -1
            with (directory / f"{phase}-{worker}.jsonl").open() as stream:
                for line in stream:
                    require(line.endswith("\n") and len(line) <= 8192, "Partial/oversized sink receipt")
                    row = json.loads(line); sequence = row["sequence"]
                    require(type(sequence) is int and 0 <= sequence < len(rows) and sequence not in seen and sequence > previous_sequence
                            and row["worker"] == worker and sequence % profile["concurrency"] == worker
                            and row["request_id"] == selected["first_request"] + sequence, "Sink duplicate/foreign request")
                    seen.add(sequence); previous_sequence = sequence
                    scheduled, begin, finish = (row[key] for key in ("scheduled_ns", "started_ns", "finished_ns"))
                    require(all(type(value) is int for value in (scheduled, begin, finish))
                            and scheduled == epoch + int(rows[sequence]["offset_ns"]) and finish >= begin >= max(scheduled, previous)
                            and row["e2e_ns"] == finish - scheduled and row["service_ns"] == finish - begin
                            and row["queue_ns"] == begin - scheduled, "Sink request clock/queue differs")
                    previous = finish; last = max(last, finish); outcomes[row["request_id"]] = row["outcome"]
                    require(row["outcome"] in ("ACK", "UNKNOWN", "NOT_SENT") and type(row["timeout"]) is bool, "Unknown sink request outcome")
                    timeouts += row["timeout"]
                    if row["outcome"] != "ACK": errors += 1; continue
                    sql = (f"INSERT INTO {config['catalog']}.public.p4_sink_{start['token']}"
                        f"(run_id,request_id,id,grp,v,payload) SELECT '{start['token']}',{row['request_id']},id,grp,v,payload "
                        "FROM internal.license_perf.point_rows WHERE id >= 0 AND id < 100")
                    require(row["execute_calls"] == 1 and row["affected_rows"] == 0 and row["error_code"] == 0 and row["sql_state"] == "NONE"
                            and row["connection_aborted"] is False and row["timeout"] is False
                            and row["server_connection_id"] == session["server_connection_id"]
                            and row["socket_local_port"] == session["socket_local_port"] and finish - begin < 120 * 10**9
                            and row["sql_sha256"] == hashlib.sha256(sql.encode()).hexdigest(), "Sink ACK/protocol differs from real baseline")
                    latencies.append(row["e2e_ns"] / 1e6); service.append(row["service_ns"] / 1e6); queue.append(row["queue_ns"] / 1e6)
        duration = profile["warmup_seconds"] if phase == "warmup" else profile["duration_seconds"]
        interval = max(epoch + duration * 10**9, last)
        require(len(seen) == len(rows) and end["epoch_ns"] == epoch and end["last_request_end_ns"] == last
                and end["request_interval_end_ns"] == interval and end["java_monotonic_ns"] >= interval
                and end["scheduled_requests"] == len(rows) and end["successful_requests"] == len(latencies)
                and end["arrival_schedule_sha256"] == stats.digest(directory / (phase + "-arrivals.tsv")), "Sink window raw denominator differs")
        cpus = {}
        for role in ("fe", "be"):
            first, final = start["cpu"][role], end["cpu"][role]
            require(first["sample_started_java_ns"] <= first["sample_ended_java_ns"] <= epoch
                    and final["sample_ended_java_ns"] >= final["sample_started_java_ns"] >= interval, "Sink CPU interval incomplete")
            pin = config["cpu_services"][role]
            delta = external.cpu_ticks(final, pin, config["clock_ticks_per_second"]) - external.cpu_ticks(first, pin, config["clock_ticks_per_second"])
            require(delta >= 0, "Sink CPU decreased")
            cpus[role + "_cpu_seconds_per_success"] = delta / config["clock_ticks_per_second"] / len(latencies) if latencies else None
        seconds = (interval - epoch) / 1e9
        phases[phase] = {"scheduled_requests": len(rows), "observed_requests": len(seen), "successful_requests": len(latencies),
            "error_count": errors, "timeout_count": timeouts, "retry_count": 0,
            "effective_duration_seconds": seconds, "arrival_schedule_sha256": end["arrival_schedule_sha256"],
            "success_qps": len(latencies) / seconds, "p95_ms": dml.percentile(latencies, .95), "p99_ms": dml.percentile(latencies, .99),
            "service_p95_ms": dml.percentile(service, .95), "service_p99_ms": dml.percentile(service, .99),
            "queue_p95_ms": dml.percentile(queue, .95), "queue_p99_ms": dml.percentile(queue, .99), **cpus}
    return {"phases": phases, "outcomes": outcomes}


def audit_models(directory, profile, summary, requests):
    expected = lifecycle.expected_source_digest()
    before = summary["source_before"]
    require(before == summary["source_after"] and before["rows"] == 1000000 and before["canonical_sha256"] == expected
            and before["full_values_verified"] is True and re.fullmatch(r"[a-f0-9]{64}", before["schema_sha256"]),
            "Complete internal source schema/model changed")
    token = summary["token"]; counts = [0] * len(requests["outcomes"]); digest = hashlib.sha256(); previous = (-1, -1)
    path = directory / "native-target.tsv"
    require(path.stat().st_size <= profile["max_rows"] * 128, "Native raw model exceeds frozen disk bound")
    with path.open("rb") as stream:
        for line in stream:
            require(line.endswith(b"\n") and len(line) <= 128, "Partial native row")
            parts = line.decode("ascii").rstrip("\n").split("\t"); require(len(parts) == 6, "Native row column count differs")
            request, identifier = int(parts[1]), int(parts[2]); key = (request, identifier)
            require(0 <= request < len(counts) and 0 <= identifier < 100 and previous < key and parts[0] == token,
                    "Native target has extra/duplicate/foreign request key")
            payload = hashlib.md5(str(identifier).encode(), usedforsecurity=False).hexdigest()
            canonical = f"{token}\t{request}\t{identifier}\t{identifier % 1024}\t{identifier % 100000}\t{payload}\n".encode()
            require(line == canonical, "Native target full column model differs")
            digest.update(line); counts[request] += 1; previous = key
    resolution = read(directory / "native-resolution.json")
    require(len(resolution) == len(counts), "Native resolution incomplete")
    for index, (item, outcome) in enumerate(zip(resolution, requests["outcomes"])):
        require(item == {"request_id": index, "outcome": outcome, "rows": counts[index],
            "ack_upgraded_from_visibility": False, "absence_proves_rollback": False}, "Native resolution hid unknown ACK")
        require(outcome == "ACK" and counts[index] == 100, "Unknown/missing/partial request cannot become successful")
    require(summary["target_after"] == {"rows": sum(counts), "canonical_sha256": digest.hexdigest(),
            "all_acknowledged_batches_verified": True}, "Native target summary differs from raw rows")
    return {"verified": True, "native_rows": sum(counts), "sha256": digest.hexdigest(), "source_rows": 1000000,
            "unknown_ack_upgrades": 0, "online_visibility_claim": False}


def normalize(manifest):
    directory = Path(manifest["window_directory"]).resolve()
    def raw_files():
        paths = [path for path in sorted(directory.iterdir()) if path.is_file() and path.suffix in (".json", ".jsonl", ".tsv")]
        require(not any(path.is_symlink() for path in paths), "Sink raw symlink not allowed")
        return [ref(path) for path in paths]
    before = raw_files(); config = read(directory / "config.json"); identity = read(directory / "helper-identity.json")
    frozen = identity["frozen"]; profile = validate_config(frozen["config"]); planned = plan(profile)
    require(sum(verify(item).stat().st_size for item in before) <= profile["max_raw_ledger_bytes"], "Sink raw ledger exceeds frozen bound")
    require(all(config.get(key) == item for key, item in profile.items()) and read(frozen["input_path"]) == profile
            and stats.digest(frozen["input_path"]) == frozen["input_sha256"], "Executed sink config differs from frozen input")
    require(set(frozen["jdk_runtime"]) == {"bin/java", "bin/javac", "lib/modules", "release"}
            and len(frozen["dependencies_sha256"]) == 5 and set(Path(path).name for path in frozen["dependencies_sha256"]) == JARS
            and str(directory / "classes/LicenseExternalWritePerformance.class") in identity["classes"], "Runtime/classes incomplete")
    lifecycle.verify_frozen(SimpleNamespace(sha=stats.digest), frozen)
    require(all(frozen["source_sha256"].get(str(path)) == stats.digest(path) for path in SOURCES.values())
            and 'JAVA_VERSION="17.0.4"' in (Path(frozen["java_home"]) / "release").read_text(), "Actual source/JDK freeze missing")
    for path, digest in identity["classes"].items(): require(stats.digest(path) == digest, "Actual compiled sink helper changed")
    launch_ref = manifest["launch"]; launch = read(verify(launch_ref)); validate_launch(launch, profile)
    arrival = declared_schedule(launch, profile, directory)
    for name in ("jdbc_driver", "postgres_driver"):
        binding = launch["bindings"][name]
        require(frozen["dependencies_sha256"].get(binding["path"]) == binding["sha256"], "Executed sink driver differs from launch")
    require(config["launch"] == launch_ref == ref(directory / "p4-launch.json") and config["token"] == launch["launch_token"]
            and config["catalog"] == source(launch, profile)["catalog"] and config["target"] == launch["target"]
            and config["cpu_services"] == launch["services"], "Sink actual token/catalog/FE differs from launch")
    completion = read(verify(manifest["completion"])); bridge = read(verify(completion["bridge"])); helper = read(verify(bridge["helper_clock"]))
    require(completion["launch_token"] == launch["launch_token"] and completion["launch_sha256"] == launch_ref["sha256"]
            and completion["boot_id"] == launch["boot_id"] and completion["exit_code"] == 0 and not completion["remaining_live_pids"]
            and all(completion[key] == helper[key] for key in ("helper_pid", "helper_start_ticks")), "Sink actual helper wait invalid")
    clocks.utc_anchor(completion["utc_anchor"]); original = clocks.clock_bridge(launch, launch_ref, bridge, helper)
    process = read(directory / "sink-process.json"); pin = process["pin"]
    command = [str(Path(frozen["java_home"]) / "bin/java"), "-Xmx512m", "-cp",
               os.pathsep.join([str(directory / "classes"), *sorted(frozen["dependencies_sha256"])]),
               "LicenseExternalWritePerformance", str(directory / "config.json")]
    require(pin["pid"] == helper["helper_pid"] and pin["start_ticks"] == helper["helper_start_ticks"]
            and pin["namespace"] == config["namespace"] and pin["exe"] == str((Path(frozen["java_home"]) / "bin/java").resolve())
            and pin["command_sha256"] == process["expected_launch"]["command_sha256"]
            == hashlib.sha256(b"\0".join(os.fsencode(item) for item in command) + b"\0").hexdigest(), "Actual sink process differs")
    waits = [item for item in read(directory / "process-lifecycle.json") if item.get("helper") == "sink" and item.get("reason") == "OWNED_PARENT_WAIT"]
    require(len(waits) == 1 and waits[0]["pid"] == helper["helper_pid"] and waits[0]["exit_code"] == 0
            and waits[0]["parent_wait_complete"] is True
            and bridge["controller_after_ns"] <= waits[0]["controller_monotonic_ns"] <= completion["completed_monotonic_ns"], "Unique causal parent wait missing")
    summary = read(directory / "summary.json"); controller = read(directory / "controller.json")
    require(summary["status"] == controller["status"] == "RAW_WINDOW_COMPLETE" and not controller["errors"]
            and summary["errors"] == 0 and summary["automatic_write_replays"] == 0 and controller["owned_child_exited"] is True,
            "Invalid sink window cannot qualify")
    expected = {"token": launch["launch_token"], "launch_token": launch["launch_token"], "launch_sha256": launch_ref["sha256"],
        "boot_id": launch["boot_id"], "pid": helper["helper_pid"], "start_ticks": helper["helper_start_ticks"], "namespace": config["namespace"]}
    names = ["ready.json", "warmup-start.json", "warmup-end.json", "measurement-ready.json", "measurement-start.json",
             "measurement-end.json", "verification-ready.json", "verification-start.json", "lifecycle.json", "summary.json", "owner.json", "create-intent.json",
             "native-drop.json", "disk-before.json", "disk-after.json"]
    names += [f"worker-{worker}-{suffix}.json" for worker in range(profile["concurrency"]) for suffix in ("session", "close")]
    for name in names:
        require(all(read(directory / name).get(key) == item for key, item in expected.items()), "Sink receipt from another launch: " + name)
    owner, intent = (read(directory / name) for name in ("owner.json", "create-intent.json"))
    require(config["table"] == owner["table"] == intent["table"] == summary["table"] == "public.p4_sink_" + launch["launch_token"]
            and owner["create_acknowledged"] is True and intent["absent_before_create"] is True
            and owner["configuration_sha256"] == stats.digest(directory / "config.json")
            and owner["identity"]["exists"] is True and owner["identity"]["oid"] > 0
            and owner["identity"]["comment"] == "massdb-p4-owned:" + launch["launch_token"]
            and owner["identity"]["columns"] == SCHEMA and owner["identity"]["primary_key"] == PRIMARY_KEY
            and owner["identity"]["schema_sha256"] == schema_hash(),
            "Actual sink target ownership/schema differs")
    requests = audit_requests(directory, profile); model = audit_models(directory, profile, summary, requests)
    require(all(item["error_count"] == 0 for item in requests["phases"].values()), "Sink errors preserved")
    warm_start, warm_end, ready, start, end, verify_ready, verify_start, cleanup = (read(directory / name) for name in
        ("warmup-start.json", "warmup-end.json", "measurement-ready.json", "measurement-start.json", "measurement-end.json",
         "verification-ready.json", "verification-start.json", "lifecycle.json"))
    require(helper["jvm_sample_ns"] <= warm_start["epoch_ns"] == ready["warmup_start_ns"]
            and warm_end["java_monotonic_ns"] == ready["warmup_end_ns"] <= ready["ready_ns"] <= start["epoch_ns"]
            and warm_end["java_monotonic_ns"] - warm_start["epoch_ns"] >= profile["warmup_seconds"] * 10**9, "Sink warmup incomplete")
    ordering = [end["java_monotonic_ns"], verify_ready["java_monotonic_ns"], verify_start["java_monotonic_ns"],
                cleanup["java_monotonic_ns"], cleanup["cleanup_end_ns"]]
    require(ordering == sorted(ordering) and verify_ready["workers_closed"] is True
            and cleanup["workers_closed"] is True and cleanup["cleanup_confirmed"] is True and summary["cleanup_confirmed"] is True,
            "Sink verification/cleanup order invalid")
    dropped = read(directory / "native-drop.json")
    require(dropped["table"] == config["table"] and dropped["before"] == owner["identity"]
            and dropped["after"] == {"exists": False} and dropped["drop_acknowledged"] is True
            and cleanup["java_monotonic_ns"] <= dropped["drop_started_ns"] <= dropped["drop_ack_ns"]
            <= dropped["absence_confirmed_ns"] <= cleanup["cleanup_end_ns"], "Original native DROP ownership/ACK/absence evidence incomplete")
    for worker in range(profile["concurrency"]):
        close = read(directory / f"worker-{worker}-close.json"); session = read(directory / f"worker-{worker}-session.json")
        require(close["connection_closed"] is True and close["connection_aborted"] is False
                and close["server_connection_id"] == session["server_connection_id"]
                and end["java_monotonic_ns"] <= close["close_started_ns"] <= close["close_finished_ns"] <= verify_ready["java_monotonic_ns"],
                "Sink worker connection not closed before native oracle")
    high = min(original["offset_upper_ns"], waits[0]["controller_monotonic_ns"] - cleanup["cleanup_end_ns"])
    low = original["offset_lower_ns"]; require(low <= high, "Wait contradicts original sink clock bridge")
    offset = (low + high) // 2; mapping = {**original, "offset_upper_ns": high, "estimated_offset_ns": offset,
                                       "uncertainty_ns": max(offset - low, high - offset)}
    lower = min(item["sample_started_java_ns"] for item in warm_start["cpu"].values()) + low
    upper = max(end["java_monotonic_ns"], *(item["sample_ended_java_ns"] for item in end["cpu"].values())) + high
    require(lower >= launch["created_monotonic_ns"], "Sink warmup predates launch")
    resources = dml.external_audit(manifest["resources"], launch, launch_ref, lower, upper, "resources", profile)
    state = dml.external_audit(manifest["license_state"], launch, launch_ref, lower, upper, "license_state", profile)
    actual_source = source(launch, profile); observed = resources["external_source"]
    require(observed["pin"] == actual_source["service"] and observed["state"] == actual_source["state"]
            and observed["resources"] == actual_source["resources"] and observed["sample_count"] >= 2
            and observed["peak_cgroup_memory_bytes"] <= actual_source["resources"]["memory_limit_bytes"]
            and observed["cgroup_memory_limit_bytes"] == actual_source["resources"]["memory_limit_bytes"]
            and observed["cgroup_oom_kill_delta"] == 0 and observed["all_sample_cpu_affinities"] == [[5]],
            "Native PG sampled resource budget incomplete")
    for role in ("fe", "be"):
        actual = resources["services"][role]
        require(actual["pin"] == config["cpu_services"][role] and actual["artifact"] == launch["bindings"][role + "_artifact"]
                and actual["configuration"] == launch["service_configs"][role]
                and actual["pin"]["start_ticks"] == launch["service_start_ticks"][role], "Sink deployed CPU/artifact identity differs")
    for phase in ("before", "after"):
        disk = read(directory / ("disk-" + phase + ".json"))
        require([item["path"] for item in disk["paths"]] == profile["storage_paths"]
                and all(item["usable_bytes"] >= profile["min_disk_free_bytes"] for item in disk["paths"]), "Sink disk admission failed")
    measured = requests["phases"]["measurement"]
    window = {"window_id": launch["window_id"], "pair_id": launch["pair_id"], "variant": launch["variant"], "boot_id": launch["boot_id"],
        "identity": launch["identity"], "workload_sha256": business_binding(profile)["sha256"], "rate": profile["rate_per_second"],
        "arrival_schedule_sha256": measured["arrival_schedule_sha256"], "warmup_seconds": profile["warmup_seconds"],
        "duration_seconds": profile["duration_seconds"], "warmup_start_monotonic_ns": warm_start["epoch_ns"] + offset,
        "warmup_end_monotonic_ns": warm_end["java_monotonic_ns"] + offset, "start_monotonic_ns": start["epoch_ns"] + offset,
        "end_monotonic_ns": end["request_interval_end_ns"] + offset, "monotonic_clock_domain": "bounded_jvm_mapping",
        "monotonic_mapping": mapping, "monotonic_mapping_uncertainty_ns": mapping["uncertainty_ns"],
        "effective_duration_seconds": measured["effective_duration_seconds"], "scheduled_requests": measured["scheduled_requests"],
        "observed_requests": measured["observed_requests"], "successful_requests": measured["successful_requests"],
        "error_count": 0, "timeout_count": 0, "retry_count": 0, "oracle_verified": True, "cleanup_verified": True,
        "cpu_boundary_verified": True, "metrics": {key: measured[key] for key in stats.METRICS}}
    dependencies = [launch["workload"], *launch["bindings"].values(), launch["external_source"], *external.source_references(launch),
                    resources["auditor"], state["auditor"], *launch["service_configs"].values(),
                    {"path": frozen["input_path"], "sha256": frozen["input_sha256"]}]
    if arrival is not None: dependencies += [launch["arrival_schedule"], arrival["warmup"], arrival["measurement"]]
    for items in (identity["classes"], frozen["source_sha256"], frozen["dependencies_sha256"]):
        dependencies.extend({"path": path, "sha256": digest} for path, digest in items.items())
    dependencies.extend({"path": str((Path(frozen["java_home"]) / name).resolve()), "sha256": digest} for name, digest in frozen["jdk_runtime"].items())
    if launch["phase"] == "AB":
        require(read(verify(launch["publication"]))["published_monotonic_ns"] <= lower, "Sink warmup predates A/B publication")
        window.update(freeze_sha256=launch["freeze"]["sha256"], freeze_publication_sha256=launch["publication"]["sha256"])
        dependencies += [launch["freeze"], launch["publication"]]
    after = raw_files(); require(before == after, "Sink raw changed during audit")
    raw = {item["path"]: item for item in after}
    for item in (manifest["launch"], manifest["completion"], completion["bridge"], bridge["helper_clock"], manifest["resources"],
                 manifest["license_state"], *resources["raw_artifacts"], *state["raw_artifacts"]):
        verify(item); raw[item["path"]] = item
    dependencies = list({item["path"]: item for item in dependencies}.values())
    for item in dependencies: verify(item)
    status = "VERIFIED" if profile["qualification"] == "formal" and launch["phase"] != "DIAGNOSTIC" else "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED"
    return {"status": status, "window": window, "auditor": ref(SOURCE), "raw_artifacts": list(raw.values()),
        "dependency_bindings": dependencies, "request_audit": requests["phases"], "full_model_audit": model,
        "clock_causality_audit": {"original_mapping": original, "effective_mapping": mapping, "parent_wait": waits[0]},
        "formal_shape_met": status == "VERIFIED" and measured["successful_requests"] >= 10000, "formal_performance_pass": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("mode", choices=("plan", "normalize"))
    parser.add_argument("input", type=Path); args = parser.parse_args()
    result = plan(read(args.input)) if args.mode == "plan" else normalize(read(args.input))
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__": main()
