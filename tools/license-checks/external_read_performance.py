#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""One owned G2 catalog/S3 streamed external read window, or offline plan/compile/audit. Never qualifies performance by itself."""

import argparse
import csv
import functools
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time

import p4_jdbc_evidence as clocks
import p4_jdbc_lifecycle as lifecycle
import p4_statistics as statistics

SOURCE = Path(__file__).resolve()
JAVA = SOURCE.with_name("LicenseExternalReadPerformance.java")
PROFILE = "g2_external_read_v1"
MODEL_SHA = "b2b90b17ef5b149fa1deca05a37b48198d0e709790be44ea2ecb80979d9cef7c"
LABELS = ["id", "grp", "v", "payload"]
COLUMN_TYPES = [-5, 4, -5, 12]
CASES = {"catalog": "LP-005", "s3_tvf": "LP-008"}
EXPECTED_JARS = {"mariadb-java-client-3.0.9.jar", "jackson-annotations-2.16.0.jar",
                 "jackson-core-2.16.0.jar", "jackson-databind-2.16.0.jar"}
require = statistics.require
read_json = statistics.read_json
reference = statistics.reference
verify_reference = statistics.verify_reference
publish = lifecycle.publish
BOUNDS = {"warmup_seconds": (1, 7200), "duration_seconds": (1, 604800), "drain_seconds": (1, 3600),
          "max_requests": (2, 25000),
          "max_raw_ledger_bytes": (1048576, 8589934592)}
SOURCES = {"runner": SOURCE, "java_helper": JAVA, "clock_adapter": Path(clocks.__file__), "lifecycle": Path(lifecycle.__file__),
           "statistics": Path(statistics.__file__)}
IDENTITIES = {"fe_artifact": "fe_sha256", "be_artifact": "be_sha256", "environment": "environment_sha256",
              "configuration": "configuration_sha256", "fixture": "fixture_sha256", "client": "client_sha256"}


def validate_profile(value):
    require(isinstance(value, dict) and set(value) == set(BOUNDS) | {"schema_version", "profile", "qualification",
            "seed", "source_kind", "source_data_sha256", "column_types", "concurrency", "rate"}, "External read profile has missing or extra fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["profile"] == PROFILE,
            "External read schema/profile invalid")
    require(type(value["seed"]) is int and value["seed"] == 20260922, "External read seed changed")
    require(value["source_kind"] in CASES and type(value["concurrency"]) is int and value["concurrency"] in (1, 8),
            "External read retained G2 matrix changed")
    require(re.fullmatch(r"[a-f0-9]{64}", value["source_data_sha256"]), "Missing frozen external source data SHA")
    require(isinstance(value["column_types"], list) and all(type(item) is int for item in value["column_types"])
            and value["column_types"] == COLUMN_TYPES, "Freeze actual four-column JDBC metadata before execution")
    for key, (low, high) in BOUNDS.items():
        require(type(value[key]) is int and low <= value[key] <= high, "External read bound invalid: " + key)
    require(type(value["rate"]) in (int, float) and math.isfinite(value["rate"]) and 0 < value["rate"] <= 1000,
            "External read arrival rate invalid")
    require(value["qualification"] in ("diagnostic", "formal"), "External read qualification invalid")
    require(value["qualification"] != "formal" or value["warmup_seconds"] >= 180 and value["duration_seconds"] >= 600,
            "External read formal duration cannot be shortened")
    require(value["rate"] * max(value["warmup_seconds"], value["duration_seconds"]) < value["max_requests"] * .95,
            "External read expected arrivals exceed frozen bound")
    return value


def arrivals(rate, seconds, maximum):
    """Independent Java Random model; numerical cross-language comparison permits at most 1 ns."""
    state = (20260922 ^ 0x5DEECE66D) & ((1 << 48) - 1)
    def bits(count):
        nonlocal state
        state = (state * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return state >> (48 - count)
    elapsed, result = 0.0, []
    while True:
        uniform = ((bits(26) << 27) + bits(27)) / float(1 << 53)
        if uniform == 0: continue
        elapsed += -math.log(uniform) * 1e9 / rate
        if elapsed >= seconds * 1e9: return result
        require(len(result) < maximum, "External read generated arrivals exceed bound")
        result.append(int(elapsed))


def plan(profile):
    validate_profile(profile); result = {}
    for phase, key in (("warmup", "warmup_seconds"), ("measurement", "duration_seconds")):
        offsets = arrivals(profile["rate"], profile[key], profile["max_requests"])
        require(offsets, "External read phase has no scheduled operations")
        text = "sequence\toffset_ns\n" + "".join(f"{index}\t{offset}\n" for index, offset in enumerate(offsets))
        result[phase] = {"offsets": offsets, "requests": len(offsets), "tsv": text,
                         "sha256": hashlib.sha256(text.encode()).hexdigest()}
    require(profile["qualification"] != "formal" or result["measurement"]["requests"] >= 10000,
            "Formal External read needs at least 10000 complete logical queries, never Arrow rows or batches")
    return result


def business_binding(profile):
    validate_profile(profile)
    fields = {key: profile[key] for key in ("profile", "seed", "source_kind", "source_data_sha256", "column_types",
        "concurrency", "drain_seconds", "max_requests", "max_raw_ledger_bytes")}
    fields.update(case_id=CASES[profile["source_kind"]], connection_mode="reuse_jdbc_streaming", rows_per_operation=1000000,
        model_sha256=MODEL_SHA, column_labels=LABELS, query_template="SELECT id, grp, v, payload FROM {SOURCE}",
        session={"enable_sql_cache": False, "enable_query_cache": False, "enable_file_cache": False,
                 "query_timeout": 60, "batch_size": 8192, "exec_mem_limit": 536870912},
        driver={"class": "org.mariadb.jdbc.Driver", "version": "3.0.9", "fetch_size": 1024, "forward_only": True,
                "auto_reconnect": False, "automatic_retries": 0, "query_timeout_seconds": 0,
                "deadline_action": "close_exact_owned_driver_socket_no_cancel_connection"},
        timeout_contract={"connect_seconds": 10, "query_seconds": 60, "socket_idle_seconds": 60,
                          "dispatch_seconds": 120, "close_seconds": 5, "queue_included_in_e2e": True,
                          "queue_in_dispatch_deadline": False},
        arrival_model="JavaRandom20260922_StrictMathPoisson_v1", complete_oracle_in_service_time=True)
    return {"sha256": hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "fields": fields}

@functools.lru_cache(maxsize=1)
def verify_model():
    checksum = hashlib.sha256()
    for identifier in range(1000000):
        payload = hashlib.md5(str(identifier).encode("ascii"), usedforsecurity=False).hexdigest()
        checksum.update(f"{identifier},{identifier % 1024},{identifier % 100000},{payload}\n".encode("ascii"))
    require(checksum.hexdigest() == MODEL_SHA, "Independent complete four-column model digest differs")
    return MODEL_SHA


def raw_bindings(directory):
    result = []
    for path in sorted(Path(directory).rglob("*")):
        require(not path.is_symlink(), "External read raw symlink is not an independent receipt")
        if path.is_file(): result.append(reference(path))
    return result


def check_runtime(runtime):
    require(runtime["schema_version"] == 1 and runtime["main_class"] == "LicenseExternalReadPerformance",
            "External read compiled runtime invalid")
    require(set(runtime["sources"]) == set(SOURCES), "External read runtime source set changed")
    for key, source in SOURCES.items(): require(runtime["sources"][key] == reference(source), "External read source drift: " + key)
    require(set(runtime["jdk"]) == {"bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so", "release"},
            "External read JDK runtime incomplete")
    for refs in (runtime["sources"].values(), runtime["jdk"].values(), runtime["jars"], runtime["classes"]):
        for item in refs: verify_reference(item)
    require(len(runtime["jars"]) == 4 and {Path(item["path"]).name for item in runtime["jars"]} == EXPECTED_JARS,
            "External read requires exactly the frozen driver and three Jackson JARs")
    names = {Path(item["path"]).name for item in runtime["classes"]}
    require({"LicenseExternalReadPerformance.class", "LicenseExternalReadPerformance$Session.class", "LicenseExternalReadPerformance$RowOracle.class"} <= names, "External read compiled ABI missing")
    java_home = Path(runtime["java_home"]).resolve()
    require('JAVA_VERSION="17.0.4"' in verify_reference(runtime["jdk"]["release"]).read_text(), "External read requires JDK 17.0.4")
    require(all(item == reference(java_home / key) for key, item in runtime["jdk"].items()), "External read JDK path mismatch")
    classes = Path(runtime["classes_directory"]).resolve()
    require({item["path"] for item in runtime["classes"]} == {str(path.resolve()) for path in classes.rglob("*.class")},
            "External read unbound compiled class or removed class")
    return [*runtime["sources"].values(), *runtime["jdk"].values(), *runtime["jars"], *runtime["classes"]]


def compile_helper(spec, output):
    """Offline compiler; caller owns affinity/scheduling. It never constructs a External read Session."""
    check_jvm_environment()
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=False)
    require(set(spec) == {"java_home", "jars"}, "External read compiler input changed")
    java_home = Path(spec["java_home"]).resolve(strict=True)
    jars = sorted({str(Path(path).resolve(strict=True)) for path in spec["jars"]})
    require(jars and len(jars) == len(spec["jars"]) and all(Path(path).suffix == ".jar" for path in jars),
            "External read installed jar list missing/duplicated")
    require(len(jars) == 4 and {Path(path).name for path in jars} == EXPECTED_JARS,
            "External read compiler requires exactly the frozen driver and three Jackson JARs")
    classes = output / "classes"; classes.mkdir()
    runtime = {"schema_version": 1, "main_class": "LicenseExternalReadPerformance", "java_home": str(java_home),
               "classes_directory": str(classes), "sources": {key: reference(value) for key, value in SOURCES.items()},
               "jdk": {key: reference(java_home / key) for key in ("bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so", "release")},
               "jars": [reference(path) for path in jars]}
    require('JAVA_VERSION="17.0.4"' in (java_home / "release").read_text(), "External read requires JDK 17.0.4")
    command = [str(java_home / "bin/javac"), "-J-Xmx256m", "--release", "17", "-encoding", "UTF-8", "-cp",
               os.pathsep.join(jars), "-d", str(classes), str(JAVA)]
    with (output / "compile.log").open("x") as log:
        child = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
        try: child.wait(timeout=120)
        finally: reap(child)
    publish(output / "compile-completion.json", {"pid": child.pid, "exit_code": child.returncode,
            "parent_wait_complete": True, "remaining_live_pids": [], "network_clients_created": 0})
    require(child.returncode == 0, "External read helper compilation failed")
    runtime["classes"] = [reference(path) for path in sorted(classes.rglob("*.class"))]
    check_runtime(runtime); publish(output / "runtime.json", runtime)
    return reference(output / "runtime.json")


def pin(pid):
    proc = Path("/proc", str(pid)); raw = (proc / "stat").read_text(); fields = raw[raw.rfind(")") + 1:].split()
    require(fields[0] not in ("Z", "X"), "External read service/helper is not alive")
    return {"pid": pid, "start_ticks": int(fields[19]), "namespace": os.readlink(proc / "ns/net"),
            "exe": os.readlink(proc / "exe"), "command_sha256": hashlib.sha256((proc / "cmdline").read_bytes()).hexdigest()}


def check_jvm_environment():
    for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        require(not os.environ.get(name), "Unfrozen Java environment option: " + name)


def check_services(context):
    require(set(context["services"]) == {"fe", "be"}, "External read service roles incomplete")
    require(context["services"]["fe"]["pid"] != context["services"]["be"]["pid"], "External read service roles alias")
    namespace = os.readlink("/proc/self/ns/net")
    require(namespace != context["host_namespace"], "External read requires private namespace")
    for role, actual in context["services"].items():
        require(pin(actual["pid"]) == actual and actual["namespace"] == namespace, "External read actual service pin changed: " + role)
    return namespace


def check_installed_slots(context, runtime):
    """Bind this checkout's actual installed config/JAR slots to the live original protocol processes."""
    root = SOURCE.parents[2]
    installations = {}
    for role in ("fe", "be"):
        config = Path(context["service_configs"][role]["path"])
        require(root / ".build-records" in config.parents and config.name == role + ".conf"
                and config.parent.name == "conf" and config.parent.parent.name == role,
                "External read service configuration is not an owned checkout installation")
        installations[role] = config.parent.parent
        artifact = verify_reference(context["bindings"][role + "_artifact"])
        slot = installations[role] / "lib" / ("doris-fe.jar" if role == "fe" else "doris_be")
        require(slot.samefile(artifact), "External read actual installed artifact slot differs")
    require(context["services"]["be"]["exe"] == str(Path(context["bindings"]["be_artifact"]["path"]).resolve())
            and context["services"]["fe"]["exe"] == str((Path(runtime["java_home"]) / "bin/java").resolve()),
            "External read live executable is not the bound original package/JDK")
    pid = context["services"]["fe"]["pid"]
    argv = Path('/proc', str(pid), 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    options = [argv[index + 1] for index in range(len(argv) - 1) if argv[index] in ('-cp', '-classpath', '--class-path')]
    require(len(options) <= 1 and 'org.apache.doris.DorisFE' in argv, "External read actual FE entrypoint/classpath is ambiguous")
    if options:
        classpath = options[0]
    else:
        selected = [item.partition(b'=')[2] for item in Path('/proc', str(pid), 'environ').read_bytes().split(b'\0')
                    if item.startswith(b'CLASSPATH=')]
        require(len(selected) == 1, "External read actual FE CLASSPATH missing")
        classpath = selected[0].decode()
    slots = [Path(item) for item in classpath.split(os.pathsep) if Path(item).name == 'doris-fe.jar']
    require(len(slots) == 1 and slots[0].samefile(installations['fe'] / 'lib/doris-fe.jar'),
            "External read actual FE classpath differs from the installed slot")


def source_references(context):
    source = read_json(verify_reference(context['external_source']))
    bindings = [source[key] for key in ('state', 'native_evidence', 'reachability', 'metadata_evidence', 'plan')]
    native = read_json(verify_reference(source['native_evidence']))
    if source['source_kind'] == 'catalog': bindings.append(native['csv'])
    return bindings


def prepare_private_query(source_ref, output, s3_client_path=None):
    """Offline writer accepts a private config path, never an inline credential or returned SQL string."""
    source = read_json(verify_reference(source_ref)); prefix = 'SELECT id, grp, v, payload FROM '
    if source['source_kind'] == 'catalog':
        require(s3_client_path is None and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', source['catalog']),
                'Fixed catalog descriptor or private path differs')
        sql = prefix + source['catalog'] + '.public.source_rows'
    else:
        require(source['source_kind'] == 's3_tvf' and s3_client_path is not None, 'S3 private config path required')
        private = Path(s3_client_path)
        require(not private.is_symlink() and private.is_file() and private.stat().st_mode & 0o777 == 0o600
                and 0 < private.stat().st_size <= 65536, 'S3 config must be a bounded mode0600 private file')
        settings = read_json(private)
        require(set(settings) == {'endpoint', 'region', 'access_key', 'secret_key'}
                and source['uri'].startswith(settings['endpoint'].rstrip('/') + '/'), 'Private S3 endpoint/config shape differs')
        values = {'uri': source['uri'], 'format': 'parquet', 's3.access_key': settings['access_key'],
                  's3.secret_key': settings['secret_key'], 's3.region': settings['region'], 'use_path_style': 'true'}
        require(all(isinstance(value, str) and value and not re.search(r'["\\\r\n]', value) for value in values.values()),
                'Private S3 values do not fit the frozen literal grammar')
        sql = prefix + 's3(' + ', '.join(f'"{key}" = "{value}"' for key, value in values.items()) + ')'
    path = Path(output).resolve(); path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump({'source_kind': source['source_kind'], 'sql': sql}, stream, sort_keys=True); stream.write('\n')
    return reference(path)


def check_external_service(context):
    source = read_json(verify_reference(context['external_source']))
    require(pin(source['service']['pid']) == source['service'], 'External source process lifetime changed')
    require(sorted(os.sched_getaffinity(source['service']['pid'])) == source['resources']['cpu_affinity'],
            'External source actual CPU affinity changed')


def external_source(context, profile, live=False):
    source = read_json(verify_reference(context['external_source']))
    common = {'schema_version', 'source_kind', 'source_data_sha256', 'service', 'resources',
              'state', 'native_evidence', 'reachability', 'metadata_evidence', 'plan'}
    kind = profile['source_kind']; descriptor = 'catalog' if kind == 'catalog' else 'uri'
    require(set(source) == common | {descriptor} and source['schema_version'] == 1 and source['source_kind'] == kind,
            'External source has missing/unknown fields; no inline credential inputs')
    require(set(source['resources']) == {'cpu_affinity', 'memory_limit_bytes'}
            and source['resources']['cpu_affinity'] == [5] and source['resources']['memory_limit_bytes'] == 536870912,
            'External source resource declaration changed')
    state, native, reachability, prepared = (read_json(verify_reference(source[key]))
        for key in ('state', 'native_evidence', 'reachability', 'plan'))
    require(state['status'] == 'ATTACHED_PRIVATE_POINT_LINK' and state['process'] == source['service'],
            'External source state is not the actually attached process')
    require(native['rows'] == 1000000 and reachability['status'] == 'ORIGINAL_A_CATALOG_AND_S3_REACHABILITY_VERIFIED'
            and reachability['source_rows'] == 1000000 and reachability['external_plan'] == source['plan']
            and native['plan'] == source['plan'] and prepared['total_rows'] == 1000000,
            'External source native/SQL reachability provenance incomplete')
    require({item['source_kind'] for item in reachability['queries'] if item['status'] == 'AGGREGATE_MODEL_VERIFIED'}
            == {'catalog', 's3_tvf'}, 'Original aggregate preflight incomplete; it is not a timed streaming oracle')
    metadata = read_json(verify_reference(source['metadata_evidence']))
    expected_metadata = [{'label': label, 'jdbc_type': jdbc_type, 'type_name': type_name}
                         for label, jdbc_type, type_name in zip(LABELS, COLUMN_TYPES, ('BIGINT', 'INTEGER', 'BIGINT', 'VARCHAR'))]
    require(metadata['status'] == 'ACTUAL_JDBC_METADATA_VERIFIED_NO_DATA_ROWS' and metadata['actual_exit_code'] == 0
            and metadata['driver'] == '3.0.9'
            and {item['kind'] for item in metadata['sources']} == {'catalog', 's3_tvf'}
            and all(item['columns'] == expected_metadata for item in metadata['sources']),
            'Actual original JDBC metadata preflight missing or changed')
    if kind == 'catalog':
        require(native['status'] == 'NATIVE_SOURCE_ALL_ROWS_VERIFIED'
                and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', source['catalog'])
                and source['catalog'] == reachability['catalog'] and native['csv']['sha256'] == MODEL_SHA,
                'Catalog source native full model or actual catalog differs')
        verify_reference(native['csv']); actual = MODEL_SHA
    else:
        require(native['status'] == 'NATIVE_S3_ALL_BYTES_VERIFIED' and len(native['objects']) == 100
                and len(prepared['canonical_objects']) == 100, 'S3 needs complete 100-object native byte proof')
        expected = [{key: item[key] for key in ('key', 'bytes', 'sha256')} for item in prepared['canonical_objects']]
        require(native['objects'] == expected and all(item['rows'] == 10000 for item in prepared['canonical_objects']),
                'S3 original object bytes or 100x10000 model differs')
        settings = prepared['minio']
        require(source['uri'] == f"http://{settings['ip']}:{settings['port']}/{settings['source_bucket']}/lp008/*.parquet",
                'S3 private SQL must use the actually prepared fixed object prefix')
        actual = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(actual == source['source_data_sha256'] == profile['source_data_sha256'], 'Frozen actual external data hash differs')
    if live: check_external_service(context)
    return source


def private_query(context, profile):
    path = verify_reference(context['private_query'])
    require(not Path(context['private_query']['path']).is_symlink() and path.stat().st_mode & 0o777 == 0o600
            and 0 < path.stat().st_size <= 65536, 'Private query needs mode0600 and bounded bytes')
    value = read_json(path)
    require(set(value) == {'source_kind', 'sql'} and value['source_kind'] == profile['source_kind']
            and isinstance(value['sql'], str), 'Private query shape differs')
    source = read_json(verify_reference(context['external_source'])); sql = value['sql']
    prefix = 'SELECT id, grp, v, payload FROM '
    if value['source_kind'] == 'catalog':
        require(sql == prefix + source['catalog'] + '.public.source_rows', 'Private catalog query is not the fixed full read')
    else:
        require(sql.startswith(prefix + 's3(') and sql.endswith(')'), 'Private S3 query is not the fixed full read')
        content = sql[len(prefix + 's3('):-1]
        parts = list(re.finditer(r'"([a-z0-9_.]+)" = "([^"\\\r\n]*)"', content))
        require(', '.join(item[0] for item in parts) == content, 'Private S3 properties grammar differs')
        properties = {item[1]: item[2] for item in parts}
        require(len(parts) == len(properties) == 6 and set(properties) ==
                {'uri', 'format', 's3.access_key', 's3.secret_key', 's3.region', 'use_path_style'}, 'Private S3 properties differ')
        require(properties['uri'] == source['uri'] and properties['format'] == 'parquet'
                and properties['use_path_style'] == 'true' and properties['s3.region'] == 'us-east-1'
                and properties['s3.access_key'] and properties['s3.secret_key'], 'Private S3 source/format changed')
    # Return only a digest. No caller receives a SQL or credential value from this public validator.
    return {'sql_sha256': hashlib.sha256(sql.encode()).hexdigest()}


def validate_context(context, profile, runtime=None, live=False):
    allowed = {"schema_version", "phase", "variant", "window_id", "pair_id", "identity", "bindings", "workload",
               "max_clock_uncertainty_ns", "coordination_seconds", "context_deadline_monotonic_ns", "services",
               "service_configs", "endpoints", "host_namespace", "runtime", "launch_token", "boot_id",
               "created_monotonic_ns", "namespace", "utc_anchor", "freeze", "publication", "private_query", "external_source"}
    require(isinstance(context, dict) and set(context) <= allowed,
            "External read context has unknown fields; credentials/certificates are not context inputs")
    require(context["schema_version"] == 1 and context["phase"] in ("DIAGNOSTIC", "CAPACITY", "AA", "AB")
            and context["variant"] in ("A", "B"), "External read actual phase/variant invalid")
    require(context["phase"] not in ("AA", "CAPACITY") or context["variant"] == "A", "External read A-only phase cannot run B")
    require(isinstance(context["window_id"], str) and context["window_id"] and type(context["pair_id"]) is int
            and context["pair_id"] >= 0, "External read window identity missing")
    statistics.validate_identity(context["identity"])
    require(isinstance(context["host_namespace"], str) and re.fullmatch(r"net:\[\d+\]", context["host_namespace"]),
            "External read explicit host namespace missing")
    require(set(context["bindings"]) == set(IDENTITIES) | set(SOURCES), "External read launch bindings incomplete")
    for key, source in SOURCES.items(): require(context["bindings"][key] == reference(source), "External read actual source differs: " + key)
    for key, field in IDENTITIES.items():
        verify_reference(context["bindings"][key])
        require(context["bindings"][key]["sha256"] == context["identity"][field], "External read identity differs: " + key)
    require(read_json(verify_reference(context["workload"])) == profile, "External read launch profile differs")
    require(type(context["max_clock_uncertainty_ns"]) is int and 0 < context["max_clock_uncertainty_ns"] <= 10**9,
            "External read missing bounded clock uncertainty")
    require(type(context["coordination_seconds"]) is int and 1 <= context["coordination_seconds"] <= 300,
            "External read coordination bound invalid")
    require(type(context["context_deadline_monotonic_ns"]) is int, "External read missing launch deadline")
    if live:
        now = time.monotonic_ns()
        require(now < context["context_deadline_monotonic_ns"] <= now + 300 * 10**9, "External read launch context expired/unbounded")
        check_services(context)
    require(set(context["endpoints"]) == {"query_port", "user", "password_env"},
            "External read endpoint profile incomplete")
    for name in ("query_port",):
        value = context["endpoints"][name]
        require(type(value) is int and 0 < value < 65536, "External read endpoint invalid")
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", context["endpoints"]["password_env"])
            and re.fullmatch(r"[A-Za-z0-9_@.:-]{1,128}", context["endpoints"]["user"]), "External read account reference invalid")
    require(set(context["service_configs"]) == {"fe", "be"}, "External read actual configuration refs missing")
    for role, binding in context["service_configs"].items():
        text = verify_reference(binding).read_text()
        if role != "fe": continue
        port_name = "query_port"
        ports = re.findall(r"(?m)^\s*" + port_name + r"\s*=\s*(\d+)\s*(?:#.*)?$", text)
        endpoint = "query_port"
        require(len(ports) == 1 and int(ports[0]) == context["endpoints"][endpoint],
                "External read configured endpoint differs: " + role)
    external_source(context, profile, live=live)
    private = private_query(context, profile)
    require(read_json(verify_reference(context['bindings']['environment']))['external_source'] == context['external_source'],
            'Environment identity does not bind the actual external service and source evidence')
    client = read_json(verify_reference(context['bindings']['client']))
    require(client['user'] == context['endpoints']['user'] and client['password_env'] == context['endpoints']['password_env']
            and client['private_query'] == context['private_query'] and client['sql_sha256'] == private['sql_sha256']
            and client['connection_mode'] == 'reuse_jdbc_streaming',
            'Client identity does not bind the actual account, private query and connection mode')
    data = read_json(verify_reference(context['bindings']['fixture']))
    require(data['external_source'] == context['external_source'] and data['model_sha256'] == MODEL_SHA
            and data['source_data_sha256'] == profile['source_data_sha256'],
            'Fixture identity does not bind the actual source and complete model')
    if runtime is not None:
        check_runtime(runtime)
        if live:
            check_installed_slots(context, runtime)
    if context["phase"] == "AB":
        frozen, publication = (read_json(verify_reference(context[key])) for key in ("freeze", "publication"))
        require(frozen["status"] == "FROZEN_ELIGIBLE" and frozen["identities"][context["variant"]] == context["identity"]
                and publication["freeze"] == context["freeze"], "External read A/B freeze identity invalid")
        cell = frozen["cell"]; scheduled = plan(profile)["measurement"]
        require(cell["group"] == "G2" and cell["case_id"] == CASES[profile["source_kind"]]
                and cell["workload_sha256"] == business_binding(profile)["sha256"]
                and cell["rate"] == profile["rate"] and cell["concurrency"] == profile["concurrency"]
                and cell["seed"] == 20260922 and cell["warmup_seconds"] == profile["warmup_seconds"]
                and cell["duration_seconds"] == profile["duration_seconds"]
                and cell["request_count"] == scheduled["requests"] and cell["arrival_schedule_sha256"] == scheduled["sha256"]
                and cell["connection_mode"] == "reuse_jdbc_streaming", "External read frozen A/B business/schedule differs")
        if "created_monotonic_ns" in context:
            require(publication["boot_id"] == context["boot_id"]
                    and publication["published_monotonic_ns"] <= context["created_monotonic_ns"], "External read A/B freeze published after launch")
    else:
        require("freeze" not in context and "publication" not in context, "External read A-only phase claims A/B freeze")
    return context


def reap(child):
    """Only our direct Popen process group; never signal a service or an arbitrary recorded PID."""
    if child.poll() is None:
        try: os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=10)
    else: child.wait()


def acquire_process(child, command, deadline):
    """Popen creation is not the execution identity: require actual exe and the complete argv digest."""
    expected_exe = str(Path(command[0]).resolve())
    expected_command = hashlib.sha256(b"\0".join(os.fsencode(value) for value in command) + b"\0").hexdigest()
    while time.monotonic() < deadline:
        require(child.poll() is None, "External read child exited before actual execution identity")
        actual = pin(child.pid)
        if actual["exe"] == expected_exe and actual["command_sha256"] == expected_command:
            return actual
        time.sleep(.002)
    raise statistics.EvidenceError("External read owned child never executed the frozen command")


def command_for(runtime, config_path):
    return [str(Path(runtime["java_home"]) / "bin/java"), "-Xms256m", "-Xmx768m", "-XX:MaxDirectMemorySize=536870912",
            "-Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.NoOpLog",
            "--add-opens=java.base/java.nio=ALL-UNNAMED", "-cp",
            os.pathsep.join([runtime["classes_directory"], *[item["path"] for item in runtime["jars"]]]),
            "LicenseExternalReadPerformance", str(config_path)]


def run_window(profile_ref, context, runtime_ref, output, stop_file=None):
    """Execute only when explicitly called. Caller enters the owned namespace and runs one service group."""
    check_jvm_environment()
    profile = validate_profile(read_json(verify_reference(profile_ref))); plan(profile); verify_model()
    runtime = read_json(verify_reference(runtime_ref)); validate_context(context, profile, runtime, live=True)
    require(context["workload"] == profile_ref, "External read run profile ref differs")
    directory = Path(output).resolve(); directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    launch = dict(context)
    launch.update(launch_token=secrets.token_hex(32), boot_id=statistics.boot_id(), created_monotonic_ns=time.monotonic_ns(),
                  utc_anchor=lifecycle.anchor(), runtime=runtime_ref, namespace=os.readlink("/proc/self/ns/net"))
    validate_context(launch, profile, runtime, live=True)
    publish(directory / "p4-launch.json", launch); launch_ref = reference(directory / "p4-launch.json")
    config = {**context["endpoints"], "profile": profile, "launch": launch_ref, "namespace": launch["namespace"],
              "host_namespace": context["host_namespace"], "services": context["services"], "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
              "coordination_seconds": context["coordination_seconds"]}
    private = private_query(context, profile)
    destination = directory / "query.private.json"
    with destination.open("xb") as stream:
        os.chmod(destination, 0o600); stream.write(verify_reference(context["private_query"]).read_bytes())
    config.update(private_query=reference(destination), sql_sha256=private["sql_sha256"])
    publish(directory / "config.json", config); config_ref = reference(directory / "config.json")
    dependencies = [launch_ref, config_ref, runtime_ref, profile_ref, *context["bindings"].values(),
                    *context["service_configs"].values(), *check_runtime(runtime)]
    if launch["phase"] == "AB": dependencies += [launch["freeze"], launch["publication"]]
    dependencies += source_references(context) + [context["private_query"], context["external_source"]]
    child = None; actual = None; bridge = None; request = None; errors = []; warm_verified = False
    interrupted = [None]
    previous_signals = {number: signal.signal(number, lambda sig, _frame: interrupted.__setitem__(0, sig))
                        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    deadline = time.monotonic() + profile["warmup_seconds"] + profile["duration_seconds"] + 2 * profile["drain_seconds"] + 480
    def check():
        require(interrupted[0] is None, "External read controller interrupted")
        require(time.monotonic() < deadline, "External read absolute client deadline exceeded")
        require(stop_file is None or not Path(stop_file).exists(), "External read own-client stop requested")
        check_services(context)
        check_external_service(context)
        # Large JDK/jar content is checked at start and finish, outside measurement; do not poll SHA every 10 ms.
        require(statistics.digest(launch_ref["path"]) == launch_ref["sha256"], "External read launch changed")
    try:
        with (directory / "client.log").open("x") as log:
            child = subprocess.Popen(command_for(runtime, directory / "config.json"), stdout=log, stderr=log, start_new_session=True)
            actual = acquire_process(child, command_for(runtime, directory / "config.json"), min(deadline, time.monotonic() + 5))
            publish(directory / "process.json", {"pin": actual, "command": command_for(runtime, directory / "config.json")})
            while child.poll() is None:
                check()
                if bridge is None:
                    require(time.monotonic_ns() < launch["context_deadline_monotonic_ns"], "External read context expired before warmup")
                    ready_path = directory / "p4-clock-ready.json"
                    if request is None and ready_path.exists():
                        ready = read_json(ready_path)
                        require(ready["helper_pid"] == actual["pid"] and ready["helper_start_ticks"] == actual["start_ticks"]
                                and ready["launch_token"] == launch["launch_token"] and ready["launch_sha256"] == launch_ref["sha256"],
                                "External read ready identity differs")
                        request = {"launch_token": launch["launch_token"], "launch_sha256": launch_ref["sha256"],
                                   "nonce": secrets.token_hex(32), "ready_nonce": ready["ready_nonce"]}
                        before = time.monotonic_ns(); publish(directory / "clock-request.json", request)
                    helper_path = directory / "p4-helper-clock.json"
                    if request is not None and helper_path.exists():
                        helper = read_json(helper_path); after = time.monotonic_ns()
                        require(helper["helper_pid"] == actual["pid"] and helper["helper_start_ticks"] == actual["start_ticks"],
                                "External read clock helper changed")
                        bridge = {"schema_version": 1, "launch_token": launch["launch_token"], "launch_sha256": launch_ref["sha256"],
                                  "boot_id": launch["boot_id"], "nonce": request["nonce"], "controller_before_ns": before,
                                  "controller_after_ns": after, "helper_clock": reference(helper_path)}
                        mapping = clocks.clock_bridge(launch, launch_ref, bridge, helper)
                        for binding in dependencies: verify_reference(binding)
                        require(time.monotonic_ns() < launch["context_deadline_monotonic_ns"], "External read ACK context expired")
                        publish(directory / "p4-clock-bridge.json", bridge)
                        publish(directory / "clock-ack.json", {**request, "helper_clock_sha256": bridge["helper_clock"]["sha256"],
                                "bridge_sha256": statistics.digest(directory / "p4-clock-bridge.json")})
                elif not warm_verified and (directory / "measurement-ready.json").exists():
                    ready = read_json(directory / "measurement-ready.json")
                    require(ready["warmup_start_ns"] + mapping["offset_upper_ns"] <= launch["context_deadline_monotonic_ns"],
                            "External read actual warmup exceeds context lifetime")
                    warm_verified = True
                time.sleep(.01)
            child.wait()
    except BaseException as error:
        errors.append({"stage": "run", "error_class": type(error).__name__})
    finally:
        if child is not None:
            try: reap(child)
            except BaseException as error: errors.append({"stage": "reap", "error_class": type(error).__name__})
        try:
            for binding in dependencies: verify_reference(binding)
            check_services(context)
            check_installed_slots(context, runtime)
            check_external_service(context)
        except BaseException as error: errors.append({"stage": "bindings", "error_class": type(error).__name__})
        if bridge is not None:
            try:
                cleanup = read_json(directory / "lifecycle.json")
                until = cleanup["cleanup_end_ns"] + mapping["offset_upper_ns"]
                require(until - time.monotonic_ns() <= 2 * launch["max_clock_uncertainty_ns"], "External read cleanup clock beyond bounded wait")
                while time.monotonic_ns() < until: time.sleep(min(.01, (until - time.monotonic_ns()) / 1e9))
            except (OSError, ValueError, KeyError, TypeError) as error:
                errors.append({"stage": "cleanup", "error_class": type(error).__name__})
        remaining = []
        if actual is not None:
            try:
                if lifecycle.start_ticks(actual["pid"]) == actual["start_ticks"]: remaining.append(actual["pid"])
            except FileNotFoundError: pass
        completion = {"schema_version": 1, "launch_token": launch["launch_token"], "launch_sha256": launch_ref["sha256"],
                      "boot_id": launch["boot_id"], "helper_pid": actual["pid"] if actual else None,
                      "helper_start_ticks": actual["start_ticks"] if actual else None,
                      "exit_code": child.returncode if child else None, "parent_wait_complete": child is not None and child.returncode is not None,
                      "completed_monotonic_ns": time.monotonic_ns(), "utc_anchor": lifecycle.anchor(),
                      "remaining_live_pids": remaining, "controller_errors": errors}
        if bridge is not None: completion["bridge"] = reference(directory / "p4-clock-bridge.json")
        publish(directory / "p4-completion.json", completion)
        for number, handler in previous_signals.items():
            signal.signal(number, handler)
    return {"status": "RAW_WINDOW_COMPLETE" if completion["exit_code"] == 0 and not errors and not remaining else "INVALID_WINDOW",
            "launch": launch_ref, "completion": reference(directory / "p4-completion.json"),
            "window_directory": str(directory), "formal_performance_pass": False}


def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered: return None
    index = (len(ordered) - 1) * fraction; lower = int(index)
    return ordered[lower] + (ordered[min(lower + 1, len(ordered) - 1)] - ordered[lower]) * (index - lower)


def cpu_ticks(value, pin_value, hz):
    raw = value["raw_stat"]; fields = raw[raw.rfind(")") + 1:].split()
    require(int(raw[:raw.find(" ")]) == value["pid"] == pin_value["pid"]
            and int(fields[19]) == value["start_ticks"] == pin_value["start_ticks"] and fields[0] not in ("Z", "X"),
            "External read CPU raw lifetime differs")
    require(type(hz) is int and hz > 0, "External read CPU clock ticks missing")
    return int(fields[11]) + int(fields[12])


def audit_operation(directory, row, profile, config, phase, worker, sequence, contexts):
    require(row["finished_ns"] < row["dispatch_deadline_ns"] == row["started_ns"] + 120 * 10**9
            and row["dispatch_deadline_exceeded"] is False and row["connection_aborted"] is False,
            "External read dispatch deadline or aborted connection differs")
    require(row["rows_verified"] == row["rows_observed"] == 1000000
            and row["complete_unordered_set"] == {"rows": 1000000, "distinct_ids": 1000000,
                "min_id": 0, "max_id": 999999, "sum_id": 499999500000, "sum_grp": 511370976,
                "sum_v": 49999500000, "null_fields": 0, "sha256_sorted_actual_rows": MODEL_SHA},
            "External read complete four-column unordered million-row model missing")
    require(row["column_labels"] == LABELS and row["column_types"] == profile["column_types"]
            and row["fetch_size"] == 1024 and row["streaming"] is True
            and row["driver_query_timeout_seconds"] == 0
            and row["result_class"] == "org.mariadb.jdbc.client.result.StreamingResult"
            and row["statement_class"] == "org.mariadb.jdbc.Statement"
            and row["sql_sha256"] == config["sql_sha256"] and row["execute_calls"] == 1,
            "External read actual JDBC stream/schema/query evidence differs")
    opened = read_json(directory / f"session-{worker}-open.json")
    require(row["connection_reused"] is True and row["server_connection_id"] == opened["server_connection_id"]
            and row["socket_local_port"] == opened["socket_local_port"]
            and row["socket_remote_port"] == opened["socket_remote_port"] == config["query_port"]
            and row["result_closed"] is True and row["statement_closed"] is True,
            "External read connection reuse/result closure missing")


def audit_requests(directory, profile, config):
    planned = plan(profile); derived = {}; contexts = set(); calls = [0] * profile["concurrency"]
    for phase, length in (("warmup", profile["warmup_seconds"]), ("measurement", profile["duration_seconds"])):
        expected = planned[phase]
        with (directory / (phase + "-arrivals.tsv")).open() as stream:
            arrival_rows = list(csv.DictReader(stream, delimiter="\t"))
        require(len(arrival_rows) == expected["requests"], "External read missing/excess arrivals")
        offsets = []
        for index, (row, offset) in enumerate(zip(arrival_rows, expected["offsets"])):
            require(set(row) == {"sequence", "offset_ns"} and int(row["sequence"]) == index
                    and abs(int(row["offset_ns"]) - offset) <= 1, "External read arrival changed")
            offsets.append(int(row["offset_ns"]))
        start, end = (read_json(directory / (phase + "-" + point + ".json")) for point in ("start", "end"))
        epoch = start["epoch_ns"]; last = epoch; seen = set(); latency = []; service = []; queue = []; errors = 0; timeouts = 0
        require(type(epoch) is int and epoch > 0 and end["epoch_ns"] == epoch, "External read epoch changed")
        for worker in range(profile["concurrency"]):
            previous = epoch
            with (directory / f"{phase}-{worker}.jsonl").open() as stream:
                for line in stream:
                    row = json.loads(line); sequence = row["sequence"]
                    require(type(sequence) is int and 0 <= sequence < len(offsets) and sequence not in seen
                            and sequence % profile["concurrency"] == worker and row["worker"] == worker, "External read duplicate/foreign receipt")
                    seen.add(sequence); scheduled, started, finished = (row[key] for key in ("scheduled_ns", "started_ns", "finished_ns"))
                    require(all(type(value) is int for value in (scheduled, started, finished)) and scheduled == epoch + offsets[sequence]
                            and finished >= started >= max(scheduled, previous) and row["e2e_ns"] == finished - scheduled
                            and row["service_ns"] == finished - started and row["queue_ns"] == started - scheduled,
                            "External read queue/service/E2E receipt differs")
                    previous = finished; last = max(last, finished)
                    if "session_call" in row:
                        calls[worker] += 1
                        require(row["session_id"] == worker and row["session_call"] == calls[worker], "External read session call sequence changed")
                    if row["status"] != "READ_PASS":
                        require(row["status"] == "ERROR" and row["error_class"] and row["error_code"]
                                and type(row.get("timeout")) is bool, "External read unknown error receipt")
                        errors += 1; timeouts += row.get("timeout") is True
                        continue
                    require(row["session_id"] == worker and row["session_call"] == calls[worker] and row["execute_calls"] == 1,
                            "External read actual JDBC execute/session sequence missing")
                    audit_operation(directory, row, profile, config, phase, worker, sequence, contexts)
                    latency.append(row["e2e_ns"] / 1e6); service.append(row["service_ns"] / 1e6); queue.append(row["queue_ns"] / 1e6)
        require(len(seen) == len(offsets), "External read missing completion receipts")
        interval_end = max(epoch + length * 10**9, last)
        require(end["last_request_end_ns"] == last and end["request_interval_end_ns"] == interval_end
                and end["java_monotonic_ns"] >= interval_end and end["scheduled_requests"] == len(seen)
                and end["successful_requests"] == len(latency)
                and end["arrival_schedule_sha256"] == statistics.digest(directory / (phase + "-arrivals.tsv")),
                "External read summary/denominator differs from complete raw window")
        seconds = (interval_end - epoch) / 1e9; cpus = {}
        for role in ("fe", "be"):
            first, final = start["cpu"][role], end["cpu"][role]
            require(first["sample_started_java_ns"] <= first["sample_ended_java_ns"] <= epoch
                    and final["sample_ended_java_ns"] >= final["sample_started_java_ns"] >= interval_end,
                    "External read CPU sample does not enclose all requests")
            delta = cpu_ticks(final, config["services"][role], config["clock_ticks_per_second"]) - cpu_ticks(first, config["services"][role], config["clock_ticks_per_second"])
            require(delta >= 0, "External read CPU counter decreased")
            cpus[role + "_cpu_seconds_per_success"] = delta / config["clock_ticks_per_second"] / len(latency) if latency else None
        derived[phase] = {"scheduled_requests": len(seen), "observed_requests": len(seen), "successful_requests": len(latency),
            "error_count": errors, "timeout_count": timeouts, "retry_count": 0, "effective_duration_seconds": seconds,
            "arrival_schedule_sha256": end["arrival_schedule_sha256"], "success_qps": len(latency) / seconds,
            "p95_ms": percentile(latency, .95), "p99_ms": percentile(latency, .99),
            "service_p95_ms": percentile(service, .95), "service_p99_ms": percentile(service, .99),
            "queue_p95_ms": percentile(queue, .95), "queue_p99_ms": percentile(queue, .99), **cpus}
    return derived


def normalize(manifest):
    directory = Path(manifest["window_directory"]).resolve(); before = raw_bindings(directory)
    launch_ref = manifest["launch"]; launch = read_json(verify_reference(launch_ref))
    require(launch_ref == reference(directory / "p4-launch.json"), "External read launch from another window")
    config = read_json(directory / "config.json"); profile = validate_profile(config["profile"]); plan(profile); verify_model()
    require(sum(path.stat().st_size for path in directory.glob("*.jsonl")) <= profile["max_raw_ledger_bytes"],
            "External read raw/private archive exceeds frozen bound")
    runtime = read_json(verify_reference(launch["runtime"])); dependencies = check_runtime(runtime)
    validate_context(launch, profile, runtime)
    require(config["launch"] == launch_ref and config["services"] == launch["services"] and config["namespace"] == launch["namespace"]
            and all(config[key] == value for key, value in launch["endpoints"].items()), "External read actual helper configuration differs")
    completion = read_json(verify_reference(manifest["completion"])); process = read_json(directory / "process.json")
    for key in ("launch_token", "boot_id"):
        require(completion[key] == launch[key], "External read completion from another launch")
    require(completion["launch_sha256"] == launch_ref["sha256"] and completion["exit_code"] == 0
            and completion["parent_wait_complete"] is True and completion["remaining_live_pids"] == []
            and not completion["controller_errors"], "External read actual parent wait/exit failed")
    clocks.utc_anchor(launch["utc_anchor"]); clocks.utc_anchor(completion["utc_anchor"])
    bridge = read_json(verify_reference(completion["bridge"])); helper = read_json(verify_reference(bridge["helper_clock"]))
    require(all(helper[key] == completion[key] for key in ("helper_pid", "helper_start_ticks"))
            and helper["helper_pid"] == process["pin"]["pid"] and helper["helper_start_ticks"] == process["pin"]["start_ticks"],
            "External read waited process differs from clock helper")
    command = command_for(runtime, directory / "config.json")
    require(process["command"] == command and process["pin"]["command_sha256"] == hashlib.sha256(
            b"\0".join(os.fsencode(value) for value in command) + b"\0").hexdigest()
            and process["pin"]["exe"] == str((Path(runtime["java_home"]) / "bin/java").resolve())
            and process["pin"]["namespace"] == helper["namespace"] == launch["namespace"], "External read actual helper command/namespace differs")
    mapping = clocks.clock_bridge(launch, launch_ref, bridge, helper); offset = mapping["estimated_offset_ns"]
    expected_identity = {key: helper[key] for key in ("launch_token", "launch_sha256", "boot_id", "helper_pid", "helper_start_ticks", "namespace")}
    for name in ("p4-clock-ready.json", "warmup-start.json", "warmup-end.json", "measurement-ready.json",
                 "measurement-start.json", "measurement-end.json", "lifecycle.json", "summary.json"):
        actual = read_json(directory / name)
        require(all(actual.get(key) == value for key, value in expected_identity.items()), "External read receipt identity differs: " + name)
    requests = audit_requests(directory, profile, config)
    require(all(value["error_count"] == 0 for value in requests.values()), "External read warmup/measured failures preserved")
    warm_start, warm_end, ready, start, end, cleanup, summary = (read_json(directory / name) for name in (
        "warmup-start.json", "warmup-end.json", "measurement-ready.json", "measurement-start.json",
        "measurement-end.json", "lifecycle.json", "summary.json"))
    warm = warm_start["epoch_ns"]; warm_finished = warm_end["java_monotonic_ns"]
    require(helper["jvm_sample_ns"] <= warm <= warm_finished <= ready["ready_ns"] <= start["epoch_ns"]
            and ready["warmup_start_ns"] == warm and ready["warmup_end_ns"] == warm_finished
            and warm_finished - warm >= profile["warmup_seconds"] * 10**9, "External read actual warmup missing/overlapping")
    lower = warm + mapping["offset_lower_ns"]; upper = end["request_interval_end_ns"] + mapping["offset_upper_ns"]
    observed_lower = min(item["sample_started_java_ns"] for item in warm_start["cpu"].values()) + mapping["offset_lower_ns"]
    observed_upper = max(end["java_monotonic_ns"],
                         *(item["sample_ended_java_ns"] for item in end["cpu"].values())) + mapping["offset_upper_ns"]
    require(lower >= launch["created_monotonic_ns"]
            and warm + mapping["offset_upper_ns"] <= launch["context_deadline_monotonic_ns"], "External read actual warmup predates/exceeds launch")
    require(cleanup["cleanup_end_ns"] >= end["java_monotonic_ns"] and cleanup["sessions_closed"] is True
            and cleanup["workers_stopped"] is True and summary["cleanup_confirmed"] is True
            and summary["status"] == "RAW_WINDOW_COMPLETE" and summary["errors"] == 0 and summary["harness_retries"] == 0
            and cleanup["cleanup_end_ns"] + mapping["offset_upper_ns"] <= completion["completed_monotonic_ns"],
            "External read cleanup/wait ordering failed")
    connection_ids = set()
    for worker in range(profile["concurrency"]):
        opened, closed = (read_json(directory / f"session-{worker}-{point}.json") for point in ("open", "close"))
        require(opened["worker"] == opened["session_id"] == closed["worker"] == worker
                and opened["jdbc_connections_opened"] == 1 and opened["opened_ns"] <= helper["jvm_sample_ns"]
                and opened["driver_class"] == "org.mariadb.jdbc.Driver" and opened["driver_version"] == "3.0.9"
                and opened["connection_class"] == "org.mariadb.jdbc.Connection"
                and opened["client_class"] == "org.mariadb.jdbc.client.impl.StandardClient"
                and opened["cache_readback"] == business_binding(profile)["fields"]["session"]
                and type(opened["server_connection_id"]) is int and opened["server_connection_id"] > 0
                and opened["server_connection_id"] not in connection_ids,
                "External read actual unique JDBC connection or session readback missing")
        connection_ids.add(opened["server_connection_id"])
        require(end["java_monotonic_ns"] <= closed["close_started_ns"] <= closed["close_finished_ns"] <= cleanup["cleanup_end_ns"]
                and closed["jdbc_connection_closed"] is True and closed["jdbc_connections_closed"] == 1
                and closed["connection_aborted"] is False, "External read persistent connection close missing")
    private = private_query(launch, profile)
    require(config["sql_sha256"] == private["sql_sha256"]
            and config["private_query"] == reference(directory / "query.private.json")
            and config["private_query"]["sha256"] == launch["private_query"]["sha256"], "Private SQL actual launch/config binding differs")
    private_query({**launch, "private_query": config["private_query"]}, profile)
    raw_extra = [manifest["launch"], manifest["completion"], completion["bridge"], bridge["helper_clock"]]
    # This narrow observer contract is supplied by the outer real-window controller, never inferred from config.
    formal = profile["qualification"] == "formal" and launch["phase"] != "DIAGNOSTIC"
    if formal or "observer" in manifest:
        observer = read_json(verify_reference(manifest["observer"]))
        require(observer["status"] == "VERIFIED" and observer["launch_sha256"] == launch_ref["sha256"]
                and observer["boot_id"] == launch["boot_id"] and observer["coverage_start_monotonic_ns"] <= observed_lower
                and observer["coverage_end_monotonic_ns"] >= observed_upper and observer["resource_failures"] == []
                and observer["budget_verified"] is True
                and observer["observed_license_state"] == ("ORIGINAL_A_NO_LICENSE" if launch["variant"] == "A" else "VALID"),
                "External read resource/license observation incomplete")
        require(observer["raw_artifacts"], "External read observer has no original data")
        for role in ("fe", "be"):
            require(observer["services"][role]["pin"] == launch["services"][role]
                    and observer["services"][role]["artifact"] == launch["bindings"][role + "_artifact"]
                    and observer["services"][role]["configuration"] == launch["service_configs"][role],
                    "External read observer did not bind actual deployed binary/config")
        source = external_source(launch, profile)
        observed = observer["external_source"]
        require(observed["pin"] == source["service"] and observed["state"] == source["state"]
                and observed["resources"] == source["resources"] and observed["sample_count"] >= 2
                and observed["peak_rss_bytes"] <= source["resources"]["memory_limit_bytes"]
                and observed["cgroup_memory_limit_bytes"] == source["resources"]["memory_limit_bytes"]
                and observed["peak_cgroup_memory_bytes"] <= source["resources"]["memory_limit_bytes"]
                and observed["cgroup_oom_kill_delta"] == 0
                and observed["all_sample_cpu_affinities"] == [source["resources"]["cpu_affinity"]],
                "External source actual process/RSS/cgroup/CPU observation incomplete")
        raw_extra += [manifest["observer"], *observer["raw_artifacts"]]; dependencies += [observer["auditor"]]
    measured = requests["measurement"]
    window = {"window_id": launch["window_id"], "pair_id": launch["pair_id"], "variant": launch["variant"],
        "boot_id": launch["boot_id"], "identity": launch["identity"], "workload_sha256": business_binding(profile)["sha256"],
        "arrival_schedule_sha256": measured["arrival_schedule_sha256"], "rate": profile["rate"],
        "warmup_seconds": profile["warmup_seconds"], "duration_seconds": profile["duration_seconds"],
        "warmup_start_monotonic_ns": warm + offset, "warmup_end_monotonic_ns": warm_finished + offset,
        "start_monotonic_ns": start["epoch_ns"] + offset, "end_monotonic_ns": end["request_interval_end_ns"] + offset,
        "monotonic_clock_domain": "bounded_jvm_mapping", "monotonic_mapping": mapping,
        "monotonic_mapping_uncertainty_ns": mapping["uncertainty_ns"], "effective_duration_seconds": measured["effective_duration_seconds"],
        **{key: measured[key] for key in ("scheduled_requests", "observed_requests", "successful_requests", "error_count", "timeout_count", "retry_count")},
        "oracle_verified": True, "cleanup_verified": True, "cpu_boundary_verified": True,
        "metrics": {key: measured[key] for key in statistics.METRICS}}
    dependencies += [launch["runtime"], launch["workload"], *launch["bindings"].values(), *launch["service_configs"].values()]
    dependencies += source_references(launch) + [launch["private_query"], launch["external_source"]]
    if launch["phase"] == "AB":
        publication = read_json(verify_reference(launch["publication"]))
        require(publication["published_monotonic_ns"] <= lower, "External read warmup precedes publication")
        window.update(freeze_sha256=launch["freeze"]["sha256"], freeze_publication_sha256=launch["publication"]["sha256"])
        dependencies += [launch["freeze"], launch["publication"]]
    after = raw_bindings(directory); require(before == after, "External read raw changed during audit")
    raw = {item["path"]: item for item in after + raw_extra}
    dependencies = list({item["path"]: item for item in dependencies}.values())
    for item in [*raw.values(), *dependencies]: verify_reference(item)
    return {"status": "VERIFIED" if formal else "DIAGNOSTIC_VERIFIED_NOT_QUALIFIED", "window": window,
            "auditor": reference(SOURCE), "raw_artifacts": list(raw.values()), "dependency_bindings": dependencies,
            "request_audit": requests, "formal_shape_met": formal and measured["successful_requests"] >= 10000,
            "formal_performance_pass": False,
            "scope": "One complete million-row four-column streamed external SELECT and confirmed result close is one operation; capacity/A/A/A/B remains external"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "prepare-private", "compile", "run", "normalize"))
    parser.add_argument("--input", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = read_json(args.input)
        if args.mode == "prepare-private":
            require(set(value) <= {"external_source", "s3_client_path"} and "external_source" in value,
                    "Private preparation accepts source reference/config path only")
            result = prepare_private_query(value["external_source"], args.output, value.get("s3_client_path"))
        elif args.mode == "compile":
            result = compile_helper(value, args.output)
        elif args.mode == "run":
            result = run_window(value["workload"], value["context"], value["runtime"], args.output, value.get("stop_file"))
        else:
            require(not args.output.exists(), "Never overwrite External read evidence")
            if args.mode == "normalize":
                require(Path(value["window_directory"]).resolve() not in args.output.resolve().parents,
                        "External read audit must be outside raw directory")
                result = normalize(value)
            else: result = {"business": business_binding(value), "plan": plan(value), "formal_performance_pass": False}
            publish(args.output, result)
        print(json.dumps({"status": result.get("status", "OFFLINE_COMPLETE"), "output": str(args.output), "formal_performance_pass": False}))
        return 2 if result.get("status") == "INVALID_WINDOW" else 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "REJECTED", "error_class": type(error).__name__, "reason": str(error),
                          "formal_performance_pass": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
