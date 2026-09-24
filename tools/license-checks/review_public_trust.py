#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Review explicitly provided public keys with the delivered FE artifact; never install trust."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve()
JAVA = SOURCE.with_name("LicensePublicTrustProbe.java")
ISSUER = ROOT / "tools/license-issuer/license_issuer.py"
PURPOSES = {"license", "time_repair"}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def bounded(path):
    with Path(path).open("rb") as stream:
        value = stream.read(65537)
    require(0 < len(value) <= 65536, "Public manifest/dependency input outside byte bound")
    return value


def issuer_module():
    specification = importlib.util.spec_from_file_location("massdb_public_review_issuer", ISSUER)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def public_model(raw, issuer):
    manifest = issuer.validate_trust_manifest(issuer.parse_json(raw))
    result = []
    for key in manifest["keys"]:
        der = base64.urlsafe_b64decode(key["public_key_spki"] + "=")
        result.append({"kid": key["kid"], "purpose": key["purpose"],
                       "spki_sha256": hashlib.sha256(der).hexdigest(), "spki_bytes": len(der)})
    return sorted(result, key=lambda key: (key["purpose"], key["kid"]))


def retention_model(raw, previous_raw, previous, issuer):
    value = issuer.parse_json(raw)
    require(isinstance(value, dict)
            and set(value) == {"schema_version", "previous_manifest_sha256", "license_kids", "time_repair_kids"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1,
            "Retention input has unknown/missing fields")
    require(value["previous_manifest_sha256"] == hashlib.sha256(previous_raw).hexdigest(),
            "Retention input does not identify the previous manifest")
    for purpose in PURPOSES:
        kids = value[purpose + "_kids"]
        available = {key["kid"] for key in previous if key["purpose"] == purpose}
        require(isinstance(kids, list) and len(kids) <= 32 and all(isinstance(key, str) for key in kids)
                and len(set(kids)) == len(kids) and set(kids) <= available,
                "Retention key dependency is duplicate, unknown or assigned to the wrong purpose")
    return value


def rotation_model(previous, current, retention):
    by_id = {key["kid"]: key for key in current}
    for old in previous:
        new = by_id.get(old["kid"])
        require(new is None or (new["purpose"] == old["purpose"]
                and new["spki_sha256"] == old["spki_sha256"]), "A retained key identifier changed meaning")
        require(not any(key["purpose"] != old["purpose"] and key["spki_sha256"] == old["spki_sha256"]
                        for key in current), "A public key changed purpose across manifests")
        if old["kid"] in retention[old["purpose"] + "_kids"]:
            require(new == old, "A declared retained key dependency was removed or changed")
    return {"removed_keys": [key["kid"] for key in previous if key["kid"] not in by_id],
            "declared_retention_checked": True, "retention_completeness_verified": False}


def validate_child_rss(status, waitable):
    memory = re.findall(r"(?m)^(?:VmRSS|VmHWM):\s+(\d+) kB$", status)
    if memory:
        require(max(map(int, memory)) <= 768 * 1024, "Public review child RSS bound")
    else:
        # Linux may drop memory accounting at exit before waitid exposes the child as waitable.
        # Z/X cannot execute; the original absolute deadline and final exit-status check still apply.
        require(waitable or re.search(r"(?m)^State:\s+[ZX](?:\s|$)", status),
                "Live review child RSS unavailable")


def bounded_process(argv, receipts, name, seconds=120, cancelled=lambda: False):
    """Drain both pipes and reap only this owned child; no raw diagnostic text enters the report."""
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH")}
    if cancelled():
        raise InterruptedError("Public review cancelled before child launch")
    process = None
    data, failure = {"stdout": bytearray(), "stderr": bytearray()}, None
    deadline = time.monotonic() + seconds
    selector = selectors.DefaultSelector()
    cleanup_errors = []
    def exited():
        # WNOWAIT retains the leader PID until group cleanup, preventing process-group ID reuse.
        return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    try:
        process = subprocess.Popen([str(value) for value in argv], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=environment, start_new_session=True)
        for key, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, key)
        while selector.get_map() or exited() is None:
            if cancelled():
                raise InterruptedError("Public review cancelled")
            require(time.monotonic() < deadline, "Public review child exceeded its deadline")
            if exited() is None:
                try:
                    status = Path(f"/proc/{process.pid}/status").read_text()
                    validate_child_rss(status, exited() is not None)
                except FileNotFoundError:
                    require(exited() is not None, "Public review child identity disappeared")
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                require(len(data[key.data]) + len(chunk) <= 1024 * 1024, "Public review child output bound")
                data[key.data].extend(chunk)
        status = exited()
        require(status.si_code == os.CLD_EXITED and status.si_status == 0,
                "Public review child rejected input or failed")
        return bytes(data["stdout"])
    except BaseException as error:
        failure = type(error).__name__
        raise
    finally:
        selector.close()
        if process is not None:
            # The unreaped leader anchors this exact owned session even if descendants hold pipes.
            # Public review children have no external mutation to finish; terminate the whole group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                cleanup_errors.append(type(error).__name__)
            try:
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(type(error).__name__)
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except OSError as error:
                    cleanup_errors.append(type(error).__name__)
        receipts.append({"stage": name, "exit_code": process.returncode if process else None, "error_class": failure,
                         "owned_leader_reaped": process is None or process.returncode is not None,
                         "owned_process_group_cleanup_requested": process is not None,
                         "cleanup_errors": cleanup_errors,
                         "output": {key: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                                    for key, value in data.items()}})
        require(not cleanup_errors, "Owned public review process cleanup was incomplete")


def validate_loaded(result, artifact, jars):
    classes = result.get("loaded_classes")
    expected = {"org.apache.doris.massdb.license." + name: artifact for name in
                ("LicenseTrustStore", "LicenseTrustStore$Purpose", "LicenseException",
                 "LicenseText", "LicenseDocument", "LicenseErrorCode", "LicenseVerifier", "LicenseClockRepairVerifier")}
    expected.update({"com.fasterxml.jackson.databind.ObjectMapper": jars["jackson-databind"],
                     "com.fasterxml.jackson.core.JsonFactory": jars["jackson-core"]})
    require(isinstance(classes, dict) and set(classes) == set(expected), "Loaded class inventory differs")
    for name, source in expected.items():
        actual = classes[name]
        require(Path(actual["source"]).resolve() == source, "A class loaded from an undeclared artifact")
        with zipfile.ZipFile(source) as archive:
            info = archive.getinfo(name.replace(".", "/") + ".class")
            require(info.file_size <= 2 * 1024 * 1024, "Class entry exceeds bound")
            data = archive.read(info)
        require(hashlib.sha256(data).hexdigest() == actual["sha256"], "Loaded class bytes differ from delivered jar")
        if name.startswith("org.apache.doris.massdb.license."):
            require(actual["major"] == 52, "Delivered license class is not release 8")


def validate_release_metadata(release, expected_runtime):
    # Vendor release files do not share a mandatory runtime-build field. Temurin uses FULL_VERSION.
    # The launched probe must still report the exact declared java.runtime.version before acceptance.
    require(release.get("JAVA_VERSION") == "17.0.4", "Actual JDK release is not 17.0.4")
    require(all(release[key] == expected_runtime for key in ("JAVA_RUNTIME_VERSION", "FULL_VERSION")
                if key in release), "JDK release metadata differs from the declared runtime build")


def review(args):
    # Importing this guard does not start a process, SQL service or observer.
    from background_http_fixture import no_active_benchmark
    no_active_benchmark()
    require(args.cpu in os.sched_getaffinity(0), "Review CPU is unavailable")
    os.sched_setaffinity(0, {args.cpu})
    require(all(not os.environ.get(key) for key in
                ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH")),
            "Ambient JVM/classpath injection differs from the declared runtime")
    require(re.fullmatch(r"[a-f0-9]{64}", args.manifest_sha256 or ""), "Declare the supplied public manifest digest")
    require(bool(args.previous_manifest) == bool(args.retention), "Rotation requires previous manifest and retention")
    output = args.output.resolve()
    require(ROOT / ".build-records" in output.parents and not output.exists(), "Use a new checkout-owned output directory")
    manifest = args.manifest.resolve(strict=True)
    artifact = args.artifact.resolve(strict=True)
    java_home = args.java_home.resolve(strict=True)
    require(artifact.is_file() and artifact.suffix == ".jar", "Select an actual delivered FE jar")
    release = dict(re.findall(r'^([A-Z_]+)="([^"]*)"$', (java_home / "release").read_text(), re.M))
    validate_release_metadata(release, args.expected_java_runtime_version)
    raw = bounded(manifest)
    require(hashlib.sha256(raw).hexdigest() == args.manifest_sha256, "Supplied public manifest digest differs")
    issuer_digest_before_import = sha(ISSUER)
    issuer = issuer_module()
    require(sha(ISSUER) == issuer_digest_before_import, "Issuer implementation changed during import")
    initial_input_digests = {str(manifest): hashlib.sha256(raw).hexdigest()}
    current = public_model(raw, issuer)
    require({entry["purpose"] for entry in current} == PURPOSES, "Complete review requires both purpose-specific key sets")
    previous_path = args.previous_manifest.resolve(strict=True) if args.previous_manifest else None
    retention_path = args.retention.resolve(strict=True) if args.retention else None
    rotation = {"checked": False, "retention_completeness_verified": False}
    if previous_path:
        previous_raw = bounded(previous_path)
        previous = public_model(previous_raw, issuer)
        retention_raw = bounded(retention_path)
        initial_input_digests.update({str(previous_path): hashlib.sha256(previous_raw).hexdigest(),
                                     str(retention_path): hashlib.sha256(retention_raw).hexdigest()})
        dependencies = retention_model(retention_raw, previous_raw, previous, issuer)
        rotation = {"checked": True, **rotation_model(previous, current, dependencies)}
    jars = {}
    for prefix in ("jackson-core", "jackson-databind", "jackson-annotations"):
        values = sorted(args.fe_lib.resolve(strict=True).glob(prefix + "-*.jar"))
        require(len(values) == 1, "Select unambiguous packaged Jackson dependencies")
        jars[prefix] = values[0].resolve(strict=True)
    inputs = [SOURCE, JAVA, ISSUER, SOURCE.with_name("background_http_fixture.py"),
              SOURCE.with_name("background_http_resources.py"), manifest, artifact, *jars.values(),
              *[java_home / path for path in ("release", "bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so")]]
    if previous_path:
        inputs += [previous_path, retention_path]
    frozen = {str(path): sha(path) for path in inputs}
    require(all(frozen[path] == checksum for path, checksum in initial_input_digests.items())
            and frozen[str(ISSUER)] == issuer_digest_before_import,
            "An input changed between initial parsing and runtime freezing")
    output.mkdir(mode=0o700, parents=True)
    classes = output / "classes"
    classes.mkdir()
    report = {"status": "RUNNING", "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
              "files_sha256": frozen, "keys": current, "rotation": rotation, "commands": [],
              "actual_host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
              "cpu_affinity": [args.cpu], "trust_installed": False, "private_keys_generated": False,
              "signature_ownership_or_authorized_issuer_proven": False, "production_release_qualified": False,
              "full_goal_complete": False}
    cancellation = [False]
    def interrupted(_signal, _frame):
        # Defer cancellation until a safe point, including repeated signals during owned-child cleanup.
        cancellation[0] = True
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        classpath = os.pathsep.join(map(str, [classes, artifact, *jars.values()]))
        bounded_process([java_home / "bin/javac", "-J-Xmx256m", "--release", "8", "-proc:none", "-encoding", "UTF-8",
                         "-cp", classpath, "-d", classes, JAVA], report["commands"], "compile",
                        cancelled=lambda: cancellation[0])
        compiled = {str(path.relative_to(classes)): sha(path) for path in classes.rglob("*.class")}
        require(set(compiled) == {"LicensePublicTrustProbe.class"}, "Unexpected generated class inventory")
        require(all(sha(path) == checksum for path, checksum in frozen.items()), "An input changed during compilation")
        result = json.loads(bounded_process([java_home / "bin/java", "-Xmx256m", "-XX:+UseG1GC", "-cp", classpath,
                            "LicensePublicTrustProbe", manifest, previous_path or "-", retention_path or "-"],
                            report["commands"], "actual_delivered_trust_store", cancelled=lambda: cancellation[0]))
        require(result.get("status") == "PUBLIC_MANIFEST_ACCEPTED"
                and result.get("license_verifier_constructed") is True
                and result.get("repair_verifier_constructed") is True
                and result.get("manifest_sha256") == args.manifest_sha256
                and result.get("java_runtime_version") == args.expected_java_runtime_version
                and result.get("rotation_checked") is bool(previous_path), "Delivered parser/runtime evidence differs")
        require(sorted(result.get("keys", []), key=lambda key: (key["purpose"], key["kid"])) == current,
                "Java/Python public purpose/key fingerprints differ")
        if previous_path:
            require(result.get("previous_manifest_sha256") == initial_input_digests[str(previous_path)]
                    and result.get("retention_sha256") == initial_input_digests[str(retention_path)],
                    "Java and Python reviewed different previous/retention bytes")
        validate_loaded(result, artifact, jars)
        require(all(sha(path) == checksum for path, checksum in frozen.items())
                and compiled == {str(path.relative_to(classes)): sha(path) for path in classes.rglob("*.class")},
                "An input or compiled class changed during review")
        require(not cancellation[0], "Public review was cancelled before completion")
        report.update(status="PUBLIC_TRUST_REVIEW_PASS", java_result=result, compiled_classes_sha256=compiled)
    except BaseException as error:
        report.update(status="FAIL", error_class=type(error).__name__)
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--previous-manifest", type=Path)
    parser.add_argument("--retention", type=Path)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--expected-java-runtime-version", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--fe-lib", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        result = review(args)
        print(json.dumps({"status": result["status"], "production_release_qualified": False, "trust_installed": False}))
        return 0 if result["status"] == "PUBLIC_TRUST_REVIEW_PASS" else 2
    except Exception as error:
        print(json.dumps({"status": "FAIL", "error_class": type(error).__name__, "production_release_qualified": False}))
        return 2


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
