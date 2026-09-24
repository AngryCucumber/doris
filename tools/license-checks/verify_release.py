#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline, explicit-runtime license/repair release probe; temporary test keys are always removed."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ISSUER = ROOT / "tools/license-issuer/license_issuer.py"
SOURCES = ROOT / "fe/fe-core/src/main/java/org/apache/doris/massdb/license"
PROBE = HERE / "LicenseReleaseProbe.java"
COMPILE_NAMES = ("LicenseText", "LicenseDocument", "LicenseErrorCode", "LicenseException", "LicenseVerifier",
                 "LicenseTrustStore", "LicenseRepairException", "LicenseClockRepairVerifier")
DEPLOYMENT = "003aaf16-b828-455a-8ce2-1bd393572102"
AT = 1_900_000_000


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_file(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def python_unicode_digest():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("massdb_release_issuer", ISSUER)
    issuer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(issuer)
    names = ("identifier", "display_bare", "display_wrapped")
    digests = {name: hashlib.sha256() for name in names}
    counts = {name: 0 for name in names}
    for point in range(0x110000):
        text = chr(point)
        for name, value, spaces in ((names[0], text, False), (names[1], text, True),
                                    (names[2], "a" + text + "z", True)):
            try:
                issuer._text(value, 8, allow_spaces=spaces)
                accepted = True
            except issuer.IssuerError:
                accepted = False
            digests[name].update(bytes((int(accepted),)))
            counts[name] += int(accepted)
    result = {name + "_sha256": digest.hexdigest() for name, digest in digests.items()}
    result.update({name + "_accepted": count for name, count in counts.items()})
    result.update(code_points=0x110000, unicode_scalars=0x110000 - 0x800)
    return result


class Run:
    def __init__(self, args, report, temporary):
        self.args = args
        self.report = report
        self.temporary = temporary
        self.java = args.java_home / "bin/java"
        self.javac = (args.compiler_java_home or args.java_home) / "bin/javac"
        self.cp = None

    def command(self, command, expected=0, case=None, timeout=120):
        result = subprocess.run([str(item) for item in command], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, check=False, timeout=timeout)
        sanitize = lambda text: text.replace(str(self.temporary), "<ephemeral-test-dir>")
        entry = {"argv": [sanitize(str(item)) for item in command], "expected_exit": expected,
                 "actual_exit": result.returncode, "stdout": sanitize(result.stdout.strip()),
                 "stderr": sanitize(result.stderr.strip())}
        if case:
            entry["case"] = case
            self.report["tests"].append({"case": case, "passed": result.returncode == expected})
        self.report["commands"].append(entry)
        if result.returncode != expected:
            raise RuntimeError("Unexpected exit for " + (case or "setup command"))
        return entry["stdout"] or entry["stderr"]

    def probe(self, *arguments, expected=0, case=None):
        text = self.command([self.java, "-cp", self.cp, "LicenseReleaseProbe", *arguments], expected, case)
        result = json.loads(text)
        if expected == 2 and (result.get("status") != "REJECTED" or not result.get("error_code")):
            raise RuntimeError("Negative case did not report a verifier rejection")
        return result

    def issuer(self, *arguments, expected=0, case=None):
        return self.command([sys.executable, ISSUER, "--openssl", self.args.openssl, *arguments], expected, case)

    def setup(self):
        dependencies = []
        for artifact in ("jackson-core", "jackson-databind", "jackson-annotations"):
            found = list(self.args.fe_lib.glob(artifact + "-*.jar"))
            if len(found) != 1:
                raise RuntimeError("Expected exactly one packaged " + artifact + " jar")
            dependencies.append(found[0].resolve())
        self.report["packaged_dependencies"] = {str(path): sha(path) for path in dependencies}
        if self.args.package:
            matched = {}
            names = {dependency.name: dependency for dependency in dependencies}
            seen = set()
            with tarfile.open(self.args.package, "r|*") as archive:
                for entry in archive:
                    name = Path(entry.name).name
                    if not entry.isfile() or name not in names or not entry.name.endswith("/fe/lib/" + name):
                        continue
                    if name in seen:
                        raise RuntimeError("Cannot uniquely bind dependency to supplied package archive")
                    seen.add(name)
                    with archive.extractfile(entry) as stream:
                        actual = hashlib.sha256(stream.read()).hexdigest()
                    if actual != sha(names[name]):
                        raise RuntimeError("FE lib differs from supplied package archive")
                    matched[entry.name] = actual
            if seen != set(names):
                raise RuntimeError("Supplied package archive is missing the selected FE dependencies")
            self.report["package"] = {"path": str(self.args.package), "sha256": sha(self.args.package),
                                      "matching_entries": matched}
        classes = self.temporary / "classes"
        classes.mkdir()
        source_paths = [SOURCES / (name + ".java") for name in COMPILE_NAMES]
        self.report["source_sha256"] = {str(path.relative_to(ROOT)): sha(path)
                                        for path in [ISSUER, PROBE, Path(__file__), *source_paths]}
        compilation_sources = [PROBE]
        target = self.args.classes_from
        if target:
            if not target.exists():
                raise RuntimeError("Explicit built classes artifact is missing")
            self.report["mode"] = "built_artifact"
            self.report["built_artifact"] = {"path": str(target),
                                             "sha256": sha(target) if target.is_file() else None}
            self.report["source_provenance"] = "Reference checkout hashes only; target bytecode is measured separately"
        else:
            self.report["mode"] = "source_with_packaged_dependencies"
            self.report["source_provenance"] = "Actual listed verifier sources compiled --release 8 in temporary directory"
            compilation_sources.extend(source_paths)
            target = classes
        self.cp = os.pathsep.join(str(item) for item in [classes, target, *dependencies])
        self.report["java_version_command"] = self.command([self.java, "-version"])
        self.report["javac_version"] = self.command([self.javac, "-version"])
        self.report["openssl"] = self.command([self.args.openssl, "version", "-a"])
        self.command([self.javac, "--release", "8", "-encoding", "UTF-8", "-cp", self.cp,
                      "-d", classes, *compilation_sources], case="compile_probe_and_explicit_target")
        self.report["runtime"] = self.probe("info", case="actual_jca_ed25519_provider_available")
        majors = [item["major"] for item in self.report["runtime"]["loaded_classes"].values()]
        passed = all(major == 52 for major in majors)
        self.report["tests"].append({"case": "all_loaded_license_targets_class_major_52", "passed": passed})
        if not passed:
            raise RuntimeError("License target class file is not Java 8 bytecode")

    def verify(self, purpose, certificate, public, kid, manifest, challenge=None, expected=0, label=""):
        self.probe("verify", purpose, manifest, certificate, expected=expected, case=label + "_java")
        command = ["verify" if purpose == "license" else "repair-verify", "--certificate", certificate,
                   "--public-key", public, "--kid", kid, "--at", str(AT)]
        if challenge:
            command.extend(["--challenge", challenge])
        self.issuer(*command, expected=expected, case=label + "_openssl")

    def run(self):
        self.setup()
        pairs = {}
        manifest = None
        for engine in ("openssl", "java"):
            for purpose in ("license", "time_repair"):
                kid = engine + "-" + purpose
                private, public = self.temporary / (kid + "-private.pem"), self.temporary / (kid + "-public.pem")
                if engine == "openssl":
                    self.issuer("keygen", "--private-key", private, "--public-key", public)
                else:
                    self.probe("keygen", private, public)
                next_manifest = self.temporary / (kid + "-trust.json")
                command = ["export-trust", "--public-key", public, "--kid", kid, "--purpose", purpose,
                           "--output", next_manifest]
                if manifest:
                    command.extend(["--existing", manifest])
                self.issuer(*command, case=kid + "_export_explicit_trust")
                manifest = next_manifest
                pairs[(engine, purpose)] = (private, public, kid)
        trust = json.loads(manifest.read_text(encoding="utf-8"))
        challenge_value = {"schema_version": 1, "product": "MassDB SQL", "deployment_id": DEPLOYMENT,
                           "nonce": encode(os.urandom(32)), "clock_epoch": 4, "repair_authorization_version": 12,
                           "leader_term": "dc8c8126-1d8b-493d-aad8-eb8f1b2026fb", "observed_wall_at": AT,
                           "observed_high_water_at": 4_070_908_800, "valid_for_seconds": 86400}
        challenge = json_file(self.temporary / "challenge.json", challenge_value)
        certificates = {}
        for engine in ("openssl", "java"):
            for purpose in ("license", "time_repair"):
                private, public, kid = pairs[(engine, purpose)]
                if purpose == "license":
                    claims = {"schema_version": 1, "policy_version": 1, "product": "MassDB SQL",
                              "deployment_id": DEPLOYMENT, "license_id": "release-" + engine,
                              "issuer": "Ephemeral Release Test", "customer_id": "互通客户 🫨",
                              "edition": "Enterprise", "issued_at": 1_800_000_000, "not_before": 1_800_000_000,
                              "expires_at": 2_000_000_000, "sequence": 42, "features": ["DATA_QUERY"],
                              "limits": {"max_fe_nodes": 3, "max_be_nodes": 8}}
                    document_type = "massdb-license+jws"
                else:
                    names = ("schema_version", "product", "deployment_id", "nonce", "clock_epoch",
                             "repair_authorization_version", "leader_term")
                    claims = {name: challenge_value[name] for name in names}
                    claims.update(repair_id="ee43d188-73d6-4c6a-b68e-4bf0e648af61", issued_at=AT,
                                  not_before=AT - 60, expires_at=AT + 3600)
                    document_type = "massdb-license-clock-repair+jws"
                claims_path = json_file(self.temporary / (kid + "-claims.json"), claims)
                certificate = self.temporary / (kid + ".jws")
                if engine == "java":
                    self.probe("sign", private, claims_path, document_type, kid, certificate)
                elif purpose == "license":
                    self.issuer("sign", "--claims", claims_path, "--private-key", private,
                                "--kid", kid, "--output", certificate)
                else:
                    self.issuer("repair-sign", "--challenge", challenge, "--private-key", private, "--kid", kid,
                                "--output", certificate, "--repair-id", claims["repair_id"],
                                "--issued-at", iso(AT), "--not-before", iso(AT - 60), "--expires-at", iso(AT + 3600))
                certificates[(engine, purpose)] = certificate
                self.verify(purpose, certificate, public, kid, manifest,
                            challenge if purpose == "time_repair" else None, label=kid + "_signed_valid")
                header, payload, signature = certificate.read_text(encoding="ascii").split(".")
                mutated = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
                mutated["expires_at"] += 100
                tampered = self.temporary / (kid + "-tampered.jws")
                tampered.write_text(header + "." + encode(json.dumps(mutated).encode("utf-8")) + "." + signature)
                self.verify(purpose, tampered, public, kid, manifest,
                            challenge if purpose == "time_repair" else None, expected=2, label=kid + "_tamper_rejected")
                alternate = pairs[("java" if engine == "openssl" else "openssl", purpose)]
                wrong_trust = json.loads(json.dumps(trust))
                source_key = next(entry["public_key_spki"] for entry in trust["keys"] if entry["kid"] == alternate[2])
                next(entry for entry in wrong_trust["keys"] if entry["kid"] == kid)["public_key_spki"] = source_key
                wrong_manifest = json_file(self.temporary / (kid + "-wrong-key.json"), wrong_trust)
                self.verify(purpose, certificate, alternate[1], kid, wrong_manifest,
                            challenge if purpose == "time_repair" else None, expected=2, label=kid + "_wrong_key_rejected")
                opposite = "license" if purpose == "time_repair" else "time_repair"
                self.probe("verify", opposite, manifest, certificate, expected=2, case=kid + "_wrong_type_rejected")
                wrong_purpose = json.loads(json.dumps(trust))
                next(entry for entry in wrong_purpose["keys"] if entry["kid"] == kid)["purpose"] = opposite
                purpose_manifest = json_file(self.temporary / (kid + "-wrong-purpose.json"), wrong_purpose)
                self.probe("verify", purpose, purpose_manifest, certificate, expected=2,
                           case=kid + "_purpose_filtered_key_rejected")
        wrong_challenge = dict(challenge_value, leader_term="00ea65e9-7e4a-4e1d-a1cb-584ec85fd8ec")
        wrong_challenge_path = json_file(self.temporary / "wrong-challenge.json", wrong_challenge)
        self.issuer("repair-verify", "--certificate", certificates[("java", "time_repair")],
                    "--public-key", pairs[("java", "time_repair")][1], "--kid", "java-time_repair",
                    "--challenge", wrong_challenge_path, "--at", str(AT), expected=2,
                    case="signed_repair_wrong_challenge_rejected")
        java_unicode = self.probe("text-digest", case="java_exhaustive_unicode_calculation")
        python_unicode = python_unicode_digest()
        self.report["unicode"] = {"java": java_unicode, "python": python_unicode,
                                  "encoding": "one 0/1 acceptance byte per ascending code point for each rule"}
        matches = all(java_unicode.get(name) == value for name, value in python_unicode.items())
        self.report["tests"].append({"case": "all_unicode_scalars_and_surrogates_match", "passed": matches})
        if not matches:
            raise RuntimeError("Java/Python full Unicode-domain acceptance differs")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-home", type=Path, required=True, help="Explicit JDK with java and javac (release runtime: 17)")
    parser.add_argument("--compiler-java-home", type=Path,
                        help="Optional explicit JDK for compilation; java-home still selects the tested runtime")
    parser.add_argument("--fe-lib", type=Path, required=True, help="Actual unpacked FE distribution lib directory")
    parser.add_argument("--openssl", type=Path, required=True, help="Explicit OpenSSL 3 executable")
    parser.add_argument("--report", type=Path, required=True, help="Output evidence JSON; contains no key material")
    parser.add_argument("--package", type=Path, help="Optional real distribution archive; match the selected jars to it")
    parser.add_argument("--classes-from", type=Path, help="Actual compiled classes directory or FE jar; else compile sources")
    args = parser.parse_args(argv)
    for name in ("java_home", "compiler_java_home", "fe_lib", "openssl", "report", "package", "classes_from"):
        value = getattr(args, name)
        if value is not None:
            setattr(args, name, value.resolve())
    report = {"schema_version": 1, "started_at_utc": datetime.now(timezone.utc).isoformat(), "tests": [], "commands": [],
              "scope": "Offline cryptographic verifier/issuer compatibility only; no FE/BE services or query hooks",
              "platform": {"os": platform.platform(), "machine": platform.machine(), "python": sys.version},
              "required_product_runtime": "JDK 17; other JDK results are compatibility probes only",
              "private_key_policy": "Ephemeral restrictive temporary directory; all test keys removed on exit",
              "unverified_platforms": "No inference about OS/architectures other than the actual recorded runtime"}
    temporary = None
    try:
        with tempfile.TemporaryDirectory(prefix="massdb-license-release-") as directory:
            temporary = Path(directory)
            Run(args, report, temporary).run()
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        report["temporary_directory_removed"] = temporary is not None and not temporary.exists()
        if not report["temporary_directory_removed"]:
            report["status"] = "FAIL"
        report["passed"] = sum(item["passed"] for item in report["tests"])
        report["failed"] = sum(not item["passed"] for item in report["tests"])
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        json_file(args.report, report)
    print(json.dumps({key: report[key] for key in ("status", "passed", "failed", "temporary_directory_removed")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
