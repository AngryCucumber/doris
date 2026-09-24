#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Construct exact LP023 payloads and verify them offline with issuer and production P1 bytecode."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ISSUER = ROOT / "tools/license-issuer/license_issuer.py"
SPEC = importlib.util.spec_from_file_location("lp023_issuer", ISSUER)
issuer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(issuer)
SIZES = (512, 4096, 16384)
AT = 1800000000
CLASS_NAMES = ("LicenseVerifier", "LicenseDocument", "LicenseSnapshot", "LicenseQueryStatus",
               "LicenseClock", "LicenseText", "LicenseException", "LicenseErrorCode")


def schema_minimum():
    return {"schema_version": 1, "policy_version": 1, "product": "MassDB SQL",
            "deployment_id": "00000000-0000-0000-0000-000000000000", "license_id": "a",
            "issuer": "a", "customer_id": "a", "edition": "a", "issued_at": 0,
            "not_before": 0, "expires_at": 1, "sequence": 1, "features": [],
            "limits": {"max_fe_nodes": 1, "max_be_nodes": 1}}


def query_minimum():
    claims = schema_minimum()
    claims.update(features=["DATA_QUERY"], expires_at=2000000000)
    return claims


def valid_payload(size):
    if size not in SIZES:
        raise ValueError("Use one of the frozen VALID payload sizes")
    claims = query_minimum()
    if size == 512:
        claims["customer_id"] = "a" * (1 + size - len(issuer._json_bytes(claims)))
    else:
        while len(issuer._json_bytes(claims)) < size:
            remaining = size - len(issuer._json_bytes(claims))
            length = min(128, remaining - 3)  # comma and two quotes for each additional feature
            if length < 4:
                raise ValueError("Cannot fill payload with a unique bounded feature")
            claims["features"].append(("F%03d" % len(claims["features"]) + "a" * 128)[:length])
    issuer.validate_claims(claims)
    payload = issuer._json_bytes(claims)
    if len(payload) != size:
        raise ValueError("Payload size construction failed")
    return payload


def invalid_payload():
    # Exact, canonical, parseable JSON with a single missing mandatory claim. This is
    # intentionally signed by the fixture-only path; the production issuer must refuse it.
    claims = schema_minimum()
    del claims["deployment_id"]
    claims["customer_id"] = "a" * (1 + 256 - len(issuer._json_bytes(claims)))
    payload = issuer._json_bytes(claims)
    if len(payload) != 256:
        raise ValueError("Negative payload size construction failed")
    return payload


def minimum_proof():
    claims = schema_minimum()
    issuer.validate_claims(claims)
    # Each encoded value attains its schema lower bound: one-character text, UUID36,
    # one-digit integers, empty feature array, and both mandatory positive limits.
    # Sum exact encoded key/value lengths and fixed object separators independently.
    terms = {key: len(issuer._json_bytes(key)) + 1 + len(issuer._json_bytes(value))
             for key, value in claims.items()}
    separators = 2 + len(claims) - 1
    payload = issuer._json_bytes(claims)
    if sum(terms.values()) + separators != len(payload) or len(payload) != 295:
        raise ValueError("Schema minimum proof drifted; review the protocol")
    return {"decoded_canonical_json_bytes": len(payload), "field_count": len(claims),
            "encoded_field_terms_bytes": terms, "outer_separator_bytes": separators,
            "schema_valid": True, "valid_query_fixture": False,
            "reason": "Minimum is expired and has no DATA_QUERY; never count it as VALID management work",
            "query_capable_fixture_bytes_at_fixed_epoch": len(issuer._json_bytes(query_minimum())),
            "normal_three_ten_digit_epochs_bytes": len(issuer._json_bytes(dict(
                query_minimum(), issued_at=1700000000, not_before=1700000000)))}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run(command, timeout=60):
    result = subprocess.run([str(part) for part in command], stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("Offline fixture subprocess failed: " + result.stderr.strip())
    return result.stdout


def generate(output, openssl_path, java_home, fe_lib, classes_from):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "RUNNING", "case_id": "LP-023", "performance_pass": False,
              "scope": "Offline fixture correctness only; no cluster, imports, timing or release gate",
              "payload_size_unit": "decoded canonical JSON UTF-8 bytes; compact JWS recorded separately",
              "evaluation_epoch_seconds": AT, "minimum_proof": minimum_proof(), "fixtures": [],
              "source_sha256": {str(path.relative_to(ROOT)): sha256(path.read_bytes()) for path in
                                (Path(__file__), HERE / "LicensePayloadFixtureProbe.java", ISSUER)}}
    try:
        openssl = issuer.OpenSsl(str(openssl_path))
        report["openssl_version"] = openssl.run(["version"]).decode().strip()
        report["java_version"] = run([java_home / "bin/java", "--version"]).strip()
        jars = []
        for name in ("jackson-core", "jackson-databind", "jackson-annotations"):
            matches = list(fe_lib.glob(name + "-*.jar"))
            if len(matches) != 1:
                raise ValueError("Expected exactly one actual FE dependency for " + name)
            jars.append(matches[0])
        report["dependency_sha256"] = {str(path): sha256(path.read_bytes()) for path in jars}
        report["classes_from"] = str(classes_from)
        report["actual_class_sha256"] = {}
        for name in CLASS_NAMES:
            relative = "org/apache/doris/massdb/license/" + name + ".class"
            if classes_from.is_dir():
                data = (classes_from / relative).read_bytes()
            else:
                with zipfile.ZipFile(classes_from) as archive:
                    data = archive.read(relative)
            report["actual_class_sha256"][name] = sha256(data)
        with tempfile.TemporaryDirectory(prefix="massdb-lp023-") as directory:
            temporary = Path(directory)
            private, public = temporary / "private.pem", temporary / "public.pem"
            issuer.generate_keys(openssl, private, public)
            public_der = output / "ephemeral-public.spki.der"
            public_der.write_bytes(openssl.run(["pkey", "-pubin", "-in", str(public), "-outform", "DER"]))
            examples = [("schema-minimum", issuer._json_bytes(schema_minimum()), "EXPIRED"),
                        ("query-minimum", issuer._json_bytes(query_minimum()), "VALID")]
            examples += [("valid-%d" % size, valid_payload(size), "VALID") for size in SIZES]
            examples.append(("invalid-256", invalid_payload(), "INVALID_CLAIMS"))
            for name, payload, expected in examples:
                claims_path, certificate = output / (name + ".json"), output / (name + ".jws")
                claims_path.write_bytes(payload)
                entry = {"name": name, "decoded_payload_bytes": len(payload), "payload_sha256": sha256(payload),
                         "expected": expected, "counts_as_valid_management_work": name.startswith("valid-")}
                if expected != "INVALID_CLAIMS":
                    issuer.sign(openssl, claims_path, private, "a", certificate)
                    entry["issuer_result"] = issuer.verify(openssl, certificate, public, "a", at=AT,
                                                          deployment_id=query_minimum()["deployment_id"])
                    if entry["issuer_result"]["time_status"] != expected:
                        raise ValueError("Issuer positive fixture status mismatch")
                else:
                    try:
                        issuer.sign(openssl, claims_path, private, "a", certificate)
                    except issuer.IssuerError as error:
                        entry["production_issuer_rejection"] = str(error)
                    else:
                        raise ValueError("Production issuer accepted the malformed negative fixture")
                    if certificate.exists():
                        raise ValueError("Production issuer published a rejected certificate")
                    header = issuer._json_bytes({"alg": "Ed25519", "typ": "massdb-license+jws", "kid": "a"})
                    message = (issuer._encode(header) + "." + issuer._encode(payload)).encode("ascii")
                    message_path, signature_path = temporary / "message", temporary / "signature"
                    message_path.write_bytes(message)
                    signature = openssl.run(["pkeyutl", "-sign", "-rawin", "-inkey", str(private),
                                             "-in", str(message_path)])
                    signature_path.write_bytes(signature)
                    openssl.run(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public),
                                 "-in", str(message_path), "-sigfile", str(signature_path)])
                    entry["independent_openssl_signature_valid"] = True
                    certificate.write_bytes(message + b"." + issuer._encode(signature).encode("ascii"))
                    try:
                        issuer.verify(openssl, certificate, public, "a", at=AT)
                    except issuer.IssuerError as error:
                        entry["issuer_verifier_rejection"] = str(error)
                    else:
                        raise ValueError("Issuer verifier accepted the malformed negative fixture")
                compact = certificate.read_bytes()
                if issuer._decode(compact.decode().split(".")[1]) != payload:
                    raise ValueError("Signed payload differs from canonical fixture bytes")
                entry.update(compact_jws_bytes=len(compact), certificate_sha256=sha256(compact))
                report["fixtures"].append(entry)
            classpath = os.pathsep.join(str(path) for path in [temporary, classes_from, *jars])
            run([java_home / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-cp", classpath,
                 "-d", temporary, HERE / "LicensePayloadFixtureProbe.java"])
            result = json.loads(run([java_home / "bin/java", "-cp", classpath, "LicensePayloadFixtureProbe",
                                     public_der, AT, *(output / (entry["name"] + ".jws")
                                                      for entry in report["fixtures"])]))
            for entry in report["fixtures"]:
                actual = result[entry["name"] + ".jws"]
                entry["production_java_result"] = actual
                if entry["expected"] == "INVALID_CLAIMS":
                    if actual != {"verified": False, "error_code": "INVALID_CLAIMS"}:
                        raise ValueError("Production Java rejected for the wrong reason or accepted the negative")
                elif not actual.get("verified") or actual.get("query_status") != entry["expected"]:
                    raise ValueError("Production Java positive fixture status mismatch")
        report["private_key_retained"] = False
        report["status"] = "FIXTURE_PASS"
    except Exception as error:
        report.update(status="FAILED", error=type(error).__name__ + ": " + str(error))
        raise
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--fe-lib", type=Path, required=True)
    parser.add_argument("--classes-from", type=Path, required=True)
    args = parser.parse_args()
    report = generate(args.output, args.openssl.resolve(), args.java_home.resolve(),
                      args.fe_lib.resolve(), args.classes_from.resolve())
    print(json.dumps({"status": report["status"], "performance_pass": False,
                      "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()
