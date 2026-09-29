#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Vendor-side offline Ed25519 license issuer; no production key is bundled."""

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid


MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_EPOCH_SECOND = 253402300799
MAX_SEQUENCE = 9223372036854775807
MAX_NODES = 2147483647
MAX_REPAIR_BYTES = 16 * 1024
REPAIR_TTL_SECONDS = 24 * 60 * 60
SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")
CLAIM_NAMES = {
    "schema_version", "policy_version", "license_id", "issuer", "customer_id",
    "product", "deployment_id", "issued_at", "not_before", "expires_at",
    "sequence", "edition", "features", "limits",
}
CHALLENGE_NAMES = {
    "schema_version", "product", "deployment_id", "nonce", "clock_epoch",
    "repair_authorization_version", "leader_term", "observed_wall_at",
    "observed_high_water_at", "valid_for_seconds",
}
REPAIR_NAMES = {
    "schema_version", "product", "deployment_id", "repair_id", "nonce", "clock_epoch",
    "repair_authorization_version", "leader_term", "issued_at", "not_before", "expires_at",
}
# Protocol v1's fixed scalar table, independent of Python/JDK Unicode database versions.
FORBIDDEN_TEXT_RANGES = (
    (0x0000, 0x001F), (0x007F, 0x009F), (0x00AD, 0x00AD), (0x0600, 0x0605),
    (0x061C, 0x061C), (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891),
    (0x08E2, 0x08E2), (0x180E, 0x180E), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x2064), (0x2066, 0x206F), (0xD800, 0xDFFF), (0xE000, 0xF8FF),
    (0xFDD0, 0xFDEF), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD),
    (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0001, 0xE0001), (0xE0020, 0xE007F),
    (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD),
)
WHITESPACE_RANGES = (
    (0x0009, 0x000D), (0x0020, 0x0020), (0x0085, 0x0085), (0x00A0, 0x00A0),
    (0x1680, 0x1680), (0x2000, 0x200A), (0x2028, 0x2029), (0x202F, 0x202F),
    (0x205F, 0x205F), (0x3000, 0x3000),
)


class IssuerError(Exception):
    """A safe error message which never includes input contents or key material."""


def read_bounded(path, limit):
    try:
        with open(path, "rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        raise IssuerError("Cannot read the supplied input file") from None
    if len(data) > limit:
        raise IssuerError("Input exceeds the permitted size")
    return data


def _integer(text):
    if len(text) > 20:
        raise IssuerError("JSON integer exceeds the lexical size limit")
    return int(text)


def _not_integer(_text):
    raise IssuerError("Floating-point and non-finite JSON numbers are not supported")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IssuerError("Duplicate JSON object key")
        if _utf16_length(key) > 128:
            raise IssuerError("JSON field name exceeds the size limit")
        result[key] = value
    return result


def _utf16_length(value):
    return sum(2 if ord(char) > 0xFFFF else 1 for char in value)


def _check_json_bounds(value, depth=1):
    if depth > 8:
        raise IssuerError("JSON nesting exceeds the depth limit")
    if isinstance(value, dict):
        for item in value.values():
            _check_json_bounds(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_json_bounds(item, depth + 1)
    elif isinstance(value, str):
        if _utf16_length(value) > 4096 or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise IssuerError("JSON string exceeds the limit or contains invalid Unicode")


def parse_json(data):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_int=_integer, parse_float=_not_integer,
                           parse_constant=_not_integer)
        _check_json_bounds(value)
    except (UnicodeError, ValueError, RecursionError):
        raise IssuerError("Invalid UTF-8 JSON input") from None
    if not isinstance(value, dict):
        raise IssuerError("JSON input must be an object")
    return value


def _exact_fields(value, expected):
    if not isinstance(value, dict) or set(value) != expected:
        raise IssuerError("Missing or unsupported JSON fields")


def _text(value, limit, allow_spaces=False):
    if not isinstance(value, str) or not value or _utf16_length(value) > limit:
        raise IssuerError("Invalid license text field")
    for index, char in enumerate(value):
        point = ord(char)
        whitespace = any(start <= point <= end for start, end in WHITESPACE_RANGES)
        if (any(start <= point <= end for start, end in FORBIDDEN_TEXT_RANGES)
                or (point & 0xFFFF) in (0xFFFE, 0xFFFF)
                or (whitespace and (not allow_spaces or index in (0, len(value) - 1)))):
            raise IssuerError("Unsupported whitespace or control character in license text")


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        raise IssuerError("Expected a canonical lowercase UUID") from None


def _bounded_integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise IssuerError("License integer is outside its permitted range")


def validate_claims(claims):
    _exact_fields(claims, CLAIM_NAMES)
    _bounded_integer(claims["schema_version"], 1, 1)
    _bounded_integer(claims["policy_version"], 1, 1)
    if claims["product"] != "MassDB SQL":
        raise IssuerError("License is for an unsupported product")
    _text(claims["license_id"], 256)
    for name in ("issuer", "customer_id", "edition"):
        _text(claims[name], 256, allow_spaces=True)
    _uuid(claims["deployment_id"])
    for name in ("issued_at", "not_before", "expires_at"):
        _bounded_integer(claims[name], 0, MAX_EPOCH_SECOND)
    if claims["issued_at"] > claims["expires_at"] or claims["not_before"] >= claims["expires_at"]:
        raise IssuerError("License timestamps have an invalid ordering")
    _bounded_integer(claims["sequence"], 1, MAX_SEQUENCE)
    features = claims["features"]
    if not isinstance(features, list) or len(features) > 128:
        raise IssuerError("features must be a list of at most 128 unique strings")
    for feature in features:
        _text(feature, 128)
    if len(set(features)) != len(features):
        raise IssuerError("Duplicate feature")
    _exact_fields(claims["limits"], {"max_fe_nodes", "max_be_nodes"})
    for limit in claims["limits"].values():
        _bounded_integer(limit, 1, MAX_NODES)
    return claims


def _encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(text):
    if not text or re.fullmatch(r"[A-Za-z0-9_-]+", text) is None:
        raise IssuerError("Invalid unpadded base64url encoding")
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, binascii.Error):
        raise IssuerError("Invalid base64url encoding") from None
    if _encode(decoded) != text:
        raise IssuerError("Noncanonical base64url encoding")
    return decoded


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _parse_jws(data, expected_kid, expected_type, validator, maximum):
    _text(expected_kid, 128)
    if len(data) > maximum:
        raise IssuerError("Signed document exceeds the permitted size")
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise IssuerError("Compact JWS must be ASCII") from None
    parts = text.split(".")
    if len(parts) != 3:
        raise IssuerError("Certificate must contain exactly three JWS segments")
    header = parse_json(_decode(parts[0]))
    _exact_fields(header, {"alg", "typ", "kid"})
    if header["alg"] != "Ed25519" or header["typ"] != expected_type:
        raise IssuerError("Unsupported JWS algorithm or type")
    _text(header["kid"], 128)
    if header["kid"] != expected_kid:
        raise IssuerError("Certificate kid does not match the pinned key")
    claims = validator(parse_json(_decode(parts[1])))
    signature = _decode(parts[2])
    if len(signature) != 64:
        raise IssuerError("Ed25519 signature must be exactly 64 bytes")
    return claims, (parts[0] + "." + parts[1]).encode("ascii"), signature


def parse_certificate(data, expected_kid):
    return _parse_jws(data, expected_kid, "massdb-license+jws", validate_claims, MAX_CERTIFICATE_BYTES)


def _repair_binding(value):
    _bounded_integer(value["schema_version"], 1, 1)
    if value["product"] != "MassDB SQL":
        raise IssuerError("Repair document is for an unsupported product")
    _uuid(value["deployment_id"])
    _uuid(value["leader_term"])
    nonce = value["nonce"]
    if not isinstance(nonce, str) or len(nonce) != 43 or len(_decode(nonce)) != 32:
        raise IssuerError("Repair nonce must be 32 bytes of canonical base64url")
    _bounded_integer(value["clock_epoch"], 0, MAX_SEQUENCE - 1)
    _bounded_integer(value["repair_authorization_version"], 1, MAX_SEQUENCE - 1)


def validate_challenge(challenge):
    _exact_fields(challenge, CHALLENGE_NAMES)
    _repair_binding(challenge)
    _bounded_integer(challenge["valid_for_seconds"], REPAIR_TTL_SECONDS, REPAIR_TTL_SECONDS)
    for name in ("observed_wall_at", "observed_high_water_at"):
        _bounded_integer(challenge[name], 0, MAX_EPOCH_SECOND)
    return challenge


def validate_repair(claims):
    _exact_fields(claims, REPAIR_NAMES)
    _repair_binding(claims)
    _uuid(claims["repair_id"])
    for name in ("issued_at", "not_before", "expires_at"):
        _bounded_integer(claims[name], 0, MAX_EPOCH_SECOND)
    if (claims["issued_at"] > claims["expires_at"]
            or not 0 < claims["expires_at"] - claims["not_before"] <= REPAIR_TTL_SECONDS):
        raise IssuerError("Repair timestamps must define a positive window of at most 24 hours")
    return claims


def parse_repair(data, expected_kid):
    return _parse_jws(data, expected_kid, "massdb-license-clock-repair+jws", validate_repair,
                      MAX_REPAIR_BYTES)


class OpenSsl:
    def __init__(self, executable):
        self.executable = executable
        version = self.run(["version"])
        if not version.startswith(b"OpenSSL 3."):
            raise IssuerError("OpenSSL 3 is required; select it with --openssl")

    def run(self, args):
        try:
            result = subprocess.run([self.executable, *args], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    check=False, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise IssuerError("OpenSSL could not run; check the executable and runtime") from None
        if result.returncode != 0:
            raise IssuerError("OpenSSL operation failed; check the key format or signature")
        return result.stdout

    def key_material(self, source, directory, private=False):
        material = read_bounded(source, 16384)
        marker = b"PRIVATE KEY" if private else b"PUBLIC KEY"
        if not material.startswith(b"-----BEGIN " + marker + b"-----\n"):
            raise IssuerError("Expected an unencrypted PKCS8 private key or SPKI public key")
        key_path = Path(directory) / ("private.pem" if private else "public.pem")
        key_path.write_bytes(material)
        key_path.chmod(0o600)
        arguments = ["pkey", "-in", str(key_path)]
        if not private:
            arguments.append("-pubin")
        public = self.run([*arguments, "-pubout", "-outform", "DER"])
        if len(public) != 44 or not public.startswith(SPKI_ED25519_PREFIX):
            raise IssuerError("The supplied key is not an Ed25519 key")
        return key_path


def _check_outputs(paths):
    if len({os.path.abspath(path) for path in paths}) != len(paths):
        raise IssuerError("Output paths must be distinct")
    if any(os.path.lexists(path) for path in paths):
        raise IssuerError("An output already exists; no existing file will be overwritten")


def _publish(outputs):
    """Atomically publish each staged file without replacing any existing path."""
    _check_outputs([path for path, _data, _mode in outputs])
    published = []
    try:
        for destination, data, mode in outputs:
            destination = Path(destination)
            staged = None
            try:
                descriptor, staged = tempfile.mkstemp(prefix=".license-", dir=destination.parent)
                with os.fdopen(descriptor, "wb") as stream:
                    os.fchmod(stream.fileno(), mode)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.link(staged, destination)
                published.append((destination, os.stat(staged)))
            finally:
                if staged is not None:
                    os.unlink(staged)
    except OSError:
        for destination, original in reversed(published):
            try:
                current = os.lstat(destination)
                if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
                    os.unlink(destination)
            except OSError:
                pass
        raise IssuerError("Cannot create outputs; paths must be writable and must not already exist") from None


def generate_keys(openssl, private_key, public_key):
    _check_outputs([private_key, public_key])
    with tempfile.TemporaryDirectory(prefix="massdb-license-") as directory:
        private = Path(directory) / "generated-private.pem"
        openssl.run(["genpkey", "-algorithm", "ED25519", "-out", str(private)])
        private.chmod(0o600)
        public = openssl.run(["pkey", "-in", str(private), "-pubout"])
        _publish([(private_key, private.read_bytes(), 0o600), (public_key, public, 0o644)])
    return {"status": "KEY_PAIR_CREATED"}


def _sign_claims(openssl, claims, private_key, kid, output, document_type, maximum):
    _check_outputs([output])
    _text(kid, 128)
    header = {"alg": "Ed25519", "typ": document_type, "kid": kid}
    signing_input = (_encode(_json_bytes(header)) + "." + _encode(_json_bytes(claims))).encode("ascii")
    if len(signing_input) + 87 > maximum:
        raise IssuerError("Resulting signed document would exceed its size limit")
    with tempfile.TemporaryDirectory(prefix="massdb-license-") as directory:
        key = openssl.key_material(private_key, directory, private=True)
        message = Path(directory) / "signing-input"
        message.write_bytes(signing_input)
        signature = openssl.run(["pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message)])
    if len(signature) != 64:
        raise IssuerError("Unexpected Ed25519 signature size")
    certificate = signing_input + b"." + _encode(signature).encode("ascii")
    _publish([(output, certificate, 0o600)])
    return {"status": "SIGNED", "kid": kid, "sha256": hashlib.sha256(certificate).hexdigest()}


def _verify_signature(openssl, data, public_key, kid, parser=parse_certificate):
    claims, signing_input, signature = parser(data, kid)
    with tempfile.TemporaryDirectory(prefix="massdb-license-") as directory:
        key = openssl.key_material(public_key, directory)
        message = Path(directory) / "signing-input"
        signature_file = Path(directory) / "signature"
        message.write_bytes(signing_input)
        signature_file.write_bytes(signature)
        openssl.run(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(key),
                     "-in", str(message), "-sigfile", str(signature_file)])
    return claims


def _now(at):
    now = int(time.time()) if at is None else at
    _bounded_integer(now, 0, MAX_EPOCH_SECOND)
    return now


def check_renewal(candidate, previous, at):
    for name in ("product", "deployment_id", "customer_id"):
        if candidate[name] != previous[name]:
            raise IssuerError("Renewal identity does not match the previous certificate")
    if candidate["sequence"] <= previous["sequence"]:
        raise IssuerError("Renewal sequence must strictly increase")
    if candidate["license_id"] == previous["license_id"]:
        raise IssuerError("Renewal must use a new license_id")
    if previous["expires_at"] > at:
        if (candidate["expires_at"] < previous["expires_at"]
                or (previous["not_before"] > at and candidate["not_before"] > previous["not_before"])
                or not set(previous["features"]).issubset(candidate["features"])
                or any(candidate["limits"][key] < value for key, value in previous["limits"].items())):
            raise IssuerError("Renewal must preserve unexpired coverage, features and node limits")
    return max(0, candidate["not_before"] - previous["expires_at"])


def sign(openssl, claims_path, private_key, kid, output, previous=None,
         previous_public_key=None, previous_kid=None, at=None):
    claims = validate_claims(parse_json(read_bounded(claims_path, MAX_CERTIFICATE_BYTES)))
    gap = None
    if any(item is not None for item in (previous, previous_public_key, previous_kid)):
        if any(item is None for item in (previous, previous_public_key, previous_kid)):
            raise IssuerError("Previous certificate, public key and kid must be provided together")
        old = _verify_signature(openssl, read_bounded(previous, MAX_CERTIFICATE_BYTES),
                                previous_public_key, previous_kid)
        gap = check_renewal(claims, old, _now(at))
    result = _sign_claims(openssl, claims, private_key, kid, output, "massdb-license+jws",
                          MAX_CERTIFICATE_BYTES)
    if gap is not None:
        result["coverage_gap_seconds"] = gap
    return result


def verify(openssl, certificate_path, public_key, kid, at=None, deployment_id=None):
    data = read_bounded(certificate_path, MAX_CERTIFICATE_BYTES)
    claims = _verify_signature(openssl, data, public_key, kid)
    if deployment_id is not None:
        _uuid(deployment_id)
    if deployment_id is not None and claims["deployment_id"] != deployment_id:
        raise IssuerError("Certificate does not match the expected deployment")
    now = _now(at)
    temporal = "VALID"
    if now < claims["not_before"]:
        temporal = "NOT_YET_VALID"
    elif now >= claims["expires_at"]:
        temporal = "EXPIRED"
    return {"status": "VERIFIED", "signature_valid": True, "time_status": temporal,
            "kid": kid, "sha256": hashlib.sha256(data).hexdigest(),
            "data_query_feature": "DATA_QUERY" in claims["features"]}


def repair_sign(openssl, challenge_path, private_key, kid, output, repair_id,
                issued_at, not_before, expires_at):
    challenge = validate_challenge(parse_json(read_bounded(challenge_path, MAX_REPAIR_BYTES)))
    claims = {name: challenge[name] for name in REPAIR_NAMES & CHALLENGE_NAMES}
    claims.update(repair_id=repair_id, issued_at=issued_at, not_before=not_before, expires_at=expires_at)
    validate_repair(claims)
    return _sign_claims(openssl, claims, private_key, kid, output,
                        "massdb-license-clock-repair+jws", MAX_REPAIR_BYTES)


def repair_verify(openssl, certificate_path, public_key, kid, challenge_path, at=None):
    data = read_bounded(certificate_path, MAX_REPAIR_BYTES)
    claims = _verify_signature(openssl, data, public_key, kid, parser=parse_repair)
    challenge = validate_challenge(parse_json(read_bounded(challenge_path, MAX_REPAIR_BYTES)))
    if any(claims[name] != challenge[name] for name in REPAIR_NAMES & CHALLENGE_NAMES):
        raise IssuerError("Repair certificate does not match the supplied challenge")
    now = _now(at)
    temporal = "VALID" if claims["not_before"] <= now < claims["expires_at"] else "OUTSIDE_REPAIR_WINDOW"
    return {"status": "VERIFIED", "signature_valid": True, "time_status": temporal,
            "kid": kid, "sha256": hashlib.sha256(data).hexdigest()}


def validate_trust_manifest(manifest):
    _exact_fields(manifest, {"schema_version", "keys"})
    _bounded_integer(manifest["schema_version"], 1, 1)
    keys = manifest["keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= 32:
        raise IssuerError("Trust manifest must contain between 1 and 32 keys")
    kids = set()
    purposes_by_material = {}
    for entry in keys:
        _exact_fields(entry, {"kid", "purpose", "public_key_spki"})
        _text(entry["kid"], 128)
        if entry["purpose"] not in ("license", "time_repair"):
            raise IssuerError("Unsupported trust key purpose")
        if entry["kid"] in kids:
            raise IssuerError("Trust key identifiers must be globally unique")
        kids.add(entry["kid"])
        encoded = entry["public_key_spki"]
        if not isinstance(encoded, str):
            raise IssuerError("Trust key must use canonical base64url SPKI")
        material = _decode(encoded)
        if len(material) != 44 or not material.startswith(SPKI_ED25519_PREFIX):
            raise IssuerError("Trust manifest contains a non-Ed25519 key")
        previous_purpose = purposes_by_material.get(material)
        if previous_purpose is not None and previous_purpose != entry["purpose"]:
            raise IssuerError("License and repair purposes must use distinct keys")
        purposes_by_material[material] = entry["purpose"]
    return manifest


def export_trust(openssl, public_key, kid, purpose, output, existing=None):
    _check_outputs([output])
    entries = []
    if existing is not None:
        entries = validate_trust_manifest(parse_json(read_bounded(existing, MAX_CERTIFICATE_BYTES)))["keys"]
    with tempfile.TemporaryDirectory(prefix="massdb-license-") as directory:
        key = openssl.key_material(public_key, directory)
        public = openssl.run(["pkey", "-pubin", "-in", str(key), "-pubout", "-outform", "DER"])
    manifest = validate_trust_manifest({"schema_version": 1,
                                       "keys": [*entries, {"kid": kid, "purpose": purpose,
                                                          "public_key_spki": _encode(public)}]})
    data = _json_bytes(manifest)
    if len(data) > MAX_CERTIFICATE_BYTES:
        raise IssuerError("Trust manifest exceeds 64 KiB")
    _publish([(output, data, 0o644)])
    return {"status": "TRUST_EXPORTED", "key_count": len(manifest["keys"]),
            "sha256": hashlib.sha256(data).hexdigest()}


def parse_datetime(value):
    """Accept explicit numeric offsets only; never consult the host time zone."""
    if not isinstance(value, str) or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})", value) is None:
        raise IssuerError("Use YYYY-MM-DDTHH:MM:SSZ or an explicit +/-HH:MM offset")
    if value.endswith("-00:00"):
        raise IssuerError("Unknown local offset -00:00 is not supported; use Z for UTC")
    if not value.endswith("Z"):
        hours, minutes = int(value[-5:-3]), int(value[-2:])
        if hours > 23 or minutes > 59:
            raise IssuerError("Date has an invalid UTC offset")
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        delta = date.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        epoch = delta.days * 86400 + delta.seconds
    except (ValueError, OverflowError):
        raise IssuerError("Invalid or unsupported calendar date") from None
    _bounded_integer(epoch, 0, MAX_EPOCH_SECOND)
    return epoch


def prepare_claims(request_path, output, license_id, issuer, customer_id, edition,
                   sequence, issued_at, not_before, expires_at, features, max_fe_nodes, max_be_nodes):
    request = parse_json(read_bounded(request_path, MAX_CERTIFICATE_BYTES))
    _exact_fields(request, {"schema_version", "product", "deployment_id",
                            "registered_fe_nodes", "registered_be_nodes"})
    _bounded_integer(request["schema_version"], 1, 1)
    if request["product"] != "MassDB SQL":
        raise IssuerError("Deployment request is for an unsupported product")
    _uuid(request["deployment_id"])
    for name in ("registered_fe_nodes", "registered_be_nodes"):
        _bounded_integer(request[name], 0, MAX_NODES)
    claims = validate_claims({
        "schema_version": 1, "policy_version": 1, "license_id": license_id, "issuer": issuer,
        "customer_id": customer_id, "edition": edition, "product": request["product"],
        "deployment_id": request["deployment_id"], "issued_at": parse_datetime(issued_at),
        "not_before": parse_datetime(not_before), "expires_at": parse_datetime(expires_at),
        "sequence": sequence, "features": features,
        "limits": {"max_fe_nodes": max_fe_nodes, "max_be_nodes": max_be_nodes},
    })
    if max_fe_nodes < request["registered_fe_nodes"] or max_be_nodes < request["registered_be_nodes"]:
        raise IssuerError("License limits are below the deployment request's registered node counts")
    _publish([(output, _json_bytes(claims), 0o600)])
    return {"status": "CLAIMS_PREPARED"}


def _epoch_argument(value):
    if re.fullmatch(r"0|[1-9][0-9]{0,11}", value) is None or int(value) > MAX_EPOCH_SECOND:
        raise argparse.ArgumentTypeError("Use UTC integer epoch seconds in the supported range")
    return int(value)


def _positive_argument(value):
    if re.fullmatch(r"[1-9][0-9]{0,18}", value) is None or int(value) > MAX_SEQUENCE:
        raise argparse.ArgumentTypeError("Use a positive integer within the signed 64-bit range")
    return int(value)


def _add_signing_arguments(command):
    command.add_argument("--private-key", required=True)
    command.add_argument("--kid", required=True)
    command.add_argument("--output", required=True)


def _add_verification_arguments(command):
    command.add_argument("--certificate", required=True)
    command.add_argument("--public-key", required=True)
    command.add_argument("--kid", required=True)
    command.add_argument("--at", type=_epoch_argument, help="Verification time as UTC integer epoch seconds")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl", help="OpenSSL 3 executable (prefer an absolute path)")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="Explicitly generate an Ed25519 key pair")
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-key", required=True)
    signing = commands.add_parser("sign", help="Sign validated claims from a UTF-8 JSON file")
    signing.add_argument("--claims", required=True)
    _add_signing_arguments(signing)
    signing.add_argument("--previous", help="Previous certificate for authenticated renewal preflight")
    signing.add_argument("--previous-public-key")
    signing.add_argument("--previous-kid")
    signing.add_argument("--at", type=_epoch_argument, help="Preflight time as UTC integer epoch seconds")
    verification = commands.add_parser("verify", help="Verify using an explicitly pinned public key and kid")
    _add_verification_arguments(verification)
    verification.add_argument("--deployment-id", help="Expected canonical deployment UUID")
    repair_signing = commands.add_parser("repair-sign", help="Sign a dedicated clock repair challenge")
    _add_signing_arguments(repair_signing)
    repair_signing.add_argument("--challenge", required=True)
    repair_signing.add_argument("--repair-id", required=True, help="Unique canonical UUID for this authorization")
    for name in ("issued-at", "not-before", "expires-at"):
        repair_signing.add_argument("--" + name, required=True, help="Date with explicit Z or UTC offset")
    repair_verification = commands.add_parser("repair-verify", help="Verify a repair certificate and challenge binding")
    _add_verification_arguments(repair_verification)
    repair_verification.add_argument("--challenge", required=True)
    trust = commands.add_parser("export-trust", help="Export an Ed25519 public key in the FE trust manifest format")
    trust.add_argument("--public-key", required=True)
    trust.add_argument("--kid", required=True)
    trust.add_argument("--purpose", required=True, choices=("license", "time_repair"))
    trust.add_argument("--existing", help="Existing manifest whose public keys will be retained")
    trust.add_argument("--output", required=True)
    conversion = commands.add_parser("date-to-epoch", help="Convert an explicitly zoned date to UTC integer seconds")
    conversion.add_argument("--date", required=True)
    preparation = commands.add_parser("prepare-claims", help="Prepare license claims from an actual deployment request")
    preparation.add_argument("--request", required=True)
    preparation.add_argument("--output", required=True)
    for name in ("license-id", "issuer", "customer-id", "edition", "issued-at", "not-before", "expires-at"):
        preparation.add_argument("--" + name, required=True)
    for name in ("sequence", "max-fe-nodes", "max-be-nodes"):
        preparation.add_argument("--" + name, required=True, type=_positive_argument)
    preparation.add_argument("--feature", action="append", default=[], help="Repeat for each explicitly granted capability")
    args = parser.parse_args(argv)
    try:
        if args.command == "date-to-epoch":
            result = {"epoch_seconds": parse_datetime(args.date)}
        elif args.command == "prepare-claims":
            result = prepare_claims(args.request, args.output, args.license_id, args.issuer,
                                    args.customer_id, args.edition, args.sequence, args.issued_at,
                                    args.not_before, args.expires_at, args.feature,
                                    args.max_fe_nodes, args.max_be_nodes)
        else:
            openssl = OpenSsl(args.openssl)
        if args.command == "keygen":
            result = generate_keys(openssl, args.private_key, args.public_key)
        elif args.command == "sign":
            result = sign(openssl, args.claims, args.private_key, args.kid, args.output,
                          args.previous, args.previous_public_key, args.previous_kid, args.at)
        elif args.command == "verify":
            result = verify(openssl, args.certificate, args.public_key, args.kid,
                            args.at, args.deployment_id)
        elif args.command == "repair-sign":
            result = repair_sign(openssl, args.challenge, args.private_key, args.kid, args.output,
                                 args.repair_id, parse_datetime(args.issued_at),
                                 parse_datetime(args.not_before), parse_datetime(args.expires_at))
        elif args.command == "repair-verify":
            result = repair_verify(openssl, args.certificate, args.public_key, args.kid, args.challenge, args.at)
        elif args.command == "export-trust":
            result = export_trust(openssl, args.public_key, args.kid, args.purpose, args.output, args.existing)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except IssuerError as error:
        print("License issuer error: " + str(error), file=sys.stderr)
        return 2
    except OSError:
        print("License issuer error: filesystem operation failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
