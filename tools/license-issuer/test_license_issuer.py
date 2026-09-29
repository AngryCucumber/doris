#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Protocol tests using temporary random keys and public RFC test keys, never production keys."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("license_issuer", Path(__file__).with_name("license_issuer.py"))
issuer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(issuer)
OPENSSL = os.environ.get("MASSDB_TEST_OPENSSL", "/usr/bin/openssl")


def claims():
    return {
        "schema_version": 1,
        "policy_version": 1,
        "license_id": "test-license",
        "issuer": "Test Issuer",
        "customer_id": "Test Customer",
        "edition": "Enterprise Test",
        "product": "MassDB SQL",
        "deployment_id": "c9b82051-a34e-455b-bff3-2f09306c6aa8",
        "issued_at": 1700000000,
        "not_before": 1700000010,
        "expires_at": 1800000000,
        "sequence": 1,
        "features": ["DATA_QUERY"],
        "limits": {"max_fe_nodes": 3, "max_be_nodes": 10},
    }


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def challenge():
    return {
        "schema_version": 1, "product": "MassDB SQL", "deployment_id": claims()["deployment_id"],
        "nonce": b64(bytes(range(32))), "clock_epoch": 0, "repair_authorization_version": 1,
        "leader_term": "26ecdeab-acf9-4f5a-a27e-2b25eb53701f", "observed_wall_at": 1700000000,
        "observed_high_water_at": 4070908800, "valid_for_seconds": 86400,
    }


class LicenseIssuerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = issuer.OpenSsl(OPENSSL)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="massdb-license-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = self.root / "private.pem"
        self.public = self.root / "public.pem"
        issuer.generate_keys(self.openssl, self.private, self.public)
        self.claims_file = self.root / "claims.json"
        self.claims_file.write_text(json.dumps(claims()), encoding="utf-8")
        self.certificate = self.root / "test.massdb-license"

    def sign(self):
        return issuer.sign(self.openssl, self.claims_file, self.private, "test-key", self.certificate)

    def verify(self, **kwargs):
        return issuer.verify(self.openssl, self.certificate, self.public, "test-key", **kwargs)

    def raw_sign(self, payload, header=None):
        header = header or b'{"alg":"Ed25519","typ":"massdb-license+jws","kid":"test-key"}'
        message = (b64(header) + "." + b64(payload)).encode("ascii")
        message_path = self.root / "raw-message"
        message_path.write_bytes(message)
        signature = self.openssl.run(["pkeyutl", "-sign", "-rawin", "-inkey", str(self.private),
                                     "-in", str(message_path)])
        self.certificate.write_bytes(message + b"." + b64(signature).encode("ascii"))

    def test_sign_verify_time_boundaries_and_private_permissions(self):
        result = self.sign()
        self.assertEqual("SIGNED", result["status"])
        self.assertNotIn("certificate", result)
        self.assertEqual(0o600, stat.S_IMODE(self.private.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.certificate.stat().st_mode))
        self.assertTrue(self.private.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(self.public.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----"))
        for at, expected in [(1700000009, "NOT_YET_VALID"), (1700000010, "VALID"),
                             (1799999999, "VALID"), (1800000000, "EXPIRED")]:
            with self.subTest(at=at):
                verified = self.verify(at=at, deployment_id=claims()["deployment_id"])
                self.assertEqual(expected, verified["time_status"])
                self.assertTrue(verified["signature_valid"])

    def test_verification_uses_original_json_bytes(self):
        # Spaces and source key order are deliberately different from issuer serialization.
        self.raw_sign(json.dumps(claims(), indent=2).encode("utf-8"))
        self.assertTrue(self.verify(at=1700000100)["signature_valid"])

    def test_tampered_limit_expiry_signature_wrong_key_and_kid(self):
        self.sign()
        original = self.certificate.read_text()
        header, payload, signature = original.split(".")
        for name in ("limits", "expires_at"):
            changed = claims()
            if name == "limits":
                changed["limits"]["max_be_nodes"] = 999
            else:
                changed["expires_at"] += 100000000
            self.certificate.write_text(header + "." + b64(json.dumps(changed).encode()) + "." + signature)
            with self.subTest(name=name), self.assertRaises(issuer.IssuerError):
                self.verify()
        raw_signature = bytearray(base64.urlsafe_b64decode(signature + "=="))
        raw_signature[0] ^= 1
        self.certificate.write_text(header + "." + payload + "." + b64(raw_signature))
        with self.assertRaises(issuer.IssuerError):
            self.verify()
        self.certificate.write_text(original)
        other_private, other_public = self.root / "other-private", self.root / "other-public"
        issuer.generate_keys(self.openssl, other_private, other_public)
        with self.assertRaises(issuer.IssuerError):
            issuer.verify(self.openssl, self.certificate, other_public, "test-key")
        with self.assertRaises(issuer.IssuerError):
            issuer.verify(self.openssl, self.certificate, self.public, "wrong-key")
        with self.assertRaises(issuer.IssuerError):
            self.verify(deployment_id="00000000-0000-0000-0000-000000000000")

    def test_claim_bounds_and_type_confusion(self):
        invalid = [
            ("schema_version", 2), ("policy_version", True), ("product", "other"),
            ("sequence", 0), ("sequence", 9223372036854775808), ("sequence", "1"),
            ("sequence", 1.0), ("issued_at", -1), ("issued_at", 1800000001),
            ("not_before", 1800000000), ("expires_at", 253402300800),
            ("deployment_id", claims()["deployment_id"].upper()), ("license_id", ""),
            ("license_id", "has space"), ("license_id", "x" * 257),
            ("issuer", " leading"), ("customer_id", "trailing "), ("edition", "a\nb"),
            ("features", ["DATA_QUERY", "DATA_QUERY"]), ("features", ["bad feature"]),
            ("features", ["x" * 129]), ("features", ["X" + str(n) for n in range(129)]),
            ("features", [1]), ("features", None),
            ("limits", {"max_fe_nodes": 0, "max_be_nodes": 1}),
            ("limits", {"max_fe_nodes": 1, "max_be_nodes": 2147483648}),
            ("limits", {"max_fe_nodes": 1, "max_be_nodes": True}),
            ("limits", {"max_fe_nodes": 1}),
        ]
        for field, value in invalid:
            candidate = claims()
            candidate[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(issuer.IssuerError):
                issuer.validate_claims(candidate)
        maximum = claims()
        maximum.update(sequence=9223372036854775807, issued_at=253402300799,
                       not_before=253402300798, expires_at=253402300799)
        maximum["limits"] = {"max_fe_nodes": 2147483647, "max_be_nodes": 2147483647}
        maximum["features"] = []
        issuer.validate_claims(maximum)
        for category_character in ("\u200b", "\ud800", "\U000e0001", "\u0085"):
            candidate = claims()
            candidate["license_id"] += category_character
            with self.subTest(character=repr(category_character)), self.assertRaises(issuer.IssuerError):
                issuer.validate_claims(candidate)
        candidate = claims()
        candidate["license_id"] = "\U0001f600" * 129
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_claims(candidate)

    def test_signed_duplicate_json_unknown_fields_and_headers_are_rejected(self):
        valid = json.dumps(claims()).encode()
        variants = [valid.replace(b'"sequence": 1', b'"sequence": 1, "sequence": 2'),
                    valid.replace(b'"max_be_nodes": 10', b'"max_be_nodes": 10, "max_be_nodes": 11'),
                    valid.replace(b'"sequence": 1', b'"sequence": 1.0'),
                    valid.replace(b'"sequence": 1', b'"sequence": NaN'),
                    valid[:-1] + b', "unknown": 1}', valid.decode().encode("utf-16")]
        for payload in variants:
            self.raw_sign(payload)
            with self.subTest(payload_length=len(payload)), self.assertRaises(issuer.IssuerError):
                self.verify()
        header = {"alg": "Ed25519", "typ": "massdb-license+jws", "kid": "test-key"}
        bad_headers = []
        for name, value in [("crit", []), ("jwk", {}), ("jku", "https://example.invalid/key"),
                            ("b64", False), ("zip", "DEF"), ("alg", "none"), ("alg", "EdDSA"),
                            ("typ", "other"), ("kid", "test-key ")]:
            bad = dict(header)
            bad[name] = value
            bad_headers.append(json.dumps(bad).encode())
        bad_headers.append(json.dumps(header).encode()[:-1] + b', "kid": "test-key"}')
        for bad in bad_headers:
            self.raw_sign(valid, bad)
            with self.subTest(header=bad), self.assertRaises(issuer.IssuerError):
                self.verify()

    def test_compact_jws_size_encoding_and_signature_length(self):
        self.sign()
        original = self.certificate.read_text()
        parts = original.split(".")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        # A 64-byte signature has four unused bits in its final base64url character.
        alternate = parts[2][:-1] + alphabet[alphabet.index(parts[2][-1]) + 1]
        variants = [original + "\n", original + ".extra", parts[0] + "=." + parts[1] + "." + parts[2],
                    parts[0] + ".." + parts[2], ".".join(parts[:2] + [alternate]),
                    ".".join(parts[:2] + [b64(b"x" * 63)]), "x" * 65537]
        for variant in variants:
            self.certificate.write_text(variant)
            with self.subTest(length=len(variant)), self.assertRaises(issuer.IssuerError):
                self.verify()

    def test_does_not_overwrite_and_rolls_back_partial_output(self):
        original = self.private.read_bytes()
        with self.assertRaises(issuer.IssuerError):
            issuer.generate_keys(self.openssl, self.private, self.root / "new-public")
        self.assertEqual(original, self.private.read_bytes())
        self.assertFalse((self.root / "new-public").exists())
        self.sign()
        certificate = self.certificate.read_bytes()
        with self.assertRaises(issuer.IssuerError):
            self.sign()
        self.assertEqual(certificate, self.certificate.read_bytes())
        target = self.root / "existing-target"
        target.write_bytes(b"keep")
        symlink = self.root / "symlink"
        symlink.symlink_to(target)
        with self.assertRaises(issuer.IssuerError):
            issuer.sign(self.openssl, self.claims_file, self.private, "test-key", symlink)
        self.assertEqual(b"keep", target.read_bytes())
        first_output = self.root / "rollback-private"
        with self.assertRaises(issuer.IssuerError):
            issuer.generate_keys(self.openssl, first_output, self.root / "missing-parent" / "pub")
        self.assertFalse(first_output.exists())
        self.assertEqual([], list(self.root.glob(".license-*")))

    def test_wrong_algorithm_and_failed_openssl_are_sanitized(self):
        rsa_key = self.root / "rsa.pem"
        self.openssl.run(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024", "-out", str(rsa_key)])
        with self.assertRaises(issuer.IssuerError):
            issuer.sign(self.openssl, self.claims_file, rsa_key, "test-key", self.certificate)
        self.assertFalse(self.certificate.exists())
        result = subprocess.run([sys.executable, str(Path(issuer.__file__)), "--openssl", OPENSSL,
                                 "sign", "--claims", str(self.claims_file), "--private-key", str(rsa_key),
                                 "--kid", "test-key", "--output", str(self.certificate)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(2, result.returncode)
        self.assertNotIn("BEGIN", result.stdout + result.stderr)
        self.assertNotIn("Test Customer", result.stdout + result.stderr)
        self.assertNotIn(str(self.root), result.stderr)
        with self.assertRaises(issuer.IssuerError):
            issuer.OpenSsl(str(self.root / "no-openssl"))

    def test_json_resource_limits(self):
        for text in ('{"v":' + "[" * 10 + "0" + "]" * 10 + "}",
                     '{"v":123456789012345678901}', '{"' + "x" * 129 + '":0}',
                     '{"v":"' + "x" * 4097 + '"}', '{"v":"\\ud800"}'):
            with self.subTest(length=len(text)), self.assertRaises(issuer.IssuerError):
                issuer.parse_json(text.encode())

    def test_fixed_unicode_table_is_independent_of_unicode_database(self):
        for accepted in ("客户 中文", "公司😀", "客户🫠", "公司\u0378", "客户\u00a0名称"):
            candidate = claims()
            candidate["customer_id"] = accepted
            issuer.validate_claims(candidate)
        for ranges in (issuer.FORBIDDEN_TEXT_RANGES,):
            for start, end in ranges:
                for point in (start, end):
                    candidate = claims()
                    candidate["customer_id"] = "A" + chr(point) + "B"
                    with self.subTest(point=hex(point)), self.assertRaises(issuer.IssuerError):
                        issuer.validate_claims(candidate)
        for point in (0xFFFE, 0xFFFF, 0x1FFFE, 0x10FFFF):
            with self.subTest(point=hex(point)), self.assertRaises(issuer.IssuerError):
                issuer._text("A" + chr(point), 256, allow_spaces=True)
        for start, end in issuer.WHITESPACE_RANGES:
            for point in (start, end):
                for value, spaces in [("a" + chr(point) + "b", False),
                                      (chr(point) + "b", True), ("a" + chr(point), True)]:
                    with self.subTest(point=hex(point), spaces=spaces), self.assertRaises(issuer.IssuerError):
                        issuer._text(value, 256, allow_spaces=spaces)
        candidate = claims()
        candidate["customer_id"] = "客户🫠"
        self.claims_file.write_text(json.dumps(candidate), encoding="utf-8")
        self.sign()
        self.assertTrue(self.verify(at=1700000100)["signature_valid"])

    def test_date_conversion_offsets_boundaries_and_invalid_forms(self):
        for value in ("2026-01-01T00:00:00Z", "2026-01-01T08:00:00+08:00",
                      "2025-12-31T19:00:00-05:00"):
            self.assertEqual(1767225600, issuer.parse_datetime(value))
        self.assertEqual(0, issuer.parse_datetime("1970-01-01T00:00:00Z"))
        self.assertEqual(253402300799, issuer.parse_datetime("9999-12-31T23:59:59Z"))
        for invalid in ("2026-01-01", "2026-01-01T00:00:00", "2026-01-01 00:00:00Z",
                        "2026-01-01T00:00:00z", "2026-01-01T00:00:00+0800",
                        "2026-01-01T00:00:00.1Z", "2026-01-01T00:00:00-00:00",
                        "2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00+08:60",
                        "2026-02-29T00:00:00Z", "2024-12-31T23:59:60Z",
                        "1969-12-31T23:59:59Z", "9999-12-31T23:59:59-01:00", 1):
            with self.subTest(value=invalid), self.assertRaises(issuer.IssuerError):
                issuer.parse_datetime(invalid)

    def test_prepare_claims_uses_request_identity_and_explicit_zone(self):
        request = {"schema_version": 1, "product": "MassDB SQL", "deployment_id": claims()["deployment_id"],
                   "registered_fe_nodes": 3, "registered_be_nodes": 7}
        request_file = self.root / "request.json"
        request_file.write_text(json.dumps(request), encoding="utf-8")
        output = self.root / "prepared.json"
        args = [request_file, output, "new-license", "Issuer", "客户😀", "Enterprise", 2,
                "2026-01-01T08:00:00+08:00", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z",
                ["DATA_QUERY"], 3, 10]
        self.assertEqual("CLAIMS_PREPARED", issuer.prepare_claims(*args)["status"])
        prepared = issuer.parse_json(output.read_bytes())
        self.assertEqual(request["deployment_id"], prepared["deployment_id"])
        self.assertEqual(1767225600, prepared["issued_at"])
        self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
        with self.assertRaises(issuer.IssuerError):
            issuer.prepare_claims(*args)
        output.unlink()
        for field, value in [("registered_fe_nodes", 4), ("registered_be_nodes", 11),
                             ("registered_be_nodes", True),
                             ("deployment_id", None), ("schema_version", 2), ("secret", "bad")]:
            invalid = dict(request)
            invalid[field] = value
            request_file.write_text(json.dumps(invalid), encoding="utf-8")
            with self.subTest(field=field), self.assertRaises(issuer.IssuerError):
                issuer.prepare_claims(*args)
            self.assertFalse(output.exists())

    def test_trust_export_rotation_purposes_and_no_private_material(self):
        manifest_file = self.root / "trust.json"
        issuer.export_trust(self.openssl, self.public, "test-key", "license", manifest_file)
        first = issuer.parse_json(manifest_file.read_bytes())
        issuer.validate_trust_manifest(first)
        self.assertEqual(1, len(first["keys"]))
        self.assertNotIn(b"PRIVATE", manifest_file.read_bytes())
        self.assertEqual(0o644, stat.S_IMODE(manifest_file.stat().st_mode))
        repair_private, repair_public = self.root / "repair-private", self.root / "repair-public"
        issuer.generate_keys(self.openssl, repair_private, repair_public)
        rotated = self.root / "rotated.json"
        issuer.export_trust(self.openssl, repair_public, "repair-key", "time_repair", rotated, manifest_file)
        complete = issuer.parse_json(rotated.read_bytes())
        self.assertEqual(first["keys"][0], complete["keys"][0])
        self.assertEqual("time_repair", complete["keys"][1]["purpose"])
        for key, kid, purpose in [(self.public, "test-key", "license"),
                                  (self.public, "shared-key", "time_repair"),
                                  (self.private, "private-key", "license")]:
            with self.subTest(purpose=purpose, kid=kid), self.assertRaises(issuer.IssuerError):
                issuer.export_trust(self.openssl, key, kid, purpose, self.root / "rejected.json", manifest_file)
        self.assertFalse((self.root / "rejected.json").exists())

    def test_trust_manifest_strict_shapes_and_bounds(self):
        output = self.root / "trust.json"
        issuer.export_trust(self.openssl, self.public, "key", "license", output)
        good = issuer.parse_json(output.read_bytes())
        invalid = [{"schema_version": True, "keys": good["keys"]},
                   {"schema_version": 1, "keys": []}, {"schema_version": 1, "keys": good["keys"] * 33},
                   {"schema_version": 1, "keys": good["keys"], "extra": 1}]
        for field, value in [("purpose", "admin"), ("public_key_spki", "x"),
                             ("public_key_spki", 1), ("kid", "\u00a0key"), ("private_key", "secret")]:
            entry = dict(good["keys"][0])
            entry[field] = value
            invalid.append({"schema_version": 1, "keys": [entry]})
        for candidate in invalid:
            with self.subTest(candidate_fields=list(candidate)), self.assertRaises(issuer.IssuerError):
                issuer.validate_trust_manifest(candidate)

    def test_authenticated_renewal_and_rotation(self):
        self.sign()
        renewed = claims()
        renewed.update(sequence=2, license_id="renewed-license", not_before=1750000000, expires_at=1900000000)
        self.claims_file.write_text(json.dumps(renewed), encoding="utf-8")
        new_private, new_public = self.root / "new-private", self.root / "new-public"
        issuer.generate_keys(self.openssl, new_private, new_public)
        output = self.root / "renewed.license"
        issuer.sign(self.openssl, self.claims_file, new_private, "rotated-key", output,
                    self.certificate, self.public, "test-key", 1700000100)
        self.assertTrue(issuer.verify(self.openssl, output, new_public, "rotated-key", 1800000000)["signature_valid"])
        for field, value in [("sequence", 1), ("license_id", "test-license"),
                             ("customer_id", "Other"), ("expires_at", 1799999999),
                             ("features", []),
                             ("limits", {"max_fe_nodes": 2, "max_be_nodes": 10})]:
            candidate = dict(renewed)
            candidate[field] = value
            self.claims_file.write_text(json.dumps(candidate), encoding="utf-8")
            with self.subTest(field=field), self.assertRaises(issuer.IssuerError):
                issuer.sign(self.openssl, self.claims_file, new_private, "rotated-key", self.root / "bad-renewal",
                            self.certificate, self.public, "test-key", 1700000100)
        self.assertFalse((self.root / "bad-renewal").exists())
        renewed["not_before"] = 1800000010
        self.claims_file.write_text(json.dumps(renewed), encoding="utf-8")
        with_gap = issuer.sign(self.openssl, self.claims_file, new_private, "rotated-key", self.root / "gap.license",
                               self.certificate, self.public, "test-key", 1700000100)
        self.assertEqual(10, with_gap["coverage_gap_seconds"])

    def test_renewal_pending_coverage_and_expired_features(self):
        old = claims()
        old["not_before"] = 1750000000
        candidate = claims()
        candidate.update(sequence=2, license_id="renewed-license", not_before=1750000001, expires_at=1900000000)
        with self.assertRaises(issuer.IssuerError):
            issuer.check_renewal(candidate, old, 1700000100)
        candidate["not_before"] = 1750000000
        issuer.check_renewal(candidate, old, 1700000100)
        candidate.update(features=[], not_before=1800000001)
        issuer.check_renewal(candidate, old, 1800000000)

    def test_renewal_node_reduction_requires_previous_expiry(self):
        old = claims()
        for limits in ({"max_fe_nodes": 2, "max_be_nodes": 10},
                       {"max_fe_nodes": 3, "max_be_nodes": 5},
                       {"max_fe_nodes": 2, "max_be_nodes": 5}):
            candidate = claims()
            candidate.update(sequence=2, license_id="smaller-renewal", expires_at=1900000000,
                             limits=limits)
            for at in (old["not_before"] - 1, old["expires_at"] - 1):
                with self.subTest(limits=limits, at=at), self.assertRaises(issuer.IssuerError):
                    issuer.check_renewal(candidate, old, at)
            for at in (old["expires_at"], old["expires_at"] + 1):
                with self.subTest(limits=limits, at=at):
                    self.assertEqual(0, issuer.check_renewal(candidate, old, at))

    def test_expired_renewal_keeps_identity_and_sequence_checks(self):
        old = claims()
        for field, value in [("product", "other"), ("deployment_id", "00000000-0000-0000-0000-000000000000"),
                             ("customer_id", "Other"), ("sequence", 1), ("license_id", old["license_id"])]:
            candidate = claims()
            candidate.update(sequence=2, license_id="smaller-renewal", expires_at=1900000000,
                             limits={"max_fe_nodes": 2, "max_be_nodes": 5})
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(issuer.IssuerError):
                issuer.check_renewal(candidate, old, old["expires_at"])

    def test_authenticated_reduced_renewal_and_following_renewal(self):
        self.sign()
        smaller = claims()
        smaller.update(sequence=2, license_id="smaller-renewal", not_before=1800000000,
                       expires_at=1900000000, limits={"max_fe_nodes": 2, "max_be_nodes": 5})
        self.claims_file.write_text(json.dumps(smaller), encoding="utf-8")
        output = self.root / "smaller.license"
        with self.assertRaises(issuer.IssuerError):
            issuer.sign(self.openssl, self.claims_file, self.private, "test-key", output,
                        self.certificate, self.public, "test-key", 1799999999)
        self.assertFalse(output.exists())
        result = issuer.sign(self.openssl, self.claims_file, self.private, "test-key", output,
                             self.certificate, self.public, "test-key", 1800000000)
        self.assertEqual("SIGNED", result["status"])
        self.assertEqual(0, result["coverage_gap_seconds"])
        verified = issuer.verify(self.openssl, output, self.public, "test-key", 1800000000,
                                 smaller["deployment_id"])
        self.assertTrue(verified["signature_valid"])
        self.assertEqual("VALID", verified["time_status"])
        self.assertEqual(smaller, issuer.parse_certificate(output.read_bytes(), "test-key")[0])
        following = dict(smaller)
        following.update(sequence=3, license_id="following-renewal", expires_at=2000000000)
        self.claims_file.write_text(json.dumps(following), encoding="utf-8")
        following_output = self.root / "following.license"
        issuer.sign(self.openssl, self.claims_file, self.private, "test-key", following_output,
                    output, self.public, "test-key", 1850000000)
        self.assertEqual("VALID", issuer.verify(self.openssl, following_output, self.public,
                                               "test-key", 1950000000)["time_status"])

    def test_renewal_rejects_unverified_previous_and_partial_arguments(self):
        self.sign()
        old = self.certificate.read_bytes()
        parts = old.split(b".")
        bad_signature = bytearray(base64.urlsafe_b64decode(parts[2] + b"=="))
        bad_signature[0] ^= 1
        self.certificate.write_bytes(b".".join(parts[:2]) + b"." + b64(bad_signature).encode())
        candidate = claims()
        candidate["sequence"] = 2
        self.claims_file.write_text(json.dumps(candidate), encoding="utf-8")
        for previous_args in [(self.certificate, self.public, "test-key"),
                              (self.certificate, None, None), (None, self.public, "test-key")]:
            with self.subTest(arguments=len(previous_args)), self.assertRaises(issuer.IssuerError):
                issuer.sign(self.openssl, self.claims_file, self.private, "test-key", self.root / "renewal",
                            *previous_args, at=1700000100)

    def test_repair_sign_verify_binding_and_poisoned_high_water_independence(self):
        challenge_file = self.root / "challenge.json"
        original = challenge()
        challenge_file.write_text(json.dumps(original), encoding="utf-8")
        issuer.repair_sign(self.openssl, challenge_file, self.private, "repair-key", self.certificate,
                           "7c2aa6bc-078f-499e-bd31-b5874fcc5b05", 1700000000, 1700000000, 1700086400)
        for at, expected in [(1699999999, "OUTSIDE_REPAIR_WINDOW"), (1700000000, "VALID"),
                             (1700086399, "VALID"), (1700086400, "OUTSIDE_REPAIR_WINDOW")]:
            result = issuer.repair_verify(self.openssl, self.certificate, self.public,
                                          "repair-key", challenge_file, at)
            self.assertEqual(expected, result["time_status"])
        with self.assertRaises(issuer.IssuerError):
            issuer.verify(self.openssl, self.certificate, self.public, "repair-key", 1700000000)
        for field, value in [("deployment_id", "00000000-0000-0000-0000-000000000000"),
                             ("nonce", b64(b"n" * 32)), ("clock_epoch", 1),
                             ("repair_authorization_version", 2),
                             ("leader_term", "00000000-0000-0000-0000-000000000000")]:
            changed = dict(original)
            changed[field] = value
            challenge_file.write_text(json.dumps(changed), encoding="utf-8")
            with self.subTest(field=field), self.assertRaises(issuer.IssuerError):
                issuer.repair_verify(self.openssl, self.certificate, self.public, "repair-key", challenge_file,
                                     1700000000)

    def test_repair_challenge_and_authorization_strict_validation(self):
        for field, value in [("schema_version", True), ("nonce", b64(b"n" * 31)),
                             ("nonce", b64(b"n" * 32) + "="), ("clock_epoch", -1),
                             ("clock_epoch", issuer.MAX_SEQUENCE), ("repair_authorization_version", 0),
                             ("repair_authorization_version", issuer.MAX_SEQUENCE),
                             ("observed_wall_at", -1), ("observed_high_water_at", issuer.MAX_EPOCH_SECOND + 1),
                             ("valid_for_seconds", 86401), ("license", {}), ("product", "Other")]:
            changed = challenge()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(issuer.IssuerError):
                issuer.validate_challenge(changed)
        payload = {name: value for name, value in challenge().items() if name in issuer.REPAIR_NAMES}
        payload.update(repair_id="7c2aa6bc-078f-499e-bd31-b5874fcc5b05", issued_at=1700000000,
                       not_before=1700000000, expires_at=1700086400)
        issuer.validate_repair(payload)
        for field, value in [("expires_at", 1700086401), ("expires_at", 1700000000),
                             ("issued_at", 1700086401), ("repair_id", "not-uuid"), ("limits", {})]:
            changed = dict(payload)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(issuer.IssuerError):
                issuer.validate_repair(changed)

    def test_repair_wrong_type_signature_and_duplicate_challenge_rejected(self):
        challenge_file = self.root / "challenge.json"
        challenge_file.write_text(json.dumps(challenge()), encoding="utf-8")
        self.sign()
        with self.assertRaises(issuer.IssuerError):
            issuer.repair_verify(self.openssl, self.certificate, self.public, "test-key", challenge_file)
        self.certificate.unlink()
        issuer.repair_sign(self.openssl, challenge_file, self.private, "repair-key", self.certificate,
                           "7c2aa6bc-078f-499e-bd31-b5874fcc5b05", 1700000000, 1700000000, 1700000100)
        data = self.certificate.read_bytes().split(b".")
        signature = bytearray(base64.urlsafe_b64decode(data[2] + b"=="))
        signature[1] ^= 1
        self.certificate.write_bytes(b".".join(data[:2]) + b"." + b64(signature).encode())
        with self.assertRaises(issuer.IssuerError):
            issuer.repair_verify(self.openssl, self.certificate, self.public, "repair-key", challenge_file)
        challenge_file.write_text(json.dumps(challenge())[:-1] + ', "clock_epoch": 2}', encoding="utf-8")
        with self.assertRaises(issuer.IssuerError):
            issuer.repair_sign(self.openssl, challenge_file, self.private, "repair-key", self.root / "rejected",
                               "7c2aa6bc-078f-499e-bd31-b5874fcc5b05", 1700000000, 1700000000, 1700000100)

    def test_cli_date_conversion_needs_no_openssl_and_errors_are_sanitized(self):
        command = [sys.executable, str(Path(issuer.__file__)), "--openssl", "/nonexistent/openssl"]
        success = subprocess.run([*command, "date-to-epoch", "--date", "2026-01-01T08:00:00+08:00"],
                                 capture_output=True, text=True, check=False)
        self.assertEqual(0, success.returncode, success.stderr)
        self.assertEqual({"epoch_seconds": 1767225600}, json.loads(success.stdout))
        rejected = subprocess.run([*command, "date-to-epoch", "--date", "customer-secret"],
                                  capture_output=True, text=True, check=False)
        self.assertEqual(2, rejected.returncode)
        self.assertNotIn("customer-secret", rejected.stderr + rejected.stdout)

    def test_cli_prepare_sign_renew_trust_and_repair_commands(self):
        command = [sys.executable, str(Path(issuer.__file__)), "--openssl", OPENSSL]

        def run(*args):
            result = subprocess.run([*command, *map(str, args)], capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            return json.loads(result.stdout)

        request = self.root / "deployment.json"
        request.write_text(json.dumps({"schema_version": 1, "product": "MassDB SQL",
                                      "deployment_id": claims()["deployment_id"],
                                      "registered_fe_nodes": 3, "registered_be_nodes": 7}), encoding="utf-8")
        prepared = self.root / "prepared.json"
        self.assertEqual("CLAIMS_PREPARED", run(
            "prepare-claims", "--request", request, "--output", prepared, "--license-id", "cli-license",
            "--issuer", "Issuer", "--customer-id", "Customer", "--edition", "Enterprise", "--sequence", "1",
            "--issued-at", "2026-01-01T00:00:00Z", "--not-before", "2026-01-01T08:00:00+08:00",
            "--expires-at", "2027-01-01T00:00:00Z", "--max-fe-nodes", "3", "--max-be-nodes", "10",
            "--feature", "DATA_QUERY")["status"])
        run("sign", "--claims", prepared, "--private-key", self.private, "--kid", "test-key",
            "--output", self.certificate)
        renewal = issuer.parse_json(prepared.read_bytes())
        renewal.update(sequence=2, license_id="cli-renewal", expires_at=1830297600)
        prepared.write_text(json.dumps(renewal), encoding="utf-8")
        result = run("sign", "--claims", prepared, "--private-key", self.private, "--kid", "test-key",
                     "--output", self.root / "renewed", "--previous", self.certificate,
                     "--previous-public-key", self.public, "--previous-kid", "test-key", "--at", "1767225600")
        self.assertEqual(0, result["coverage_gap_seconds"])
        self.assertEqual("TRUST_EXPORTED", run("export-trust", "--public-key", self.public,
                         "--kid", "test-key", "--purpose", "license", "--output", self.root / "trust.json")["status"])
        challenge_file = self.root / "challenge.json"
        challenge_file.write_text(json.dumps(challenge()), encoding="utf-8")
        repair = self.root / "repair.jws"
        run("repair-sign", "--challenge", challenge_file, "--repair-id", "7c2aa6bc-078f-499e-bd31-b5874fcc5b05",
            "--issued-at", "2026-01-01T00:00:00Z", "--not-before", "2026-01-01T08:00:00+08:00",
            "--expires-at", "2026-01-02T00:00:00Z", "--private-key", self.private,
            "--kid", "repair-key", "--output", repair)
        result = run("repair-verify", "--certificate", repair, "--challenge", challenge_file,
                     "--public-key", self.public, "--kid", "repair-key", "--at", "1767225600")
        self.assertEqual("VALID", result["time_status"])


class LicenseFixedVectorTest(unittest.TestCase):
    """Shared known answers are frozen on disk; tests never regenerate expected signatures."""

    @classmethod
    def setUpClass(cls):
        fixture = (Path(__file__).resolve().parents[2]
                   / "fe/fe-core/src/test/resources/license/ed25519-fixed-vectors.json")
        cls.vectors = json.loads(fixture.read_text(encoding="utf-8"))
        cls.openssl = issuer.OpenSsl(OPENSSL)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="massdb-public-fixed-vectors-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write_keys(self, vector):
        # These two seeds are published by RFC 8032, not newly created operational private keys.
        private_der = bytes.fromhex("302e020100300506032b657004220420" + vector["seed_hex"])
        public_der = bytes.fromhex("302a300506032b6570032100" + vector["public_key_hex"])
        private, public = self.root / "private.pem", self.root / "public.pem"
        for path, label, data in ((private, "PRIVATE KEY", private_der), (public, "PUBLIC KEY", public_der)):
            path.write_text(f"-----BEGIN {label}-----\n" + base64.encodebytes(data).decode("ascii")
                            + f"-----END {label}-----\n", encoding="ascii")
            path.chmod(0o600)
        derived = self.openssl.run(["pkey", "-in", str(private), "-pubout", "-outform", "DER"])
        self.assertEqual(public_der, derived)
        return private, public

    def test_matches_published_rfc8032_known_answers(self):
        for vector in self.vectors["rfc8032"]:
            with self.subTest(vector=vector["name"]):
                private, public = self.write_keys(vector)
                message, signature = self.root / "message", self.root / "signature"
                message.write_bytes(bytes.fromhex(vector["message_hex"]))
                expected = bytes.fromhex(vector["signature_hex"])
                actual = self.openssl.run(["pkeyutl", "-sign", "-rawin", "-inkey", str(private),
                                           "-in", str(message)])
                self.assertEqual(expected, actual)
                signature.write_bytes(expected)
                verify = ["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public),
                          "-in", str(message), "-sigfile", str(signature)]
                self.openssl.run(verify)
                signature.write_bytes(bytes([expected[0] ^ 1]) + expected[1:])
                with self.assertRaises(issuer.IssuerError):
                    self.openssl.run(verify)

    def fixed_jws(self, purpose):
        vector = next(item for item in self.vectors["massdb_jws"] if item["purpose"] == purpose)
        rfc = next(item for item in self.vectors["rfc8032"] if item["name"] == vector["key_vector"])
        private, public = self.write_keys(rfc)
        claims = json.loads(vector["payload_utf8"])
        output = self.root / "fixed.jws"
        if purpose == "license":
            claim_file = self.root / "claims.json"
            claim_file.write_text(vector["payload_utf8"], encoding="utf-8")
            issuer.sign(self.openssl, claim_file, private, vector["kid"], output)

            def verify():
                return issuer.verify(self.openssl, output, public, vector["kid"], at=1800000000,
                                     deployment_id=claims["deployment_id"])
        else:
            challenge_file = self.root / "challenge.json"
            challenge_file.write_text(json.dumps(self.vectors["repair_challenge"]), encoding="utf-8")
            issuer.repair_sign(self.openssl, challenge_file, private, vector["kid"], output,
                               claims["repair_id"], claims["issued_at"], claims["not_before"], claims["expires_at"])

            def verify():
                return issuer.repair_verify(self.openssl, output, public, vector["kid"], challenge_file,
                                            at=1800000000)
        self.assertEqual(vector["compact"].encode("ascii"), output.read_bytes())
        self.assertEqual(vector["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual("VALID", verify()["time_status"])
        segments = vector["compact"].split(".")
        self.assertEqual(vector["header_utf8"].encode("utf-8"), issuer._decode(segments[0]))
        self.assertEqual(vector["payload_utf8"].encode("utf-8"), issuer._decode(segments[1]))
        claims["expires_at"] += 1
        output.write_text(segments[0] + "." + b64(json.dumps(claims).encode()) + "." + segments[2], encoding="ascii")
        with self.assertRaises(issuer.IssuerError):
            verify()
        signature = issuer._decode(segments[2])
        output.write_text(segments[0] + "." + segments[1] + "."
                          + b64(signature[:32] + bytes([signature[32] ^ 1]) + signature[33:]), encoding="ascii")
        with self.assertRaises(issuer.IssuerError):
            verify()

    def test_license_signing_exactly_matches_shared_fixed_jws(self):
        self.fixed_jws("license")

    def test_repair_signing_exactly_matches_shared_fixed_jws(self):
        self.fixed_jws("time_repair")


if __name__ == "__main__":
    unittest.main()
