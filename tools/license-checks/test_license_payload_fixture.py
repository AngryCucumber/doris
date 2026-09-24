#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""LP023 size semantics and schema boundary tests; no cluster access."""

import json
import unittest

import license_payload_fixture as fixture


class LicensePayloadFixtureTest(unittest.TestCase):
    def test_all_valid_sizes_are_exact_canonical_query_capable_claims(self):
        for size, count in ((512, 1), (4096, 30), (16384, 124)):
            with self.subTest(size=size):
                payload = fixture.valid_payload(size)
                claims = fixture.issuer.validate_claims(fixture.issuer.parse_json(payload))
                self.assertEqual(size, len(payload))
                self.assertEqual(payload, fixture.issuer._json_bytes(claims))
                self.assertEqual(count, len(claims["features"]))
                self.assertIn("DATA_QUERY", claims["features"])
                self.assertLessEqual(claims["not_before"], fixture.AT)
                self.assertGreater(claims["expires_at"], fixture.AT)
                self.assertEqual(set(claims), fixture.issuer.CLAIM_NAMES)

    def test_256_negative_is_canonical_but_missing_only_deployment_claim(self):
        payload = fixture.invalid_payload()
        self.assertEqual(256, len(payload))
        claims = fixture.issuer.parse_json(payload)
        self.assertEqual(fixture.issuer.CLAIM_NAMES - {"deployment_id"}, set(claims))
        self.assertEqual(payload, fixture.issuer._json_bytes(claims))
        with self.assertRaisesRegex(fixture.issuer.IssuerError, "Missing or unsupported JSON fields"):
            fixture.issuer.validate_claims(claims)
        claims["deployment_id"] = fixture.schema_minimum()["deployment_id"]
        fixture.issuer.validate_claims(claims)

    def test_minimum_proof_is_not_a_valid_query_cost_fixture(self):
        proof = fixture.minimum_proof()
        self.assertEqual(14, proof["field_count"])
        self.assertEqual(295, proof["decoded_canonical_json_bytes"])
        self.assertEqual(316, proof["query_capable_fixture_bytes_at_fixed_epoch"])
        self.assertEqual(334, proof["normal_three_ten_digit_epochs_bytes"])
        self.assertFalse(proof["valid_query_fixture"])
        self.assertEqual(295, sum(proof["encoded_field_terms_bytes"].values()) + proof["outer_separator_bytes"])

    def test_reducing_mandatory_minimum_values_is_rejected(self):
        changes = [(key, "") for key in ("license_id", "issuer", "customer_id", "edition")]
        changes += [("deployment_id", "0" * 35), ("schema_version", 0), ("policy_version", 0),
                    ("sequence", 0), ("expires_at", 0), ("product", "MassDB SQ")]
        for name, value in changes:
            with self.subTest(name=name), self.assertRaises(fixture.issuer.IssuerError):
                fixture.issuer.validate_claims(dict(fixture.schema_minimum(), **{name: value}))
        for name in ("max_fe_nodes", "max_be_nodes"):
            claims = fixture.schema_minimum()
            claims["limits"][name] = 0
            with self.subTest(name=name), self.assertRaises(fixture.issuer.IssuerError):
                fixture.issuer.validate_claims(claims)

    def test_contract_valid_and_rejected_sizes_are_separate(self):
        contract = json.loads((fixture.ROOT / "docs/license-performance-cases-20260922.json").read_text())
        case = next(case for case in contract["cases"] if case["id"] == "LP-023")
        self.assertEqual(list(fixture.SIZES), case["load_shape"]["payload_sizes_bytes"])
        self.assertEqual("decoded_canonical_json_utf8_bytes", case["load_shape"]["payload_size_unit"])
        self.assertEqual([256], case["negative_payload_cases"]["payload_sizes_bytes"])
        self.assertFalse(case["negative_payload_cases"]["count_as_valid_management_work"])

    def test_unsupported_valid_sizes_fail_instead_of_emitting_invalid_certificates(self):
        for size in (256, 295, 316, 513, 65536):
            with self.subTest(size=size), self.assertRaises(ValueError):
                fixture.valid_payload(size)


if __name__ == "__main__":
    unittest.main()
