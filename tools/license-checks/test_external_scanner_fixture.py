#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline plan-routing, offset/EOS, cleanup and complete-matrix evidence rejection tests."""

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import external_scanner_fixture as fixture


PORT = 29060
PLAN = base64.b64encode(b"offline plan-shaped bytes, never submitted to a server").decode()
PLAN_HASH = hashlib.sha256(PLAN.encode()).hexdigest()
MODEL_HASH = "a" * 64
TABLET_IDS = list(range(100, 116))


def plan_response():
    return {"code": 0, "data": {"status": 200, "opaqued_query_plan": PLAN,
            "partitions": {str(identifier): {"routings": [f"127.0.0.1:{PORT}"]}
                           for identifier in TABLET_IDS}}}


def valid_report():
    runs = []
    for size in fixture.BATCH_SIZES:
        for attempt in (0, 1):
            tablets = []
            for identifier in TABLET_IDS:
                batches = []
                offset = 0
                while offset < 62500:
                    rows = min(size, 62500 - offset)
                    batches.append({"request_offset": offset, "next_offset": offset + rows,
                                    "rows": rows, "arrow_rows": rows, "eos": False,
                                    "status": "OK", "arrow_ipc_bytes": rows * 40})
                    offset += rows
                batches.append({"request_offset": offset, "next_offset": offset, "rows": 0,
                                "eos": True, "status": "OK"})
                tablets.append({"tablet_id": identifier, "open_status": "OK", "close_status": "OK",
                                "closed": True, "close_attempted": True, "eos": True, "rows": offset,
                                "context_id_sha256": hashlib.sha256(
                                    f"{size}/{attempt}/{identifier}".encode()).hexdigest(),
                                "batches": batches})
            runs.append({"batch_size": size, "attempt": attempt, "plan_sha256": PLAN_HASH,
                         "status": "READ_PASS", "rows_verified": fixture.ROWS, "tablets": tablets,
                         "complete_unordered_set": {"rows": fixture.ROWS, "distinct_ids": fixture.ROWS,
                                                    "min_id": 0, "max_id": fixture.ROWS - 1,
                                                    "sum_id": fixture.ROWS * (fixture.ROWS - 1) // 2,
                                                    "sha256_sorted_actual_rows": MODEL_HASH}})
    return {"status": "FIXTURE_PASS", "unique_context_count": 64, "runs": runs}


class ExternalScannerFixtureTest(unittest.TestCase):
    def check(self, value):
        fixture.check_report(value, PLAN_HASH, MODEL_HASH, TABLET_IDS)

    def test_plan_exact_owned_routes_and_sorted_tablets(self):
        parsed = fixture.parse_plan(200, plan_response(), PORT)
        self.assertEqual(TABLET_IDS, [item["tablet_id"] for item in parsed["tablets"]])
        self.assertEqual(PLAN_HASH, parsed["plan_sha256"])

    def test_plan_http_and_business_errors_are_not_success(self):
        for status in (307, 401, 500):
            with self.subTest(status=status), self.assertRaises(ValueError):
                fixture.parse_plan(status, plan_response(), PORT)
        for code in (False, "0", 401, None):
            value = plan_response()
            value["code"] = code
            with self.subTest(code=code), self.assertRaises(ValueError):
                fixture.parse_plan(200, value, PORT)

    def test_plan_data_error_not_confused_with_http_200(self):
        value = plan_response()
        value["data"]["status"] = 401
        with self.assertRaises(ValueError):
            fixture.parse_plan(200, value, PORT)

    def test_plan_rejects_external_alias_credential_and_wrong_port_routes(self):
        for route in ("192.0.2.1:29060", "localhost:29060", "127.0.0.1:1", "user:secret@127.0.0.1:29060"):
            value = plan_response()
            value["data"]["partitions"]["100"]["routings"] = [route]
            with self.subTest(route=route), self.assertRaises(ValueError):
                fixture.parse_plan(200, value, PORT)

    def test_plan_requires_all_sixteen_and_no_additional_routes(self):
        value = plan_response()
        value["data"]["partitions"].pop("100")
        with self.assertRaises(ValueError):
            fixture.parse_plan(200, value, PORT)
        value = plan_response()
        value["data"]["partitions"]["100"]["routings"] *= 2
        with self.assertRaises(ValueError):
            fixture.parse_plan(200, value, PORT)

    def test_plan_rejects_empty_invalid_base64_and_oversized_ids(self):
        for plan in ("", "not a base64 plan!", None):
            value = plan_response()
            value["data"]["opaqued_query_plan"] = plan
            with self.subTest(plan=plan), self.assertRaises(ValueError):
                fixture.parse_plan(200, value, PORT)
        value = plan_response()
        value["data"]["partitions"][str(2**63)] = value["data"]["partitions"].pop("100")
        with self.assertRaises(ValueError):
            fixture.parse_plan(200, value, PORT)

    def test_private_plan_mode_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            fixture.save_private(path, {"opaque_plan": PLAN})
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                fixture.save_private(path, {"opaque_plan": "replacement"})
            self.assertEqual(PLAN, json.loads(path.read_text())["opaque_plan"])

    def test_model_uses_exact_known_lowercase_payload_csv(self):
        known = (b"0,cfcd208495d565ef66e7dff9f98764da\n"
                 b"1,c4ca4238a0b923820dcc509a6f75849b\n"
                 b"2,c81e728d9d4c2f636f067f89cc14862c\n")
        self.assertEqual(hashlib.sha256(known).hexdigest(), fixture.model_digest(3))

    def test_http_has_one_direct_request_no_redirect_and_sanitized_record(self):
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read1.side_effect = [json.dumps(plan_response()).encode(), b""]
        record = {}
        with patch.object(fixture.http.client, "HTTPConnection", return_value=connection) as constructor, \
                patch.dict(fixture.os.environ, {"TEST_SCANNER_PASSWORD": "private-test-secret"}):
            status, body = fixture.request_plan(28030, "root", "TEST_SCANNER_PASSWORD", record)
        constructor.assert_called_once_with("127.0.0.1", 28030, timeout=5)
        self.assertEqual(1, connection.request.call_count)
        self.assertEqual(1, connection.close.call_count)
        self.assertEqual(200, status)
        self.assertEqual(PLAN, body["data"]["opaqued_query_plan"])
        self.assertNotIn("private-test-secret", json.dumps(record))
        self.assertNotIn(PLAN, json.dumps(record))
        self.assertEqual(1, record["request_count"])

    def test_http_redirect_does_not_retry(self):
        connection = MagicMock()
        connection.getresponse.return_value.status = 307
        with patch.object(fixture.http.client, "HTTPConnection", return_value=connection), \
                self.assertRaises(ValueError):
            fixture.request_plan(28030, "root", "UNSET_TEST_PASSWORD", {})
        self.assertEqual(1, connection.request.call_count)
        self.assertEqual(1, connection.close.call_count)

    def test_complete_matrix_is_accepted(self):
        self.check(valid_report())

    def test_missing_matrix_case_or_changed_plan_is_rejected(self):
        value = valid_report()
        value["runs"].pop()
        with self.assertRaises(ValueError):
            self.check(value)
        value = valid_report()
        value["runs"][1]["plan_sha256"] = "b" * 64
        with self.assertRaises(ValueError):
            self.check(value)

    def test_incomplete_or_wrong_payload_digest_cannot_pass(self):
        for field, altered in (("rows", fixture.ROWS - 1), ("distinct_ids", fixture.ROWS - 1),
                               ("sum_id", 0), ("sha256_sorted_actual_rows", "b" * 64)):
            value = valid_report()
            value["runs"][0]["complete_unordered_set"][field] = altered
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(value)

    def test_unconfirmed_close_or_reused_context_is_rejected(self):
        for field, value in (("closed", False), ("close_attempted", False), ("close_status", "NOT_FOUND")):
            report = valid_report()
            report["runs"][0]["tablets"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(report)
        report = valid_report()
        report["runs"][1]["tablets"][0]["context_id_sha256"] = report["runs"][0]["tablets"][0]["context_id_sha256"]
        with self.assertRaises(ValueError):
            self.check(report)

    def test_offset_retry_stale_or_skipped_rows_are_rejected(self):
        for field, value in (("request_offset", 0), ("next_offset", 1)):
            report = valid_report()
            report["runs"][0]["tablets"][0]["batches"][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(report)

    def test_missing_early_or_data_bearing_eos_is_rejected(self):
        for mutation in ("missing", "early", "data"):
            report = valid_report()
            batches = report["runs"][0]["tablets"][0]["batches"]
            if mutation == "missing":
                batches[-1]["eos"] = False
            elif mutation == "early":
                batches[0]["eos"] = True
            else:
                batches[-1]["rows"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(report)

    def test_empty_non_eos_or_oversized_batch_is_rejected(self):
        for rows in (0, 1025):
            report = valid_report()
            report["runs"][0]["tablets"][0]["batches"][0].update(rows=rows, arrow_rows=rows)
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.check(report)

    def test_different_tablet_set_cannot_masquerade_as_reopen(self):
        report = valid_report()
        for run in report["runs"]:
            run["tablets"][0]["tablet_id"] = 999
        with self.assertRaises(ValueError):
            self.check(report)

    def test_declared_helper_failure_never_passes(self):
        report = valid_report()
        report["status"] = "FAIL"
        with self.assertRaises(ValueError):
            self.check(report)


if __name__ == "__main__":
    unittest.main()
