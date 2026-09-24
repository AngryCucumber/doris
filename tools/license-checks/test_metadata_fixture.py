#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline oracle/error-contract tests; these never contact a database or HTTP server."""

import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import metadata_fixture as fixture
from stream_load_fixture import SqlOracle


class MetadataFixtureTest(unittest.TestCase):
    def test_http_200_business_error_is_not_success(self):
        for code in (1, 401, 500, "0", False, None):
            with self.subTest(code=code), self.assertRaises(ValueError):
                fixture.http_data({"http_status": 200, "body": {"code": code, "data": []}})

    def test_http_permission_denial_requires_original_reason(self):
        response = {"http_status": 200, "body": {
            "code": 401, "msg": "Unauthorized", "data": "Access denied; missing ADMIN"}}
        fixture.http_data(response, 401)
        response["body"]["data"] = "license expired"
        with self.assertRaises(ValueError):
            fixture.http_data(response, 401)

    def test_http_redirect_or_error_is_never_accepted(self):
        for status in (307, 401, 500):
            with self.subTest(status=status), self.assertRaises(ValueError):
                fixture.http_data({"http_status": status, "body": {"code": 0, "data": []}})

    def test_http_and_sql_result_types_normalize_without_losing_null(self):
        sql = {"success": True, "columns": [{"name": "a"}, {"name": "b"}], "rows": [{"a": "1", "b": None}]}
        http = {"http_status": 200, "body": {"code": 0, "data": {
            "type": "result_set", "meta": [{"name": "a"}, {"name": "b"}], "data": [[1, None]]}}}
        self.assertEqual(fixture.sql_result(sql), fixture.http_result(http))
        http["body"]["data"]["data"] = [[1]]
        with self.assertRaises(ValueError):
            fixture.http_result(http)

    def test_mix_rejects_missing_requests_and_extra_metadata(self):
        results = [{"columns": ["1"], "rows": [["1"]]}, {"columns": ["1"], "rows": [["1"]]},
                   {"columns": ["Tables_in_license_perf"], "rows": [["point_rows"]]},
                   {"columns": ["Field", "Type"], "rows": [["id", "BIGINT"]]}]
        fixture.check_mix(results, ["point_rows"], ["id"])
        with self.assertRaises(ValueError):
            fixture.check_mix(results[:1], ["point_rows"], ["id"])
        with self.assertRaises(ValueError):
            fixture.check_mix(results, [], ["id"])
        with self.assertRaises(ValueError):
            fixture.check_mix(results, ["point_rows"], ["id", "secret"])

    def test_schema_compares_all_fields_and_original_null_display(self):
        sql = {"rows": [{"Field": "id", "Type": "BIGINT", "Default": "NULL"}]}
        http = {"http_status": 200, "body": {"code": 0, "data": {
            "point_rows": {"is_base": True, "schema": [{"Field": "id", "Type": "BIGINT", "Default": None}]}}}}
        fixture.check_schema(http, sql)
        http["body"]["data"]["point_rows"]["schema"][0]["Type"] = "INT"
        with self.assertRaises(ValueError):
            fixture.check_schema(http, sql)

    def test_sql_denial_does_not_accept_arbitrary_sql_failure(self):
        result = {"success": False, "error_code": 1105, "sql_state": "HY000", "error_message":
                  "(conn=16) errCode = 2, detailMessage = DESCRIBE command denied to user 'lp005_n_012345abcdef'"
                  "@'127.0.0.1' for table 'license_perf.point_rows'"}
        fixture.check_sql_denied(result)
        for field, value in (("error_code", 1045), ("sql_state", "42000"), ("error_message", "syntax error")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture.check_sql_denied(dict(result, **{field: value}))

    def test_auth_config_rejects_missing_or_ambiguous_values(self):
        for key in ("enable_all_http_auth", "experimental_enable_all_http_auth"):
            self.assertEqual("false", fixture.auth_config_value({"success": True, "rows": [{"Key": key, "Value": "false"}]}))
        for rows in ([], [{"Value": "false"}, {"Value": "true"}], [{"Value": "anything"}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                fixture.auth_config_value({"success": True, "rows": rows})

    def sql_oracle(self, directory):
        oracle = SqlOracle.__new__(SqlOracle)
        oracle.args = SimpleNamespace(user="admin", password_env="TEST_PASSWORD")
        oracle.state, oracle.output, oracle.sequence = {"query_port": 29030}, Path(directory), 0
        oracle.java, oracle.classpath = Path("java"), "offline-placeholder"
        return oracle

    def test_sql_oracle_remains_fail_fast_and_archives_structured_error(self):
        response = {"success": False, "stopped_on_error": True, "statements": [{
            "success": False, "error_code": 1142, "sql_state": "42000"}]}
        with tempfile.TemporaryDirectory() as directory:
            oracle = self.sql_oracle(directory)
            with patch("stream_load_fixture.subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 2, json.dumps(response), "not archived")) as run, self.assertRaises(RuntimeError):
                oracle.execute(["DESCRIBE protected", "SELECT 1"])
            config = json.loads((Path(directory) / "sql-001.json").read_text())
            self.assertFalse(config["continue_on_error"])
            self.assertEqual(response, json.loads((Path(directory) / "sql-001.result.json").read_text()))
            self.assertEqual(1, run.call_count)

    def test_sql_oracle_continuation_is_explicit_and_complete(self):
        response = {"success": False, "statements": [{"success": False, "error_code": 1142}, {"success": True}]}
        with tempfile.TemporaryDirectory() as directory:
            oracle = self.sql_oracle(directory)
            with patch("stream_load_fixture.subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(response), "")):
                self.assertEqual(response["statements"], oracle.execute(
                    ["DESCRIBE protected", "SELECT 1"], continue_on_error=True, user="reader", password_env="EMPTY"))
            config = json.loads((Path(directory) / "sql-001.json").read_text())
            self.assertTrue(config["continue_on_error"])
            self.assertEqual("reader", config["user"])
            self.assertNotIn("password", config)
            response["statements"].pop()
            with patch("stream_load_fixture.subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(response), "")), self.assertRaises(RuntimeError):
                oracle.execute(["DESCRIBE protected", "SELECT 1"], continue_on_error=True)


if __name__ == "__main__":
    unittest.main()
