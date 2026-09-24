#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Prove LP005 SQL/HTTP metadata equivalence and original permissions in an owned private cluster."""

import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import re
import time
import uuid

from stream_load_fixture import ROOT, SqlOracle, digest, owned, save, utc, validate_cluster


MIX = ("SELECT 1", "SELECT 1", "SHOW TABLES FROM license_perf", "DESCRIBE license_perf.point_rows")
QUERY_PATH = "/api/query/default_cluster/license_perf"
TABLES_PATH = "/api/meta/namespaces/default_cluster/databases/license_perf/tables"
SCHEMA_PATH = TABLES_PATH + "/point_rows/schema?with_mv=0"
EMPTY_PASSWORD_ENV = "MASSDB_LP005_EMPTY_PASSWORD"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
AUTH_CONFIG_SQL = "ADMIN SHOW FRONTEND CONFIG LIKE '%enable_all_http_auth'"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def scalar(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def sql_result(result):
    require(result.get("success") is True, "Expected successful SQL result")
    columns = result.get("columns")
    rows = result.get("rows")
    require(isinstance(columns, list) and isinstance(rows, list), "Expected bounded SQL result set")
    names = [column["name"] for column in columns]
    require(len(names) == len(set(names)), "Duplicate columns are outside this fixture")
    require(all(set(row) == set(names) for row in rows), "SQL row shape differs from column metadata")
    return {"columns": names, "rows": [[scalar(row[name]) for name in names] for row in rows]}


def http_data(response, code=0):
    require(response.get("http_status") == 200, "Unexpected HTTP transport status")
    body = response.get("body")
    require(isinstance(body, dict) and type(body.get("code")) is int and body["code"] == code,
            "HTTP JSON business code differs from the expected result")
    if code == 401:
        require(body.get("msg") == "Unauthorized" and "Access denied" in str(body.get("data")),
                "HTTP denial did not preserve the original authorization error")
    return body.get("data")


def http_result(response):
    data = http_data(response)
    require(isinstance(data, dict) and data.get("type") == "result_set", "Expected HTTP SQL result_set")
    columns, rows = data.get("meta"), data.get("data")
    require(isinstance(columns, list) and isinstance(rows, list), "HTTP SQL metadata or rows are missing")
    names = [column["name"] for column in columns]
    require(len(names) == len(set(names)), "Duplicate HTTP columns are outside this fixture")
    require(all(isinstance(row, list) and len(row) == len(names) for row in rows), "HTTP SQL row shape mismatch")
    return {"columns": names, "rows": [[scalar(value) for value in row] for row in rows]}


def check_mix(results, tables, fields):
    require(len(results) == len(MIX), "LP005 requires exactly the frozen four-request sequence")
    require(results[0]["rows"] == [["1"]] and results[1]["rows"] == [["1"]], "SELECT 1 oracle mismatch")
    require(len(results[0]["columns"]) == 1 and len(results[1]["columns"]) == 1, "SELECT 1 column mismatch")
    require(len(results[2]["columns"]) == 1 and results[2]["rows"] == [[name] for name in tables],
            "SHOW TABLES differs from the frozen table count/order")
    require("Field" in results[3]["columns"], "DESCRIBE does not contain its Field column")
    index = results[3]["columns"].index("Field")
    require([row[index] for row in results[3]["rows"]] == fields, "DESCRIBE differs from frozen column count/order")


def check_schema(response, describe):
    data = http_data(response)
    require(isinstance(data, dict) and set(data) == {"point_rows"}, "Schema GET returned unexpected indexes")
    base = data["point_rows"]
    require(base.get("is_base") is True and isinstance(base.get("schema"), list), "Missing base schema")
    # The REST endpoint translates the SQL display value "NULL" into JSON null.
    wanted = [{key: None if value == "NULL" else value for key, value in row.items()}
              for row in describe["rows"]]
    require(base["schema"] == wanted, "Schema GET differs from the complete SQL DESCRIBE structure")


def check_sql_denied(result):
    # Original rc02 maps the internal analysis exception to the generic MySQL error packet.
    require(result.get("success") is False and result.get("error_code") == 1105
            and result.get("sql_state") == "HY000"
            and re.search(r"errCode = 2, detailMessage = DESCRIBE command denied to user 'lp005_n_[a-f0-9]{12}'"
                          r"@'127\.0\.0\.1' for table 'license_perf\.point_rows'$", result.get("error_message", "")),
            "DESCRIBE must preserve the original rc02 wrapped table-access denial (1105/HY000)")


def auth_config_value(result):
    require(result.get("success") is True, "HTTP authentication config query failed")
    rows = result.get("rows", [])
    require(len(rows) == 1, "Expected one HTTP authentication config value")
    key = next((value for key, value in rows[0].items() if key.lower() == "key"), None)
    require(key in ("enable_all_http_auth", "experimental_enable_all_http_auth"), "Unexpected authentication config key")
    value = str(next((value for key, value in rows[0].items() if key.lower() == "value"), "")).lower()
    require(value in ("true", "false"), "HTTP authentication config must be a boolean")
    return value


class HttpOracle:
    def __init__(self, state, output):
        self.port, self.output, self.sequence = int(state["http_port"]), output, 0

    def request(self, user, password_env, path, statement=None):
        require(path in (QUERY_PATH, TABLES_PATH, SCHEMA_PATH), "Unexpected LP005 HTTP endpoint")
        require((path == QUERY_PATH) == (statement is not None), "Wrong HTTP method for fixture endpoint")
        require(statement is None or statement in MIX, "Unexpected fixture HTTP SQL statement")
        secret = os.environ.get(password_env, "")
        token = base64.b64encode((user + ":" + secret).encode()).decode()
        headers = {"Authorization": "Basic " + token, "X-Doris-Stream": "false"}
        payload = None if statement is None else {"is_sync": True, "limit": 1000, "stmt": statement}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        started_at, started = utc(), time.perf_counter_ns()
        try:
            connection.request("GET" if payload is None else "POST", path,
                               body=None if payload is None else json.dumps(payload), headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            require(len(raw) <= MAX_RESPONSE_BYTES, "HTTP fixture response exceeded its size bound")
            text = raw.decode("utf-8", errors="strict")
            require(token not in text and (not secret or secret not in text), "Refuse to archive echoed credentials")
            body = json.loads(text)
            record = {"method": "GET" if payload is None else "POST", "path": path,
                      "user": user, "request_body": payload, "x_doris_stream": "false",
                      "http_status": response.status, "content_type": response.getheader("Content-Type"),
                      "body": body, "started_at_utc": started_at, "finished_at_utc": utc(),
                      "elapsed_nanos": time.perf_counter_ns() - started,
                      "cookies_reused": False, "credentials_recorded": False}
        finally:
            connection.close()
        self.sequence += 1
        save(self.output / f"http-{self.sequence:03d}.json", record)
        return record


def probe(args):
    state, _ = validate_cluster(args.cluster_record)
    require(not os.environ.get(EMPTY_PASSWORD_ENV), "LP005 reserved empty-password environment must be unset")
    tables, fields = args.expected_tables.split(","), args.expected_columns.split(",")
    require(tables == sorted(set(tables)) and "point_rows" in tables, "Freeze sorted unique expected table names")
    require(fields and len(fields) == len(set(fields)), "Freeze unique ordered point_rows columns")
    require(all(re.fullmatch(r"[a-z][a-z0-9_]*", item) for item in tables + fields), "Invalid frozen object names")
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    report = {"case_id": "LP-005", "status": "RUNNING", "started_at_utc": utc(),
              "scope": "Original-release correctness/reachability; no license-state or performance qualification",
              "namespace": state["namespace"], "cluster_record_sha256": digest(args.cluster_record),
              "fe_jar_sha256": state["fe_jar_sha256"], "java_home": state["java_home"],
              "mix": list(MIX), "mix_counts_per_client": {"SELECT 1": 2, "SHOW TABLES": 1, "DESCRIBE": 1},
              "frozen_tables": tables, "frozen_columns": fields, "credentials_recorded": False,
              "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in (
                  Path(__file__), ROOT / "tools/license-checks/stream_load_fixture.py",
                  ROOT / "tools/license-checks/LicenseFixtureSql.java")}}
    save(output / "report.json", report)
    sql, created, original_auth, auth_changed = None, [], None, False
    try:
        sql = SqlOracle(args, state, output)
        config = sql.execute([AUTH_CONFIG_SQL])[0]
        report["http_auth_config"] = config
        original_auth = auth_config_value(config)
        report["explicit_http_auth_fixture_configuration"] = original_auth != "true"
        if original_auth != "true":
            require(args.enable_http_auth_for_probe, "LP005 requires enable_all_http_auth=true or the explicit probe flag")
            auth_changed = True
            report["http_auth_setup"] = sql.execute([
                'ADMIN SET FRONTEND CONFIG ("enable_all_http_auth"="true")',
                AUTH_CONFIG_SQL])
            require(auth_config_value(report["http_auth_setup"][-1]) == "true", "HTTP auth setup was not confirmed")
        admin = sql.execute(list(MIX))
        normalized = [sql_result(item) for item in admin]
        check_mix(normalized, tables, fields)
        report["sql_admin_mix"] = admin
        http = HttpOracle(state, output)
        http_admin = [http.request(args.user, args.password_env, QUERY_PATH, statement) for statement in MIX]
        http_normalized = [http_result(item) for item in http_admin]
        check_mix(http_normalized, tables, fields)
        require(normalized == http_normalized, "Equivalent admin SQL and HTTP mixed results differ")
        report["http_admin_mix"] = http_admin
        report["sql_http_equivalent"] = True
        reader, denied = "lp005_r_" + uuid.uuid4().hex[:12], "lp005_n_" + uuid.uuid4().hex[:12]
        report["temporary_users"] = {"reader": reader, "denied": denied}
        report["setup"] = []
        for user in (reader, denied):
            result = sql.execute([f"CREATE USER '{user}'@'127.0.0.1'"])
            created.append(user)
            report["setup"].extend(result)
        report["setup"].extend(sql.execute([
            f"GRANT SELECT_PRIV ON license_perf.point_rows TO '{reader}'@'127.0.0.1'",
            f"SHOW GRANTS FOR '{reader}'@'127.0.0.1'", f"SHOW GRANTS FOR '{denied}'@'127.0.0.1'"]))
        allowed = sql.execute(list(MIX), user=reader, password_env=EMPTY_PASSWORD_ENV)
        check_mix([sql_result(item) for item in allowed], ["point_rows"], fields)
        require(sql_result(allowed[3]) == normalized[3], "Reader DESCRIBE differs from admin DESCRIBE")
        report["sql_reader_mix"] = allowed
        forbidden = sql.execute(list(MIX), continue_on_error=True, user=denied, password_env=EMPTY_PASSWORD_ENV)
        require([sql_result(item)["rows"] for item in forbidden[:2]] == [[["1"]], [["1"]]],
                "Unprivileged SELECT 1 must remain available")
        require(sql_result(forbidden[2])["rows"] == [], "Unprivileged SHOW TABLES must filter protected tables")
        check_sql_denied(forbidden[3])
        report["sql_unprivileged_mix"] = forbidden
        report["metadata_get"] = {}
        for role, user, password_env, expected in (
                ("admin", args.user, args.password_env, tables),
                ("reader", reader, EMPTY_PASSWORD_ENV, ["point_rows"]),
                ("unprivileged", denied, EMPTY_PASSWORD_ENV, [])):
            table_response = http.request(user, password_env, TABLES_PATH)
            require(http_data(table_response) == expected, "Metadata GET table filtering differs from expected privileges")
            schema_response = http.request(user, password_env, SCHEMA_PATH)
            if role == "unprivileged":
                http_data(schema_response, 401)
            else:
                check_schema(schema_response, admin[3])
            report["metadata_get"][role] = {"tables": table_response, "schema": schema_response}
        report["http_non_admin_rejections"] = []
        for user in (reader, denied):
            response = http.request(user, EMPTY_PASSWORD_ENV, QUERY_PATH, MIX[0])
            http_data(response, 401)
            report["http_non_admin_rejections"].append(response)
        report["status"] = "FIXTURE_PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["failure"] = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
        raise
    finally:
        cleanup_failed = False
        try:
            report["cleanup"] = []
            if sql is not None:
                for user in reversed(created):
                    report["cleanup"].extend(sql.execute([f"DROP USER '{user}'@'127.0.0.1'"], continue_on_error=True))
                require(all(item.get("success") is True for item in report["cleanup"]), "Temporary user cleanup failed")
        except Exception:
            report["status"], report["cleanup_failed"] = "FAIL", True
            cleanup_failed = True
        finally:
            try:
                if sql is not None and original_auth is not None:
                    restore = ['ADMIN SET FRONTEND CONFIG ("enable_all_http_auth"="' + original_auth + '")'] \
                        if auth_changed else []
                    report["http_auth_restore"] = sql.execute(restore + [AUTH_CONFIG_SQL])
                    require(auth_config_value(report["http_auth_restore"][-1]) == original_auth,
                            "HTTP authentication config restoration was not confirmed")
                    report["http_auth_restored"] = True
            except Exception:
                report["status"], report["http_auth_restored"] = "FAIL", False
                cleanup_failed = True
            report["finished_at_utc"] = utc()
            save(output / "report.json", report)
        if cleanup_failed:
            raise RuntimeError("Fixture cleanup or HTTP authentication config restoration failed")
    print(json.dumps({"status": report["status"], "report": str(output / "report.json")}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="MASSDB_BASELINE_PASSWORD")
    parser.add_argument("--expected-tables", default="point_rows")
    parser.add_argument("--expected-columns", default="id,grp,v,payload")
    parser.add_argument("--enable-http-auth-for-probe", action="store_true",
                        help="Explicitly enable HTTP authentication in this owned test FE, then restore its prior value")
    probe(parser.parse_args())


if __name__ == "__main__":
    main()
