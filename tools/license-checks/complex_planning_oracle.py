#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Independent LP006/007 full-value and DDL-overlap oracles; no database or network side effects."""

import argparse
import hashlib
import json
from pathlib import Path
import re

from stream_load_fixture import ROOT, digest, owned, save


CONTRACT = ROOT / "docs/license-p0-contract-20260922.json"
COLUMNS = ("matched_rows",) + tuple("sum_expr_%02d" % value for value in range(1, 33))
VIEW = "license_perf.license_complex_view"
NUMERIC_TYPES = {"BIGINT", "LARGEINT", "INTEGER", "INT", "SMALLINT", "TINYINT", "DECIMAL", "NUMERIC"}
QUERY_ID = r"[0-9a-f]{1,16}-[0-9a-f]{1,16}"
FROZEN_QUERY_SHA256 = "df4655191fb71a17d4a7c19baa84f7cf4cd350ea9ab44418baef885a9c545a37"
FROZEN_BLOCKS = [14813, 11787, 11019, 11913, 5916, 1676, 14987, 8292,
                 126, 8381, 1236, 9049, 10566, 8509, 636, 1069]
SUBSECOND = r"(?:0|[1-9][0-9]{0,2})ms"
MINUTE_OR_SECOND = r"(?:[1-9]|[1-5][0-9])"
TIME_MS = (rf"(?:{SUBSECOND}|{MINUTE_OR_SECOND}sec{SUBSECOND}|"
           rf"{MINUTE_OR_SECOND}min(?:{MINUTE_OR_SECOND}sec)?|"
           rf"[1-9][0-9]*hour(?:{MINUTE_OR_SECOND}min)?)")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def values_for_blocks(blocks, delta):
    """Enumerate the selected source IDs without evaluating SQL or trusting saved expected sums."""
    require(isinstance(blocks, list) and len(blocks) == 16, "Expected sixteen 64-ID blocks")
    require(all(type(block) is int and 0 <= block < 1000000 // 64 for block in blocks),
            "Block lies outside the complete million-row source")
    require(len(set(blocks)) == 16, "Expected sixteen different 64-ID blocks")
    require(type(delta) is int and delta in (0, 1), "Only the frozen view's v or v+1 is supported")
    result = {column: 0 for column in COLUMNS}
    for block in blocks:
        for identifier in range(block * 64, (block + 1) * 64):
            result["matched_rows"] += 1
            # The same view appears in u and in all four primary-key joins.
            joined_value = 5 * (identifier % 100000 + delta)
            for number, column in enumerate(COLUMNS[1:], 1):
                result[column] += joined_value * number + identifier % 1024
    return result


def query_for_blocks(blocks):
    values_for_blocks(blocks, 0)
    branches = [f"    SELECT id, grp, v FROM {VIEW} WHERE id >= {block * 64} AND id < {(block + 1) * 64}"
                for block in blocks]
    expressions = [f"    SUM((u.v + j1.v + j2.v + j3.v + j4.v) * {number} + u.grp) AS {column}"
                   for number, column in enumerate(COLUMNS[1:], 1)]
    joins = [f"INNER JOIN {VIEW} j{number} ON j{number}.id = u.id" for number in range(1, 5)]
    return ("WITH u AS (\n" + "\n    UNION ALL\n".join(branches)
            + "\n)\nSELECT COUNT(*) AS matched_rows,\n" + ",\n".join(expressions)
            + "\nFROM u\n" + "\n".join(joins))


def verified_definition(contract):
    fixture = contract["complex_planning_fixture"]
    blocks = fixture["selected_64_id_blocks"]
    require(blocks == FROZEN_BLOCKS and fixture["query_sha256_utf8"] == FROZEN_QUERY_SHA256,
            "The workload must match the original frozen block selection and SQL digest")
    initial, changed = values_for_blocks(blocks, 0), values_for_blocks(blocks, 1)
    query = query_for_blocks(blocks)
    require(fixture["schema_version"] == 1 and fixture["seed"] == 20260922
            and fixture["matched_rows"] == 1024, "Frozen fixture identity changed")
    require(fixture["query_sql"] == query
            and fixture["query_sha256_utf8"] == hashlib.sha256(query.encode("utf-8")).hexdigest(),
            "SQL differs from the exact sixteen-branch/four-join/thirty-two-expression shape")
    require(fixture["expected_result_initial"] == initial
            and fixture["event"]["expected_result_after_commit"] == changed,
            "Saved expected values differ from independent integer enumeration")
    require(fixture["event"]["offset_seconds_from_measurement_start"] == 180,
            "The dependency event must remain at the frozen 180-second offset")
    base = "SELECT id, grp, v, payload FROM license_perf.point_rows"
    require(fixture["create_dependency_sql"] == f"CREATE OR REPLACE VIEW {VIEW} AS {base}"
            and fixture["reset_after_window_sql"] == f"ALTER VIEW {VIEW} AS {base}"
            and fixture["event"]["sql"] == f"ALTER VIEW {VIEW} AS SELECT id, grp, v + 1 AS v, payload "
            "FROM license_perf.point_rows", "Unexpected view mutation")
    return {"columns": list(COLUMNS), "initial": initial, "changed": changed,
            "query_sql": query, "query_sha256_utf8": fixture["query_sha256_utf8"],
            "event_offset_seconds": 180}


def read_values(columns, rows):
    require(isinstance(columns, list) and len(columns) == len(COLUMNS), "Wrong result width")
    require(all(isinstance(column, dict) and isinstance(column.get("name"), str)
                and isinstance(column.get("type"), str) for column in columns), "Malformed column metadata")
    require([column["name"] for column in columns] == list(COLUMNS),
            "Column labels/order differ, including missing or duplicate aliases")
    require(all(column["type"].upper() in NUMERIC_TYPES for column in columns),
            "An aggregate was returned with a nonnumeric JDBC type")
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], list)
            and len(rows[0]) == len(COLUMNS), "Expected exactly one complete aggregate row")
    require(all(isinstance(value, str) and re.fullmatch(r"0|-?[1-9][0-9]*", value) for value in rows[0]),
            "Expected non-NULL, exact canonical integer strings; floating-point conversion is forbidden")
    return dict(zip(COLUMNS, (int(value) for value in rows[0])))


def verify_request(record, definition, event=None):
    """Check all values, retaining ambiguous in-flight DDL results instead of guessing snapshot time.

    The future JDBC event adapter must obtain all timestamps from the SAME JVM clock
    and record the start immediately before execute, end after complete result consumption.
    These caller-supplied facts alone are not evidence that such an adapter has run.
    """
    started, finished = record["started_ns"], record["finished_ns"]
    # nanoTime has an arbitrary origin and can be negative. Only elapsed ordering
    # within the same adapter JVM is meaningful; do not compare it with wall time.
    require(type(started) is int and type(finished) is int and started <= finished,
            "Invalid request monotonic boundaries")
    require(isinstance(record["clock_domain"], str) and record["clock_domain"], "Missing JVM clock identity")
    actual = read_values(record["columns"], record["rows"])
    phase = "initial"
    permitted = [definition["initial"]]
    if event is not None:
        begin, ack = event["started_ns"], event["commit_ack_ns"]
        require(event.get("ddl_success") is True and record["clock_domain"] == event["clock_domain"],
                "Missing successful DDL or timestamps from different clock domains")
        require(type(begin) is int and type(ack) is int and begin <= ack,
                "Invalid DDL monotonic boundaries")
        if finished < begin:
            phase = "completed_before_ddl"
        elif started > ack:
            phase, permitted = "started_after_commit_ack", [definition["changed"]]
        else:
            # Equality cannot establish event order at a quantized clock boundary.
            phase, permitted = "overlaps_ddl_or_boundary", [definition["initial"], definition["changed"]]
    require(actual in permitted, "Full aggregate values disagree with the permitted view snapshot")
    return {"phase": phase, "matched_model": "initial" if actual == definition["initial"] else "changed",
            "columns_verified": len(COLUMNS), "snapshot_time_inferred": False}


def verify_profile(text, query_id, query_sql, *, cached):
    require(type(cached) is bool and re.fullmatch(QUERY_ID, query_id), "Invalid profile expectation")
    summaries = list(re.finditer(r"(?m)^Summary:[ \t]*$", text))
    executions = list(re.finditer(r"(?m)^Execution Summary:[ \t]*$", text))
    require(len(summaries) == len(executions) == 1 and summaries[0].end() < executions[0].start()
            and not text[:summaries[0].start()].strip(), "Expected one ordered Summary and Execution Summary")
    summary = text[summaries[0].end():executions[0].start()]
    execution = text[executions[0].end():]
    next_section = re.search(r"(?m)^\S", execution)
    if next_section:
        execution = execution[:next_section.start()]

    def field_value(field, section):
        pattern = r"(?m)^[ \t]*- " + re.escape(field) + r": ([^\n]*)$"
        matches = re.findall(pattern, section)
        require(len(matches) == 1 and len(re.findall(pattern, text)) == 1,
                "Missing, misplaced or duplicate profile field: " + field)
        return matches[0].strip()

    require(field_value("Profile ID", summary) == query_id,
            "Profile query ID differs from the same-session query receipt")
    task_state = field_value("Task State", summary)
    # StmtExecutor reports coordinator OK for distributed execution, but its
    # successful SQL-cache path sends all rows then sets QueryState.EOF. Both are
    # original terminal success states; neither replaces the result/identity oracle.
    require(task_state in ("OK", "EOF"), "Unexpected Task State")
    for field, value in (("Is Nereids", "Yes"), ("Is Cached", "Yes" if cached else "No")):
        require(field_value(field, execution) == value, "Unexpected " + field)
    field_value("Sql Statement", summary)
    statement = re.search(r"(?m)^[ \t]*- Sql Statement: (.*)", summary)
    require(statement is not None, "Profile has no actual SQL statement")
    tail = summary[statement.start(1):]
    boundary = re.search(r"(?m)^   - [A-Za-z][A-Za-z0-9 ()/]*:|^Execution Summary:", tail)
    actual_sql = tail[:boundary.start()] if boundary else tail
    require(" ".join(actual_sql.split()) == " ".join(query_sql.split()), "Profile belongs to another SQL statement")
    fields = ("Parse SQL Time", "Plan Time", "Nereids Analysis Time", "Nereids Rewrite Time",
              "Nereids Optimize Time", "Nereids Translate Time")
    timings = {}
    for field in fields:
        timings[field] = field_value(field, execution)
        require(timings[field] == "N/A" or re.fullmatch(TIME_MS, timings[field]),
                "Malformed original TIME_MS planning field: " + field)
    if not cached:
        for field in fields:
            if field != "Nereids Optimize Time":
                require(timings[field] != "N/A", "Cold query lacks recorded planning activity: " + field)
    # Original SummaryProfile can render Optimize as N/A when pre-MV rewrite has
    # no timestamp. Preserve that lack of timing evidence rather than inventing zero.
    return {"query_id": query_id, "cached": cached, "task_state": task_state, "raw_stage_timings": timings,
            "unavailable_stage_timings": [field for field, value in timings.items() if value == "N/A"],
            "all_stage_timings_available": all(value != "N/A" for value in timings.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    definition = verified_definition(json.loads(CONTRACT.read_text()))
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "ORACLE_DEFINED_NOT_EXECUTED", "definition": definition,
              "contract_sha256": digest(CONTRACT), "source_sha256": digest(Path(__file__)),
              "remaining": ["Actual concurrent ADMIN event adapter and raw JVM clock receipts",
                            "All required connection/concurrency/rate/window matrices",
                            "Full query-ID-linked cold/warm/invalidation/rebuilt profiles and precision"],
              "SQL_requests_sent": 0, "runtime_verified": False, "performance_pass": False}
    save(output / "oracle.json", report)
    print(json.dumps({"status": report["status"], "output": str(output)}))


if __name__ == "__main__":
    main()
