#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline tests of LP026 oracles, planning, recorder boundaries and failure cleanup."""

import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import background_http_fixture as probe


def arguments(**changes):
    result = dict(dictionary_timeout=750, statistics_timeout=300, mv_timeout=120,
                  timeout=2400, poll_seconds=5)
    result.update(changes)
    return argparse.Namespace(**result)


def result(records, columns=None):
    names = list(records[0]) if records else columns or ["empty"]
    return {"success": True, "columns": [{"name": name, "type": "STRING"} for name in names], "rows": records}


def dictionary(version="2", **changes):
    value = {"DictionaryId": "123", "DictionaryName": "dict_test", "BaseTableName": "internal.test.dict_source",
             "Version": version, "Status": "NORMAL", "DataDistribution": "{127.0.0.1:29060 ver=2 memory=100}",
             "LastUpdateResult": "2026-09-24 13:01:35: succeed"}
    value.update(changes)
    return value


def stats_rows():
    return [{"column_name": name, "count": "3.0", "ndv": "3.0", "num_null": "0.0",
             "min": str(low), "max": str(high), "method": "SAMPLE", "trigger": "SYSTEM"}
            for name, low, high in (("k0", 1, 3), ("v", 10, 30))]


def input_files(directory):
    entries = []
    for format_name, name, content in (("CSV", "rows.csv", probe.CSV_BYTES),
                                       ("PARQUET", "rows.parquet", b"PAR1test-only-placeholderPAR1")):
        path = directory / name
        path.write_bytes(content)
        entries.append({"format": format_name, "uri": probe.FILE_URIS[format_name], "path": str(path),
                        "size": len(content), "sha256": probe.sha(content)})
    manifest = directory / "input-manifest.json"
    probe.save(manifest, {"schema_version": 1, "files": entries})
    return manifest, entries


def input_validation(entries):
    by_format = {entry["format"]: entry for entry in entries}
    expected = [{"id": 1, "payload": "lp026-a"}, {"id": 2, "payload": "lp026-b"}]
    return {"schema_version": 1, "schema_valid": True, "rows_match_model": True,
            "independent_reader": "ParquetFileReader+GroupRecordConverter",
            "csv_rows": expected, "parquet_rows": copy.deepcopy(expected),
            "csv_sha256": by_format["CSV"]["sha256"], "parquet_sha256": by_format["PARQUET"]["sha256"],
            "parquet_size": by_format["PARQUET"]["size"]}


class BackgroundHttpFixtureTest(unittest.TestCase):
    def test_plan_retains_all_stages_and_full_performance_obligations(self):
        value = probe.plan(arguments())
        self.assertEqual(set(probe.PHASES), set(value["phases"]))
        self.assertTrue(all(state == "not_run" for state in value["phases"].values()))
        self.assertEqual([1, 8, 32], value["full_contract_retained"]["concurrency"])
        self.assertEqual(600, value["full_contract_retained"]["window_seconds"])
        self.assertEqual(5, value["full_contract_retained"]["required_pairs"])
        self.assertFalse(value["LP026_complete"])
        self.assertFalse(value["release_performance_pass"])

    def test_default_plan_does_not_validate_cluster_compile_or_start_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "new"
            with patch.object(probe.fixture, "owned", side_effect=lambda path: Path(path)), \
                    patch.object(sys, "argv", ["fixture", "--output", str(target)]), \
                    patch.object(probe.fixture, "validate_cluster", side_effect=AssertionError("No cluster in plan")), \
                    patch.object(probe.subprocess, "Popen", side_effect=AssertionError("No child in plan")), \
                    patch.object(probe, "EsServer", side_effect=AssertionError("No listener in plan")), \
                    patch.object(probe.http.client, "HTTPConnection", side_effect=AssertionError("No HTTP in plan")):
                probe.main()
            self.assertEqual("PLANNED", json.loads((target / "report.json").read_text())["status"])

    def test_probe_requires_explicit_original_hashes_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "new"
            with patch.object(sys, "argv", ["fixture", "--mode", "probe", "--output", str(target)]), \
                    self.assertRaisesRegex(ValueError, "explicit original"):
                probe.main()
            self.assertFalse(target.exists())

    def test_foreign_cluster_is_rejected_before_java_or_network(self):
        with patch.object(probe.fixture, "validate_cluster", side_effect=ValueError("foreign namespace")), \
                patch.object(probe.subprocess, "Popen", side_effect=AssertionError("No child")), \
                self.assertRaisesRegex(ValueError, "foreign namespace"):
            probe.cluster_identity(SimpleNamespace(cluster_record=Path("irrelevant")))

    def test_live_identity_rejects_service_restart_supervisor_replacement_and_namespace_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            installation = Path(temporary)
            services = {}
            for component, pid in (("fe", 100), ("be", 200)):
                directory = installation / component / "bin"
                directory.mkdir(parents=True)
                (directory / (component + ".pid")).write_text(str(pid))
                services[component] = {"pid": pid, "start_ticks": str(pid), "executable": "/pinned/executable"}
            state = {"namespace": "net:[123]", "host_namespace": "net:[1]", "installation": str(installation),
                     "verified_identity": {"services": services, "supervisor_pid": 300, "supervisor_start_ticks": "300"}}
            with patch.object(probe.os, "readlink", return_value="net:[123]") as namespace, \
                    patch.object(probe, "process_ticks", side_effect=lambda pid: str(pid)) as ticks, \
                    patch.object(probe.Path, "resolve", return_value=Path("/pinned/executable")):
                self.assertTrue(probe.validate_live_identity(state))
                ticks.side_effect = lambda pid: "changed" if pid == 100 else str(pid)
                with self.assertRaisesRegex(ValueError, "Original fe identity changed"):
                    probe.validate_live_identity(state)
                ticks.side_effect = lambda pid: "changed" if pid == 300 else str(pid)
                with self.assertRaisesRegex(ValueError, "supervisor identity changed"):
                    probe.validate_live_identity(state)
                ticks.side_effect = lambda pid: str(pid)
                namespace.return_value = "net:[456]"
                with self.assertRaisesRegex(ValueError, "private namespace"):
                    probe.validate_live_identity(state)

    def test_sql_refuses_replaced_identity_before_creating_or_running_request(self):
        processes = Mock()
        sql = probe.Sql(arguments(), {}, Path("unused"), processes, "unused")
        with patch.object(probe, "validate_live_identity", side_effect=ValueError("Original fe identity changed")), \
                self.assertRaisesRegex(ValueError, "identity changed"):
            sql.execute(["DROP DATABASE owned"], continue_on_error=True)
        processes.run.assert_not_called()

    def test_new_load_and_review_controllers_are_detected_before_helper_launch(self):
        for name in ("stream_load_baseline.py", "complex_planning_fixture.py", "ui_baseline_fixture.py",
                     "ui_concurrent_fixture.py", "background_http_fixture.py", "kafka_routine_fixture.py",
                     "kafka_routine_baseline.py", "review_public_trust.py"):
            with self.subTest(name=name):
                self.assertTrue(probe.is_owned_benchmark(["python3", "-B", "tools/license-checks/" + name],
                                                        str(probe.ROOT)))
                self.assertTrue(probe.is_owned_benchmark(["python3", str(probe.ROOT / "tools/license-checks" / name)],
                                                        "/foreign"))
                self.assertFalse(probe.is_owned_benchmark(["python3", name], "/foreign"))

    def test_test_names_or_embedded_command_text_do_not_become_active_load_controllers(self):
        self.assertFalse(probe.is_owned_benchmark(["python3", "-m", "unittest", "test_stream_load_baseline.py"],
                                                 str(probe.ROOT)))
        self.assertFalse(probe.is_owned_benchmark(["python3", "-c", "print('review_public_trust.py')"], str(probe.ROOT)))

    def test_benchmark_guard_covers_relative_controller_between_jvm_windows(self):
        self.assertTrue(probe.is_owned_benchmark(
            ["python3", "tools/license-checks/measure_license_primitives.py", "--output", ".build-records/formal"],
            str(probe.ROOT)))
        self.assertTrue(probe.is_owned_benchmark(
            ["java", "-cp", str(probe.ROOT / ".build-records/classes"), "LicensePrimitiveCostProbe"], "/tmp"))
        self.assertTrue(probe.is_owned_benchmark(
            ["python3", "./measure_license_primitives.py"], str(probe.ROOT / "tools/license-checks")))
        self.assertFalse(probe.is_owned_benchmark(["python3", "measure_license_primitives.py"], "/foreign"))
        self.assertFalse(probe.is_owned_benchmark(["python3", "test_measure_license_primitives.py"], str(probe.ROOT)))
        self.assertFalse(probe.is_owned_benchmark(["python3", "-c", "print('LicensePrimitiveCostProbe')"], str(probe.ROOT)))

    def test_new_controllers_resolve_relative_paths_against_the_observed_cwd(self):
        for name in ("ui_concurrent_fixture.py", "kafka_routine_baseline.py"):
            with self.subTest(name=name):
                self.assertTrue(probe.is_owned_benchmark(["/usr/bin/python3.13", "./" + name], str(probe.SOURCE.parent)))
                self.assertTrue(probe.is_owned_benchmark(["python3", "../tools/license-checks/" + name],
                                                        str(probe.ROOT / "ui")))
                self.assertFalse(probe.is_owned_benchmark(["python3", "./" + name], str(probe.ROOT / "ui")))

    def test_foreign_same_named_script_cannot_borrow_checkout_cwd_or_output_ownership(self):
        for name in ("ui_concurrent_fixture.py", "kafka_routine_baseline.py"):
            for directory in (probe.ROOT, Path("/foreign")):
                with self.subTest(name=name, directory=directory):
                    self.assertFalse(probe.is_owned_benchmark(
                        ["python3", "/foreign/" + name, "--output", str(probe.ROOT / ".build-records")], str(directory)))
            self.assertFalse(probe.is_owned_benchmark(
                ["python3", "../massdb-sql-other/tools/license-checks/" + name], str(probe.ROOT)))

    def test_python_option_values_do_not_hide_the_actual_controller(self):
        for name in ("ui_concurrent_fixture.py", "kafka_routine_baseline.py"):
            argv = ["python3", "-B", "-W", "error::RuntimeWarning", "-X", "utf8", "--", "./" + name]
            self.assertTrue(probe.is_owned_benchmark(argv, str(probe.SOURCE.parent)))
        self.assertTrue(probe.is_owned_benchmark(
            ["python3", "-Werror", "-Xutf8", str(probe.SOURCE.parent / "ui_concurrent_fixture.py")], "/foreign"))

    def test_controller_paths_as_command_module_or_reader_arguments_are_not_live_controllers(self):
        controller = str(probe.SOURCE.parent / "ui_concurrent_fixture.py")
        for argv in (["python3", "-c", controller], ["python3", "-cpass", controller],
                     ["python3", "-m", "unittest", controller], ["python3", "other.py", controller],
                     ["cat", controller], ["python3", "-c", "LicensePrimitiveCostProbe"]):
            with self.subTest(argv=argv):
                self.assertFalse(probe.is_owned_benchmark(argv, str(probe.SOURCE.parent)))

    def test_direct_controller_path_and_empty_argv_are_classified_exactly(self):
        self.assertTrue(probe.is_owned_benchmark([str(probe.SOURCE.parent / "ui_concurrent_fixture.py")], "/foreign"))
        self.assertFalse(probe.is_owned_benchmark([], str(probe.ROOT)))
        self.assertFalse(probe.is_owned_benchmark(["python3", "--"], str(probe.ROOT)))

    def test_guard_skips_only_self_and_still_rejects_another_owned_controller(self):
        for name in ("ui_concurrent_fixture.py", "kafka_routine_baseline.py"):
            reads = []
            def read_cmdline(path):
                reads.append(path)
                self.assertEqual(path, Path("/proc/202/cmdline"))
                return ("python3\0./" + name + "\0").encode()
            with self.subTest(name=name), \
                    patch.object(probe.os, "getpid", return_value=101), \
                    patch.object(probe.Path, "iterdir", return_value=iter([Path("/proc/101"), Path("/proc/self"), Path("/proc/202")])), \
                    patch.object(probe.Path, "read_bytes", autospec=True, side_effect=read_cmdline), \
                    patch.object(probe.os, "readlink", return_value=str(probe.SOURCE.parent)), \
                    self.assertRaisesRegex(ValueError, "owned timed workload"):
                probe.no_active_benchmark()
            self.assertEqual(reads, [Path("/proc/202/cmdline")])

    def test_guard_allows_self_but_still_reads_and_classifies_foreign_process(self):
        with patch.object(probe.os, "getpid", return_value=101), \
                patch.object(probe.Path, "iterdir", return_value=iter([Path("/proc/101"), Path("/proc/202")])), \
                patch.object(probe.Path, "read_bytes", return_value=b"python3\0/foreign/ui_concurrent_fixture.py\0") as read, \
                patch.object(probe.os, "readlink", return_value=str(probe.ROOT)):
            probe.no_active_benchmark()
        read.assert_called_once()

    def test_disappearing_process_does_not_skip_a_later_absolute_owned_controller(self):
        command = ("python3\0" + str(probe.SOURCE.parent / "kafka_routine_baseline.py") + "\0").encode()
        with patch.object(probe.os, "getpid", return_value=101), \
                patch.object(probe.Path, "iterdir", return_value=iter([Path("/proc/202"), Path("/proc/303")])), \
                patch.object(probe.Path, "read_bytes", side_effect=[FileNotFoundError(), command]), \
                patch.object(probe.os, "readlink", return_value="/foreign"), \
                self.assertRaisesRegex(ValueError, "owned timed workload"):
            probe.no_active_benchmark()

    def test_orphan_kafka_java_workloads_keep_exact_class_and_checkout_ownership(self):
        for name in ("LicenseKafkaBaseline", "LicenseKafkaFixture"):
            with self.subTest(name=name):
                self.assertTrue(probe.is_owned_benchmark(["java", "-cp", "classes", name], str(probe.ROOT)))
                self.assertTrue(probe.is_owned_benchmark(
                    ["/exact/jdk/bin/java", "-cp", str(probe.ROOT / ".build-records/classes"), name], "/foreign"))
                self.assertFalse(probe.is_owned_benchmark(["java", "-cp", "/foreign/classes", name], "/foreign"))
                self.assertFalse(probe.is_owned_benchmark(["java", name + "Test"], str(probe.ROOT)))
                self.assertFalse(probe.is_owned_benchmark(["python3", "-c", name], str(probe.ROOT)))

    def test_orphan_ui_node_drivers_use_their_exact_owned_absolute_or_relative_script(self):
        for name in ("LicenseUiConcurrentFixture.cjs", "LicenseUiBaselineFixture.cjs"):
            with self.subTest(name=name):
                self.assertTrue(probe.is_owned_benchmark(["/exact/bin/node", str(probe.SOURCE.parent / name)], "/foreign"))
                self.assertTrue(probe.is_owned_benchmark(["node", "./" + name], str(probe.SOURCE.parent)))
                self.assertTrue(probe.is_owned_benchmark(["nodejs", "--", "tools/license-checks/" + name], str(probe.ROOT)))
                self.assertFalse(probe.is_owned_benchmark(["node", "/foreign/" + name], str(probe.ROOT)))
                self.assertFalse(probe.is_owned_benchmark(["python3", str(probe.SOURCE.parent / name)], str(probe.ROOT)))

    def test_node_test_eval_and_reader_arguments_do_not_impersonate_an_orphan_driver(self):
        driver = str(probe.SOURCE.parent / "LicenseUiConcurrentFixture.cjs")
        for argv in (["node", "--test", driver], ["node", "-e", driver], ["node", "--eval=" + driver],
                     ["node", "--check", driver], ["node", "other.cjs", driver], ["cat", driver]):
            with self.subTest(argv=argv):
                self.assertFalse(probe.is_owned_benchmark(argv, str(probe.ROOT)))

    def test_guard_rejects_orphan_java_and_node_without_a_python_parent(self):
        for command in (("java\0-cp\0classes\0LicenseKafkaBaseline\0").encode(),
                        ("node\0" + str(probe.SOURCE.parent / "LicenseUiConcurrentFixture.cjs") + "\0").encode()):
            with self.subTest(command=command), \
                    patch.object(probe.os, "getpid", return_value=101), \
                    patch.object(probe.Path, "iterdir", return_value=iter([Path("/proc/202")])), \
                    patch.object(probe.Path, "read_bytes", return_value=command), \
                    patch.object(probe.os, "readlink", return_value=str(probe.ROOT)), \
                    self.assertRaisesRegex(ValueError, "owned timed workload"):
                probe.no_active_benchmark()

    def test_complete_row_oracle_rejects_extra_rows_columns_null_and_wrong_content(self):
        expected = [{"k0": "1", "payload": "lp026-a"}]
        self.assertEqual(expected, probe.exact_rows(result(expected), expected)["rows"])
        for records in ([{"k0": "1", "payload": "wrong"}], [{"k0": "1", "payload": None}],
                        expected + expected, [{"k0": "1", "payload": "lp026-a", "extra": "1"}]):
            with self.subTest(records=records), self.assertRaises(ValueError):
                probe.exact_rows(result(records), expected)

    def test_empty_dictionary_is_not_ready_and_old_version_cannot_prove_refresh(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            probe.dictionary_state(result([], ["DictionaryName"]), "dict_test")
        self.assertFalse(probe.dictionary_state(result([dictionary()]), "dict_test", previous=2))
        self.assertTrue(probe.dictionary_state(result([dictionary()]), "dict_test", previous=1,
                                              backends=["127.0.0.1:29060"]))

    def test_dictionary_requires_complete_distribution_current_versions_and_success(self):
        for change in ({"DataDistribution": "{}"}, {"DataDistribution": "{127.0.0.1:29060 ver=1 memory=100}"},
                       {"DataDistribution": "{127.0.0.1:29061 ver=2 memory=100}"}, {"LastUpdateResult": "failed"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                probe.dictionary_state(result([dictionary(**change)]), "dict_test", previous=1,
                                       backends=["127.0.0.1:29060"])

    def test_dictionary_original_timestamp_success_is_exact_and_fix_version_matches(self):
        self.assertTrue(probe.dictionary_state(result([dictionary(
            LastUpdateResult="2026-09-24 13:01:35: succeed fix version 2")]), "dict_test", previous=1))
        for text in ("succeed", "2026-09-24 13:01:35: failed: succeed",
                     "2026-09-24 13:01:35: succeed fix version 1", "2026-09-24 13:01:35: succeed garbage"):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "successful distribution"):
                probe.dictionary_state(result([dictionary(LastUpdateResult=text)]), "dict_test", previous=1)

    def test_dictionary_log_requires_real_scheduler_submission_and_completion_after_offset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "fe/log").mkdir(parents=True)
            path = root / "fe/log/fe.log"
            path.write_text("Submit dictionary dict_test refresh task\nDictionary dict_test refresh succeed\n")
            with patch.object(probe.fixture, "owned", side_effect=Path):
                evidence = probe.DictionaryLog({"installation": str(root)}, "dict_test")
                with self.assertRaisesRegex(ValueError, "No server scheduler"):
                    evidence.finish()
                evidence = probe.DictionaryLog({"installation": str(root)}, "dict_test")
                with path.open("a") as stream:
                    stream.write("Submit dictionary dict_test refresh task, it's OUT_OF_DATE now\n")
                    stream.write("Dictionary dict_test refresh succeed. now version is 2\n")
                self.assertEqual(2, len(evidence.finish()["matching_lines"]))

    def test_mv_previous_success_and_failed_new_task_never_pass(self):
        old = {"TaskId": "1", "JobName": "job", "Status": "SUCCESS"}
        self.assertFalse(probe.mv_task_ready(result([old]), "job", {"1"}))
        self.assertTrue(probe.mv_task_ready(result([old, {**old, "TaskId": "2"}]), "job", {"1"}))
        with self.assertRaisesRegex(ValueError, "failed/cancelled"):
            probe.mv_task_ready(result([{**old, "TaskId": "2", "Status": "FAILED"}]), "job", {"1"})

    def test_stats_requires_natural_system_automatic_finished_job_for_owned_table(self):
        job = {"db_name": "owned", "tbl_name": "stats_source", "state": "FINISHED",
               "job_type": "SYSTEM", "schedule_type": "AUTOMATIC"}
        self.assertFalse(probe.stats_job_ready(result([], list(job)), "owned"))
        self.assertTrue(probe.stats_job_ready(result([job]), "owned"))
        for changes in ({"db_name": "foreign"}, {"tbl_name": "other"}, {"job_type": "MANUAL"},
                        {"schedule_type": "ONCE"}, {"state": "FAILED"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                probe.stats_job_ready(result([{**job, **changes}]), "owned")

    def test_column_stats_independent_three_row_model_and_method_are_both_required(self):
        self.assertEqual(3, probe.check_column_stats(result(stats_rows()))["expected"]["rows"])
        for key, value in (("count", "2"), ("ndv", "4"), ("num_null", "1"), ("min", "NaN"),
                           ("max", "999"), ("method", "FULL"), ("trigger", "MANUAL")):
            records = stats_rows()
            records[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.check_column_stats(result(records))

    def test_statistics_policy_uses_supported_alter_and_waits_for_natural_job(self):
        commands = []
        sql = Mock()
        job = {"job_id": "123", "db_name": "owned", "tbl_name": "stats_source", "state": "FINISHED",
               "job_type": "SYSTEM", "schedule_type": "AUTOMATIC"}
        model = [{"k0": str(key), "v": str(key * 10)} for key in range(1, 4)]
        def one(command):
            commands.append(command)
            if command.startswith("SHOW GLOBAL VARIABLES LIKE '"):
                name = command.split("'")[1]
                return result([{"Variable_name": name, "Value": "true" if name.startswith("enable_")
                               else "0" if name == "huge_table_lower_bound_size_in_bytes" else "00:00:00"}])
            if command == "SELECT k0,v FROM stats_source ORDER BY k0":
                return result(model)
            if command == "SHOW AUTO ANALYZE stats_source":
                return result([job])
            if command == "SHOW ANALYZE TASK STATUS 123":
                return result([{"state": "FINISHED"}])
            if command == "SHOW COLUMN STATS stats_source":
                return result(stats_rows())
            if command == "SHOW INDEX STATS stats_source stats_source":
                return result([{"index_name": "stats_source"}])
            self.fail("Unexpected command or explicit ANALYZE: " + command)
        def execute(statements):
            self.assertEqual(3, len(statements))
            self.assertTrue(statements[0].startswith("CREATE TABLE stats_source("))
            self.assertNotIn("auto_analyze_policy", statements[0], "Original CREATE rejects this property")
            self.assertEqual("ALTER TABLE stats_source SET ('auto_analyze_policy'='enable')", statements[1])
            self.assertEqual("INSERT INTO stats_source VALUES(1,10),(2,20),(3,30)", statements[2])
            commands.extend(statements)
        sql.one.side_effect, sql.execute.side_effect = one, execute
        context = SimpleNamespace(sql=sql, names={"database": "owned"}, args=arguments(), budget=probe.Budget(60))
        evidence = probe.probe_statistics(context)
        self.assertEqual([job], evidence["jobs"])
        self.assertEqual(0, evidence["explicit_analyze_commands"])
        self.assertFalse(any(command.startswith(("ANALYZE", "SET GLOBAL")) for command in commands))

    def test_statistics_nonzero_threshold_is_rejected_before_table_or_analyze_mutations(self):
        sql = Mock()
        def one(command):
            name = command.split("'")[1]
            return result([{"Variable_name": name, "Value": "true" if name.startswith("enable_") else "1024"}])
        sql.one.side_effect = one
        context = SimpleNamespace(sql=sql)
        with self.assertRaisesRegex(ValueError, "global zero threshold"):
            probe.probe_statistics(context)
        sql.execute.assert_not_called()

    def test_selected_phases_remain_subset_and_never_adopt_historical_passes(self):
        full = probe.plan(arguments())
        self.assertEqual(list(probe.PHASES), full["selected_phases"])
        self.assertTrue(full["same_run_full_phase_scope"])
        partial = probe.plan(arguments(phases=["es", "statistics"]))
        self.assertEqual(["statistics", "es"], partial["selected_phases"])
        self.assertFalse(partial["same_run_full_phase_scope"])
        self.assertFalse(partial["historical_results_combined"])
        self.assertEqual("ORIGINAL_FUNCTIONAL_SUBSET_COMPLETE", partial["successful_scope_status"])
        self.assertTrue(all(value == "not_run" for value in partial["phases"].values()))
        for selected in ([], ["es", "es"], ["unknown"]):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                probe.selected_phases(arguments(phases=selected))

    def test_es_fixed_routes_return_real_distinct_mapping_and_business_payloads(self):
        root = probe.es_payload("GET", "/", b"")
        self.assertEqual("lp026-fixture", root["name"])
        mapping = probe.es_payload("GET", "/lp026_rows/_mapping", b"")
        search = probe.es_payload("POST", "/lp026_rows/_search", probe.canonical(probe.SEARCH_BODY))
        self.assertEqual({"type": "keyword"}, mapping["lp026_rows"]["mappings"]["properties"]["payload"])
        self.assertEqual([1, 2], [row["_source"]["id"] for row in search["hits"]["hits"]])
        for method, path, body in (("GET", "/lp026_rows/_search", b""), ("PUT", "/", b""),
                                   ("GET", "/secret", b""), ("POST", "/lp026_rows/_search", b"{}")):
            with self.subTest(method=method, path=path), self.assertRaises(ValueError):
                probe.es_payload(method, path, body)

    def test_es_envelope_and_business_oracle_detects_wrong_payload_and_count(self):
        original = {"catalog": "owned", "table": "lp026_rows", "result": probe.es_payload(
            "POST", "/lp026_rows/_search", probe.canonical(probe.SEARCH_BODY))}
        probe.check_es_response(original, "owned", "search")
        changed = copy.deepcopy(original)
        changed["result"]["hits"]["hits"][0]["_source"]["payload"] = "incorrect"
        with self.assertRaisesRegex(ValueError, "business values"):
            probe.check_es_response(changed, "owned", "search")
        changed = copy.deepcopy(original)
        changed["result"]["hits"]["total"]["value"] = 1
        with self.assertRaisesRegex(ValueError, "count/timeout"):
            probe.check_es_response(changed, "owned", "search")

    def test_recorder_preserves_failed_route_without_archiving_arbitrary_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            recorder = probe.EsRecorder(Path(temporary) / "events.jsonl")
            status, _ = recorder.respond("GET", "/contains-private-path", b"")
            self.assertEqual(400, status)
            self.assertEqual("<unexpected>", recorder.events[0]["path"])
            self.assertNotIn("contains-private-path", recorder.path.read_text())
            self.assertTrue(recorder.errors)

    def test_manifest_rejects_changed_file_duplicate_uri_and_escape(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(probe.fixture, "owned", side_effect=lambda path: Path(path).resolve()):
            directory = Path(temporary) / "owned"
            directory.mkdir()
            manifest, entries = input_files(directory)
            self.assertEqual({"CSV", "PARQUET"}, set(probe.validate_input_manifest(manifest, directory)))
            for change in ("digest", "duplicate", "outside"):
                changed = copy.deepcopy(entries)
                if change == "digest":
                    changed[0]["sha256"] = "0" * 64
                elif change == "duplicate":
                    changed[1] = copy.deepcopy(changed[0])
                else:
                    outside = Path(temporary) / "outside.csv"
                    outside.write_bytes(probe.CSV_BYTES)
                    changed[0]["path"] = str(outside)
                probe.save(manifest, {"schema_version": 1, "files": changed})
                with self.subTest(change=change), self.assertRaises(ValueError):
                    probe.validate_input_manifest(manifest, directory)

    def test_input_validation_needs_independent_rows_schema_and_matching_content_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, entries = input_files(Path(temporary))
            by_format = {item["format"]: item for item in entries}
            original = input_validation(entries)
            probe.validate_broker_input_validation(original, by_format)
            for key, value in (("schema_valid", False), ("independent_reader", "same writer"),
                               ("parquet_rows", []), ("parquet_sha256", "wrong")):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    probe.validate_broker_input_validation({**original, key: value}, by_format)

    def test_dependency_origins_accept_java_file_url_and_reject_foreign_classes(self):
        names = ("org.apache.parquet.avro.AvroParquetWriter", "org.apache.parquet.hadoop.ParquetFileReader",
                 "org.apache.parquet.example.data.simple.convert.GroupRecordConverter", "org.apache.avro.Schema",
                 "org.apache.hadoop.conf.Configuration")
        origins = {name: "file:/owned/package/fe/lib/fixture.jar" for name in names}
        origins["org.apache.parquet.format.PageHeader"] = (
            "file:/owned/package/fe/lib/parquet-format-structures-1.17.0.jar")
        probe.validate_loaded_origins(origins, Path("/owned/package"))
        for value in ("file:/foreign/fixture.jar", "https://example.com/fixture.jar", "file://remote/fixture.jar"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                probe.validate_loaded_origins({**origins, names[0]: value}, Path("/owned/package"))
        with self.assertRaises(ValueError):
            probe.validate_loaded_origins({**origins, "org.apache.parquet.format.PageHeader":
                                           "file:/owned/package/fe/lib/fe-common-1.2-SNAPSHOT.jar"},
                                          Path("/owned/package"))

    def test_jdk_build_accepts_temurin_release_metadata_without_losing_exact_binding(self):
        for build_key in ("JAVA_RUNTIME_VERSION", "FULL_VERSION"):
            probe.validate_jdk_release({"JAVA_VERSION": "17.0.4", build_key: "17.0.4+8"}, "17.0.4+8")
        for release in ({"JAVA_VERSION": "17.0.4"},
                        {"JAVA_VERSION": "17.0.2", "FULL_VERSION": "17.0.4+8"},
                        {"JAVA_VERSION": "17.0.4", "FULL_VERSION": "17.0.4+7"},
                        {"JAVA_VERSION": "17.0.4", "FULL_VERSION": "17.0.4+8",
                         "JAVA_RUNTIME_VERSION": "17.0.4+7"}):
            with self.subTest(release=release), self.assertRaises(ValueError):
                probe.validate_jdk_release(release, "17.0.4+8")

    def test_helper_dependency_order_prevents_old_fe_common_parquet_shadowing(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)
            library = package / "fe/lib"
            library.mkdir(parents=True)
            for name in ("fe-common-1.2-SNAPSHOT.jar", "parquet-hadoop-1.17.0.jar",
                         "parquet-format-structures-1.17.0.jar"):
                (library / name).touch()
            dependencies = probe.helper_dependencies(package)
            self.assertEqual(dependencies[0].name, "parquet-format-structures-1.17.0.jar")
            self.assertEqual(len(dependencies), 3)
            (library / "parquet-format-structures-1.17.0.jar").unlink()
            with self.assertRaises(ValueError):
                probe.helper_dependencies(package)
            for version in ("1.16.0", "1.17.0"):
                (library / ("parquet-format-structures-" + version + ".jar")).touch()
            with self.assertRaises(ValueError):
                probe.helper_dependencies(package)

    def test_preview_rejects_file_metadata_schema_and_full_value_mismatch(self):
        entry = {"size": 20, "uri": probe.FILE_URIS["PARQUET"]}
        original = {"reviewStatistic": {"fileNumber": 1, "fileSize": 20},
                    "fileSample": {"sampleFileName": entry["uri"], "fileLineNumber": 2, "maxColumnSize": 2,
                                   "sampleFileLines": [["1", "lp026-a"], ["2", "lp026-b"]], "colNames": ["id", "payload"]}}
        probe.check_preview(original, entry, "PARQUET")
        for key, value in (("sampleFileName", "foreign"), ("fileLineNumber", 1), ("maxColumnSize", 3),
                           ("sampleFileLines", [["1", "wrong"], ["2", "lp026-b"]]), ("colNames", ["payload", "id"])):
            changed = copy.deepcopy(original)
            changed["fileSample"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.check_preview(changed, entry, "PARQUET")

    def test_broker_phase_requires_real_reads_and_exposes_unclosed_reader(self):
        uri = probe.FILE_URIS["CSV"]
        events = [{"allowed_uri": uri, "method": method, "status_name": "OK", "returned_bytes": count}
                  for method, count in (("listPath", 0), ("openReader", 0), ("pread", 20))]
        observed = probe.check_broker_phase(events, uri, 0)
        self.assertEqual(1, observed["open_count"])
        self.assertEqual(0, observed["close_count"])
        with self.assertRaisesRegex(ValueError, "actual file bytes"):
            probe.check_broker_phase([{**row, "returned_bytes": 0} for row in events], uri, 0)
        with self.assertRaisesRegex(ValueError, "different broker"):
            probe.check_broker_phase(events + [{"allowed_uri": probe.FILE_URIS["PARQUET"],
                                               "method": "pread", "status_name": "OK"}], uri, 0)

    def test_cleanup_continues_after_sql_and_stop_marker_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            sql = Mock()
            sql.one.side_effect = ValueError("SQL failed")
            sql.execute.side_effect = ValueError("SQL failed")
            processes = Mock()
            processes.stop_all.return_value = [{"stopped": True}]
            server, thread, recorder = Mock(), Mock(), SimpleNamespace(active=0)
            thread.is_alive.side_effect = [True, False]
            context = SimpleNamespace(budget=probe.Budget(10), sql=sql, output=output, report={},
                                      names={"database": "owned", "catalog": "ownedcat", "broker": "ownedbroker"},
                                      created={"database": True, "catalog": True, "broker": True},
                                      es=(server, thread, recorder), broker_directory=output / "absent",
                                      broker_process=Mock(), broker_port=23456, processes=processes)
            cleanup = probe.cleanup(context)
            self.assertFalse(cleanup["complete"])
            server.shutdown.assert_called_once()
            server.server_close.assert_called_once()
            processes.stop_all.assert_called_once()
            self.assertTrue(any(row["name"] == "broker_stop_marker" for row in cleanup["errors"]))
            self.assertTrue(any("DROP CATALOG" in call.args[0] for call in sql.one.call_args_list))

    def test_broker_summary_requires_bound_identity_complete_events_and_client_cleanup(self):
        ready = {"pid": 42, "namespace": "net:[123]", "input_manifest_sha256": "a" * 64}
        events = [{"schema_version": 1, "request_id": 1, "method": "ping", "status_name": "OK",
                   "returned_bytes": 0}]
        summary = {**ready, "schema_version": 1, "stop_reason": "stop_file", "protocol_errors": 0,
                   "active_readers": 0, "worker_threads_terminated": True, "evidence_error": False,
                   "active_readers_before_cleanup": 0, "cleanup_closed_readers": 0, "requests": 1,
                   "counts": {"ping": 1}, "status_counts": {"OK": 1}, "returned_bytes": 0}
        self.assertEqual(summary, probe.check_broker_summary(summary, ready, events))
        for changed in ({"pid": 43}, {"namespace": "net:[456]"}, {"input_manifest_sha256": "b" * 64},
                        {"protocol_errors": 1}, {"stop_reason": "deadline"}, {"requests": 2},
                        {"counts": {}}, {"returned_bytes": 1}, {"cleanup_closed_readers": 1}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                probe.check_broker_summary({**summary, **changed}, ready, events)
        with self.assertRaisesRegex(ValueError, "missing or reordered"):
            probe.check_broker_summary(summary, ready, [{**events[0], "request_id": 2}])

    def test_child_timeout_still_stops_owned_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            manager = probe.Processes(probe.Budget(20), Path(temporary), "ns")
            child = Mock()
            with patch.object(manager, "start", return_value=child), patch.object(manager, "stop") as stop, \
                    patch.object(probe, "read_process_output", side_effect=subprocess.TimeoutExpired("helper", 1)), \
                    self.assertRaises(subprocess.TimeoutExpired):
                manager.run(["helper"], "test", 1)
            stop.assert_called_once_with(child)
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()

    def test_exec_transition_waits_for_exact_command_before_registration(self):
        manager = probe.Processes(probe.Budget(20), Path("unused"), "owned")
        child = Mock(pid=42)
        child.poll.return_value = None
        record = {"start_ticks": "7", "expected_executable": str(Path(sys.executable).resolve()),
                  "launch_command_sha256": "a" * 64}
        pin = {"start_ticks": 7, "namespace": "owned", "executable": str(Path(sys.executable).resolve()),
               "command_sha256": "a" * 64}
        with patch.object(probe.resources_module, "process_identity", side_effect=[ValueError("empty command"),
                          {**pin, "command_sha256": "b" * 64}, pin]), \
                patch.object(probe, "process_ticks", return_value="7"), \
                patch.object(probe.os, "readlink", return_value="owned"), patch.object(manager.budget, "pause"):
            manager.await_exec_identity(child, record)
        self.assertEqual(3, record["exec_identity_attempts"])
        self.assertEqual(pin, record["exec_identity"])
        self.assertEqual(["incomplete_proc_ValueError", "exec_mismatch", "exact"],
                         [item["reason"] for item in record["exec_identity_observations"]])

    def test_exec_identity_early_exit_never_fabricates_registration(self):
        manager = probe.Processes(probe.Budget(20), Path("unused"), "owned")
        child = Mock(pid=42)
        child.poll.return_value = 1
        record = {"start_ticks": "7", "expected_executable": str(Path(sys.executable).resolve()),
                  "launch_command_sha256": "a" * 64}
        with patch.object(probe.resources_module, "process_identity") as identity, \
                self.assertRaisesRegex(ValueError, "exited before"):
            manager.await_exec_identity(child, record)
        identity.assert_not_called()
        self.assertNotIn("exec_identity", record)

    def test_persistent_wrong_exec_is_deadline_failure_and_cleanup_still_runs(self):
        manager = probe.Processes(probe.Budget(20), Path("unused"), "owned")
        child = Mock(pid=42)
        child.poll.return_value = None
        pin = {"start_ticks": 7, "namespace": "owned", "executable": "/foreign/java",
               "command_sha256": "b" * 64}
        command = [str(Path(sys.executable).resolve())]
        with patch.object(probe.subprocess, "Popen", return_value=child), \
                patch.object(probe.resources_module, "process_identity", return_value=pin), \
                patch.object(probe, "process_ticks", return_value="7"), \
                patch.object(probe.os, "readlink", return_value="owned"), \
                patch.object(manager.budget, "checkpoint"), patch.object(manager.budget, "pause"), \
                patch.object(probe.time, "monotonic", side_effect=[10, 10, 10, 13]), \
                patch.object(manager, "stop") as stop, self.assertRaisesRegex(ValueError, "two seconds"):
            manager.start(command, "owned-helper")
        stop.assert_called_once_with(child)
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()
        self.assertNotIn("exec_identity", manager.children[0][1])

    def test_exec_transition_rejects_replacement_and_never_accepts_wrong_command(self):
        manager = probe.Processes(probe.Budget(20), Path("unused"), "owned")
        child = Mock(pid=42)
        child.poll.return_value = None
        record = {"start_ticks": "7", "expected_executable": str(Path(sys.executable).resolve()),
                  "launch_command_sha256": "a" * 64}
        with patch.object(probe.resources_module, "process_identity", side_effect=ValueError("empty command")), \
                patch.object(probe, "process_ticks", return_value="8"), \
                self.assertRaisesRegex(ValueError, "identity changed"):
            manager.await_exec_identity(child, record)
        self.assertNotIn("exec_identity", record)
        with patch.object(manager.budget, "checkpoint"), \
                patch.object(probe.time, "monotonic", side_effect=[10, 13]), \
                self.assertRaisesRegex(ValueError, "two seconds"):
            manager.await_exec_identity(child, record)

    def test_child_output_bound_is_enforced_while_reading_before_full_capture(self):
        child, selected = Mock(), Mock()
        key = SimpleNamespace(fileobj=child.stdout, data="stdout")
        selected.__enter__ = Mock(return_value=selected)
        selected.__exit__ = Mock(return_value=False)
        selected.get_map.return_value = {1: key}
        selected.select.return_value = [(key, probe.selectors.EVENT_READ)]
        with patch.object(probe.selectors, "DefaultSelector", return_value=selected), \
                patch.object(probe.os, "set_blocking"), patch.object(probe, "MAX_RESPONSE", 4), \
                patch.object(probe.os, "read", side_effect=[b"1234", b"5"]) as read, \
                self.assertRaisesRegex(ValueError, "output exceeds bound"):
            probe.read_process_output(child, probe.Budget(20), 10)
        self.assertEqual(2, read.call_count)
        child.wait.assert_not_called()

    def test_http_body_checks_absolute_deadline_and_handles_closed_socket_after_last_block(self):
        response, transport = Mock(), Mock()
        response.read1.return_value = b"{}"
        response.isclosed.return_value = True
        with patch.object(probe.time, "monotonic", return_value=10):
            self.assertEqual(b"{}", probe.read_http_body(response, transport, probe.Budget(20), 15))
        response.read1.assert_called_once()
        transport.settimeout.assert_called_once_with(5)
        response.reset_mock()
        with patch.object(probe.time, "monotonic", return_value=10):
            budget = probe.Budget(20)
        with patch.object(probe.time, "monotonic", side_effect=[10, 10, 16, 16]), \
                self.assertRaisesRegex(ValueError, "HTTP absolute deadline"):
            probe.read_http_body(response, transport, budget, 15)

    def test_http_body_rejects_oversized_response_during_chunk_collection(self):
        response, transport = Mock(), Mock()
        response.read1.side_effect = [b"1234", b"5"]
        response.isclosed.return_value = False
        with patch.object(probe, "MAX_RESPONSE", 4), patch.object(probe.time, "monotonic", return_value=10), \
                self.assertRaisesRegex(ValueError, "response exceeded"):
            probe.read_http_body(response, transport, probe.Budget(20), 15)
        self.assertEqual(2, response.read1.call_count)

    def test_replaced_process_is_never_signaled(self):
        manager = probe.Processes(probe.Budget(20), Path("unused"), "owned")
        child = Mock(pid=100)
        child.poll.return_value = None
        manager.children = [(child, {"start_ticks": "before"})]
        with patch.object(probe, "process_ticks", return_value="after"), \
                patch.object(probe.os, "killpg") as kill, self.assertRaisesRegex(ValueError, "replaced"):
            manager.stop(child)
        kill.assert_not_called()

    def test_stop_proc_disappearance_needs_owned_wait_and_closes_pipes(self):
        manager = probe.Processes(probe.Budget(20), Path("unused"), "owned")
        child = Mock(pid=42, returncode=0)
        child.poll.return_value = None
        child.wait.return_value = 0
        record = {"name": "short", "start_ticks": "7"}
        manager.children = [(child, record)]
        with patch.object(probe, "process_ticks", return_value="7"), \
                patch.object(probe.os, "readlink", side_effect=FileNotFoundError()), \
                patch.object(probe.os, "killpg") as kill:
            self.assertTrue(manager.stop(child)["stopped"])
        kill.assert_not_called()
        child.wait.assert_any_call(timeout=0.05)
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()

    def test_stop_missing_pin_of_live_child_does_not_signal_or_claim_exit(self):
        manager = probe.Processes(probe.Budget(20), Path("unused"), "owned")
        child = Mock(pid=42)
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("helper", 0.05)
        record = {"name": "live", "start_ticks": "7"}
        manager.children = [(child, record)]
        with patch.object(probe, "process_ticks", side_effect=FileNotFoundError()), \
                patch.object(probe.os, "killpg") as kill, self.assertRaisesRegex(ValueError, "remains live"):
            manager.stop(child)
        kill.assert_not_called()
        self.assertFalse(record.get("stopped", False))

    def test_operation_error_survives_separate_cleanup_failure(self):
        manager = probe.Processes(probe.Budget(20), Path("unused"), "owned")
        child = Mock(pid=42)
        record = {"name": "owned"}
        manager.children = [(child, record)]
        with patch.object(manager, "start", return_value=child), \
                patch.object(probe, "read_process_output", side_effect=ValueError("primary resource failure")), \
                patch.object(manager, "stop", side_effect=FileNotFoundError()), \
                self.assertRaisesRegex(ValueError, "primary resource failure"):
            manager.run(["owned"], "owned")
        self.assertEqual("FileNotFoundError", record["initial_cleanup_errors"][0]["class"])
        self.assertEqual(("owned", "helper_cleanup_error"), manager.budget.resource_failure)
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()

    def test_cancellation_is_deferred_but_cleanup_gets_a_new_bounded_budget(self):
        budget = probe.Budget(60)
        budget.cancelled = True
        with self.assertRaises(probe.Cancelled):
            budget.checkpoint()
        budget.begin_cleanup()
        self.assertTrue(budget.cleanup)
        self.assertLessEqual(budget.seconds(1000), 180)

    def test_resource_failure_interrupts_work_but_never_blocks_cleanup_budget(self):
        budget = probe.Budget(60)
        resources = Mock()
        resources.failed.is_set.return_value = True
        resources.check.side_effect = ValueError("resource limit")
        budget.resources = resources
        self.assertTrue(budget.abort_requested())
        with self.assertRaisesRegex(ValueError, "resource limit"):
            budget.checkpoint()
        budget.begin_cleanup()
        resources.begin_cleanup.assert_called_once()
        budget.checkpoint()
        self.assertFalse(budget.abort_requested())
        resources.check.assert_called_once()

    def test_resource_failure_stops_local_helpers_before_cleanup_sql(self):
        with tempfile.TemporaryDirectory() as temporary:
            order = []
            sql, processes, server, thread = Mock(), Mock(), Mock(), Mock()
            sql.one.side_effect = lambda statement: order.append("sql") or result([], ["Database"])
            processes.stop_all.side_effect = lambda: order.append("local_processes") or [{"stopped": True}]
            thread.is_alive.side_effect = [True, False]
            budget = probe.Budget(30)
            budget.resource_failure = ("broker_output", "limit")
            context = SimpleNamespace(budget=budget, sql=sql, output=Path(temporary), report={},
                                      names={"database": "owned"}, created={"database": True},
                                      es=(server, thread, SimpleNamespace(active=0)), broker_directory=None,
                                      broker_process=None, processes=processes)
            receipt = probe.cleanup(context)
            self.assertLess(order.index("local_processes"), order.index("sql"))
            server.stop_requests.assert_called_once()
            self.assertTrue(receipt["complete"])


if __name__ == "__main__":
    unittest.main()
