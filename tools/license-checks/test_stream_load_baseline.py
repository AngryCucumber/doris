#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline LP012 protocol/model/lifecycle tests; no real FE/BE or complete fixture generation."""

import asyncio
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

import stream_load_baseline as baseline


class StreamLoadBaselineTest(unittest.TestCase):
    def test_pending_capacities_follow_frozen_full_arrivals_without_rate_changes(self):
        for batch in (1000, 10000):
            for workers in (1, 8, 32):
                for seconds in (600, 601, 3600):
                    arrivals = baseline.schedule(batch, workers, seconds)
                    model = baseline.queue_model(arrivals, workers)
                    for phase in ("warmup", "measurement"):
                        for worker in range(workers):
                            offsets = [x["offset_ns"] for x in arrivals[phase] if x["worker"] == worker]
                            # Independent integer endpoint/binary-search oracle, not the production deque algorithm.
                            import bisect
                            expected = max([1] + [i + 1 - bisect.bisect_right(offsets, offset - 60 * baseline.NANO)
                                                  for i, offset in enumerate(offsets)])
                            self.assertEqual(expected, model["capacities"][phase][worker])
                    self.assertEqual(10000000, sum(x["rows"] for x in arrivals["measurement"]))
        self.assertEqual([125] * 8, baseline.queue_model(baseline.schedule(1000, 8, 600), 8)
                         ["capacities"]["measurement"])

    def test_pending_capacity_exact_deadline_equality_is_expired(self):
        def arrivals(offsets):
            return [{"worker": 0, "offset_ns": value} for value in offsets]
        self.assertEqual([1], baseline.pending_capacities(arrivals([0, 60, 120]), 1, 60))
        self.assertEqual([2], baseline.pending_capacities(arrivals([0, 59, 60]), 1, 60))
        self.assertEqual([3], baseline.pending_capacities(arrivals([0, 1, 59, 60, 61]), 1, 60))

    def test_pending_capacity_rejects_invalid_or_unordered_arrivals(self):
        for arrivals in ([{"worker": True, "offset_ns": 0}], [{"worker": 1, "offset_ns": 0}],
                         [{"worker": 0, "offset_ns": -1}], [{"worker": 0, "offset_ns": True}],
                         [{"worker": 0, "offset_ns": 60}, {"worker": 0, "offset_ns": 59}]):
            with self.subTest(arrivals=arrivals), self.assertRaises(ValueError):
                baseline.pending_capacities(arrivals, 1, 60)

    def test_three_second_service_stall_does_not_invent_an_early_queue_deadline(self):
        arrivals = baseline.schedule(1000, 8, 600)["measurement"]
        capacity = baseline.pending_capacities(arrivals, 8, 60 * baseline.NANO)[0]
        references = [x for x in arrivals if x["worker"] == 0 and 0 < x["offset_ns"] < 3 * baseline.NANO]
        old, corrected = asyncio.Queue(maxsize=2), asyncio.Queue(maxsize=capacity)
        old_drops = 0
        for item in references:
            try:
                old.put_nowait(item)
            except asyncio.QueueFull:
                old_drops += 1
            corrected.put_nowait(item)
        self.assertEqual(4, old_drops)
        self.assertEqual(6, corrected.qsize())
        self.assertTrue(all(corrected.get_nowait() is item for item in references))

    def test_expired_pending_references_are_recorded_and_live_order_preserved(self):
        queue, results = asyncio.Queue(maxsize=4), {}
        items = [{"index": i, "worker": 0, "offset_ns": i * baseline.NANO} for i in range(4)]
        for item in items:
            queue.put_nowait(item)
        baseline.expire_pending(queue, results, "warmup", 0, 61 * baseline.NANO)
        self.assertEqual([0, 1], list(results))
        self.assertTrue(all(x["status"] == "DEADLINE_EXPIRED_NOT_SENT" for x in results.values()))
        self.assertEqual("NOT_SUBMITTED_TO_BE", baseline.server_transaction_state(results[0]))
        self.assertIs(items[2], queue.get_nowait())
        self.assertIs(items[3], queue.get_nowait())
        self.assertNotIn("ACK_SUCCESS", {x["status"] for x in results.values()})

    def test_server_transaction_unknown_survives_local_close_and_elapsed_timeout(self):
        value = {"status": "FAILED_OR_COMMIT_UNKNOWN", "deadline_exceeded": True,
                 "hops": [{"component": "be", "request_headers_write_attempted": True,
                           "request_headers_handed_to_writer": False, "local_transport_closed": True}]}
        evidence = baseline.transaction_evidence([value])
        self.assertTrue(evidence["server_transaction_termination_not_proven"])
        self.assertEqual("TERMINATION_NOT_PROVEN", value["server_transaction_state"])
        self.assertFalse(evidence["timeout_elapsed_or_local_cleanup_proves_server_termination"])

    def test_positive_transaction_number_without_validated_ACK_is_not_terminal_proof(self):
        for changes in ({"txn_id": 12}, {"txn_id": True, "acknowledged_commit_retained": True},
                        {"txn_id": 12, "acknowledged_commit_retained": False}):
            value = {"hops": [{"component": "be", "request_headers_handed_to_writer": True}], **changes}
            self.assertEqual("TERMINATION_NOT_PROVEN", baseline.server_transaction_state(value))

    def test_validated_late_and_cancelled_ACKs_remain_acknowledged_transactions(self):
        for status in ("ACK_SUCCESS", "ACK_LATE", "ACK_CANCELLED_AFTER_RESPONSE", "ACK_WITH_TRANSPORT_CLEANUP_FAILURE"):
            value = {"status": status, "txn_id": 12, "acknowledged_commit_retained": True}
            self.assertEqual("ACKNOWLEDGED_SUCCESS", baseline.server_transaction_state(value))

    def test_FE_only_or_BE_connection_without_header_attempt_is_not_a_submission(self):
        value = {"hops": [{"component": "fe", "request_headers_write_attempted": True},
                           {"component": "be", "connected": True, "request_headers_write_attempted": False}]}
        self.assertEqual("NOT_SUBMITTED_TO_BE", baseline.server_transaction_state(value))

    def test_successful_owned_DROP_does_not_clear_unknown_server_transaction(self):
        sql, processes, resources, budget = (Mock() for _ in range(4))
        sql.one.return_value = {"success": True, "columns": [{"name": "Database"}], "rows": []}
        processes.stop_all.return_value = []
        resources.stop.return_value = {"complete": True}
        budget.resource_failure = None
        budget.stream_load_request_results = {"measurement": {0: {
            "hops": [{"component": "be", "request_headers_handed_to_writer": True, "local_transport_closed": True}]}}}
        with patch.object(baseline, "verify_owner", return_value=True):
            result = baseline.cleanup(sql, True, "lp012w_" + "a" * 24, {}, None, processes, resources, budget)
        self.assertTrue(result["database_absent"])
        self.assertFalse(result["manual_cleanup_required"])
        self.assertTrue(result["server_transaction_termination_not_proven"])
        self.assertIn({"step": "server_transaction_termination", "error_class": "NotProven"}, result["errors"])
        self.assertEqual(2, sql.one.call_count)  # DROP + existing absence confirmation; no transaction polling.

    def freeze_synthetic_package(self, release):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package, jdk, installation = (root / name for name in ("package", "jdk", "installation"))
            for path in (package / "fe/lib", package / "be/lib", jdk / "bin", jdk / "lib/server"):
                path.mkdir(parents=True)
            for name in ("fe", "be"):
                (installation / name / "bin").mkdir(parents=True)
                (installation / name / "conf").mkdir()
                (installation / name / "conf" / (name + ".conf")).write_text("owned=true\n")
                (installation / name / "bin" / (name + ".pid")).write_text("101" if name == "fe" else "102")
            with baseline.zipfile.ZipFile(package / "fe/lib/doris-fe.jar", "w") as jar:
                jar.writestr("synthetic-original-marker", "not an executable distribution")
            for path in (package / "be/lib/doris_be", jdk / "bin/java", jdk / "bin/javac",
                         jdk / "lib/modules", jdk / "lib/server/libjvm.so"):
                path.write_bytes(b"offline-binding-fixture")
            (jdk / "release").write_text(release)
            fe, be = baseline.digest(package / "fe/lib/doris-fe.jar"), baseline.digest(package / "be/lib/doris_be")
            state = {"installation": str(installation), "package": str(package), "java_home": str(jdk),
                     "namespace": "net:[owned]", "host_namespace": "net:[host]", "supervisor_pid": 100,
                     "fe_jar_sha256": fe, "be_binary_sha256": be}
            cluster = root / "cluster.json"
            cluster.write_text(json.dumps(state))
            def pin(pid):
                executable = jdk / "bin/java" if pid == 101 else package / "be/lib/doris_be"
                return {"pid": pid, "namespace": "net:[owned]", "executable": str(executable),
                        "start_ticks": 1, "command_sha256": "0" * 64}
            with patch.object(baseline, "ROOT", root), patch.object(baseline, "owned", side_effect=Path), \
                    patch.object(baseline.support.resources_module, "process_identity", side_effect=pin):
                result = baseline.frozen_files(cluster, fe, be, "17.0.4+8")
            return result, str(jdk / "release"), baseline.digest(jdk / "release")

    def test_actual_temurin_full_version_field_preserves_complete_JDK_binding(self):
        result, release_path, checksum = self.freeze_synthetic_package(
            'JAVA_VERSION="17.0.4"\nIMPLEMENTOR="Eclipse Adoptium"\nFULL_VERSION="17.0.4+8"\n')
        self.assertEqual("17.0.4+8", result["jdk_release"]["FULL_VERSION"])
        self.assertNotIn("JAVA_RUNTIME_VERSION", result["jdk_release"])
        self.assertEqual(checksum, result["files"][release_path])
        for suffix in ("bin/java", "bin/javac", "lib/modules", "lib/server/libjvm.so"):
            self.assertIn(str(Path(result["java_home"]) / suffix), result["files"])

    def test_missing_wrong_or_conflicting_JDK_build_cannot_bind_original_package(self):
        for release in ('JAVA_VERSION="17.0.4"\n',
                        'JAVA_VERSION="17.0.4"\nFULL_VERSION="17.0.4+7"\n',
                        'JAVA_VERSION="17.0.4"\nFULL_VERSION="17.0.4+8"\nJAVA_RUNTIME_VERSION="17.0.4+7"\n'):
            with self.subTest(release=release), self.assertRaises(ValueError):
                self.freeze_synthetic_package(release)

    def test_cli_defaults_to_plan_without_dispatching_probe(self):
        with patch.object(baseline, "make_plan", return_value={"status": "PLANNED_NOT_RUN"}) as plan, \
                patch.object(baseline, "probe", side_effect=AssertionError("network forbidden")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, baseline.main([]))
            plan.assert_called_once()

    def test_probe_requires_explicit_plan(self):
        with self.assertRaises(ValueError):
            baseline.main(["--mode", "probe"])

    def test_active_measurement_guard_precedes_probe_reads(self):
        with patch.object(baseline.support, "no_active_benchmark", side_effect=ValueError("active")), \
                patch.object(baseline, "read_json", side_effect=AssertionError("unexpected read")):
            with self.assertRaises(ValueError):
                baseline.probe(SimpleNamespace(plan=Path("unused")))

    def test_complete_constant_rate_schedule_never_replays_rows(self):
        for batch in (1000, 10000):
            for concurrency in (1, 8, 32):
                value = baseline.schedule(batch, concurrency, 600)
                measured = value["measurement"]
                self.assertEqual(10000000, sum(item["rows"] for item in measured))
                self.assertEqual(list(range(10000000 // batch)), [item["index"] for item in measured])
                self.assertEqual(0, measured[0]["offset_ns"])
                self.assertLess(measured[-1]["offset_ns"], 600 * baseline.NANO)
                self.assertEqual([index * batch for index in range(len(measured))],
                                 [item["first_id"] for item in measured])
                self.assertEqual(3000000, sum(item["rows"] for item in value["warmup"]))
                self.assertEqual(value, baseline.schedule(batch, concurrency, 600))

    def test_invalid_or_reduced_matrix_parameters_are_rejected(self):
        for batch, concurrency, duration in ((1, 1, 600), (1000, 2, 600), (1000, True, 600),
                                             (1000, 1, 599), (10000, 1, 3601), (True, 1, 600)):
            with self.subTest(values=(batch, concurrency, duration)), self.assertRaises(ValueError):
                baseline.schedule(batch, concurrency, duration)

    def test_longer_window_does_not_silently_increase_batch_samples(self):
        value = baseline.schedule(10000, 32, 3600)
        self.assertEqual(1000, len(value["measurement"]))
        self.assertEqual(0, value["rows_replayed_in_measurement"])
        self.assertEqual(50, len(value["warmup"]))

    def test_independent_input_model_handles_width_boundaries(self):
        for identifier in (0, 9, 10, 1023, 1024, 99999, 100000, 9999999):
            row = baseline.model_record(identifier)
            self.assertEqual(128, len(row))
            first, group, value, payload = row[:-1].decode().split(",")
            self.assertEqual(str(identifier), first)
            self.assertEqual(identifier % 1024, int(group))
            self.assertEqual(identifier % 100000, int(value))
            self.assertTrue(payload.startswith(hashlib.md5(str(identifier).encode(), usedforsecurity=False).hexdigest()))
            self.assertEqual(b"\n", row[-1:])

    def test_duplicate_json_keys_are_not_accepted_as_original_receipts(self):
        with self.assertRaises(ValueError):
            json.loads('{"Status":"Fail","Status":"Success"}', object_pairs_hook=baseline.unique_object)

    def test_ack_requires_exact_original_integer_row_counts_and_transaction(self):
        value = {"Status": "Success", "Label": "owned", "NumberTotalRows": 1000, "NumberLoadedRows": 1000,
                 "NumberFilteredRows": 0, "NumberUnselectedRows": 0, "TxnId": 9}
        self.assertEqual(9, baseline.validate_receipt(value, "owned", 1000))
        mutations = (("Status", "Publish Timeout"), ("Label", "other"), ("TxnId", True),
                     ("NumberLoadedRows", 999), ("NumberTotalRows", "1000"), ("NumberFilteredRows", 1))
        for field, replacement in mutations:
            with self.subTest(field=field), self.assertRaises(ValueError):
                baseline.validate_receipt({**value, field: replacement}, "owned", 1000)

    def test_redirect_cannot_leave_owned_exact_endpoint_or_change_credentials(self):
        plan = {"user": "root", "password_env": "MASSDB_STREAM_ADMIN_PASSWORD"}
        path = "/api/owned/table/_stream_load"
        with patch.dict(os.environ, {plan["password_env"]: "synthetic-password"}):
            self.assertEqual(8081, baseline.redirect_port("http://root:synthetic-password@127.0.0.1:8081" + path,
                                                         path, plan, {}, 8081))
            for location in ("http://example.test:8081" + path, "http://127.0.0.1:8082" + path,
                             "http://root:other@127.0.0.1:8081" + path, "http://127.0.0.1:8081" + path + "?q=1",
                             "https://127.0.0.1:8081" + path, "http://127.0.0.1:8081/other"):
                with self.subTest(location=location), self.assertRaises(ValueError):
                    baseline.redirect_port(location, path, plan, {}, 8081)

    def test_full_column_oracle_rejects_duplicates_corruption_and_missing_groups(self):
        row = {"batch_index": "0", "n": "1000", "d": "1000", "bad": "0"}
        self.assertEqual([0], baseline.audit_visibility([row], 2, 1000))
        self.assertEqual([], baseline.audit_visibility([{**row, "n": "999", "d": "999"}], 2, 1000))
        for values in ([row, row], [{**row, "bad": "1"}], [{**row, "d": "999"}],
                       [{**row, "batch_index": "2"}], [{**row, "n": "1001", "d": "1001"}],
                       [{**row, "bad": False}], [{**row, "n": "1e3"}]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                baseline.audit_visibility(values, 2, 1000)

    def test_oracle_checks_nulls_payload_length_and_every_value(self):
        sql = baseline.group_visibility_sql("lp012w_" + "a" * 24, "measurement_rows", 10000000, 1000)
        for expression in ("id IS NULL", "grp IS NULL", "v IS NULL", "payload IS NULL", "LENGTH(payload)",
                           "COUNT(DISTINCT id)", "grp != id % 1024", "v != id % 100000", "payload !="):
            self.assertIn(expression, sql)
        with self.assertRaises(ValueError):
            baseline.group_visibility_sql("customer", "measurement_rows", 10000000, 1000)

    def test_p99_counts_batches_and_does_not_hide_drain_completions(self):
        requests = [{"status": "ACK_SUCCESS", "finished_monotonic_ns": 601 * baseline.NANO,
                     "latency_ns_including_queue": 2 * baseline.NANO, "rows": 10000} for _ in range(1000)]
        value = baseline.latency_summary(requests, 0, 600)
        self.assertEqual(1000, value["ack_success_batches"])
        self.assertEqual(0, value["completed_within_offered_window"])
        self.assertEqual(1000, value["drain_completions"])
        self.assertIsNone(value["p99_ms_including_queue"])
        self.assertFalse(value["P99_sample_floor_met"])
        self.assertFalse(value["performance_pass"])

    def test_ten_thousand_batch_samples_still_do_not_establish_AA_precision(self):
        requests = [{"status": "ACK_SUCCESS", "finished_monotonic_ns": baseline.NANO,
                     "latency_ns_including_queue": baseline.NANO} for _ in range(10000)]
        value = baseline.latency_summary(requests, 0, 600)
        self.assertEqual(1000, value["p99_ms_including_queue"])
        self.assertTrue(value["P99_sample_floor_met"])
        self.assertFalse(value["AA_precision_proven"])

    def test_receipt_archive_reserves_before_failed_write_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = baseline.Archive(Path(temporary), maximum=5)
            archive.write("receipt.json", b"123")
            with self.assertRaises(FileExistsError):
                archive.write("receipt.json", b"4")
            self.assertEqual(4, archive.used)
            with self.assertRaises(ValueError):
                archive.write("other.json", b"67")

    def test_same_database_name_with_new_ID_is_not_owned(self):
        owner = {"database": "lp012w_" + "a" * 24, "db_id": "100", "create_acknowledged": True, "tables": {}}
        with patch.object(baseline, "database_id", return_value="101"), \
                patch.object(baseline, "table_inventory", side_effect=AssertionError("must fail before tables")):
            with self.assertRaises(ValueError):
                baseline.verify_owner(Mock(), owner)

    def test_unexpected_or_replaced_table_is_not_owned(self):
        owner = {"database": "lp012w_" + "a" * 24, "db_id": "100", "create_acknowledged": True,
                 "tables": {"measurement_rows": {"table_id": "200"}}}
        for tables in ({"measurement_rows": "201"}, {"measurement_rows": "200", "foreign": "300"}, {}):
            with patch.object(baseline, "database_id", return_value="100"), \
                    patch.object(baseline, "table_inventory", return_value=tables), self.assertRaises(ValueError):
                baseline.verify_owner(Mock(), owner)

    def test_changed_schema_or_tablet_ID_blocks_cleanup_ownership(self):
        original = {"table_id": "200", "show_create": [{"Create Table": "original"}], "tablet_ids": ["1"]}
        owner = {"database": "lp012w_" + "a" * 24, "db_id": "100", "create_acknowledged": True,
                 "tables": {"measurement_rows": original}}
        for changed in ({**original, "tablet_ids": ["2"]}, {**original, "show_create": [{"Create Table": "changed"}]}):
            with patch.object(baseline, "database_id", return_value="100"), \
                    patch.object(baseline, "table_inventory", return_value={"measurement_rows": "200"}), \
                    patch.object(baseline, "table_identity", return_value=changed), self.assertRaises(ValueError):
                baseline.verify_owner(Mock(), owner)

    def test_SQL_and_metric_failures_do_not_skip_local_cleanup(self):
        sql, metrics, processes, resources, budget = (Mock() for _ in range(5))
        sql.one.side_effect = ValueError("identity changed")
        metrics.stop.side_effect = OSError("evidence")
        processes.stop_all.return_value = [{"stopped": True}]
        resources.stop.return_value = {"complete": True}
        budget.resource_failure = None
        with patch.object(baseline, "verify_owner", side_effect=ValueError("replacement")):
            result = baseline.cleanup(sql, True, "lp012w_" + "a" * 24, {}, metrics, processes, resources, budget)
        processes.stop_all.assert_called_once()
        resources.stop.assert_called_once()
        self.assertTrue(result["manual_cleanup_required"])
        self.assertTrue(result["errors"])
        self.assertFalse(any(call.args[0].startswith("DROP") for call in sql.one.call_args_list))

    def test_unknown_CREATE_never_adopts_database_by_name(self):
        sql, processes, resources, budget = (Mock() for _ in range(4))
        processes.stop_all.return_value = []
        resources.stop.return_value = {"complete": True}
        budget.resource_failure = None
        value = baseline.cleanup(sql, False, "lp012w_" + "a" * 24, None, None, processes, resources, budget)
        sql.one.assert_not_called()
        self.assertTrue(value["manual_cleanup_required"])
        processes.stop_all.assert_called_once()

    def test_incomplete_helper_exit_or_resource_evidence_cannot_complete(self):
        processes, resources, budget = (Mock() for _ in range(3))
        processes.stop_all.return_value = [{"stopped": False, "cleanup_error": "PinChanged"}]
        resources.stop.return_value = {"complete": False}
        budget.resource_failure = ("output", "overflow")
        result = baseline.cleanup(None, False, None, None, None, processes, resources, budget)
        self.assertGreaterEqual(len(result["errors"]), 2)


class StreamLoadProtocolTest(unittest.IsolatedAsyncioTestCase):
    async def test_expiring_backlog_does_not_finish_join_while_active_request_remains(self):
        queue, results = asyncio.Queue(maxsize=3), {}
        for index in range(3):
            queue.put_nowait({"index": index, "worker": 0, "offset_ns": index * baseline.NANO})
        active = await queue.get()
        waiter = asyncio.create_task(queue.join())
        await asyncio.sleep(0)
        baseline.expire_pending(queue, results, "warmup", 0, 100 * baseline.NANO)
        await asyncio.sleep(0)
        self.assertFalse(waiter.done())
        self.assertEqual([1, 2], list(results))
        self.assertEqual(0, active["index"])
        queue.task_done()
        await asyncio.wait_for(waiter, .1)
        self.assertTrue(queue.empty())

    async def test_scheduler_expiry_never_reads_body_or_calls_upload(self):
        arrivals = [{"index": 0, "worker": 0, "offset_ns": 0, "rows": 1000, "first_id": 0}]
        plan = {"window_seconds": 600, "concurrency": 1,
                "queue_model": {"capacities": {"warmup": [1]}}}
        budget, archive, metrics = Mock(), Mock(), Mock()
        budget.stream_load_request_results = {}
        metrics.boundary.return_value = {}
        archive.write.return_value = {"path": "offline"}
        calls = iter([0])
        def now():
            return next(calls, 100 * baseline.NANO)
        async def immediate(awaitable, *_):
            return await awaitable
        with tempfile.TemporaryDirectory() as temporary, patch.object(baseline.time, "monotonic_ns", side_effect=now), \
                patch.dict(baseline.LIMITS, {"warmup_seconds": 0}), \
                patch.object(baseline, "wait_io", side_effect=immediate), \
                patch.object(baseline, "upload", new_callable=AsyncMock) as upload, \
                patch.object(baseline, "read_batch", side_effect=AssertionError("Expired body read")):
            with self.assertRaisesRegex(ValueError, "dropped, failed"):
                await baseline.run_phase(plan, {}, 1, "owned", "warmup", arrivals, [], budget,
                                         archive, metrics, Path(temporary))
            upload.assert_not_called()
        self.assertEqual("DEADLINE_EXPIRED_NOT_SENT", budget.stream_load_request_results["warmup"][0]["status"])

    def reader(self, data):
        reader = asyncio.StreamReader(limit=baseline.LIMITS["header_bytes"])
        reader.feed_data(data)
        reader.feed_eof()
        return reader

    def budget(self):
        return baseline.support.Budget(10)

    async def test_original_timeout_header_is_explicit_and_separate_from_client_deadline(self):
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
        trace = {"component": "be"}
        with patch.object(baseline.support, "validate_live_identity", return_value=True), \
                patch.object(asyncio, "open_connection", new=AsyncMock(return_value=(self.reader(raw), writer))):
            status, _, _, _ = await baseline.exchange(8040, "/api/a/b/_stream_load", "token", "label", b"row\n", True,
                                                       time.monotonic() + 2, self.budget(), {}, trace)
        self.assertEqual(200, status)
        header = writer.write.call_args_list[0].args[0]
        self.assertIn(b"\r\ntimeout: 60\r\n", header)
        self.assertEqual(60, baseline.LIMITS["server_timeout_seconds"])
        self.assertEqual(60, baseline.LIMITS["request_seconds_from_arrival"])
        self.assertTrue(trace["request_headers_write_attempted"])
        self.assertTrue(trace["local_transport_closed"])

    async def assert_changed_batch_stops_before_HTTP(self, enlarged):
        with tempfile.TemporaryDirectory() as temporary:
            data = baseline.model_record(0)
            path = Path(temporary) / "batch.csv"
            path.write_bytes(data + b"x" * 4096 if enlarged else b"x" + data[1:])
            batch = {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            item = {"index": 0, "worker": 0, "offset_ns": 0, "first_id": 0, "rows": 1}
            sizes, original_open = [], Path.open
            class Reader:
                def __init__(self, stream):
                    self.stream = stream

                def read(self, maximum=-1):
                    sizes.append(maximum)
                    if not 0 <= maximum <= len(data) + 1:
                        raise AssertionError("unbounded or oversized read")
                    return self.stream.read(maximum)
            @contextlib.contextmanager
            def tracked_open(opened_path, *args, **kwargs):
                with original_open(opened_path, *args, **kwargs) as stream:
                    yield Reader(stream)
            with patch.object(Path, "open", new=tracked_open), \
                    patch.object(baseline, "exchange", side_effect=AssertionError("HTTP must not start")) as exchange:
                result = await baseline.upload({}, {}, 8081, "lp012w_" + "a" * 24, "measurement_rows",
                                               "measurement", item, batch, time.monotonic_ns(), self.budget(), Mock(), {})
            self.assertEqual([len(data) + 1], sizes)
            self.assertEqual("FAILED_OR_COMMIT_UNKNOWN", result["status"])
            self.assertEqual("ValueError", result["error_class"])
            self.assertEqual([], result["hops"])
            exchange.assert_not_called()

    async def test_expanded_batch_is_read_with_bound_and_never_uploaded(self):
        await self.assert_changed_batch_stops_before_HTTP(enlarged=True)

    async def test_same_length_replacement_is_rejected_before_upload(self):
        await self.assert_changed_batch_stops_before_HTTP(enlarged=False)

    async def test_headers_reject_duplicates_and_truncation(self):
        for raw in (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1", b"HTTP/1.1 200 OK\r\n folded\r\n\r\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                await baseline.read_headers(self.reader(raw), time.monotonic() + 2, self.budget())

    async def test_original_FE_three_vary_lines_are_one_legal_list(self):
        # Original archived LP012 307 has these three Vary lines; no server is started here.
        raw = (b"HTTP/1.1 307 Temporary Redirect\r\nVary: Origin\r\n"
               b"Vary: Access-Control-Request-Method\r\nVary: Access-Control-Request-Headers\r\n"
               b"Location: http://127.0.0.1:28040/api/owned/table/_stream_load?\r\n"
               b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        status, fields = await baseline.read_headers(self.reader(raw), time.monotonic() + 2, self.budget())
        self.assertEqual(307, status)
        self.assertEqual("Origin, Access-Control-Request-Method, Access-Control-Request-Headers", fields["vary"])
        self.assertEqual("0", fields["content-length"])

    async def test_vary_field_names_are_case_insensitive_and_wildcard_remains_wildcard(self):
        raw = b"HTTP/1.1 307 Redirect\r\nVary: Origin\r\nvArY: *\r\nVARY: Accept-Encoding\r\n\r\n"
        _, fields = await baseline.read_headers(self.reader(raw), time.monotonic() + 2, self.budget())
        self.assertEqual("*", fields["vary"])

    async def test_vary_exception_does_not_relax_singleton_or_unknown_headers(self):
        for field in ("Content-Length", "Transfer-Encoding", "Location", "Authorization", "Set-Cookie", "X-Unknown"):
            raw = (f"HTTP/1.1 307 Redirect\r\nVary: Origin\r\nVary: Accept-Encoding\r\n"
                   f"{field}: first\r\n{field.lower()}: second\r\n\r\n").encode("ascii")
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Ambiguous duplicate HTTP header"):
                await baseline.read_headers(self.reader(raw), time.monotonic() + 2, self.budget())

    async def test_invalid_vary_list_is_rejected(self):
        for value in ("Origin; invalid", "*, Origin", "invalid field name"):
            raw = f"HTTP/1.1 307 Redirect\r\nVary: {value}\r\n\r\n".encode("ascii")
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "Invalid Vary field list"):
                await baseline.read_headers(self.reader(raw), time.monotonic() + 2, self.budget())

    async def test_chunked_response_is_complete_and_bounded(self):
        data = await baseline.read_body(self.reader(b"2\r\n{}\r\n0\r\n\r\n"), {"transfer-encoding": "chunked"},
                                        time.monotonic() + 2, self.budget())
        self.assertEqual(b"{}", data)
        for headers, raw in (({"transfer-encoding": "chunked", "content-length": "2"}, b""),
                             ({"content-length": "65537"}, b""),
                             ({"transfer-encoding": "chunked"}, b"10001\r\n"),
                             ({"transfer-encoding": "gzip"}, b"")):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                await baseline.read_body(self.reader(raw), headers, time.monotonic() + 2, self.budget())

    async def test_absolute_deadline_applies_even_to_a_silent_stream(self):
        with self.assertRaises(ValueError):
            await baseline.read_headers(asyncio.StreamReader(), time.monotonic() - 1, self.budget())

    async def test_completion_after_deadline_is_rejected_even_when_wait_returns_done(self):
        future = asyncio.get_running_loop().create_future()
        future.set_result(b"completed-body")
        clock = Mock(side_effect=(0, 2))
        with self.assertRaises(baseline.LateIo) as error:
            await baseline.wait_io(future, 1, self.budget(), clock=clock)
        self.assertEqual(b"completed-body", error.exception.result)

    async def test_complete_late_content_length_body_remains_available_for_ACK_classification(self):
        async def late(awaitable, _deadline, _budget):
            raise baseline.LateIo(await awaitable)
        with patch.object(baseline, "wait_io", new=AsyncMock(side_effect=late)):
            with self.assertRaises(baseline.LateBody) as error:
                await baseline.read_body(self.reader(b"{}"), {"content-length": "2"}, time.monotonic() + 1,
                                         self.budget())
        self.assertEqual(b"{}", error.exception.body)

    async def test_late_ACK_is_preserved_but_never_counted_as_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            data, epoch = baseline.model_record(0), time.monotonic_ns()
            path = Path(temporary) / "batch.csv"
            path.write_bytes(data)
            batch = {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            plan = {"user": "root", "password_env": "MASSDB_STREAM_ADMIN_PASSWORD"}
            item = {"index": 0, "worker": 0, "offset_ns": 0, "first_id": 0, "rows": 1}
            async def exchange(port, url, token, label, content, send_body, deadline, budget, state, trace):
                trace.update(local_transport_closed=True, request_body_bytes_sent=len(content) if send_body else 0)
                if not send_body:
                    return 307, {"location": "http://127.0.0.1:8081" + url}, b"", trace
                response = {"Status": "Success", "Label": label, "NumberTotalRows": 1, "NumberLoadedRows": 1,
                            "NumberFilteredRows": 0, "NumberUnselectedRows": 0, "TxnId": 7}
                return 200, {}, json.dumps(response).encode(), trace
            with patch.dict(os.environ, {plan["password_env"]: ""}), \
                    patch.object(baseline, "exchange", side_effect=exchange), \
                    patch.object(baseline.time, "monotonic_ns", side_effect=(epoch, epoch + 61 * baseline.NANO)):
                result = await baseline.upload(plan, {"http_port": 8030}, 8081, "lp012w_" + "a" * 24,
                                               "measurement_rows", "measurement", item, batch, epoch,
                                               self.budget(), Mock(), {})
            self.assertEqual("ACK_LATE", result["status"])
            self.assertEqual(7, result["txn_id"])
            self.assertTrue(result["acknowledged_commit_retained"])
            self.assertEqual(0, baseline.latency_summary([result], epoch, 600)["ack_success_batches"])

    async def test_failed_close_aborts_transport_and_requires_completed_close_waiter(self):
        writer = Mock()
        writer.wait_closed = AsyncMock()
        original_wait = asyncio.wait_for
        calls = 0
        async def fail_first(awaitable, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                # The shield future may be cancelled; the underlying close task must survive.
                awaitable.cancel()
                raise asyncio.TimeoutError()
            return await original_wait(awaitable, timeout)
        trace, budget = {"local_transport_closed": False}, self.budget()
        with patch.object(asyncio, "wait_for", side_effect=fail_first):
            await baseline.close_transport(writer, trace, budget)
        writer.transport.abort.assert_called_once()
        self.assertTrue(trace["local_transport_closed"])
        self.assertTrue(trace["close_task_terminated"])
        self.assertEqual("TimeoutError", trace["close_error_class"])
        self.assertIsNone(budget.resource_failure)

    async def test_cancel_exactly_during_close_exits_worker_instead_of_waiting_for_next_item(self):
        writer, gate, continued = Mock(), asyncio.Event(), asyncio.Event()
        writer.wait_closed = AsyncMock(side_effect=gate.wait)
        writer.transport.abort.side_effect = gate.set
        trace, budget = {"local_transport_closed": False}, self.budget()
        async def worker():
            await baseline.close_transport(writer, trace, budget)
            continued.set()
            await asyncio.Queue().get()
        task = asyncio.create_task(worker())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
        self.assertFalse(continued.is_set())
        self.assertTrue(task.done())
        self.assertTrue(trace["local_transport_closed"])
        writer.transport.abort.assert_called_once()

    async def test_completed_connection_handle_is_kept_before_resource_checkpoint_error(self):
        future = asyncio.get_running_loop().create_future()
        reader, writer = object(), object()
        future.set_result((reader, writer))
        budget = Mock()
        budget.checkpoint.side_effect = (None, ValueError("resource failure"))
        kept = []
        with self.assertRaises(ValueError):
            await baseline.wait_io(future, time.monotonic() + 2, budget, on_result=kept.append)
        self.assertEqual([(reader, writer)], kept)

    async def test_late_connection_still_closes_its_actual_writer(self):
        writer = Mock()
        writer.wait_closed = AsyncMock()
        trace = {}
        async def late(awaitable, deadline, budget, **kwargs):
            value = await awaitable
            kwargs["on_result"](value)
            raise baseline.LateIo(value)
        with patch.object(baseline.support, "validate_live_identity", return_value=True), \
                patch.object(asyncio, "open_connection", new=AsyncMock(return_value=(self.reader(b""), writer))), \
                patch.object(baseline, "wait_io", side_effect=late):
            with self.assertRaises(baseline.LateIo):
                await baseline.exchange(8030, "/api/a/b/_stream_load", "token", "label", b"row\n", False,
                                        time.monotonic() + 1, self.budget(), {}, trace)
        writer.close.assert_called_once()
        self.assertTrue(trace["connected"])
        self.assertTrue(trace["local_transport_closed"])
        self.assertFalse(trace["request_headers_handed_to_writer"])

    async def test_cancellation_after_complete_BE_response_retains_ACK_and_raw_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            data, epoch = baseline.model_record(0), time.monotonic_ns()
            path = Path(temporary) / "batch.csv"
            path.write_bytes(data)
            batch = {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            plan = {"user": "root", "password_env": "MASSDB_STREAM_ADMIN_PASSWORD"}
            item = {"index": 0, "worker": 0, "offset_ns": 0, "first_id": 0, "rows": 1}
            archive, results = Mock(), {}
            async def exchange(port, url, token, label, content, send_body, deadline, budget, state, trace):
                trace.update(local_transport_closed=True, request_body_bytes_sent=len(content) if send_body else 0)
                if not send_body:
                    return 307, {"location": "http://127.0.0.1:8081" + url}, b"", trace
                response = {"Status": "Success", "Label": label, "NumberTotalRows": 1, "NumberLoadedRows": 1,
                            "NumberFilteredRows": 0, "NumberUnselectedRows": 0, "TxnId": 9}
                raise baseline.ResponseInterrupted((200, {}, json.dumps(response).encode(), trace))
            with patch.dict(os.environ, {plan["password_env"]: ""}), \
                    patch.object(baseline, "exchange", side_effect=exchange), self.assertRaises(asyncio.CancelledError):
                await baseline.upload(plan, {"http_port": 8030}, 8081, "lp012w_" + "a" * 24, "measurement_rows",
                                      "measurement", item, batch, epoch, self.budget(), archive, results)
            self.assertEqual("ACK_CANCELLED_AFTER_RESPONSE", results[0]["status"])
            self.assertEqual(9, results[0]["txn_id"])
            archive.write.assert_called_once()

    async def test_cancelled_BE_send_retains_intent_and_partial_transport_progress(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = baseline.model_record(0)
            path = Path(temporary) / "batch.csv"
            path.write_bytes(data)
            batch = {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            plan = {"user": "root", "password_env": "MASSDB_STREAM_ADMIN_PASSWORD"}
            database = "lp012w_" + "a" * 24
            item = {"index": 0, "worker": 0, "offset_ns": 0, "first_id": 0, "rows": 1}
            results = {}
            async def exchange(port, url, token, label, content, send_body, deadline, budget, state, trace):
                if not send_body:
                    trace.update(local_transport_closed=True, request_body_bytes_sent=0)
                    return 307, {"location": "http://127.0.0.1:8081" + url}, b"", trace
                trace.update(connected=True, request_body_bytes_handed_to_writer=128,
                             request_body_bytes_sent=0, local_transport_closed=True)
                raise asyncio.CancelledError()
            with patch.dict(os.environ, {plan["password_env"]: ""}), \
                    patch.object(baseline, "exchange", side_effect=exchange), self.assertRaises(asyncio.CancelledError):
                await baseline.upload(plan, {"http_port": 8030}, 8081, database, "measurement_rows", "measurement",
                                      item, batch, time.monotonic_ns(), self.budget(), Mock(), results)
            self.assertEqual("FAILED_OR_COMMIT_UNKNOWN", results[0]["status"])
            self.assertEqual(128, results[0]["hops"][1]["request_body_bytes_handed_to_writer"])
            self.assertIn("finished_monotonic_ns", results[0])
            self.assertEqual("TERMINATION_NOT_PROVEN", results[0]["server_transaction_state"])

    async def test_unexpected_FE_continue_fails_and_closes_instead_of_waiting_for_body(self):
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        trace = {}
        with patch.object(baseline.support, "validate_live_identity", return_value=True), \
                patch.object(asyncio, "open_connection", new=AsyncMock(return_value=(
                    self.reader(b"HTTP/1.1 100 Continue\r\n\r\n"), writer))):
            with self.assertRaises(ValueError):
                await baseline.exchange(8030, "/api/a/b/_stream_load", "token", "label", b"row\n", False,
                                        time.monotonic() + 2, self.budget(), {}, trace)
        writer.close.assert_called_once()
        self.assertTrue(trace["local_transport_closed"])
        self.assertEqual([100], trace["interim_statuses"])
        self.assertEqual(0, trace["request_body_bytes_handed_to_writer"])


if __name__ == "__main__":
    unittest.main()
