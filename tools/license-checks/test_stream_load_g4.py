#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Current G4 offline model/transport-boundary/audit tests; no real database or HTTP requests."""

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import stream_load_baseline as runner


def context(**changes):
    value = {"group": "G4", "seed": 20260922, "phase": "DIAGNOSTIC", "variant": "A", "license_state": "VALID",
             "concurrency": 1, "batch_rows": 1000, "connection_mode": "stream_load_two_hop_close", "rate": 3.5,
             "warmup_seconds": 1, "duration_seconds": 1, "barrier_timeout_seconds": 5,
             "window_id": "G4-offline-0", "cell_id": "G4-stream-c1-b1000", "pair_id": 0,
             "identity": {name: "a" * (40 if name == "source_commit" else 64) for name in runner.p4.IDENTITY_FIELDS},
             "business_workload_sha256": "0" * 64}
    value.update(changes)
    return value


def source_file(root, rows):
    path = root / "input.csv"
    path.write_bytes(b"".join(runner.model_record(i) for i in range(rows)))
    runner.save(path.with_suffix(".csv.json"), {"case_id": "LP-012", "rows": rows, "seed": runner.SEED,
                "row_bytes_including_lf": 128, "columns": ["id", "grp", "v", "payload"], "id_start": 0,
                "input_path": str(path), "input_bytes": rows * 128, "input_sha256": runner.digest(path)})
    return path


def licensed(status="EXPIRED", **changes):
    value = {"status": status, "administrator": "true", "recovery_ready": "true", "pending": "null",
             "active": '{"fingerprint":"abc"}', "trusted_utc": "200", "expires_at": "100",
             "applied_version": "5", "highest_sequence": "3", "clock_epoch": "1"}
    if status in ("VALID", "EXPIRING"):
        value["expires_at"] = "300"
    value.update(changes)
    return value


class G4ModelTest(unittest.TestCase):
    def test_scope_keeps_only_current_concurrency_batches_and_finite_fractional_rate(self):
        runner.g4_validate_context(context())
        for key, changed in (("concurrency", 32), ("batch_rows", 1), ("rate", float("nan")), ("rate", 0),
                             ("seed", 1), ("password", "do-not-save"), ("license_state", "MISSING")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.g4_validate_context(context(**{key: changed}))

    def test_formal_short_or_small_fixture_cannot_pass_as_formal_window(self):
        with self.assertRaisesRegex(ValueError, "180s"):
            runner.g4_validate_context(context(phase="AA"))
        value = context(phase="AA", warmup_seconds=180, duration_seconds=600, rate=1)
        # Isolate sample validation from unrelated snapshot existence; never reduce the sample gate.
        with patch.object(runner, "g4_validate_context"):
            with self.assertRaisesRegex(ValueError, "sample shortage"):
                runner.g4_schedule(value, {"warmup": [1], "measurement": list(range(1000))})

    def test_each_measurement_request_has_unique_nonoverlapping_input_range(self):
        value = context(concurrency=8, batch_rows=10000)
        schedule = runner.g4_schedule(value, {"warmup": [1, 2], "measurement": list(range(1, 20))})
        self.assertEqual([i * 10000 for i in range(19)], [x["first_id"] for x in schedule["measurement"]])
        self.assertEqual([i % 8 for i in range(19)], [x["worker"] for x in schedule["measurement"]])
        self.assertEqual(schedule["warmup"][0]["first_id"], 0)
        self.assertEqual(schedule["rows_replayed_in_measurement"], 0)

    def test_business_hash_keeps_batch_workers_protocol_input_but_excludes_variant_rate_window_state(self):
        original = runner.g4_business_binding(context(), {"sha256": "a" * 64})
        changed = context(variant="B", license_state="EXPIRED", rate=7, duration_seconds=600)
        self.assertEqual(original, runner.g4_business_binding(changed, {"sha256": "a" * 64}))
        for value, source in ((context(batch_rows=10000), "a"), (context(concurrency=8), "a"), (context(), "b")):
            self.assertNotEqual(original, runner.g4_business_binding(value, {"sha256": source * 64}))

    def test_valid_and_expiring_are_query_usable_but_expired_requires_actual_expiry(self):
        for status in ("VALID", "EXPIRING"):
            runner.g4_check_license(licensed(status), "VALID")
        runner.g4_check_license(licensed(), "EXPIRED")
        for value, target in ((licensed(), "VALID"), (licensed("EXPIRING"), "EXPIRED"),
                              (licensed(trusted_utc="99"), "EXPIRED"), (licensed(pending="{}"), "EXPIRED")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.g4_check_license(value, target)

    def test_cross_window_license_version_clock_pending_changes_disqualify(self):
        plan = {"context": context(variant="B", license_state="EXPIRED")}
        before = {"values": licensed()}
        runner.g4_stable_license(plan, before, {"values": licensed(trusted_utc="220")})
        for key, changed in (("active", "different"), ("pending", "{}"), ("applied_version", "6"),
                             ("clock_epoch", "2"), ("expires_at", "150"), ("trusted_utc", "199")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.g4_stable_license(plan, before, {"values": licensed(**{key: changed})})

    def test_original_A_explicitly_has_no_license_not_a_forged_valid_state(self):
        with tempfile.TemporaryDirectory() as directory:
            sql = Mock()
            value = runner.g4_observe_license({"context": context(license_state="EXPIRED")}, sql, Path(directory), "before", "EXPIRED")
            self.assertEqual(value["values"]["status"], "ORIGINAL_A_NO_LICENSE")
            sql.one.assert_not_called()

    def test_rate_schedule_reuses_actual_java_fractional_generator_offline(self):
        javac = shutil.which("javac")
        if javac is None:
            self.skipTest("JDK17 required")
        with tempfile.TemporaryDirectory() as directory:
            result = runner.g4_generate_schedule(context(rate=10.5), Path(directory), Path(javac).resolve().parent.parent)
            self.assertGreater(len(result["measurement"]), 0)
            self.assertEqual(result["rate_batches_per_second"], 10.5)


class G4InputTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="g4-input-offline-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        patcher = patch.object(runner, "owned", side_effect=Path)
        patcher.start()
        self.addCleanup(patcher.stop)
        path = source_file(self.root, 3000)
        self.plan = {"batch_rows": 1000, "input": runner.g4_input_binding(path)}
        runner.save(self.root / "arrivals.json", runner.g4_schedule(context(), {"warmup": [1], "measurement": [1, 2]}))

    def test_full_input_checked_once_without_copy_and_each_pread_is_one_bounded_batch(self):
        batches = runner.prepare_g4_batches(self.plan, self.root, Mock())
        self.assertEqual(len(batches), 2)
        self.assertFalse((self.root / "batches").exists())
        self.assertEqual([x["offset"] for x in batches], [0, 128000])
        self.assertEqual({x["path"] for x in batches}, {self.plan["input"]["path"]})
        with patch.object(runner.os, "pread", wraps=os.pread) as read:
            result = runner.read_batch(batches[1])
            self.assertEqual(len(result), 128000)
            self.assertEqual(read.call_args.args[1:], (128000, 128000))
        self.assertTrue(result.startswith(runner.model_record(1000)))
        self.assertEqual(runner.read_json(self.root / "batches.json")["copied_input_bytes"], 0)

    def test_corrupt_unused_input_suffix_is_still_rejected_by_full_model(self):
        path = Path(self.plan["input"]["path"])
        with path.open("r+b") as stream:
            stream.seek(2500 * 128 + 16)
            stream.write(b"!")
        with self.assertRaisesRegex(ValueError, "row model"):
            runner.prepare_g4_batches(self.plan, self.root, Mock())

    def test_changed_active_slice_or_truncation_fails_before_upload(self):
        batches = runner.prepare_g4_batches(self.plan, self.root, Mock())
        path = Path(self.plan["input"]["path"])
        with path.open("r+b") as stream:
            stream.seek(128001)
            stream.write(b"!")
        with self.assertRaisesRegex(ValueError, "changed before upload"):
            runner.read_batch(batches[1])
        with self.assertRaisesRegex(ValueError, "outside"):
            runner.read_batch(dict(batches[0], offset=path.stat().st_size))

    def test_slice_limit_rejects_more_than_one_supported_maximum_batch(self):
        with self.assertRaisesRegex(ValueError, "byte bound"):
            runner.read_batch({"bytes": 1280001, "offset": 0})

    def test_large_input_generation_checks_real_disk_before_calling_existing_generator(self):
        with patch.object(runner.shutil, "disk_usage", return_value=Mock(free=28 * 1024**3)), \
                patch.object(runner.fixture, "generate", side_effect=AssertionError("must not generate")):
            with self.assertRaisesRegex(ValueError, "Insufficient disk"):
                runner.generate_g4_input(self.root / "too-big.csv", 300000000)
        with patch.object(runner.fixture, "generate", side_effect=AssertionError("must not overwrite")):
            with self.assertRaisesRegex(ValueError, "overwrite"):
                runner.generate_g4_input(self.plan["input"]["path"], 1000)


class G4BarrierAndMetricsTest(unittest.TestCase):
    def test_state_receipt_requires_live_nonce_and_plan_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = {"context": context(), "launch_token": "a" * 32}
            runner.save(root / "plan.json", plan)
            def acknowledge():
                target = root / "g4-state-ready.json"
                while not target.exists():
                    time.sleep(.001)
                value = runner.read_json(target)
                value["acknowledged_monotonic_ns"] = time.monotonic_ns()
                runner.save(root / "g4-state-ack.json", value)
            thread = threading.Thread(target=acknowledge)
            thread.start()
            budget = runner.support.Budget(5)
            result = runner.g4_barrier(plan, root, "state", budget)
            thread.join(timeout=1)
            self.assertEqual(result["launch_token"], plan["launch_token"])
            self.assertTrue((root / "g4-state-accepted.json").is_file())
            with self.assertRaisesRegex(ValueError, "cannot be reused"):
                runner.g4_barrier(plan, root, "state", budget)

    def test_stale_preexisting_ack_cannot_bypass_waiting_for_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = {"context": context(), "launch_token": "a" * 32}
            runner.save(root / "plan.json", plan)
            runner.save(root / "g4-state-ack.json", {"nonce": "old"})
            with self.assertRaisesRegex(ValueError, "Stale"):
                runner.g4_barrier(plan, root, "state", runner.support.Budget(5))

    def test_formal_observer_absence_fails_while_diagnostic_is_explicit(self):
        with self.assertRaisesRegex(ValueError, "running external observer"):
            runner.g4_observer_launch({"context": context(phase="AA")}, {})
        result = runner.g4_observer_evidence({"context": context()}, {}, {}, {}, {})
        self.assertEqual(result["status"], "DIAGNOSTIC_NO_OBSERVER")
        self.assertFalse(result["formal_qualified"])

    def test_statistics_include_queue_drain_and_unknown_failures_without_retry(self):
        rows = [{"status": "ACK_SUCCESS", "scheduled_monotonic_ns": 0, "started_monotonic_ns": 500000000,
                 "finished_monotonic_ns": 2000000000},
                {"status": "DEADLINE_EXPIRED_NOT_SENT", "scheduled_monotonic_ns": 1, "decision_monotonic_ns": 3000000000},
                {"status": "FAILED_OR_COMMIT_UNKNOWN", "error_class": "ConnectionError",
                 "scheduled_monotonic_ns": 2, "finished_monotonic_ns": 3000000000}]
        value = runner.g4_latency_summary(rows, 0, 1)
        self.assertEqual(value["success_qps"], 1 / 3)
        self.assertEqual(value["drain_seconds"], 2)
        self.assertEqual((value["error_count"], value["timeout_count"], value["retry_count"]), (2, 1, 0))
        self.assertEqual((value["p99_ms"], value["client_queue_p99_ms"], value["service_p99_ms"]), (2000, 500, 1500))


class G4WindowAuditTest(unittest.TestCase):
    def test_failed_unknown_commit_retains_phase_error_statistics_before_raising(self):
        with tempfile.TemporaryDirectory(prefix="g4-failed-phase-offline-") as directory:
            root = Path(directory)
            arrivals = runner.g4_schedule(context(), {"warmup": [1], "measurement": [1]})
            plan = {"profile": "current-g4", "concurrency": 1, "window_seconds": 1,
                    "queue_model": runner.queue_model(arrivals, 1)}
            async def failed(*args):
                item, epoch = args[6], args[8]
                return {**item, "status": "FAILED_OR_COMMIT_UNKNOWN", "error_class": "ConnectionError",
                        "scheduled_monotonic_ns": epoch + item["offset_ns"], "finished_monotonic_ns": time.monotonic_ns(),
                        "hops": [{"component": "be", "request_body_bytes_handed_to_writer": 128000,
                                  "local_transport_closed": True}]}
            metrics = Mock()
            metrics.boundary.return_value = {}
            with patch.object(runner, "upload", side_effect=failed), self.assertRaisesRegex(ValueError, "unknown"):
                asyncio.run(runner.run_phase(plan, {}, 0, "lp012w_" + "a" * 24, "measurement", arrivals["measurement"], [{}],
                                             runner.support.Budget(5), runner.Archive(root), metrics, root))
            stats = runner.read_json(root / "measurement-statistics.json")
            self.assertEqual((stats["scheduled_requests"], stats["error_count"], stats["successful_requests"]), (1, 1, 0))
            phase = runner.read_json(root / "measurement-window.json")
            self.assertTrue(phase["server_transactions"]["server_transaction_termination_not_proven"])

    def test_full_fake_window_independent_receipts_cpu_visibility_cleanup_and_tamper(self):
        with tempfile.TemporaryDirectory(prefix="g4-window-offline-") as directory, \
                patch.object(runner, "owned", side_effect=Path):
            root = Path(directory)
            value = context()
            path = source_file(root, 2000)
            inputs = runner.g4_input_binding(path)
            value["business_workload_sha256"] = runner.g4_business_binding(value, inputs)["sha256"]
            offsets = {"warmup": [1000000], "measurement": [1000000, 2000000]}
            arrivals = runner.g4_schedule(value, offsets)
            for phase in offsets:
                (root / (phase + "-arrivals.bin")).write_bytes(b"".join(struct.pack(">q", x) for x in offsets[phase]))
            runner.save(root / "arrivals.json", arrivals)
            plan = {"profile": "current-g4", "context": value, "boot_id": runner.p4.boot_id(),
                    "concurrency": 1, "batch_rows": 1000, "window_seconds": 1, "warmup_seconds": 1, "cpu": 4,
                    "input": inputs, "business_binding": runner.g4_business_binding(value, inputs),
                    "arrivals_sha256": runner.digest(root / "arrivals.json"), "launch_token": "a" * 32,
                    "queue_model": runner.queue_model(arrivals, 1), "bindings": {"files": {},
                        "pins": {name: {"start_ticks": 1} for name in ("fe", "be")}}, "current_bindings": {}}
            runner.save(root / "plan.json", plan)
            database = "lp012w_" + "a" * 24
            runner.save(root / "database-owner.json", {"database": database})
            budget = runner.support.Budget(30)
            entries = runner.prepare_g4_batches(plan, root, budget)
            def barrier(stage):
                def acknowledge():
                    target = root / ("g4-" + stage + "-ready.json")
                    while not target.exists():
                        time.sleep(.001)
                    ack = runner.read_json(target)
                    ack["acknowledged_monotonic_ns"] = time.monotonic_ns()
                    runner.save(root / ("g4-" + stage + "-ack.json"), ack)
                thread = threading.Thread(target=acknowledge)
                thread.start()
                result = runner.g4_barrier(plan, root, stage, budget)
                thread.join(1)
                return result
            state_ack = barrier("state")
            runner.g4_observe_license(plan, Mock(), root, "before", "VALID")
            class Boundaries:
                phase = "setup"
                tick = 0
                def boundary(self, label):
                    begin = time.monotonic_ns()
                    self.tick += 1
                    processes = {name: {"start_ticks": 1, "user_cpu_ticks": self.tick, "system_cpu_ticks": self.tick}
                                 for name in ("fe", "be")}
                    return {"started_monotonic_ns": begin, "finished_monotonic_ns": time.monotonic_ns(), "processes": processes}
            metrics = Boundaries()
            async def upload(plan, state, port, database, table, phase, item, batch, epoch, budget, archive, results):
                start = time.monotonic_ns()
                runner.read_batch(batch)
                label = f"{database}_{phase}_w00_c{item['worker']:02d}_b{item['index']:05d}"
                txn = item["index"] + (1 if phase == "warmup" else 100)
                receipt = {"Status": "Success", "Label": label, "NumberTotalRows": 1000,
                           "NumberLoadedRows": 1000, "NumberFilteredRows": 0, "NumberUnselectedRows": 0, "TxnId": txn}
                original = archive.write(f"{phase}-{item['index']:05d}-be.json", json.dumps(receipt).encode())
                end = time.monotonic_ns()
                return {**item, "phase": phase, "label": label, "txn_id": txn, "status": "ACK_SUCCESS",
                        "batch_sha256": batch["sha256"], "scheduled_monotonic_ns": epoch + item["offset_ns"],
                        "started_monotonic_ns": start, "finished_monotonic_ns": end,
                        "latency_ns_including_queue": end - epoch - item["offset_ns"],
                        "acknowledged_commit_retained": True, "original_be_response": original,
                        "hops": [{"component": "fe", "http_status": 307, "local_transport_closed": True},
                                 {"component": "be", "http_status": 200, "local_transport_closed": True, "request_body_bytes_sent": 128000}]}
            report = {"status": "CURRENT_G4_RAW_WINDOW_COMPLETE", "plan_sha256": runner.digest(root / "plan.json"),
                      "actual_client_affinity": [4],
                      "cleanup": {"errors": [], "database_absent": True, "server_transaction_termination_not_proven": False}}
            requests_by_phase = {}
            with patch.object(runner, "upload", side_effect=upload):
                for phase in ("warmup", "measurement"):
                    window, requests = asyncio.run(runner.run_phase(plan, {}, 0, database, phase, arrivals[phase], entries,
                                                                    budget, runner.Archive(root), metrics, root))
                    requests_by_phase[phase] = requests
                    report[phase] = {"window": window, "statistics": runner.g4_latency_summary(requests, window["epoch_monotonic_ns"], 1)}
            runner.g4_observe_license(plan, Mock(), root, "after", "VALID")
            oracle_ack = barrier("oracle")
            runner.g4_observe_license(plan, Mock(), root, "restored", "VALID")
            class Sql:
                sequence = 0
                def one(self, query):
                    self.sequence += 1
                    count = 1 if ".warmup_rows" in query else 2
                    if query.startswith("SELECT COUNT(*)"):
                        rows = [{"n": str(count * 1000), "d": str(count * 1000)}]
                    else:
                        first, stop = map(int, re.search(r"HAVING batch_index >= (\d+) AND batch_index < (\d+)", query).groups())
                        rows = [{"batch_index": str(i), "n": "1000", "d": "1000", "bad": "0"} for i in range(first, stop)]
                    result = {"sql": query, "success": True, "columns": [{"name": name} for name in rows[0]], "rows": rows}
                    runner.save(root / ("sql-%04d.result.json" % self.sequence), {"success": True, "statements": [result]})
                    return result
            sql = Sql()
            for phase in ("warmup", "measurement"):
                report[phase]["visibility"] = runner.g4_visibility(sql, database, phase, requests_by_phase[phase], 1000, budget, root)
            report["observer"] = runner.g4_observer_evidence(plan, state_ack, oracle_ack, report["warmup"]["window"], report["measurement"]["window"])
            runner.save(root / "report.json", report)
            audit = runner.g4_audit_window(root)
            self.assertEqual(audit["status"], "DIAGNOSTIC_VERIFIED")
            self.assertFalse(audit["formal_performance_pass"])
            self.assertEqual(audit["window"]["successful_requests"], 2)
            self.assertEqual(audit["window"]["monotonic_clock_domain"], "controller_monotonic_exact")
            self.assertGreater(audit["window"]["metrics"]["fe_cpu_seconds_per_success"], 0)
            runner.save(root / "g4-audit.json", audit)
            self.assertEqual(runner.g4_audit_window(root), audit)
            # A green summary cannot conceal actual post-window content corruption.
            oracle_path = root / "sql-0003.result.json"
            original = oracle_path.read_bytes()
            wrong = runner.read_json(oracle_path)
            wrong["statements"][0]["rows"][0]["bad"] = "1"
            runner.save(oracle_path, wrong)
            with self.assertRaisesRegex(ValueError, "corrupt"):
                runner.g4_audit_window(root)
            oracle_path.write_bytes(original)
            # Good content cannot validate CPU samples spanning another process lifetime.
            window = report["measurement"]["window"]
            window["end_boundary"]["processes"]["fe"]["start_ticks"] = 2
            runner.save(root / "measurement-window.json", window)
            runner.save(root / "report.json", report)
            with self.assertRaisesRegex(ValueError, "CPU process changed"):
                runner.g4_audit_window(root)


class G4ObserverTest(unittest.TestCase):
    def test_observer_raw_samples_must_cover_both_phases_with_same_live_targets(self):
        with tempfile.TemporaryDirectory(prefix="g4-observer-offline-") as directory:
            root = Path(directory)
            source = str(Path(runner.observer.__file__).resolve())
            pins = {"fe": {"pid": 101, "start_ticks": 10}, "be": {"pid": 102, "start_ticks": 20}}
            plan = {"context": context(phase="AA"), "bindings": {"namespace": "owned", "pins": pins,
                                                                    "files": {source: runner.digest(source)}}}
            launch = {"status": "RUNNING", "namespace": "owned", "services": pins, "started_monotonic_ns": 0,
                      "source_sha256": {"tools/license-checks/resource_observer.py": runner.digest(source)},
                      "observer_cpu_affinity": [0], "interval_seconds": 1}
            runner.save(root / "launch.json", launch)
            state_ack = {"observer_launch": runner.p4.reference(root / "launch.json"), "acknowledged_monotonic_ns": 1}
            samples = [{"sample_index": i, "started_monotonic_ns": i * runner.NANO,
                        "finished_monotonic_ns": i * runner.NANO + 1000000, "errors": [],
                        "processes": {name: dict(pin, metrics={"example": 1}) for name, pin in pins.items()}}
                       for i in range(4)]
            sample_path = root / "samples.jsonl"
            sample_path.write_text("".join(json.dumps(row) + "\n" for row in samples))
            summary = dict(launch, status="INTERRUPTED", samples=4, samples_with_errors=0, skipped_schedule_slots=0,
                           samples_sha256=runner.digest(sample_path), finished_monotonic_ns=4 * runner.NANO,
                           http_timeout_seconds=2)
            runner.save(root / "summary.json", summary)
            oracle_ack = {"observer_summary": runner.p4.reference(root / "summary.json"),
                          "observer_samples": runner.p4.reference(sample_path)}
            warm = {"epoch_monotonic_ns": runner.NANO}
            measured = {"interval_end_monotonic_ns": 3 * runner.NANO}
            result = runner.g4_observer_evidence(plan, state_ack, oracle_ack, warm, measured)
            self.assertEqual(result["status"], "VERIFIED")
            self.assertTrue(result["formal_qualified"])
            with self.assertRaisesRegex(ValueError, "does not cover"):
                runner.g4_observer_evidence(plan, state_ack, oracle_ack, warm, {"interval_end_monotonic_ns": 5 * runner.NANO})
            samples[1]["processes"]["fe"]["start_ticks"] = 999
            sample_path.write_text("".join(json.dumps(row) + "\n" for row in samples))
            summary["samples_sha256"] = runner.digest(sample_path)
            runner.save(root / "summary.json", summary)
            oracle_ack = {"observer_summary": runner.p4.reference(root / "summary.json"),
                          "observer_samples": runner.p4.reference(sample_path)}
            with self.assertRaisesRegex(ValueError, "target/metrics missing"):
                runner.g4_observer_evidence(plan, state_ack, oracle_ack, warm, measured)


if __name__ == "__main__":
    unittest.main()
