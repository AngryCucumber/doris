#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline oracle/ownership/timing failures; no Kafka, SQL, network or subprocesses."""

import argparse
import base64
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from unittest.mock import Mock

import kafka_routine_baseline as baseline


def args(**changes):
    values = dict(mode="plan", producer_workers=1, consumer_tasks=8, batch_rows=10000, cpu=0,
                  broker_port=39092, controller_port=39093)
    values.update(changes)
    return argparse.Namespace(**values)


def write_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def physical_files(output):
    rows, warm, workers, batch = 80, 24, 2, 8
    epochs = {"warmup": 1000000000, "measurement": 400000000000}
    acks, captures, offsets = [[], []], [], [0] * 8
    for phase, count, base in (("warmup", warm, rows), ("measurement", rows, 0)):
        for index in range(count):
            identifier = base + baseline.small.identifier_at(index, count)
            partition, worker = identifier % 8, (index // batch) % workers
            value = baseline.fixture.record(identifier)[:-1]
            scheduled = epochs[phase] + (index // batch) * baseline.PHASES[phase][2] * baseline.NANO // (count // batch)
            acks[worker].append({"phase": phase, "index": index, "id": identifier, "worker": worker,
                                 "batch_index": index // batch, "partition": partition, "offset": offsets[partition],
                                 "sent_ns": scheduled + 1, "ack_ns": scheduled + 2,
                                 "value_sha256": hashlib.sha256(value).hexdigest()})
            captures.append({"partition": partition, "offset": offsets[partition],
                             "key_base64": base64.b64encode(str(identifier).encode()).decode(),
                             "value_base64": base64.b64encode(value).decode()})
            offsets[partition] += 1
    for worker in range(workers):
        write_csv(output / f"acks-{worker}.csv", acks[worker])
    write_csv(output / "consumer-records.csv", captures)
    return rows, warm, workers, batch, epochs, acks, captures


def batch_files(output, batch=10000):
    report = {"producer_workers": 1, "batch_rows": batch, "owner_token": "a" * 32, "configuration_sha256": "b" * 64}
    warm = {"clock_domain": "same-jvm", "warmup_start_ns": baseline.NANO, "completed_ns": 181 * baseline.NANO}
    start = {**warm, "measurement_start_ns": 184 * baseline.NANO, "measurement_end_ns": 784 * baseline.NANO,
             "barrier_received_ns": 182 * baseline.NANO}
    values = []
    for phase, schedule in baseline.schedule(1, batch).items():
        epoch = warm["warmup_start_ns"] if phase == "warmup" else start["measurement_start_ns"]
        for item in schedule:
            scheduled = epoch + item["offset_ns"]
            values.append({"phase": phase, "batch_index": item["batch_index"], "worker": 0, "rows": batch,
                           "sent_rows": batch, "acknowledged_rows": batch, "success": True, "clock_domain": "same-jvm",
                           "owner_token": report["owner_token"], "configuration_sha256": report["configuration_sha256"],
                           "scheduled_ns": scheduled, "started_ns": scheduled + 2000000,
                           "finished_ns": scheduled + 5000000})
    write_batches(output, values)
    return report, start, warm, values


def write_batches(output, values):
    (output / "batches-0.jsonl").write_text("".join(json.dumps(value) + "\n" for value in values))


class KafkaBaselineTest(unittest.TestCase):
    def test_original_work_error_survives_secondary_stop_error(self):
        runner = baseline.CapturedProcesses.__new__(baseline.CapturedProcesses)
        process = SimpleNamespace(pid=42, poll=lambda: None)
        runner.budget = SimpleNamespace(deadline=float("inf"), resource_failure=None,
                                       checkpoint=Mock(side_effect=ValueError("first-work-failure")))
        runner.start = Mock(return_value=process)
        runner.stop = Mock(side_effect=RuntimeError("second-stop-failure"))
        runner.children = [(process, {"name": "helper"})]
        capture = Mock()
        runner.outputs = {42: capture}
        with self.assertRaisesRegex(ValueError, "first-work-failure"):
            runner.run(["never-executed"], "helper")
        capture.stop.assert_called_once()
        self.assertEqual(["RuntimeError"], runner.children[0][1]["initial_cleanup_errors"])

    def test_successful_work_with_failed_cleanup_is_failed(self):
        runner = baseline.CapturedProcesses.__new__(baseline.CapturedProcesses)
        process = SimpleNamespace(pid=42, poll=lambda: 0)
        runner.budget = SimpleNamespace(deadline=float("inf"), resource_failure=None)
        runner.start = Mock(return_value=process)
        runner.stop = Mock(side_effect=RuntimeError("stop-failure"))
        runner.children = [(process, {"name": "helper"})]
        runner.outputs = {42: Mock()}
        with self.assertRaisesRegex(RuntimeError, "stop-failure"):
            runner.run(["never-executed"], "helper")
    def test_all_shapes_keep_full_disjoint_input_and_fixed_offered_rate(self):
        for workers in (1, 8, 32):
            for batch in (1000, 10000):
                value = baseline.schedule(workers, batch)
                for phase, count, seconds in (("warmup", 3000000, 180), ("measurement", 10000000, 600)):
                    self.assertEqual(count, sum(item["rows"] for item in value[phase]))
                    self.assertEqual(0, value[phase][0]["offset_ns"])
                    self.assertLess(value[phase][-1]["offset_ns"], seconds * baseline.NANO)
                    self.assertEqual(batch * 600 * baseline.NANO // 10000000, value[phase][1]["offset_ns"])
                    self.assertTrue(all(item["worker"] == item["batch_index"] % workers for item in value[phase]))

    def test_plan_reports_producers_and_never_thirty_two_consumers(self):
        value = baseline.plan(args(producer_workers=32))
        self.assertEqual("producer_client_workers", value["definition_clarification"]["concurrency_axis"])
        self.assertEqual(8, value["routine_desired_tasks"])
        self.assertFalse(value["LP013_complete"])
        self.assertFalse(value["release_performance_pass"])
        self.assertFalse(value["p99_sample_floor_met"])

    def test_unsupported_shapes_are_rejected(self):
        for workers, batch in ((32, 200000), (2, 1000), (True, 1000), (1, True)):
            with self.assertRaises(ValueError):
                baseline.schedule(workers, batch)
        with self.assertRaises(ValueError):
            baseline.plan(args(consumer_tasks=32))

    def test_independent_model_matches_actual_generator_at_boundaries(self):
        for identifier in (0, 1, 9, 10, 1023, 1024, 99999, 100000, 9999999, 10000000, 12999999):
            self.assertEqual(baseline.fixture.record(identifier), baseline.model_record(identifier))
            self.assertEqual(128, len(baseline.model_record(identifier)))

    def test_sql_integer_model_for_nonzero_range(self):
        low, high = 99991, 100045
        value = baseline.range_expected(low, high)
        self.assertEqual(sum(range(low, high)), value["sum_id"])
        self.assertEqual(sum(i % 1024 for i in range(low, high)), value["sum_grp"])
        self.assertEqual(sum(i % 100000 for i in range(low, high)), value["sum_v"])
        self.assertEqual(high - low, value["distinct_ids"])

    def test_duplicate_json_fields_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text('{"success":false,"success":true}')
            with self.assertRaises(ValueError):
                baseline.read_json(path)

    def test_bitmap_duplicates_and_bounds(self):
        value = baseline.Bitmap(9)
        value.add(8)
        for position in (8, -1, 9, True):
            with self.assertRaises(ValueError):
                value.add(position)

    def physical(self, mutation=None):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rows, warm, workers, batch, epochs, acks, captures = physical_files(output)
            if mutation:
                mutation(acks, captures)
                for worker in range(workers):
                    write_csv(output / f"acks-{worker}.csv", acks[worker])
                write_csv(output / "consumer-records.csv", captures)
            return baseline.verify_physical(output, workers, batch, epochs, rows, warm)

    def test_complete_small_physical_oracle(self):
        value = self.physical()
        self.assertEqual(104, value["producer_rows"])
        self.assertEqual(104, value["consumer_rows"])
        self.assertEqual(832, value["disk_index_bytes"])
        self.assertTrue(value["contiguous_offsets"])

    def test_missing_ack_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda acks, _: acks[0].pop())

    def test_duplicate_ack_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda acks, _: acks[0].append(acks[0][0]))

    def test_ack_wrong_worker_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda acks, _: acks[0][0].update(worker=1))

    def test_ack_wrong_phase_partition_boundary_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda acks, _: acks[0][0].update(offset=3))

    def test_ack_wrong_input_order_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda acks, _: acks[0][0].update(id=80))

    def test_late_ack_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda acks, _: acks[0][0].update(ack_ns=100000000000))

    def test_missing_consumed_id_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda _, captures: captures.pop())

    def test_duplicate_consumed_offset_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda _, captures: captures.insert(1, captures[0]))

    def test_actual_value_corruption_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda _, captures: captures[0].update(value_base64=base64.b64encode(b"wrong").decode()))

    def test_noncanonical_key_fails(self):
        with self.assertRaises(ValueError):
            self.physical(lambda _, captures: captures[0].update(key_base64=base64.b64encode(b"+00080").decode()))

    def test_swapped_actual_offset_mapping_fails(self):
        def mutate(_, captures):
            left = captures[0]
            right = next(row for row in captures[1:] if row["partition"] == left["partition"])
            left["key_base64"], right["key_base64"] = right["key_base64"], left["key_base64"]
            left["value_base64"], right["value_base64"] = right["value_base64"], left["value_base64"]
        with self.assertRaises(ValueError):
            self.physical(mutate)

    def batch(self, mutation=None, batch=10000):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            report, start, warm, values = batch_files(output, batch)
            if mutation:
                mutation(values, start, warm)
                write_batches(output, values)
            return baseline.audit_batches(output, report, start, warm)[1]

    def test_primary_latency_includes_queue_and_batch10k_suppresses_p99(self):
        value = self.batch()
        self.assertEqual(5000000, value["p95_ns"])
        self.assertEqual(3000000, value["service_p95_ns"])
        self.assertEqual(2000000, value["dispatch_delay_p95_ns"])
        self.assertEqual(1000, value["samples"])
        self.assertIsNone(value["p99_ns"])
        self.assertFalse(value["qualified"])

    def test_full_1000_row_batches_have_ten_thousand_samples_not_ten_million(self):
        value = self.batch(batch=1000)
        self.assertEqual(10000, value["samples"])
        self.assertEqual(5000000, value["p99_ns"])
        self.assertFalse(value["qualified"])

    def test_batch_queue_not_equivalent_to_sum_of_percentiles(self):
        def mutate(values, *_):
            measured = [value for value in values if value["phase"] == "measurement"]
            for index, value in enumerate(measured):
                value["started_ns"] = value["scheduled_ns"] + (10000000 if index < 50 else 0)
                value["finished_ns"] = value["started_ns"] + (10000000 if 50 <= index < 100 else 1)
        value = self.batch(mutate)
        self.assertEqual(10000000, value["p95_ns"])
        self.assertEqual(1, value["service_p95_ns"])
        self.assertEqual(0, value["dispatch_delay_p95_ns"])

    def test_batch_schedule_tampering_fails(self):
        with self.assertRaises(ValueError):
            self.batch(lambda values, *_: values[-1].update(scheduled_ns=values[-1]["scheduled_ns"] + 1))

    def test_batch_missing_terminal_fails(self):
        with self.assertRaises(ValueError):
            self.batch(lambda values, *_: values.pop())

    def test_batch_duplicate_terminal_fails(self):
        with self.assertRaises(ValueError):
            self.batch(lambda values, *_: values.append(values[-1]))

    def test_same_worker_overlapping_batches_fail(self):
        with self.assertRaises(ValueError):
            self.batch(lambda values, *_: values[0].update(finished_ns=values[1]["started_ns"] + 1))

    def test_unknown_partial_commit_fails(self):
        with self.assertRaises(ValueError):
            self.batch(lambda values, *_: values[-1].update(success=False))

    def test_cross_jvm_clock_fails(self):
        with self.assertRaises(ValueError):
            self.batch(lambda _, start, warm: warm.update(clock_domain="another-jvm"))

    def test_cross_run_batch_owner_fails(self):
        with self.assertRaises(ValueError):
            self.batch(lambda values, *_: values[-1].update(owner_token="c" * 32))

    def test_warmup_barrier_cannot_precede_late_ack_batch(self):
        def mutate(values, start, warm):
            last = next(value for value in reversed(values) if value["phase"] == "warmup")
            last["finished_ns"] = warm["completed_ns"] + 1
        with self.assertRaises(ValueError):
            self.batch(mutate)

    def test_compressed_measurement_window_fails(self):
        with self.assertRaises(ValueError):
            self.batch(lambda _, start, warm: start.update(measurement_end_ns=start["measurement_start_ns"] + 60 * baseline.NANO))

    def test_overlap_warmup_measurement_fails(self):
        with self.assertRaises(ValueError):
            self.batch(lambda _, start, warm: start.update(measurement_start_ns=warm["warmup_start_ns"] + 1))

    def test_replaced_table_id_with_identical_schema_is_refused(self):
        original = {"db_id": "1", "table_id": "2", "show_create_sha256": "unchanged", "tablet_ids": ["3"]}
        replacement = {**original, "table_id": "4"}
        with patch.object(baseline, "table_identity", return_value=replacement):
            with self.assertRaises(ValueError):
                baseline.verify_table_owner(None, "lp013_fixed", original)

    def test_replaced_tablet_id_is_refused(self):
        original = {"db_id": "1", "table_id": "2", "show_create_sha256": "unchanged", "tablet_ids": ["3"]}
        with patch.object(baseline, "table_identity", return_value={**original, "tablet_ids": ["4"]}):
            with self.assertRaises(ValueError):
                baseline.verify_table_owner(None, "lp013_fixed", original)

    def test_unknown_create_cannot_adopt_job_or_send_sql(self):
        class Sql:
            def one(self, _):
                raise AssertionError("Unknown CREATE must not issue ownership/mutation SQL")
        with self.assertRaises(ValueError):
            baseline.verify_job_owner(Sql(), "lp013_fixed", None, {}, 39092)

    def test_replaced_job_id_is_refused_before_stop(self):
        name = "lp013_0123456789abcdef"
        table = {"db_id": "1", "table_id": "2"}
        row = {"Id": "3", "Name": name, "DbName": "license_perf", "TableName": name,
               "IsMultiTable": "false", "DataSourceType": "KAFKA", "CreateTime": "timestamp",
               "DataSourceProperties": json.dumps({"topic": name, "brokerList": "127.0.0.1:39092"})}
        owner = baseline.job_identity(row, name, table, 39092)
        class Sql:
            def one(self, statement):
                self.assert_readonly = statement.startswith("SHOW ALL ROUTINE LOAD")
                return {"rows": [{**row, "Id": "4"}]}
        with patch.object(baseline, "verify_table_owner"):
            with self.assertRaises(ValueError):
                baseline.verify_job_owner(Sql(), name, owner, table, 39092)

    def test_job_target_or_source_change_is_refused(self):
        name = "lp013_0123456789abcdef"
        row = {"Id": "3", "Name": name, "DbName": "license_perf", "TableName": name,
               "IsMultiTable": "false", "DataSourceType": "KAFKA", "CreateTime": "timestamp",
               "DataSourceProperties": json.dumps({"topic": name, "brokerList": "127.0.0.1:39092"})}
        for changes in ({"TableName": "replaced"}, {"IsMultiTable": "true"},
                        {"DataSourceProperties": json.dumps({"topic": "foreign", "brokerList": "127.0.0.1:39092"})}):
            with self.assertRaises(ValueError):
                baseline.job_identity({**row, **changes}, name, {"db_id": "1", "table_id": "2"}, 39092)


if __name__ == "__main__":
    unittest.main()
