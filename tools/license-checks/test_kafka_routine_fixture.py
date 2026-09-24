#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline validation of Kafka fixture safeguards/oracles; no broker or database is started."""

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import kafka_routine_fixture as probe


def arguments(**changes):
    result = dict(mode="plan", rows=10000, producer_workers=1, consumer_tasks=8,
                  batch_rows=1000, broker_port=39092, controller_port=39093)
    result.update(changes)
    return argparse.Namespace(**result)


def oracle_files(output, count=16):
    offsets = [0] * 8
    acknowledgements, records = [], []
    for index in range(count):
        identifier = probe.identifier_at(index, count)
        partition = identifier % 8
        value = probe.fixture.record(identifier).rstrip(b"\n")
        acknowledgements.append({"index": index, "id": identifier, "partition": partition,
                                 "offset": offsets[partition], "worker": 0,
                                 "value_sha256": hashlib.sha256(value).hexdigest()})
        records.append({"partition": partition, "offset": offsets[partition],
                        "key_base64": base64.b64encode(str(identifier).encode()).decode(),
                        "value_base64": base64.b64encode(value).decode()})
        offsets[partition] += 1
    save_csv(output / "producer-acks.csv", acknowledgements)
    save_csv(output / "consumer-records.csv", records)
    probe.fixture.save(output / "kafka-verify.json", {"begin_offsets": {str(p): 0 for p in range(8)},
                                                      "end_offsets_exclusive": probe.expected_offsets(count),
                                                      "records": count})
    return acknowledgements, records


def save_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def prepared_files(output, count=16):
    """Synthetic archive for offline provenance checks; never a real Kafka distribution."""
    archive = output / "synthetic.tgz"
    member_name = probe.PACKAGE + "/libs/kafka-clients-3.9.2.jar"
    content = b"synthetic trusted member, not an executable jar"
    with tarfile.open(archive, "w:gz") as source:
        member = tarfile.TarInfo(member_name)
        member.size = len(content)
        source.addfile(member, io.BytesIO(content))
    member_path = output / member_name
    member_path.parent.mkdir(parents=True)
    member_path.write_bytes(content)
    rows = output / "rows.csv"
    rows.write_bytes(b"".join(probe.fixture.record(probe.identifier_at(index, count)) for index in range(count)))
    report = probe.plan(arguments(rows=count))
    report.update(status="PREPARED_NOT_PROBED", archive_path=str(archive),
                  archive_sha256=probe.fixture.digest(archive), archive_sha512_actual=probe.ARCHIVE_SHA512,
                  input_sha256=probe.fixture.digest(rows), expected_rows=probe.fixture.expected(count),
                  distribution_files={member_name: probe.fixture.digest(member_path)})
    probe.fixture.save(output / "prepared.json", report)
    return report, member_path


class KafkaFixtureTest(unittest.TestCase):
    def test_plan_retains_full_matrix_without_claiming_coverage(self):
        report = probe.plan(arguments(producer_workers=32))
        self.assertFalse(report["LP013_complete"])
        self.assertFalse(report["release_performance_pass"])
        self.assertEqual(10000000, report["full_contract_retained"]["rows"])
        self.assertEqual([1, 8, 32], report["full_contract_retained"]["concurrency"])
        self.assertEqual(8, report["broker"]["partitions"])
        self.assertEqual(8, report["routine_desired_tasks"])
        self.assertEqual(32, report["producer_workers"])
        self.assertEqual(128, len(report["archive_sha512"]))

    def test_default_plan_cannot_download_compile_or_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"
            with patch.object(probe.fixture, "owned", side_effect=lambda path: path), \
                    patch.object(sys, "argv", ["fixture", "--output", str(output)]), \
                    patch.object(probe.subprocess, "Popen", side_effect=AssertionError("No child in plan")), \
                    patch.object(probe.urllib.request, "urlopen", side_effect=AssertionError("No download in plan")), \
                    patch.object(probe.socket, "socket", side_effect=AssertionError("No network in plan")):
                probe.main()
            self.assertEqual("PLANNED", json.loads((output / "plan.json").read_text())["status"])

    def test_failed_prepare_is_persisted_and_never_marked_prepared(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"
            with patch.object(probe.fixture, "owned", side_effect=lambda path: path), \
                    patch.object(sys, "argv", ["fixture", "--mode", "prepare", "--download", "--output", str(output)]), \
                    patch.object(probe, "download_archive", side_effect=OSError("TLS handshake failed")), \
                    self.assertRaises(OSError):
                probe.main()
            report = json.loads((output / "report.json").read_text())
            self.assertEqual("FAILED", report["status"])
            self.assertIn("TLS", report["error"]["message"])
            self.assertFalse((output / "prepared.json").exists())

    def test_wrong_owned_fe_port_is_rejected_before_sql(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fe/conf").mkdir(parents=True)
            (root / "fe/conf/fe.conf").write_text("query_port=9030\n")
            with patch.object(probe.fixture, "validate_cluster", return_value=(
                    {"installation": str(root), "query_port": 9031}, 8040)), \
                    patch.object(probe.fixture, "owned", side_effect=lambda path: Path(path)), \
                    patch.object(probe.subprocess, "Popen", side_effect=AssertionError("Must reject before SQL")), \
                    self.assertRaisesRegex(ValueError, "query_port"):
                probe.cluster_identity(root / "state.json")

    def test_fixed_seed_is_complete_repeatable_and_not_only_small_repeated_key_set(self):
        for rows in probe.ROWS:
            values = [probe.identifier_at(index, rows) for index in range(rows)]
            self.assertEqual(set(range(rows)), set(values))
            self.assertEqual(rows, len(values))
            self.assertEqual(values[:100], [probe.identifier_at(index, rows) for index in range(100)])
            self.assertNotEqual(list(range(100)), values[:100])
            self.assertEqual(rows, sum(probe.expected_offsets(rows).values()))

    def test_unsigned_or_modified_archive_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "bad.tgz"
            archive.write_bytes(b"not the release")
            with self.assertRaisesRegex(ValueError, "SHA-512"):
                probe.extract_archive(archive, root)
            self.assertFalse((root / probe.PACKAGE).exists())

    def test_changed_archive_is_rejected_before_inventory_or_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "changed.tgz"
            archive.write_bytes(b"not the release")
            with patch.object(probe.tarfile, "open", side_effect=AssertionError("Unverified archive opened")), \
                    self.assertRaisesRegex(ValueError, "SHA-512"):
                probe.archive_inventory(archive)

    def test_prepared_files_are_compared_with_the_actual_pinned_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared_files(root)
            with patch.object(probe.fixture, "owned", side_effect=lambda path: Path(path)), \
                    patch.object(probe, "sha512", return_value=probe.ARCHIVE_SHA512):
                self.assertEqual(root, probe.validate_prepared(root, arguments(rows=16))[0])

    def test_coordinated_member_and_prepared_manifest_edit_cannot_replace_official_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report, member = prepared_files(root)
            member.write_bytes(b"substituted distribution member")
            report["distribution_files"][str(member.relative_to(root))] = probe.fixture.digest(member)
            probe.fixture.save(root / "prepared.json", report)
            with patch.object(probe.fixture, "owned", side_effect=lambda path: Path(path)), \
                    patch.object(probe, "sha512", return_value=probe.ARCHIVE_SHA512), \
                    self.assertRaisesRegex(ValueError, "pinned official archive"):
                probe.validate_prepared(root, arguments(rows=16))

    def test_prepared_archive_sha256_claim_must_match_its_pinned_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report, _ = prepared_files(root)
            report["archive_sha256"] = "0" * 64
            probe.fixture.save(root / "prepared.json", report)
            with patch.object(probe.fixture, "owned", side_effect=lambda path: Path(path)), \
                    patch.object(probe, "sha512", return_value=probe.ARCHIVE_SHA512), \
                    self.assertRaisesRegex(ValueError, "SHA-256 provenance"):
                probe.validate_prepared(root, arguments(rows=16))

    def test_tar_traversal_and_links_are_rejected_even_if_digest_is_mocked(self):
        for name, link in [(probe.PACKAGE + "/../../escape", False), ("/absolute", False),
                           (probe.PACKAGE + "/symlink", True)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "bad.tgz"
                with tarfile.open(archive, "w:gz") as tar:
                    member = tarfile.TarInfo(name)
                    if link:
                        member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
                    tar.addfile(member, io.BytesIO())
                with patch.object(probe, "sha512", return_value=probe.ARCHIVE_SHA512), \
                        self.assertRaisesRegex(ValueError, "unsafe"):
                    probe.extract_archive(archive, root)

    def test_all_rows_offsets_and_payloads_are_recomputed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle_files(root)
            report = probe.verify_kafka(root, 16)
            self.assertEqual(16, report["acknowledged_rows"])
            self.assertEqual(16, report["independently_consumed_rows"])

    def test_duplicate_missing_wrong_worker_partition_and_corrupt_ack_fail(self):
        for change in ("duplicate", "missing", "partition", "offset", "payload", "worker"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                acks, _ = oracle_files(root)
                if change == "duplicate":
                    acks[-1] = acks[0]
                elif change == "missing":
                    acks.pop()
                else:
                    key = {"payload": "value_sha256"}.get(change, change)
                    acks[0][key] = "corrupt" if change == "payload" else 99
                save_csv(root / "producer-acks.csv", acks)
                with self.assertRaises(ValueError):
                    probe.verify_kafka(root, 16)

    def test_consumer_duplicate_hole_wrong_key_and_content_fail(self):
        for change in ("duplicate", "missing", "key_base64", "value_base64"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, records = oracle_files(root)
                if change == "duplicate":
                    records[-1] = records[0]
                elif change == "missing":
                    records.pop()
                else:
                    records[0][change] = base64.b64encode(b"wrong").decode()
                save_csv(root / "consumer-records.csv", records)
                with self.assertRaises(ValueError):
                    probe.verify_kafka(root, 16)

    def test_reported_success_or_end_offsets_cannot_replace_raw_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle_files(root)
            probe.fixture.save(root / "kafka-verify.json", {"success": True, "records": 16})
            with self.assertRaises(ValueError):
                probe.verify_kafka(root, 16)

    def test_routine_progress_uses_last_committed_not_exclusive_end_and_rejects_filters(self):
        statistic = {"errorRows": 0, "unselectedRows": 0, "loadedRows": 10000, "committedTaskNum": 8}
        progress = {key: str(value - 1) for key, value in probe.expected_offsets(10000).items()}
        row = {"State": "RUNNING", "Statistic": json.dumps(statistic), "Progress": json.dumps(progress),
               "CurrentTaskNum": "8"}
        self.assertTrue(probe.routine_progress(row, 10000)["complete"])
        wrong = dict(row, Progress=json.dumps(probe.expected_offsets(10000)))
        self.assertFalse(probe.routine_progress(wrong, 10000)["complete"])
        for field in ("errorRows", "unselectedRows"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe.routine_progress(dict(row, Statistic=json.dumps(dict(statistic, **{field: 1}))), 10000)
        with self.assertRaises(ValueError):
            probe.routine_progress(dict(row, State="PAUSED"), 10000)

    def test_routine_sql_preserves_parser_limits_and_private_broker(self):
        sql = probe.routine_sql("lp013_test", "lp013_test", arguments())
        # DorisParser.loadProperty requires COMMA between the separator and column mapping.
        self.assertIn("COLUMNS TERMINATED BY ',', COLUMNS(id,grp,v,payload)", sql)
        self.assertIn("'max_batch_rows'='200000'", sql)
        self.assertIn("'desired_concurrent_number'='8'", sql)
        self.assertIn("'kafka_offsets'='0,0,0,0,0,0,0,0'", sql)
        self.assertIn("127.0.0.1:39092", sql)

    def test_owned_timeout_stops_only_its_child_and_retains_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owned = probe.OwnedProcesses(root, lambda: None)
            with self.assertRaises(TimeoutError):
                owned.run([sys.executable, "-c", "import time; time.sleep(30)"], "bounded-child", .05)
            receipt = json.loads((root / "bounded-child.cleanup.json").read_text())
            self.assertTrue(receipt["clean"])
            self.assertEqual([], receipt["cleanup"]["remaining_live_pids"])
            self.assertIn("TimeoutError", receipt["original_error"])

    def test_exited_leader_does_not_hide_its_live_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owned = probe.OwnedProcesses(root, lambda: None)
            script = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])"
            owned.run([sys.executable, "-c", script], "exited-leader", 5)
            receipt = json.loads((root / "exited-leader.cleanup.json").read_text())
            self.assertEqual(0, receipt["exit_code"])
            self.assertTrue(receipt["cleanup"]["term_sent"])
            self.assertEqual([], receipt["cleanup"]["remaining_live_pids"])

    def test_cancelled_main_work_still_allows_bounded_cleanup_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def cancelled():
                raise probe.lifecycle.CalibrationInterrupted(15)
            owned = probe.OwnedProcesses(root, cancelled)
            owned.run([sys.executable, "-c", "pass"], "cleanup", 5, cleanup=True)
            self.assertTrue(json.loads((root / "cleanup.cleanup.json").read_text())["clean"])
            with self.assertRaises(probe.lifecycle.CalibrationInterrupted):
                owned.run([sys.executable, "-c", "pass"], "cancelled-main", 5)


if __name__ == "__main__":
    unittest.main()
