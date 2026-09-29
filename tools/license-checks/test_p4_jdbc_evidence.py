#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Raw-schema and bounded-clock tests; no JDBC process or database is started."""

import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import p4_jdbc_evidence as adapter


class JdbcEvidenceTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="p4-jdbc-evidence-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.directory = self.root / "window-00"
        self.directory.mkdir()
        self.ticks = {"fe": 123, "be": 456}
        self.epoch = 1_000_000_000
        self.token = "unit-test-launch-token-no-real-measurement"
        self.bindings = {"runner": adapter.reference(adapter.baseline.__file__),
                         "calibrator": adapter.reference(adapter.capacity.__file__),
                         "jdbc_helper": adapter.reference(adapter.baseline.SOURCE)}
        for key in ("jdbc_driver", "fe_artifact", "be_artifact", "environment", "configuration", "fixture", "client"):
            self.bindings[key] = adapter.reference(self.write(self.root / key, (key + " synthetic\n").encode()))
        self.identity = {"source_commit": "a" * 40}
        for key, field in (("fe_artifact", "fe_sha256"), ("be_artifact", "be_sha256"),
                           ("environment", "environment_sha256"), ("configuration", "configuration_sha256"),
                           ("fixture", "fixture_sha256"), ("client", "client_sha256")):
            self.identity[field] = self.bindings[key]["sha256"]
        self.workload = {"contract_group": "G1", "cell_id": "G1-unit", "case_id": "LP-005",
                         "database": "license_perf", "concurrency": 1, "duration_seconds": 1, "warmup_seconds": 0,
                         "pairs": 1, "rate": 4, "seed": 20260922, "timeout_seconds": 5, "connection_mode": "reuse",
                         "build_identity": {"baseline_source_commit": self.identity["source_commit"],
                                            "fe_artifact": self.bindings["fe_artifact"]["path"],
                                            "be_artifact": self.bindings["be_artifact"]["path"]},
                         "queries": [{"sql": "SELECT 1", "expected_rows": 1,
                                      "expected_result": {"columns": [{"label": "1", "jdbc_type": -6}], "rows": [["1"]]}}]}
        self.workload["business_workload_sha256"] = adapter.baseline.business_workload_binding(self.workload)["sha256"]
        workload_path = self.json(self.root / "workload.json", self.workload)
        self.launch = {"schema_version": 1, "launch_token": self.token, "window_id": "unit-window-0", "pair_id": 0,
                       "phase": "AA", "variant": "A", "boot_id": adapter.statistics.boot_id(),
                       "created_monotonic_ns": 100_000_000, "max_clock_uncertainty_ns": 1000,
                       "utc_anchor": self.anchor(100_000_000), "identity": self.identity,
                       "workload": adapter.reference(workload_path), "bindings": self.bindings,
                       "service_start_ticks": self.ticks}
        launch_path = self.json(self.root / "p4-launch.json", self.launch)
        self.launch_ref = adapter.reference(launch_path)
        self.helper = {"schema_version": 1, "launch_token": self.token, "launch_sha256": self.launch_ref["sha256"],
                       "boot_id": self.launch["boot_id"], "helper_pid": 321, "helper_start_ticks": 34,
                       "nonce": "unit-test-clock-nonce", "jvm_sample_ns": 900_000_000}
        helper_path = self.json(self.directory / "p4-helper-clock.json", self.helper)
        self.bridge = {"schema_version": 1, "launch_token": self.token, "launch_sha256": self.launch_ref["sha256"],
                       "boot_id": self.launch["boot_id"], "nonce": self.helper["nonce"],
                       "controller_before_ns": 900_001_000, "controller_after_ns": 900_003_000,
                       "helper_clock": adapter.reference(helper_path)}
        bridge_path = self.json(self.directory / "p4-clock-bridge.json", self.bridge)
        self.completion = {"schema_version": 1, "launch_token": self.token, "launch_sha256": self.launch_ref["sha256"],
                           "boot_id": self.launch["boot_id"], "helper_pid": 321, "helper_start_ticks": 34,
                           "exit_code": 0, "remaining_live_pids": [], "completed_monotonic_ns": 2_001_000_000,
                           "utc_anchor": self.anchor(2_001_000_000), "bridge": adapter.reference(bridge_path)}
        completion_path = self.json(self.root / "p4-completion.json", self.completion)
        self.manifest = {"window_directory": str(self.directory), "launch": self.launch_ref,
                         "completion": adapter.reference(completion_path)}
        self.make_raw_window()

    def write(self, path, content):
        path.write_bytes(content)
        return path

    def json(self, path, value):
        return self.write(path, (json.dumps(value) + "\n").encode())

    def anchor(self, mono):
        return {"before_monotonic_ns": mono, "utc_ns": 1_000_000_000_000_000 + mono,
                "after_monotonic_ns": mono + 1000}

    def vector(self, name, values):
        data = b"".join(struct.pack(">q", value) for value in values)
        self.write(self.directory / name, data)
        digest = hashlib.sha256(data).hexdigest()
        self.write(self.directory / (name + ".sha256"), (digest + "\n").encode())
        return digest

    def make_raw_window(self):
        arrivals = [1_000_000, 2_000_000, 3_000_000, 4_000_000]
        arrival_sha = self.vector("arrivals.bin", arrivals)
        warmup_sha = self.vector("warmup-arrivals.bin", [])
        self.write(self.directory / "arrival-count", b"4\n")
        rows = ["index,query_index,scheduled_ns,start_ns,end_ns,rows,error_code,sql_state"]
        rows.extend(f"{index},0,{arrival},{arrival+1000},{arrival+3000},1,0,00000" for index, arrival in enumerate(arrivals))
        self.write(self.directory / "worker-0.csv", ("\n".join(rows) + "\n").encode())
        def cpu(first):
            return {name: {"cpu_seconds": 1.0 if first else 2.0, "rss_bytes": 1000, "start_ticks": ticks,
                    "sample_started_ns": self.epoch - 1000 if first else self.epoch + 10**9 + 1000,
                    "sample_ended_ns": self.epoch - 500 if first else self.epoch + 10**9 + 2000}
                    for name, ticks in self.ticks.items()}
        start = {"epoch_ns": self.epoch, "cpu": cpu(True)}
        end = {"epoch_ns": self.epoch, "last_request_end_ns": self.epoch + arrivals[-1] + 3000,
               "request_interval_end_ns": self.epoch + 10**9, "measurement_end_ns": self.epoch + 10**9 + 3000,
               "cpu": cpu(False)}
        lifecycle = {"completed": True, "cleanup_start_ns": self.epoch + 10**9 + 4000,
                     "cleanup_end_ns": self.epoch + 10**9 + 10000}
        ready = {"ready_ns": self.epoch - 49_999, "warmup_start_ns": self.epoch - 100_000,
                 "warmup_end_ns": self.epoch - 50_000, "launch_token": self.token,
                 "launch_sha256": self.launch_ref["sha256"]}
        for name, value in (("measurement-start.json", start), ("measurement-end.json", end),
                            ("lifecycle.json", lifecycle), ("measurement-ready.json", ready)):
            self.json(self.directory / name, value)
        resources = {"cpu": {"start": start["cpu"], "end": end["cpu"]}, "samples": [],
                     "boundary": adapter.baseline.boundary_evidence(start, end, lifecycle)}
        self.json(self.directory / "resources.json", resources)
        driver = {"worker": 0, "connection_mode": "reuse", "driver_class": "org.mariadb.jdbc.Driver",
                  "connection_classes": {"org.mariadb.jdbc.Connection": 1}, "queries": [{"query_index": 0,
                  "prepared": False, "statement_count": 1, "warmup_execute_attempts": 0, "measured_execute_attempts": 4,
                  "same_reused_statement": True, "statement_classes": {"org.mariadb.jdbc.Statement": 1}}],
                  "fe_fast_path_proven": False, "harness_retries": 0}
        self.json(self.directory / "driver-worker-0.json", driver)
        summary = adapter.baseline.summarize(self.directory, 4, 1, resources["cpu"])
        summary.update(process_exit_code=0, cpu_boundary_verified=True, arrival_seed=20260922,
                       schedule_hash_matches_helper=True, arrival_schedule_sha256=arrival_sha,
                       warmup_arrival_schedule_sha256=warmup_sha, connection_mode="reuse", query_workload_kind="static_query_vector",
                       driver_evidence=[driver], warmup_failure=[None],
                       static_result_oracles=[{"query_index": 0,
                       "sha256": hashlib.sha256(adapter.baseline.encode_result_oracle(self.workload["queries"][0])).hexdigest(),
                       "columns": 1, "rows": 1, "ordered": True, "comparison_inside_request_timing": True}])
        self.json(self.directory / "summary.json", summary)

    def test_raw_csv_cpu_oracle_and_clock_produce_bounded_not_exact_window(self):
        result = adapter.normalize(self.manifest)
        window = result["window"]
        self.assertEqual(result["status"], "VERIFIED")
        self.assertFalse(result["formal_shape_met"])
        self.assertEqual(window["monotonic_clock_domain"], "bounded_jvm_mapping")
        self.assertEqual(window["monotonic_mapping_uncertainty_ns"], 1000)
        self.assertEqual(window["effective_duration_seconds"], 1)
        self.assertEqual(window["metrics"]["success_qps"], 4)
        self.assertEqual(window["metrics"]["p99_ms"], .003)
        self.assertEqual(window["metrics"]["fe_cpu_seconds_per_success"], .25)
        self.assertEqual(window["start_monotonic_ns"], self.epoch + 2000)

    def test_missing_actual_warmup_is_never_derived_from_mtime_or_duration(self):
        path = self.directory / "measurement-ready.json"
        self.json(path, {"ready_ns": self.epoch - 1, "launch_token": self.token,
                         "launch_sha256": self.launch_ref["sha256"]})
        with self.assertRaises(KeyError):
            adapter.normalize(self.manifest)

    def test_raw_cpu_summary_forgery_is_recomputed_and_rejected(self):
        path = self.directory / "summary.json"
        summary = adapter.read_json(path)
        summary["fe_cpu_seconds_per_success"] = .00001
        self.json(path, summary)
        with self.assertRaisesRegex(ValueError, "CPU per success"):
            adapter.normalize(self.manifest)

    def test_raw_csv_error_cannot_become_oracle_success(self):
        path = self.directory / "worker-0.csv"
        path.write_text(path.read_text().replace(",1,0,00000", ",1,123,HY000", 1))
        with self.assertRaisesRegex(ValueError, "Failed request"):
            adapter.normalize(self.manifest)

    def test_clock_offset_is_independently_bounded_by_request_and_reply(self):
        value = adapter.clock_bridge(self.launch, self.launch_ref, self.bridge, self.helper)
        self.assertEqual(value["offset_lower_ns"], 1000)
        self.assertEqual(value["offset_upper_ns"], 3000)
        self.assertEqual(value["estimated_offset_ns"], 2000)
        self.assertEqual(value["uncertainty_ns"], 1000)

    def test_slow_reversed_or_cross_launch_clock_handshake_is_rejected(self):
        for mutation in ("slow", "reversed", "nonce", "boot", "digest"):
            bridge = copy.deepcopy(self.bridge)
            if mutation == "slow":
                bridge["controller_after_ns"] += 10_000
            elif mutation == "reversed":
                bridge["controller_after_ns"] = bridge["controller_before_ns"] - 1
            elif mutation == "nonce":
                bridge["nonce"] = "a-different-nonce"
            elif mutation == "boot":
                bridge["boot_id"] = "another-boot"
            else:
                bridge["launch_sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(adapter.EvidenceError):
                adapter.clock_bridge(self.launch, self.launch_ref, bridge, self.helper)

    def test_completion_must_be_the_actual_waited_helper_lifetime(self):
        for field, value in (("helper_pid", 999), ("helper_start_ticks", 999), ("exit_code", 1), ("remaining_live_pids", [321])):
            completion = dict(self.completion, **{field: value})
            path = self.json(self.root / "bad-completion.json", completion)
            manifest = dict(self.manifest, completion=adapter.reference(path))
            with self.subTest(field=field), self.assertRaises(adapter.EvidenceError):
                adapter.normalize(manifest)

    def test_utc_anchors_are_metadata_not_latency_clock_substitutes(self):
        launch = copy.deepcopy(self.launch)
        launch["utc_anchor"]["utc_ns"] += 40 * 365 * 86400 * 10**9
        mapping = adapter.clock_bridge(launch, self.launch_ref, self.bridge, self.helper)
        self.assertEqual(mapping["estimated_offset_ns"], 2000)

    def test_conservative_sequence_rejects_nominally_separated_but_uncertain_windows(self):
        first = adapter.normalize(self.manifest)
        second = copy.deepcopy(first)
        second["window"]["warmup_start_monotonic_ns"] = first["window"]["end_monotonic_ns"] + 100
        with self.assertRaisesRegex(adapter.EvidenceError, "nonoverlapping"):
            adapter.verify_sequence([first, second])
        second["window"]["warmup_start_monotonic_ns"] += 10_000
        self.assertTrue(adapter.verify_sequence([first, second])["verified"])

    def test_only_real_current_business_shape_is_accepted(self):
        workload = dict(self.workload, concurrency=2)
        path = self.json(self.root / "invalid-workload.json", workload)
        launch = dict(self.launch, workload=adapter.reference(path))
        with self.assertRaisesRegex(ValueError, "declared concurrency"):
            adapter.launch_bindings(launch)

    def ab_manifest(self, publication_time):
        frozen_path = self.json(self.root / "frozen.json", {"status": "FROZEN_ELIGIBLE", "identities": {"B": self.identity}})
        frozen = adapter.reference(frozen_path)
        publication_path = self.json(self.root / "frozen.json.published.json", {"freeze": frozen,
                                     "boot_id": self.launch["boot_id"], "published_monotonic_ns": publication_time})
        launch = dict(self.launch, phase="AB", variant="B", freeze=frozen, publication=adapter.reference(publication_path))
        self.json(Path(self.launch_ref["path"]), launch)
        launch_ref = adapter.reference(self.launch_ref["path"])
        helper = dict(self.helper, launch_sha256=launch_ref["sha256"])
        helper_path = self.json(self.directory / "p4-helper-clock.json", helper)
        bridge = dict(self.bridge, launch_sha256=launch_ref["sha256"], helper_clock=adapter.reference(helper_path))
        bridge_path = self.json(self.directory / "p4-clock-bridge.json", bridge)
        ready_path = self.directory / "measurement-ready.json"
        ready = adapter.read_json(ready_path)
        ready["launch_sha256"] = launch_ref["sha256"]
        self.json(ready_path, ready)
        completion = dict(self.completion, launch_sha256=launch_ref["sha256"], bridge=adapter.reference(bridge_path))
        completion_path = self.json(self.root / "p4-completion.json", completion)
        return dict(self.manifest, launch=launch_ref, completion=adapter.reference(completion_path))

    def test_ab_keeps_actual_variant_and_prepublished_freeze_bindings(self):
        manifest = self.ab_manifest(self.launch["created_monotonic_ns"] - 1000)
        result = adapter.normalize(manifest)
        launch = adapter.read_json(manifest["launch"]["path"])
        self.assertEqual(result["window"]["variant"], "B")
        self.assertEqual(result["window"]["freeze_sha256"], launch["freeze"]["sha256"])
        self.assertEqual(result["window"]["freeze_publication_sha256"], launch["publication"]["sha256"])

    def test_ab_cannot_use_a_freeze_published_after_it_was_launched(self):
        manifest = self.ab_manifest(self.launch["created_monotonic_ns"] + 1)
        with self.assertRaisesRegex(adapter.EvidenceError, "published before"):
            adapter.normalize(manifest)

    def test_cannot_relabel_aa_launch_as_candidate_b(self):
        launch = dict(self.launch, variant="B")
        with self.assertRaisesRegex(adapter.EvidenceError, "A/A launch"):
            adapter.launch_bindings(launch)

    def test_external_launch_mutation_during_verification_is_not_rebound(self):
        actual_verify = adapter.capacity.verify_window
        def mutate(*args):
            value = actual_verify(*args)
            Path(self.launch_ref["path"]).write_text("changed during raw verification\n")
            return value
        with patch.object(adapter.capacity, "verify_window", side_effect=mutate), self.assertRaisesRegex(adapter.EvidenceError, "digest changed"):
            adapter.normalize(self.manifest)


if __name__ == "__main__":
    unittest.main()
