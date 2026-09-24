#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline parser, identity, bounded-transport and signal tests; never contact FE/BE."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import resource_observer as observer


def metric_body(component):
    lines = []
    for index, (name, labels) in enumerate(observer.metric_allowlist(component)):
        label_text = ", ".join(key + "=" + json.dumps(value) for key, value in reversed(labels))
        lines.append(name + ("{" + label_text + "}" if labels else "") + " " + str(index))
    return ("\n".join(lines) + "\n").encode()


class ProcParserTest(unittest.TestCase):
    def test_stat_with_spaces_and_parentheses_does_not_shift_start_ticks(self):
        fields = ["S"] + ["0"] * 21
        for index, value in {11: 150, 12: 25, 17: 9, 19: 123456, 20: 90000, 21: 10}.items():
            fields[index] = str(value)
        result = observer.parse_stat("123 (worker ) name) " + " ".join(fields), 100, 4096)
        self.assertEqual(result["start_ticks"], 123456)
        self.assertEqual(result["cpu_seconds"], 1.75)
        self.assertEqual(result["rss_bytes"], 40960)
        self.assertEqual(result["threads"], 9)

    def test_io_keeps_only_explicit_counters_and_requires_complete_set(self):
        text = "\n".join(f"{name}: {index}" for index, name in enumerate(observer.IO_FIELDS))
        parsed = observer.parse_io(text + "\ncustomer_secret: 12345")
        self.assertEqual(set(parsed), set(observer.IO_FIELDS))
        with self.assertRaises(ValueError):
            observer.parse_io("read_bytes: 1")

    def test_memory_units_and_missing_fields_are_not_silently_zeroed(self):
        self.assertEqual(observer.parse_status("VmRSS: 2 kB\nVmHWM: 3 kB\nVmSwap: 0 kB"),
                         {"VmRSS_bytes": 2048, "VmHWM_bytes": 3072, "VmSwap_bytes": 0})
        with self.assertRaises(ValueError):
            observer.parse_status("VmRSS: 2 MB\nVmHWM: 3 kB\nVmSwap: 0 kB")

    def test_namespace_loopback_rx_and_tx_are_separate_without_process_attribution(self):
        text = "Inter-| Receive | Transmit\n lo: 100 2 0 0 0 0 0 0 100 2 0 0 0 0 0 0\n"
        result = observer.parse_netdev(text)
        self.assertEqual(result["interfaces"]["lo"]["rx_bytes"], 100)
        self.assertEqual(result["interfaces"]["lo"]["tx_bytes"], 100)
        self.assertFalse(result["rx_plus_tx_total_computed"])
        self.assertFalse(result["process_attribution"])
        self.assertNotIn("total_bytes", result)


class MetricsParserTest(unittest.TestCase):
    def test_actual_fe_whitespace_and_be_label_order(self):
        for component, count in (("fe", 9), ("be", 16)):
            result = observer.parse_metrics(metric_body(component), component)
            self.assertEqual(len(result["series"]), count)
        be_gc = [series for series in observer.parse_metrics(metric_body("be"), "be")["series"]
                 if series["name"] == "doris_be_jvm_gc"]
        self.assertTrue(all("embedded JVM" in series["meaning"] for series in be_gc))

    def test_unselected_business_labels_and_values_never_leave_parser(self):
        body = metric_body("fe") + b'customer_metric{secret="DO_NOT_ARCHIVE"} 5\n'
        body += b'jvm_heap_size_bytes{type="used",table="DO_NOT_ARCHIVE"} 1234\n'
        result = observer.parse_metrics(body, "fe")
        self.assertNotIn("DO_NOT_ARCHIVE", json.dumps(result))
        self.assertEqual(result["ignored_series_count"], 2)

    def test_missing_or_duplicate_selected_series_is_an_error(self):
        lines = metric_body("fe").splitlines(keepends=True)
        for body in (b"".join(lines[1:]), b"".join(lines + [lines[0]])):
            with self.assertRaises(ValueError):
                observer.parse_metrics(body, "fe")

    def test_nonfinite_negative_and_malformed_selected_values_are_errors(self):
        for invalid in (b"NaN", b"+Inf", b"-1", b"garbage"):
            body = metric_body("fe").replace(b" 0\n", b" " + invalid + b"\n", 1)
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                observer.parse_metrics(body, "fe")

    def test_duplicate_labels_are_not_accepted_as_a_valid_metric(self):
        body = metric_body("fe") + b'jvm_gc{type="count",type="count"} 1\n'
        with self.assertRaises(ValueError):
            observer.parse_metrics(body, "fe")


class TransportTest(unittest.TestCase):
    def connection(self, body, status=200):
        response = MagicMock(status=status)
        response.read1.side_effect = [body, b""]
        response.isclosed.return_value = False
        connection = MagicMock()
        connection.getresponse.return_value = response
        return connection

    def test_direct_owned_loopback_ignores_proxy_environment_and_closes(self):
        connection = self.connection(metric_body("fe"))
        with patch.dict(os.environ, {"HTTP_PROXY": "http://untrusted.invalid:9"}), \
                patch.object(observer.http.client, "HTTPConnection", return_value=connection) as factory:
            result = observer.fetch_metrics(28030, "fe", 2)
        factory.assert_called_once_with("127.0.0.1", 28030, timeout=2)
        self.assertEqual(connection.request.call_args.args[:2], ("GET", "/metrics"))
        connection.close.assert_called_once()
        self.assertEqual(len(result["series"]), 9)

    def test_redirect_is_rejected_without_following_and_connection_closes(self):
        connection = self.connection(b"", status=302)
        with patch.object(observer.http.client, "HTTPConnection", return_value=connection) as factory:
            with self.assertRaises(ValueError):
                observer.fetch_metrics(28030, "fe", 2)
        self.assertEqual(factory.call_count, 1)
        connection.close.assert_called_once()

    def test_body_bound_rejects_unlimited_endpoint_data(self):
        connection = self.connection(b"x" * 65)
        with patch.object(observer, "MAX_BODY_BYTES", 64), \
                patch.object(observer.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaises(ValueError):
                observer.fetch_metrics(28030, "fe", 2)
        connection.close.assert_called_once()

    def test_absolute_deadline_rejects_slow_trickle(self):
        connection = self.connection(b"a")
        with patch.object(observer.time, "monotonic", side_effect=[0, 0.2, 2.01]), \
                patch.object(observer.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaises(TimeoutError):
                observer.fetch_metrics(28030, "fe", 2)
        connection.getresponse.return_value.read1.assert_not_called()
        connection.close.assert_called_once()


class IdentityTest(unittest.TestCase):
    def test_pid_reuse_prevents_any_endpoint_request(self):
        pins = {"fe": {"pid": 123, "start_ticks": 1, "http_port": 28030}}
        with patch.object(observer.os, "readlink", return_value="net:[private]"), \
                patch.object(observer, "process_stat", return_value={"start_ticks": 2}), \
                patch.object(observer, "fetch_metrics") as fetch:
            result = observer.collect_sample({"namespace": "net:[private]"}, pins, 2, observer.StopSignals())
        self.assertTrue(result["fatal_identity_error"])
        self.assertEqual(result["processes"], {})
        fetch.assert_not_called()

    def test_observer_namespace_change_prevents_scrape(self):
        with patch.object(observer.os, "readlink", return_value="net:[host]"), \
                patch.object(observer, "fetch_metrics") as fetch:
            result = observer.collect_sample({"namespace": "net:[private]"}, {}, 2, observer.StopSignals())
        self.assertTrue(result["fatal_identity_error"])
        fetch.assert_not_called()

    def test_restart_during_scrape_discards_process_and_metrics_values(self):
        pins = {"fe": {"pid": 123, "start_ticks": 1, "http_port": 28030}}
        def read(path):
            if str(path).endswith("/net/dev"):
                return "lo: " + " ".join(["1"] * 16)
            if str(path).endswith("/io"):
                return "\n".join(f"{name}: 1" for name in observer.IO_FIELDS)
            return "VmRSS: 2 kB\nVmHWM: 3 kB\nVmSwap: 0 kB"
        with patch.object(observer.os, "readlink", return_value="net:[private]"), \
                patch.object(observer, "check_identity", side_effect=[{"start_ticks": 1}, observer.IdentityChanged()]), \
                patch.object(Path, "read_text", read), \
                patch.object(observer, "fetch_metrics", return_value={"series": ["must_be_discarded"]}):
            result = observer.collect_sample({"namespace": "net:[private]"}, pins, 2, observer.StopSignals())
        self.assertTrue(result["fatal_identity_error"])
        self.assertEqual(result["processes"], {})
        self.assertNotIn("must_be_discarded", json.dumps(result))

    def test_opt_in_restart_retains_actual_observer_call_counts_without_target_attribution(self):
        pins = {"fe": {"pid": 123, "start_ticks": 1, "http_port": 28030}}
        selection = {"schema_version": 1, "be_hostnames": ["127.0.0.1"], "thrift_methods": ["report"]}
        def read(path):
            if str(path).endswith("/net/dev"):
                return "lo: " + " ".join(["1"] * 16)
            if str(path).endswith("/io"):
                return "\n".join(f"{name}: 1" for name in observer.IO_FIELDS)
            return "VmRSS: 2 kB\nVmHWM: 3 kB\nVmSwap: 0 kB"
        with patch.object(observer.os, "readlink", return_value="net:[private]"), \
                patch.object(observer, "check_identity", side_effect=[{"start_ticks": 1}, observer.IdentityChanged()]), \
                patch.object(Path, "read_text", read), \
                patch.object(observer, "fetch_metrics", return_value={"series": ["must_be_discarded"]}):
            result = observer.collect_sample({"namespace": "net:[private]"}, pins, 2, observer.StopSignals(),
                                             rpc_selection=selection)
        self.assertTrue(result["fatal_identity_error"])
        self.assertEqual(result["processes"], {})
        self.assertEqual(result["http_metrics_calls"]["attempted"], {"fe": 1})
        self.assertEqual(result["http_metrics_calls"]["returned_parsed"], {"fe": 1})
        self.assertNotIn("must_be_discarded", json.dumps(result))

    def test_wrong_owned_fe_http_port_is_rejected_before_http(self):
        with tempfile.TemporaryDirectory(prefix="resource-port-test-", dir=observer.ROOT / ".build-records") as directory:
            root = Path(directory)
            (root / "fe/conf").mkdir(parents=True)
            (root / "fe/conf/fe.conf").write_text("http_port = 28031\n")
            state = {"installation": str(root), "http_port": 28030}
            with patch.object(observer, "validate_cluster", return_value=(state, 28040)), \
                    patch.object(observer, "fetch_metrics") as fetch:
                with self.assertRaises(ValueError):
                    observer.freeze_cluster(root / "cluster.json")
            fetch.assert_not_called()


class ScheduleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="resource-observer-test-", dir=observer.ROOT / ".build-records")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)

    def test_overrun_skips_missed_slots_instead_of_burst_catch_up(self):
        clock = [0.0]
        stop = observer.StopSignals()
        stop.event.wait = lambda delay: clock.__setitem__(0, clock[0] + delay) or False
        collected = []
        def sample():
            collected.append(clock[0])
            if len(collected) == 1:
                clock[0] += 12
            return {"errors": [], "elapsed_nanos": 0}
        report = observer.observe(self.output, 20, 5, sample, stop, {}, clock=lambda: clock[0])
        self.assertEqual(collected, [0, 15, 20])
        self.assertEqual(report["skipped_schedule_slots"], 2)
        self.assertFalse(report["statistical_precision_proven"])

    def test_fatal_identity_record_is_flushed_and_stops_schedule(self):
        report = observer.observe(self.output, 20, 5, lambda: {
            "errors": [{"type": "IdentityChanged"}], "fatal_identity_error": True}, observer.StopSignals(), {})
        self.assertEqual(report["status"], "FAILED_IDENTITY_CHANGED")
        self.assertEqual(report["samples"], 1)
        self.assertTrue((self.output / "samples.jsonl").read_text().endswith("\n"))

    def test_final_summary_is_written_even_if_collector_crashes_without_leaking_message(self):
        def failed():
            raise RuntimeError("DO_NOT_ARCHIVE")
        with self.assertRaises(RuntimeError):
            observer.observe(self.output, 20, 5, failed, observer.StopSignals(), {})
        summary = (self.output / "summary.json").read_text()
        self.assertEqual(json.loads(summary)["status"], "FAILED")
        self.assertNotIn("DO_NOT_ARCHIVE", summary)

    def test_duration_is_bounded_before_sampling(self):
        collector = MagicMock()
        with self.assertRaises(ValueError):
            observer.observe(self.output, 14401, 5, collector, observer.StopSignals(), {})
        collector.assert_not_called()

    def test_real_sigterm_and_sigint_finalize_only_owned_child(self):
        for signal_number in (signal.SIGTERM, signal.SIGINT):
            output = self.output / str(signal_number)
            output.mkdir()
            script = ("import sys; from pathlib import Path; import resource_observer as o; "
                      "output=Path(sys.argv[1]); "
                      "\nwith o.StopSignals() as stop:\n"
                      " o.observe(output,60,5,lambda:{'errors':[]},stop,{})\n")
            child = subprocess.Popen([sys.executable, "-c", script, str(output)],
                                     cwd=Path(observer.__file__).parent, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if (output / "samples.jsonl").exists() and (output / "samples.jsonl").stat().st_size:
                        break
                    if child.poll() is not None:
                        self.fail("Offline signal harness exited before its first sample")
                    time.sleep(0.01)
                else:
                    self.fail("Offline signal harness did not become ready")
                child.send_signal(signal_number)
                stdout, stderr = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 0, stderr)
                report = json.loads((output / "summary.json").read_text())
                self.assertEqual(report["status"], "INTERRUPTED")
                self.assertEqual(report["signal_number"], signal_number)
                self.assertEqual(report["samples"], 1)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)


class ScopedRpcTest(unittest.TestCase):
    def setUp(self):
        self.selection = {"schema_version": 1, "be_hostnames": ["127.0.0.1"], "thrift_methods": ["report"]}

    def body(self, count=14, size=68480, handler=21, latency=15):
        return metric_body("fe") + (
            f'doris_fe_query_rpc_total{{be="127.0.0.1"}} {count}\n'
            f'doris_fe_query_rpc_size{{be="127.0.0.1"}} {size}\n'
            f'doris_fe_thrift_rpc_total{{method="report"}} {handler}\n'
            f'doris_fe_thrift_rpc_latency_ms{{method="report"}} {latency}\n').encode()

    def sample(self, body, offset=1):
        metrics = observer.parse_metrics(body, "fe", rpc_selection=self.selection)
        metrics["extensions"]["scoped_rpc"]["scrape_monotonic_ns"] = {"started": offset, "finished": offset + 1}
        return {"processes": {"fe": {"metrics": metrics}}, "errors": []}

    def test_default_return_stays_exactly_base_and_discards_rpc(self):
        base = observer.parse_metrics(self.body(), "fe")
        self.assertEqual(set(base), {"series", "ignored_series_count"})
        self.assertEqual(len(base["series"]), 9)
        self.assertEqual(base["ignored_series_count"], 4)

    def test_saved_original_values_keep_scope_and_base(self):
        # Literal values from the preserved original-A readiness inventory; not generated by the parser.
        value = observer.parse_metrics(self.body(), "fe", rpc_selection=self.selection)
        rpc = value["extensions"]["scoped_rpc"]
        values = {row["name"]: row["value"] for row in rpc["series"]}
        self.assertEqual(values, {"doris_fe_query_rpc_total": 14, "doris_fe_query_rpc_size": 68480,
                                  "doris_fe_thrift_rpc_total": 21, "doris_fe_thrift_rpc_latency_ms": 15})
        self.assertFalse(rpc["all_rpc_coverage"])
        self.assertFalse(rpc["wire_bytes"])
        self.assertEqual(len(value["series"]), 9)

    def test_known_method_list_matches_all_idl_methods_including_qualified_returns(self):
        import re
        text = (observer.ROOT / "gensrc/thrift/FrontendService.thrift").read_text().split("service FrontendService {", 1)[1]
        methods = set(re.findall(r'^\s+[\w.<>]+\s+(\w+)\(', text, re.M))
        self.assertEqual(len(methods), 68)
        self.assertEqual(observer.THRIFT_METHODS, methods)
        self.assertTrue({"finishTask", "report", "reportCommitTxnResult"} <= methods)

    def test_selection_rejects_unowned_labels_duplicates_schema_and_oversize(self):
        for change in ({"be_hostnames": ["other-host"]}, {"thrift_methods": ["report", "report"]},
                       {"thrift_methods": ["secret_business_label"]}, {"schema_version": True}, {"extra": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                observer.validate_rpc_selection({**self.selection, **change})
        with tempfile.TemporaryDirectory(dir=observer.ROOT / ".build-records") as temporary:
            path = Path(temporary) / "selection.json"
            path.write_bytes(b"x" * 65537)
            with self.assertRaises(ValueError):
                observer.load_rpc_selection(path)
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(ValueError):
                observer.load_rpc_selection(path)

    def test_unselected_labels_are_not_archived(self):
        body = self.body() + b'doris_fe_query_rpc_total{be="DO_NOT_ARCHIVE"} 7\n'
        body += b'doris_fe_thrift_rpc_total{method="report",secret="DO_NOT_ARCHIVE"} 8\n'
        rpc = observer.parse_rpc_metrics(body, self.selection)
        self.assertNotIn("DO_NOT_ARCHIVE", json.dumps(rpc))
        self.assertEqual(rpc["ignored_rpc_series"], 2)

    def test_duplicate_and_non_integer_or_negative_counts_rejected(self):
        for invalid in (b"1.0", b"NaN", b"+Inf", b"-1"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                observer.parse_rpc_metrics(self.body().replace(b" 14\n", b" " + invalid + b"\n"), self.selection)
        with self.assertRaises(ValueError):
            observer.parse_rpc_metrics(self.body() + b'doris_fe_query_rpc_total{be="127.0.0.1"} 1\n', self.selection)

    def test_late_creation_never_invents_zero_baseline(self):
        tracker = observer.RpcTracker()
        absent = self.sample(metric_body("fe"))
        tracker.update(absent)
        present = self.sample(self.body(), 3)
        tracker.update(present)
        rows = present["processes"]["fe"]["metrics"]["extensions"]["scoped_rpc"]["series"]
        self.assertTrue(all(row["delta"] is None for row in rows))
        self.assertFalse(tracker.summary()["scoped_rpc_delta_complete"])

    def test_lost_series_counter_reset_and_signed_clock_time_are_explicit(self):
        for body, error in ((metric_body("fe"), "RpcSeriesLost"), (self.body(count=13), "RpcCounterDiscontinuity"),
                            (self.body(latency=-5), "RpcCounterDiscontinuity")):
            tracker = observer.RpcTracker()
            tracker.update(self.sample(self.body()))
            sample = self.sample(body, 3)
            tracker.update(sample)
            self.assertIn(error, {row["type"] for row in sample["errors"]})
            self.assertFalse(tracker.summary()["scoped_rpc_delta_complete"])

    def test_valid_differences_retain_non_atomic_scrape_intervals(self):
        tracker = observer.RpcTracker()
        tracker.update(self.sample(self.body(), 10))
        sample = self.sample(self.body(count=16, size=70000, handler=24, latency=18), 20)
        tracker.update(sample)
        rows = sample["processes"]["fe"]["metrics"]["extensions"]["scoped_rpc"]["series"]
        values = {row["name"]: row["delta"] for row in rows}
        self.assertEqual(values["doris_fe_query_rpc_total"], 2)
        self.assertEqual(values["doris_fe_query_rpc_size"], 1520)
        self.assertTrue(all(row["from_scrape"] == {"started": 10, "finished": 11} for row in rows))
        self.assertTrue(tracker.summary()["scoped_rpc_delta_complete"])
        self.assertFalse(tracker.summary()["all_rpc_coverage"])

    def test_missing_entire_scrape_cannot_claim_complete_delta(self):
        tracker = observer.RpcTracker()
        tracker.update({"errors": []})
        tracker.update(self.sample(self.body()))
        self.assertFalse(tracker.summary()["scoped_rpc_delta_complete"])

    def test_rpc_uses_original_single_request_transport(self):
        connection = TransportTest().connection(self.body())
        with patch.object(observer.http.client, "HTTPConnection", return_value=connection) as factory:
            value = observer.fetch_metrics(28030, "fe", 2, rpc_selection=self.selection)
        factory.assert_called_once()
        connection.request.assert_called_once()
        connection.close.assert_called_once()
        self.assertEqual(value["extensions"]["scoped_rpc"]["series"][1]["presence"], "present")


class GcPauseTest(unittest.TestCase):
    REMARK = b'[2026-09-24T12:45:07.542+0800][0.826s] GC(2) Pause Remark 74M->74M(2048M) 1.444ms\n'
    CLEANUP = b'[2026-09-24T12:45:07.551+0800][0.835s] GC(2) Pause Cleanup 75M->75M(2048M) 0.085ms\n'

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gc-observer-offline-", dir=observer.ROOT / ".build-records")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "fe.gc.log.20260924-124506"
        self.path.write_bytes(b"")
        self.binding = {"path": str(self.path), "pid": 123, "start_ticks": 456,
                        "namespace": "net:[private]", "executable": "/fake/java", "cmdline_sha256": "a" * 64}
        self.identity = patch.object(observer.GcPauseReader, "_identity")
        self.identity.start()
        self.addCleanup(self.identity.stop)
        self.reader = None
        self.addCleanup(self.close_reader)

    def close_reader(self):
        if self.reader is not None and not self.reader.closed:
            self.reader.finish()

    def prepare(self):
        self.reader = observer.GcPauseReader(self.binding, self.root / "output")
        return self.reader

    def append(self, data):
        with self.path.open("ab") as stream:
            stream.write(data)

    def events(self):
        return [json.loads(line) for line in self.reader.event_path.read_text().splitlines()]

    def test_real_pause_literals_keep_two_events_with_same_gc_id(self):
        reader = self.prepare()
        self.append(self.REMARK + self.CLEANUP)
        receipt = reader.read_batch(observer.StopSignals())
        rows = self.events()
        self.assertEqual([row["duration_ns"] for row in rows], [1444000, 85000])
        self.assertEqual([row["gc_id"] for row in rows], [2, 2])
        self.assertEqual(receipt["last_event_seq"], 1)
        self.assertFalse(receipt["all_jvm_gc_pauses_proven"])
        self.assertTrue(all(row["window_assignment"] == "unmapped" for row in rows))

    def test_initial_history_is_not_replayed_and_initial_partial_is_preserved(self):
        self.path.write_bytes(self.REMARK + self.CLEANUP[:30])
        reader = self.prepare()
        self.append(self.CLEANUP[30:])
        reader.read_batch(observer.StopSignals())
        rows = self.events()
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["initial_partial"])
        self.assertEqual(rows[0]["line_start_offset"], len(self.REMARK))

    def test_split_three_chunks_creates_one_event_only(self):
        reader = self.prepare()
        for chunk in (self.REMARK[:20], self.REMARK[20:50], self.REMARK[50:]):
            self.append(chunk)
            reader.read_batch(observer.StopSignals())
        self.assertEqual(len(self.events()), 1)
        reader.read_batch(observer.StopSignals())
        self.assertEqual(len(self.events()), 1)

    def test_start_concurrent_and_child_phases_are_not_pause_events(self):
        for line in (b'[2026-09-24T12:45:07.540+0800][0.824s] GC(2) Pause Remark\n',
                     b'[2026-09-24T12:45:07.551+0800][0.835s] GC(2) Concurrent Cycle 5.0ms\n',
                     b'[2026-09-24T12:45:07.551+0800][0.835s] GC(2)   Other: 0.1ms\n'):
            self.assertIsNone(observer.parse_gc_pause(line))

    def test_invalid_duration_timestamp_category_and_utf8_fail(self):
        for line in (self.REMARK.replace(b"1.444ms", b"-1ms"), self.REMARK.replace(b"1.444ms", b"NaNms"),
                     self.REMARK.replace(b"Remark", b"Unexpected"), self.REMARK.replace(b"09-24T", b"99-24T"),
                     b"\xff\n", self.REMARK.replace(b"1.444ms", b"999999ms")):
            with self.subTest(line=line), self.assertRaises((ValueError, UnicodeError)):
                observer.parse_gc_pause(line)

    def test_rotation_reads_old_inode_tail_and_new_current_once(self):
        reader = self.prepare()
        self.append(self.REMARK)
        old = self.path.with_name(self.path.name + ".0")
        self.path.rename(old)
        self.path.write_bytes(self.CLEANUP)
        reader.read_batch(observer.StopSignals())
        self.assertEqual(sorted(row["duration_ns"] for row in self.events()), [85000, 1444000])
        reader.read_batch(observer.StopSignals())
        self.assertEqual(len(self.events()), 2)

    def test_unseen_rotated_generation_marks_gap(self):
        reader = self.prepare()
        self.path.with_name(self.path.name + ".0").write_bytes(self.REMARK)
        value = reader.read_batch(observer.StopSignals())
        self.assertIn("unseen_rotated_generation", value["detected_gaps"])
        self.assertFalse(reader.finish()["observed_retained_prefix_continuity"])

    def test_truncate_is_failure_and_cleanup_still_closes_all_owned_fds(self):
        reader = self.prepare()
        self.append(self.REMARK)
        reader.read_batch(observer.StopSignals())
        fds = [value["fd"] for value in reader.files.values()] + [reader.dirfd]
        self.path.write_bytes(b"")
        with self.assertRaises(ValueError):
            reader.read_batch(observer.StopSignals())
        result = reader.finish()
        self.assertTrue(result["files_closed"])
        self.assertFalse(result["observed_retained_prefix_continuity"])
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_pending_tail_does_not_become_zero_pause_complete(self):
        reader = self.prepare()
        self.append(self.REMARK[:-1])
        value = reader.finish()
        self.assertEqual(value["events"], 0)
        self.assertGreater(value["pending_bytes"], 0)
        self.assertFalse(value["tail_complete"])

    def test_terminal_frozen_prefix_does_not_chase_new_appends(self):
        reader = self.prepare()
        self.append(self.REMARK)
        original = reader.read_batch
        def read(stop, deadline=None, targets=None):
            self.append(self.CLEANUP)
            return original(stop, deadline, targets)
        with patch.object(reader, "read_batch", side_effect=read):
            result = reader.finish()
        self.assertEqual(result["events"], 1)

    def test_source_symlink_and_fifo_rejected_without_blocking(self):
        self.path.unlink()
        other = self.root / "other"
        other.write_bytes(b"")
        self.path.symlink_to(other)
        with self.assertRaises(ValueError):
            self.prepare()
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_overlong_pending_and_total_read_budget_fail_without_unbounded_read(self):
        for key, limit in (("line_bytes", 20), ("batch_bytes", 20), ("total_read_bytes", 20)):
            with self.subTest(key=key):
                reader = self.prepare()
                self.append(self.REMARK)
                with patch.dict(observer.GC_LIMITS, {key: limit}), self.assertRaises(ValueError):
                    reader.read_batch(observer.StopSignals())
                self.assertTrue(reader.finish()["files_closed"])
                self.reader.event_path.unlink()
                self.path.write_bytes(b"")

    def test_cancel_and_evidence_error_preserve_failure_and_close(self):
        reader = self.prepare()
        self.append(self.REMARK)
        stop = observer.StopSignals()
        stop.event.set()
        with self.assertRaises(InterruptedError):
            reader.read_batch(stop)
        value = reader.finish()
        self.assertIn("InterruptedError", value["errors"])
        self.assertTrue(value["files_closed"])

    def test_partial_output_write_is_not_counted_as_completed_event(self):
        reader = self.prepare()
        self.append(self.REMARK)
        real = reader.stream
        mocked = MagicMock(wraps=real)
        mocked.write.return_value = 1
        reader.stream = mocked
        with self.assertRaises(OSError):
            reader.read_batch(observer.StopSignals())
        result = reader.finish()
        self.assertEqual(result["events"], 0)
        self.assertGreater(result["archive_bytes_reserved"], 1)
        self.assertFalse(result["observed_retained_prefix_continuity"])
        cursor = result["final_cursors"][0]
        self.assertEqual(cursor["event_archive_confirmed_offset"], 0)
        self.assertEqual(cursor["unconfirmed_read_range"], [0, len(self.REMARK)])

    def test_flush_failure_keeps_unconfirmed_offsets_and_still_closes(self):
        reader = self.prepare()
        self.append(self.REMARK)
        real = reader.stream
        mocked = MagicMock(wraps=real)
        mocked.flush.side_effect = OSError("flush failed")
        reader.stream = mocked
        with self.assertRaises(OSError):
            reader.read_batch(observer.StopSignals())
        result = reader.finish()
        self.assertTrue(result["files_closed"])
        self.assertEqual(result["events"], 1)
        self.assertEqual(result["events_flushed_confirmed"], 0)
        self.assertEqual(result["final_cursors"][0]["unconfirmed_read_range"], [0, len(self.REMARK)])

    def test_flush_after_absolute_deadline_cannot_confirm_cursor(self):
        reader = self.prepare()
        self.append(self.REMARK)
        clock, real = [0.0], reader.stream
        mocked = MagicMock(wraps=real)
        def flush():
            real.flush()
            clock[0] = 1.0
        mocked.flush.side_effect = flush
        reader.stream = mocked
        with patch.object(observer.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(TimeoutError):
                reader.read_batch(observer.StopSignals())
        result = reader.finish()
        self.assertEqual(result["events_flushed_confirmed"], 0)
        self.assertEqual(result["final_cursors"][0]["event_archive_confirmed_offset"], 0)
        self.assertTrue(result["files_closed"])

    def test_final_hash_deadline_does_not_block_file_close(self):
        reader = self.prepare()
        self.append(self.REMARK)
        reader.read_batch(observer.StopSignals())
        clock, real_close = [0.0], reader._close
        def close():
            value = real_close()
            clock[0] = 2.0
            return value
        with patch.object(observer.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(reader, "_close", side_effect=close):
            result = reader.finish()
        self.assertTrue(result["files_closed"])
        self.assertIn("TimeoutError", result["cleanup_errors"])

    def test_first_parse_error_survives_secondary_close_error(self):
        reader = self.prepare()
        self.append(self.REMARK.replace(b"1.444ms", b"NaNms"))
        with self.assertRaises(ValueError):
            reader.read_batch(observer.StopSignals())
        real = reader.stream
        mocked = MagicMock(wraps=real)
        def close():
            real.close()
            raise OSError("close failed")
        mocked.close.side_effect = close
        reader.stream = mocked
        result = reader.finish()
        self.assertIn("ValueError", result["errors"])
        self.assertIn("OSError", result["cleanup_errors"])
        self.assertFalse(result["files_closed"])

    def test_same_size_replacement_cannot_claim_all_pause_coverage(self):
        reader = self.prepare()
        self.append(self.REMARK)
        reader.read_batch(observer.StopSignals())
        # A truncate/regrow between polls is deliberately unprovable by a polling cursor.
        self.path.write_bytes(self.REMARK.replace(b"1.444ms", b"1.555ms"))
        result = reader.finish()
        self.assertFalse(result["all_jvm_gc_pauses_proven"])
        self.assertFalse(result["window_mapping_complete"])

    def test_actual_log_option_binding_discards_unrelated_command_arguments(self):
        installation = self.root / "installation"
        log = installation / "fe/log/fe.gc.log.20260924-124506"
        log.parent.mkdir(parents=True)
        log.write_bytes(b"")
        java = self.root / "jdk/bin/java"
        java.parent.mkdir(parents=True)
        java.touch()
        option = f"-Xlog:gc*,classhisto*=trace:{log}:time,uptime:filecount=10,filesize=50M"
        command = str(java).encode() + b"\0-Dsecret=DO_NOT_ARCHIVE\0" + option.encode() + b"\0"
        state = {"installation": str(installation), "java_home": str(java.parent.parent), "namespace": "net:[private]"}
        with patch.object(observer, "check_identity"), patch.object(observer, "bounded_file", return_value=command), \
                patch.object(observer.os, "readlink", return_value=str(java)):
            value = observer.gc_binding(state, {"pid": 123, "start_ticks": 456})
        self.assertEqual(value["path"], str(log))
        self.assertEqual(value["cmdline_sha256"], hashlib.sha256(command).hexdigest())
        self.assertNotIn("DO_NOT_ARCHIVE", json.dumps(value))
        with patch.object(observer, "check_identity"), patch.object(observer, "bounded_file", return_value=command + option.encode() + b"\0"):
            with self.assertRaises(ValueError):
                observer.gc_binding(state, {"pid": 123, "start_ticks": 456})

    def test_identity_loss_marks_batch_invalid_but_closes_local_files(self):
        reader = self.prepare()
        self.append(self.REMARK)
        with patch.object(reader, "_identity", side_effect=observer.IdentityChanged("changed")):
            with self.assertRaises(observer.IdentityChanged):
                reader.read_batch(observer.StopSignals())
        self.assertTrue(reader.finish()["files_closed"])

    def test_uptime_decrease_in_same_generation_is_rejected(self):
        reader = self.prepare()
        self.append(self.CLEANUP + self.REMARK)
        with self.assertRaises(ValueError):
            reader.read_batch(observer.StopSignals())
        self.assertFalse(reader.finish()["observed_retained_prefix_continuity"])


if __name__ == "__main__":
    unittest.main()
