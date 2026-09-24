#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Check that baseline evidence cannot hide backlog, errors or missing precision."""

import importlib.util
import hashlib
import base64
import csv
import json
import os
import time
import re
import sys
from unittest.mock import patch
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("baseline", Path(__file__).with_name("run_performance_baseline.py"))
BASELINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASELINE)


class BaselineStatisticsTest(unittest.TestCase):
    def test_backlog_is_in_end_to_end_latency(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "worker-0.csv").write_text(
                "index,query_index,scheduled_ns,start_ns,end_ns,rows,error_code,sql_state\n"
                "0,0,0,100000000,110000000,1,0,00000\n")
            result = BASELINE.summarize(path, 1, .1, {"start": {}, "end": {}})
            self.assertEqual(result["p99_ms"], 110)
            self.assertEqual(result["service_p99_ms"], 10)
            self.assertEqual(result["client_queue_p99_ms"], 100)
            self.assertAlmostEqual(result["drain_seconds"], .01)

    def test_error_and_missing_requests_do_not_count_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "worker-0.csv").write_text(
                "index,query_index,scheduled_ns,start_ns,end_ns,rows,error_code,sql_state\n"
                "0,0,0,0,1000000,-1,6200,45000\n")
            result = BASELINE.summarize(path, 3, 1, {"start": {}, "end": {}})
            self.assertEqual(result["success_qps"], 0)
            self.assertEqual(result["missing_requests"], 2)
            self.assertEqual(result["errors"], {"6200/45000": 1})
            self.assertIsNone(result["p99_ms"])
            self.assertFalse(result["p99_sample_floor_met"])

    def test_cpu_pid_restart_invalidates_per_operation_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "worker-0.csv").write_text(
                "index,query_index,scheduled_ns,start_ns,end_ns,rows,error_code,sql_state\n"
                "0,0,0,0,1000000,1,0,00000\n")
            cpu = {"start": {"fe": {"start_ticks": 1, "cpu_seconds": 10}},
                   "end": {"fe": {"start_ticks": 2, "cpu_seconds": 20}}}
            result = BASELINE.summarize(path, 1, 1, cpu)
            self.assertIsNone(result["fe_cpu_seconds_per_success"])

    def test_fewer_than_five_independent_pairs_is_not_precision(self):
        windows = [{"success_qps": 100, "p95_ms": 1, "p99_ms": 2}] * 8
        analysis = BASELINE.analyze_windows(windows, 20260922)
        self.assertEqual(analysis["success_qps"]["status"], "insufficient_pairs")

    def test_high_pair_variance_is_inconclusive(self):
        windows = []
        for value in [80, 120, 70, 130, 100]:
            windows.extend([{"success_qps": 100}, {"success_qps": value}])
        result = BASELINE.analyze_windows(windows, 20260922)["success_qps"]
        self.assertEqual(result["status"], "precision_insufficient")
        self.assertGreater(result["confidence_radius_percent"], 1)

    def test_seed_is_reproducible(self):
        windows = [{"success_qps": 100 + index} for index in range(10)]
        self.assertEqual(BASELINE.analyze_windows(windows, 20260922),
                         BASELINE.analyze_windows(windows, 20260922))

    def test_precise_but_systematic_AA_drift_is_not_a_stable_baseline(self):
        windows = [{"success_qps": value} for _ in range(5) for value in (100, 110)]
        result = BASELINE.analyze_windows(windows, 20260922)["success_qps"]
        self.assertEqual(result["confidence_radius_percent"], 0)
        self.assertEqual(result["status"], "AA_directional_drift")

    def test_nonisolated_host_is_rejected_before_connecting(self):
        with self.assertRaises(ValueError):
            BASELINE.check_workload({"profile": "checkout_isolated", "host": "10.0.0.1"})
        with self.assertRaises(ValueError):
            BASELINE.check_workload({"profile": "production", "host": "127.0.0.1"})


class ServiceEndpointBindingTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="license-endpoint-test-",
                                                      dir=BASELINE.ROOT / ".build-records")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fe = self.root / "fe"
        (self.fe / "conf").mkdir(parents=True)
        (self.root / "be").mkdir()
        self.conf = self.fe / "conf/fe.conf"
        self.conf.write_text("query_port = 29030\n")
        self.workload = {"profile": "checkout_isolated", "host": "127.0.0.1", "port": 29030,
                         "database": "license_perf", "case_id": "LP-001", "duration_seconds": 1, "pairs": 1,
                         "rate": 1, "concurrency": 1, "timeout_seconds": 1, "warmup_seconds": 0, "seed": 77,
                         "queries": [{"sql": "SELECT 1", "expected_rows": 1}],
                         "services": {"fe": {"pid": 111, "root": str(self.fe)},
                                      "be": {"pid": 222, "root": str(self.root / "be")}}}

    def namespace(self, path):
        return "net:[1]"

    def test_explicit_owned_port_and_shared_namespace_are_accepted(self):
        with patch.object(BASELINE.os, "readlink", side_effect=self.namespace):
            BASELINE.check_service_endpoints(self.workload)

    def assert_rejected_before_client_launch(self, namespaces, message):
        original = Path.read_bytes
        commands = {"/proc/111/cmdline": str(self.fe).encode(),
                    "/proc/222/cmdline": str(self.root / "be").encode()}
        def read_bytes(path):
            return commands[str(path)] if str(path) in commands else original(path)
        path = self.root / "workload.json"
        path.write_text(json.dumps(self.workload))
        argv = ["baseline", "--workload", str(path), "--output", str(self.root / "output"),
                "--java-home", str(self.root / "jdk"), "--jdbc-jar", str(self.root / "driver.jar")]
        with patch.object(sys, "argv", argv), patch.object(Path, "read_bytes", read_bytes), \
                patch.object(BASELINE.os, "readlink", side_effect=namespaces), \
                patch.object(BASELINE.subprocess, "Popen") as popen, \
                patch.object(BASELINE.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, message):
                BASELINE.main()
            popen.assert_not_called()
            run.assert_not_called()
        self.assertFalse((self.root / "output").exists())

    def test_host_invocation_cannot_connect_to_an_unrelated_loopback_fe(self):
        self.assert_rejected_before_client_launch(
            lambda path: "net:[1]" if str(path) == "/proc/self/ns/net" else "net:[2]", "network namespace")

    def test_be_in_another_namespace_is_rejected_before_launch(self):
        self.assert_rejected_before_client_launch(
            lambda path: "net:[2]" if str(path) == "/proc/222/ns/net" else "net:[1]", "network namespace")

    def test_wrong_or_ambiguous_fe_port_is_rejected_before_launch(self):
        for contents in ("query_port = 29031\n", "# query_port = 29030\n",
                         "query_port = 29030\nquery_port = 29030\n", "query_port = ${PORT}\n"):
            with self.subTest(configuration=contents):
                self.conf.write_text(contents)
                self.assert_rejected_before_client_launch(self.namespace, "query_port")


FAKE_DRIVER_SOURCE = r"""
import java.sql.*;
import java.lang.reflect.Proxy;
import java.nio.file.*;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
public final class FakeBaselineDriver implements Driver {
    private static final AtomicInteger IDS = new AtomicInteger();
    public FakeBaselineDriver() throws SQLException { DriverManager.registerDriver(this); }
    private static synchronized void event(String type, int id, int delay, String value) throws Exception {
        Files.writeString(Path.of(System.getenv("MASSDB_BASELINE_FAKE_LOG")),
                type + "," + id + "," + System.nanoTime() + "," + value + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Thread.sleep(delay);
    }
    static Object empty(Class<?> type) {
        if(type == boolean.class)return false;
        if(type == int.class)return 0;
        if(type == long.class)return 0L;
        return null;
    }
    public Connection connect(String url, Properties properties) throws SQLException {
        if (!acceptsURL(url)) return null;
        int id = IDS.incrementAndGet();
        try { event("connect", id, 15, ""); } catch(Exception e) { throw new SQLException(e); }
        return (Connection)Proxy.newProxyInstance(getClass().getClassLoader(), new Class[]{Connection.class},
            (proxy, method, args) -> {
                switch(method.getName()) {
                    case "createStatement": return statement(id, false);
                    case "prepareStatement": event("prepare", id, 10, args[0].toString()); return statement(id, true);
                    case "close": event("close", id, 5, ""); return null;
                    default: return empty(method.getReturnType());
                }
            });
    }
    Object statement(int id, boolean prepared) {
        AtomicReference<String> parameter = new AtomicReference<>("");
        AtomicReference<String> returnedKey = new AtomicReference<>("0");
        return Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class[]{prepared ? PreparedStatement.class : Statement.class}, (proxy, method, args) -> {
                switch(method.getName()) {
                    case "execute":
                        if (args != null && args.length > 0 && args[0].toString().startsWith("SET")) {
                            event("initialize", id, 10, ""); return false;
                        }
                        int delay = Integer.parseInt(System.getenv().getOrDefault("MASSDB_BASELINE_FAKE_DELAY", "5"));
                        event("execute", id, delay, prepared ? parameter.get() : args[0].toString());
                        returnedKey.set(prepared ? parameter.get()
                            : args[0].toString().replaceAll("^.*WHERE id = ([0-9]+)$", "$1"));
                        return true;
                    case "getResultSet": return result(id, returnedKey.get());
                    case "setLong":
                        parameter.set(args[1].toString()); event("bind", id, 0, parameter.get()); return null;
                    default: return empty(method.getReturnType());
                }
            });
    }
    Object result(int id, String key) throws Exception {
        AtomicInteger rows = new AtomicInteger();
        String fault = System.getenv().getOrDefault("MASSDB_BASELINE_FAKE_PAYLOAD", "");
        if (fault.equals("wrong_key")) key = String.valueOf(Long.parseLong(key) + 1);
        byte[] digest = java.security.MessageDigest.getInstance("MD5").digest(key.getBytes("US-ASCII"));
        String value = String.format("%032x", new java.math.BigInteger(1, digest));
        return Proxy.newProxyInstance(getClass().getClassLoader(), new Class[]{ResultSet.class},
            (proxy, method, args) -> {
                switch(method.getName()) {
                    case "next": return rows.getAndIncrement() == 0;
                    case "getObject": return fault.equals("null") ? null : fault.equals("type") ? 1L : value;
                    case "close": event("closeResult", id, 0, ""); return null;
                    case "getMetaData": return Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class[]{ResultSetMetaData.class}, (p, m, a) ->
                        m.getName().equals("getColumnCount") ? (fault.equals("columns") ? 2 : 1) : empty(m.getReturnType()));
                    default: return empty(method.getReturnType());
                }
            });
    }
    public boolean acceptsURL(String url) {
        return url.startsWith("jdbc:licensefake:") || url.startsWith("jdbc:mariadb:");
    }
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties properties) { return new DriverPropertyInfo[0]; }
    public int getMajorVersion() { return 1; }
    public int getMinorVersion() { return 0; }
    public boolean jdbcCompliant() { return false; }
    public Logger getParentLogger() { return Logger.getGlobal(); }
}
"""


class PoissonArrivalScheduleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="license-poisson-test-")
        cls.root = Path(cls.temporary.name)
        javac = Path(shutil.which("javac")).resolve()
        cls.java = javac.with_name("java")
        driver = cls.root / "FakeBaselineDriver.java"
        driver.write_text(FAKE_DRIVER_SOURCE)
        subprocess.run([str(javac), "--release", "17", "-d", str(cls.root), str(BASELINE.SOURCE), str(driver)], check=True)
        provider = cls.root / "META-INF/services/java.sql.Driver"
        provider.parent.mkdir(parents=True, exist_ok=True)
        provider.write_text("FakeBaselineDriver\n")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def schedule(self, name, rate=1000, duration=2, seed=20260922):
        path = self.root / name
        subprocess.run([str(self.java), "-cp", str(self.root), "LicenseJdbcBaseline", "--schedule-only",
                        str(rate), str(duration), str(seed), str(path)], check=True)
        data = path.read_bytes()
        offsets = [value[0] for value in struct.iter_unpack(">q", data)]
        self.assertEqual(path.with_name(path.name + ".sha256").read_text().strip(), hashlib.sha256(data).hexdigest())
        return data, offsets

    def test_identical_seed_produces_identical_schedule_and_hash(self):
        a, offsets = self.schedule("same-a.bin")
        b, _ = self.schedule("same-b.bin")
        self.assertEqual(a, b)
        self.assertTrue(offsets)

    def test_different_seed_changes_actual_schedule(self):
        a, _ = self.schedule("seed-a.bin", seed=20260922)
        b, _ = self.schedule("seed-b.bin", seed=20260923)
        self.assertNotEqual(a, b)

    def test_poisson_intervals_and_arrival_count_are_not_fixed(self):
        _, offsets = self.schedule("intervals.bin")
        intervals = [right - left for left, right in zip([0] + offsets, offsets)]
        self.assertGreater(len(set(intervals)), 100)
        self.assertNotEqual(len(offsets), 2000)
        # A fixed seed produces both close arrivals and long gaps, not index/rate.
        self.assertLess(min(intervals), 100000)
        self.assertGreater(max(intervals), 3000000)

    def run_connection_mode(self, mode, point_mode=None, warmup=0, concurrency=1):
        directory = self.root / self._testMethodName
        settings = {"host": "127.0.0.1", "port": 29030, "database": "license_perf", "user": "test",
                    "concurrency": concurrency, "rate": 5, "duration_seconds": 1, "warmup_seconds": warmup,
                    "timeout_seconds": 2, "seed": 20260922, "connection_mode": mode,
                    "coordination_timeout_seconds": 2, "drain_timeout_seconds": 2,
                    "session_sql": ["SET fake_session=1"],
                    "services": {name: {"pid": os.getpid()} for name in ("fe", "be")}}
        if point_mode:
            settings["point_key_workload"] = {"table": "license_perf.point_rows", "mode": point_mode, "seed": 77}
        else:
            settings["queries"] = [{"sql": "SELECT ?", "mode": "prepared", "parameters": [42], "expected_rows": 1}]
        event_log = self.root / (self._testMethodName + ".driver.log")
        with patch.dict(os.environ, {"MASSDB_BASELINE_FAKE_LOG": str(event_log)}):
            summary = BASELINE.run_window(settings, directory, self.java, self.root, self.root)
        rows = []
        for path in directory.glob("worker-*.csv"):
            with path.open() as stream:
                rows.extend(csv.DictReader(stream))
        rows.sort(key=lambda row: int(row["index"]))
        events = [line.split(",", 3) for line in event_log.read_text().splitlines()]
        self.assertEqual(summary["process_exit_code"], 0)
        self.assertTrue(summary["cpu_boundary_verified"])
        self.assertFalse(summary["fixed_rate_success_qps_is_capacity"])
        return rows, events, int((directory / "arrival-count").read_text()), summary, directory

    def test_per_request_opens_initializes_prepares_and_closes_every_timed_request(self):
        rows, events, count, _, _ = self.run_connection_mode("per_request")
        self.assertGreater(count, 1)
        self.assertEqual(len(rows), count)
        for action in ("connect", "initialize", "prepare", "bind", "execute", "close"):
            self.assertEqual(sum(event[0] == action for event in events), count, action)
        self.assertEqual(len({event[1] for event in events if event[0] == "connect"}), count)
        for row in rows:
            self.assertEqual(row["error_code"], "0")
            service_ns = int(row["end_ns"]) - int(row["start_ns"])
            phases = sum(int(row[name]) for name in ("connection_ns", "session_init_ns", "prepare_ns", "execute_ns", "close_ns"))
            self.assertGreaterEqual(service_ns, phases)
            self.assertGreaterEqual(service_ns, 40_000_000)
            self.assertGreater(int(row["connection_ns"]), 10_000_000)
            self.assertGreater(int(row["prepare_ns"]), 5_000_000)

    def test_reuse_keeps_one_connection_and_original_timed_csv_boundary(self):
        rows, events, count, _, _ = self.run_connection_mode("reuse")
        for action in ("connect", "initialize", "prepare", "bind", "close"):
            self.assertEqual(sum(event[0] == action for event in events), 1, action)
        self.assertEqual(sum(event[0] == "execute" for event in events), count)
        self.assertEqual(set(rows[0]), {"index", "query_index", "scheduled_ns", "start_ns", "end_ns", "rows", "error_code", "sql_state"})

    def test_point_sequence_is_reproducible_uniform_range_and_not_a_small_repeated_vector(self):
        paths = [self.root / name for name in ("keys-a.bin", "keys-b.bin", "keys-c.bin")]
        for path, seed in zip(paths, (77, 77, 78)):
            subprocess.run([str(self.java), "-cp", str(self.root), "LicenseJdbcBaseline", "--point-keys-only",
                            "10000", str(seed), str(path)], check=True)
            self.assertEqual(path.with_name(path.name + ".sha256").read_text().strip(), hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(paths[0].read_bytes(), paths[1].read_bytes())
        self.assertNotEqual(paths[0].read_bytes(), paths[2].read_bytes())
        keys = [value[0] for value in struct.iter_unpack(">i", paths[0].read_bytes())]
        self.assertEqual(len(keys), 10000)
        self.assertGreater(len(set(keys)), 9000)
        self.assertTrue(all(0 <= key < 1000000 for key in keys))
        for bucket in range(10):
            count = sum(key // 100000 == bucket for key in keys)
            self.assertTrue(700 < count < 1300)

    def assert_point_execution(self, connection_mode, mode, warmup=0):
        rows, events, count, summary, directory = self.run_connection_mode(connection_mode, mode, warmup)
        keys = [value[0] for value in struct.iter_unpack(">i", (directory / "point-keys.bin").read_bytes())]
        warmup_keys = [value[0] for value in struct.iter_unpack(">i", (directory / "warmup-point-keys.bin").read_bytes())]
        self.assertEqual([int(row["point_key"]) for row in rows], keys)
        self.assertEqual(len(keys), count)
        self.assertTrue(summary["point_keys"]["hashes_verified"])
        self.assertEqual(summary["successful_requests"], count)
        self.assertFalse(summary["errors"])
        oracle = summary["point_result_oracle"]
        self.assertEqual(oracle["algorithm"], "lowercase_md5_ascii_decimal_id")
        self.assertEqual(oracle["unique_precomputed_keys"], len(set(keys + warmup_keys)))
        self.assertTrue(oracle["comparison_inside_request_timing"])
        self.assertTrue(oracle["precomputation_before_connections"])
        executed = [event[3] for event in events if event[0] == "execute"]
        actual = [int(value if mode == "prepared" else re.search(r"WHERE id = ([0-9]+)$", value).group(1)) for value in executed]
        self.assertEqual(actual, warmup_keys + keys)
        if mode == "prepared":
            self.assertEqual(sum(event[0] == "prepare" for event in events), 1 if connection_mode == "reuse" else count + len(warmup_keys))
            binds = [event for event in events if event[0] == "bind"][len(warmup_keys):]
            epoch = json.loads((directory / "measurement-start.json").read_text())["epoch_ns"]
            for row, event in zip(rows, binds):
                relative = int(event[2]) - epoch
                self.assertLessEqual(int(row["start_ns"]), relative)
                self.assertGreaterEqual(int(row["end_ns"]), relative)
        else:
            self.assertFalse(any(event[0] in ("prepare", "bind") for event in events))

    def test_text_point_requests_execute_saved_keys(self):
        self.assert_point_execution("reuse", "text")

    def test_prepared_point_reuses_one_statement_and_binds_each_saved_key_inside_timing(self):
        self.assert_point_execution("reuse", "prepared", warmup=1)

    def test_per_request_point_uses_the_same_saved_key_contract(self):
        self.assert_point_execution("per_request", "prepared")

    def test_text_per_request_checks_payload_as_well_as_saved_keys(self):
        self.assert_point_execution("per_request", "text")

    def assert_bad_point_payload(self, fault, connection_mode, query_mode):
        with patch.dict(os.environ, {"MASSDB_BASELINE_FAKE_PAYLOAD": fault}):
            rows, events, count, summary, _ = self.run_connection_mode(connection_mode, query_mode)
        self.assertGreater(count, 0)
        self.assertEqual(len(rows), count)
        self.assertEqual(summary["successful_requests"], 0)
        self.assertEqual(summary["errors"], {"-3/VALUE": count})
        self.assertEqual(sum(event[0] == "closeResult" for event in events), count)
        self.assertTrue(all(row["sql_state"] == "VALUE" for row in rows))

    def test_correct_row_count_with_wrong_key_payload_is_rejected(self):
        self.assert_bad_point_payload("wrong_key", "reuse", "prepared")

    def test_null_payload_is_rejected(self):
        self.assert_bad_point_payload("null", "reuse", "text")

    def test_non_string_payload_is_rejected(self):
        self.assert_bad_point_payload("type", "per_request", "prepared")

    def test_extra_payload_column_is_rejected(self):
        self.assert_bad_point_payload("columns", "per_request", "text")

    def test_cpu_end_waits_for_all_workers_and_all_connections_close_after_it(self):
        rows, events, count, _, directory = self.run_connection_mode("reuse", "prepared", concurrency=3)
        keys = [value[0] for value in struct.iter_unpack(">i", (directory / "point-keys.bin").read_bytes())]
        self.assertEqual([int(row["index"]) for row in rows], list(range(count)))
        self.assertEqual([int(row["point_key"]) for row in rows], keys)
        end = json.loads((directory / "measurement-end.json").read_text())
        last = max(int(row["end_ns"]) for row in rows) + end["epoch_ns"]
        self.assertEqual(last, end["last_request_end_ns"])
        for sample in end["cpu"].values():
            self.assertGreaterEqual(sample["sample_started_ns"], last)
        closes = [event for event in events if event[0] == "close"]
        self.assertEqual(len(closes), 3)
        self.assertTrue(all(int(event[2]) >= end["measurement_end_ns"] for event in closes))
        self.assertEqual(sum(event[0] == "prepare" for event in events), 3)

    def manual_client(self, *, coordination=1, delay=5):
        directory = self.root / self._testMethodName
        directory.mkdir()
        (directory / "queries.tsv").write_text(base64.b64encode(b"SELECT ?").decode() + "\tprepared\t1\ti42\n")
        (directory / "session.txt").write_text("")
        settings = {"queries": directory / "queries.tsv", "session": directory / "session.txt", "output": directory,
                    "url": "jdbc:licensefake:test", "user": "test", "concurrency": 1, "rate": 20,
                    "duration_seconds": 1, "warmup_seconds": 0, "timeout_seconds": 1,
                    "seed": 20260922, "connection_mode": "reuse", "coordination_timeout_seconds": coordination,
                    "drain_timeout_seconds": 1, "fe_pid": os.getpid(), "be_pid": os.getpid(),
                    "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"), "page_size": os.sysconf("SC_PAGE_SIZE")}
        config = directory / "input.properties"
        config.write_text("\n".join(str(k) + "=" + str(v) for k, v in settings.items()))
        env = dict(os.environ, MASSDB_BASELINE_FAKE_LOG=str(directory / "driver.log"), MASSDB_BASELINE_FAKE_DELAY=str(delay))
        process = subprocess.Popen([str(self.java), "-cp", str(self.root), "LicenseJdbcBaseline", str(config)],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        return process, directory

    def wait_file(self, path, process, seconds=6):
        deadline = time.monotonic() + seconds
        while not path.exists():
            self.assertIsNone(process.poll(), "Client exited before " + path.name)
            self.assertLess(time.monotonic(), deadline, "Client did not publish " + path.name)
            time.sleep(.01)
        return json.loads(path.read_text())

    def test_missing_start_ack_times_out_without_any_measured_request(self):
        process, directory = self.manual_client()
        self.wait_file(directory / "measurement-ready.json", process)
        self.assertNotEqual(process.wait(timeout=5), 0)
        failure = json.loads((directory / "client-failure.json").read_text())
        self.assertEqual(failure["phase"], "start_ack")
        self.assertFalse((directory / "measurement-start.json").exists())
        self.assertNotIn("execute,", (directory / "driver.log").read_text())

    def test_end_ack_defers_connection_cleanup_and_cpu_boundary_excludes_it(self):
        process, directory = self.manual_client(coordination=2)
        self.wait_file(directory / "measurement-ready.json", process)
        BASELINE.acknowledge(directory / "measurement-start-ack")
        end = self.wait_file(directory / "measurement-end.json", process)
        before = (directory / "measurement-end.json").read_bytes()
        time.sleep(.1)
        self.assertNotIn("close,", (directory / "driver.log").read_text())
        BASELINE.acknowledge(directory / "measurement-end-ack")
        self.assertEqual(process.wait(timeout=5), 0)
        self.assertEqual(before, (directory / "measurement-end.json").read_bytes())
        start = json.loads((directory / "measurement-start.json").read_text())
        lifecycle = json.loads((directory / "lifecycle.json").read_text())
        self.assertTrue(BASELINE.boundary_evidence(start, end, lifecycle)["verified"])
        closes = [int(line.split(",")[2]) for line in (directory / "driver.log").read_text().splitlines() if line.startswith("close,")]
        self.assertEqual(len(closes), 1)
        self.assertGreaterEqual(closes[0], lifecycle["cleanup_start_ns"])
        self.assertLessEqual(closes[0], lifecycle["cleanup_end_ns"])
        end["cpu"]["fe"]["sample_started_ns"] = end["request_interval_end_ns"] - 1
        self.assertFalse(BASELINE.boundary_evidence(start, end, lifecycle)["verified"])

    def test_missing_end_ack_times_out_and_never_reports_complete_lifecycle(self):
        process, directory = self.manual_client()
        self.wait_file(directory / "measurement-ready.json", process)
        BASELINE.acknowledge(directory / "measurement-start-ack")
        self.wait_file(directory / "measurement-end.json", process)
        self.assertNotEqual(process.wait(timeout=5), 0)
        self.assertEqual(json.loads((directory / "client-failure.json").read_text())["phase"], "end_ack")
        self.assertFalse((directory / "lifecycle.json").exists())

    def test_jdbc_request_that_ignores_timeout_cannot_hold_client_forever(self):
        process, directory = self.manual_client(delay=10000)
        self.wait_file(directory / "measurement-ready.json", process)
        BASELINE.acknowledge(directory / "measurement-start-ack")
        self.assertNotEqual(process.wait(timeout=6), 0)
        self.assertEqual(json.loads((directory / "client-failure.json").read_text())["phase"], "requests")
        self.assertFalse((directory / "measurement-end.json").exists())

    def test_all_arrivals_obey_window_boundary_and_zero_window_is_empty(self):
        _, offsets = self.schedule("boundary.bin")
        self.assertEqual(offsets, sorted(offsets))
        self.assertGreaterEqual(min(offsets), 0)
        self.assertLess(max(offsets), 2_000_000_000)
        data, offsets = self.schedule("empty.bin", duration=0)
        self.assertEqual(data, b"")
        self.assertEqual(offsets, [])


if __name__ == "__main__":
    unittest.main()
