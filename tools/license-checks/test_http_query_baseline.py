#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline HTTP transport/oracle/raw audit checks; no DB endpoint or service is contacted."""
import csv
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import http_query_baseline as runner


def workload():
    value = {'group': 'G1', 'seed': 20260922, 'concurrency': 1, 'connection_mode': 'http_keep_alive',
             'phase': 'DIAGNOSTIC', 'variant': 'A', 'warmup_seconds': 0, 'duration_seconds': 1,
             'query_timeout_seconds': 10, 'request_timeout_seconds': 1, 'drain_timeout_seconds': 1,
             'rate': 5, 'database': 'license_perf', 'table': 'license_perf.point_rows',
             'expected_column_type': 'VARCHAR', 'window_id': 'G1-offline-http', 'pair_id': 0,
             'http_port': 12345, 'user': 'test', 'password_env': 'P4_OFFLINE_ONLY_PASSWORD',
             'services': {name: {'pid': os.getpid()} for name in ('fe', 'be')},
             'identity': {name: 'a' * (40 if name == 'source_commit' else 64) for name in runner.statistics.IDENTITY_FIELDS}}
    value['business_workload_sha256'] = runner.business_binding(value)['sha256']
    return value


def success(key, **overrides):
    body = {'code': 0, 'msg': 'success', 'data': {'type': 'result_set',
            'meta': [{'name': 'payload', 'type': 'VARCHAR'}],
            'data': [[hashlib.md5(str(key).encode()).hexdigest()]]}}
    body.update(overrides)
    return body


class Transport:
    def __init__(self):
        self.shutdowns = 0
    def settimeout(self, value):
        self.timeout = value
    def shutdown(self, how):
        self.shutdowns += 1


class Response:
    def __init__(self, raw, status=200, will_close=False):
        self.raw, self.offset, self.status, self.will_close = raw, 0, status, will_close
        self.closed = False
    def read1(self, count):
        data = self.raw[self.offset:self.offset + count]
        self.offset += len(data)
        return data
    def isclosed(self):
        return self.offset == len(self.raw)
    def close(self):
        self.closed = True


class Factory:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.connections, self.requests = [], []
    def __call__(self, host, port, timeout):
        factory = self
        class Connection:
            def __init__(self):
                self.sock, self.last_body, self.closes = None, None, 0
            def connect(self):
                self.sock = Transport()
            def close(self):
                self.sock = None
                self.closes += 1
            def request(self, method, path, body, headers):
                self.last_body = body
                factory.requests.append((method, path, body, dict(headers)))
            def getresponse(self):
                if factory.responses:
                    value = factory.responses.pop(0)
                    if isinstance(value, Exception):
                        raise value
                    return value
                key = int(json.loads(self.last_body)['stmt'].rsplit(' ', 1)[1])
                return Response(json.dumps(success(key)).encode())
        instance = Connection()
        self.connections.append(instance)
        return instance


class NoDeadlineThread:
    def arm(self, *args):
        pass
    def disarm(self, *args):
        pass


class HttpOracleTest(unittest.TestCase):
    def test_full_point_shape_accepts_only_exact_string_and_column_type(self):
        expected = hashlib.md5(b'42').hexdigest()
        self.assertEqual(runner.verify_point_response(200, success(42), expected, 'VARCHAR'), ('NONE', expected))
        for field, value in (('data', [[None]]), ('data', [[1]]), ('data', [[expected], [expected]]),
                             ('meta', [{'name': 'other', 'type': 'VARCHAR'}]),
                             ('meta', [{'name': 'payload', 'type': 'CHAR'}])):
            body = success(42)
            body['data'][field] = value
            self.assertEqual(runner.verify_point_response(200, body, expected, 'VARCHAR')[0], 'RESULT_MISMATCH')

    def test_real_http_and_business_errors_are_distinct(self):
        expected = hashlib.md5(b'42').hexdigest()
        self.assertEqual(runner.verify_point_response(403, success(42), expected, 'VARCHAR')[0], 'HTTP_STATUS')
        self.assertEqual(runner.verify_point_response(200, {'code': 1, 'msg': 'secret'}, expected, 'VARCHAR')[0], 'HTTP_BUSINESS_ERROR')
        self.assertEqual(runner.verify_point_response(200, {'code': True}, expected, 'VARCHAR')[0], 'INVALID_RESPONSE')

    def test_known_server_timeout_signature_is_counted_without_archiving_error_text(self):
        expected = hashlib.md5(b'42').hexdigest()
        result = runner.verify_point_response(200, {'code': 1, 'msg': 'Failed SQL: query timeout canary secret'}, expected, 'VARCHAR')
        self.assertEqual(result, ('SERVER_TIMEOUT_REPORTED', None))

    def test_business_hash_keeps_workload_semantics_but_not_role_endpoints_or_rate(self):
        value = workload()
        actual = runner.business_binding(value)['sha256']
        self.assertEqual(actual, runner.business_binding(dict(value, variant='B', phase='AB', http_port=333,
                         rate=12.5, warmup_seconds=120, duration_seconds=300))['sha256'])
        for name, changed in (('concurrency', 16), ('expected_column_type', 'CHAR'), ('query_timeout_seconds', 20),
                              ('request_timeout_seconds', 2), ('table', 'other'), ('seed', 7)):
            self.assertNotEqual(actual, runner.business_binding(dict(value, **{name: changed}))['sha256'])

    def test_fixed_scope_and_candidate_freeze_rules_are_checked_without_network(self):
        runner.validate_shape(workload())
        for field, changed in (('seed', 1), ('concurrency', 8), ('table', 'x; DROP TABLE t'),
                              ('connection_mode', 'per_request'), ('phase', 'AA_BAD'), ('variant', 'B')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.validate_shape(dict(workload(), **{field: changed}))

    def test_inline_password_and_unknown_fields_are_not_archived(self):
        with self.assertRaisesRegex(ValueError, 'Unknown workload fields'):
            runner.validate_shape(dict(workload(), password='never-store-this'))

    def test_cli_help_loads_entrypoint_without_network(self):
        result = subprocess.run([sys.executable, runner.__file__, '--help'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--validate-only', result.stdout)

    def test_request_keeps_fixed_no_cache_point_hints_and_row_limit(self):
        body = json.loads(runner.request_body(workload(), 42))
        self.assertTrue(body['is_sync'])
        self.assertEqual(body['limit'], 1000)
        self.assertIn('enable_sql_cache=false', body['stmt'])
        self.assertTrue(body['stmt'].endswith('WHERE id = 42'))


class HttpTransportTest(unittest.TestCase):
    def execute(self, client, index=0):
        epoch = time.monotonic_ns() - 1000000
        return client.execute(index, 42, epoch, epoch)

    def client(self, factory=None, **updates):
        value = dict(workload(), **updates)
        factory = factory or Factory()
        client = runner.KeepAliveWorker(0, value, NoDeadlineThread(), factory)
        self.addCleanup(client.close)
        return client, factory

    def test_keepalive_reuses_transport_and_closes_only_at_cleanup(self):
        client, factory = self.client()
        first, second = self.execute(client), self.execute(client, 1)
        self.assertEqual((first['error_code'], second['error_code']), (0, 0))
        self.assertFalse(first['transport_reused'])
        self.assertTrue(second['transport_reused'])
        self.assertEqual(first['connection_generation'], second['connection_generation'])
        self.assertEqual(len(factory.connections), 1)
        self.assertEqual(factory.connections[0].closes, 0)
        client.close()
        self.assertTrue(client.closed)
        self.assertIsNone(factory.connections[0].sock)

    def test_server_normal_close_is_replaced_for_next_request_without_replaying_first(self):
        factory = Factory([Response(json.dumps(success(42)).encode(), will_close=True)])
        client, _ = self.client(factory)
        first, second = self.execute(client), self.execute(client, 1)
        self.assertEqual((first['error_code'], second['error_code']), (0, 0))
        self.assertEqual((first['connection_generation'], second['connection_generation']), (1, 2))
        self.assertEqual(len(factory.requests), 2)

    def test_transport_failure_is_not_retried_and_next_scheduled_request_can_reconnect(self):
        factory = Factory([http.client.RemoteDisconnected('do not archive secret')])
        client, _ = self.client(factory)
        first = self.execute(client)
        self.assertEqual(first['error_class'], 'CONNECTION_ERROR')
        self.assertEqual(len(factory.requests), 1)
        second = self.execute(client, 1)
        self.assertEqual(second['error_class'], 'NONE')
        self.assertEqual(len(factory.requests), 2)
        self.assertNotIn('secret', json.dumps(first))

    def test_non200_http_status_is_retained_without_following_redirect(self):
        client, factory = self.client(Factory([Response(json.dumps(success(42)).encode(), status=302)]))
        result = self.execute(client)
        self.assertEqual(result['http_status'], 302)
        self.assertEqual(result['error_class'], 'HTTP_STATUS')
        self.assertEqual(len(factory.requests), 1)

    def test_non_json_http_503_keeps_transport_status(self):
        client, _ = self.client(Factory([Response(b'service unavailable', status=503)]))
        result = self.execute(client)
        self.assertEqual((result['http_status'], result['error_class']), (503, 'HTTP_STATUS'))

    def test_incomplete_http_framing_is_not_a_success_even_with_a_complete_json_value(self):
        response = Response(json.dumps(success(42)).encode())
        response.length = 17
        client, _ = self.client(Factory([response]))
        self.assertEqual(self.execute(client)['error_class'], 'CONNECTION_ERROR')

    def test_response_size_bound_cannot_pass_as_success(self):
        client, _ = self.client(Factory([Response(b'x' * (runner.MAX_BODY + 1))]))
        result = self.execute(client)
        self.assertEqual(result['error_class'], 'RESPONSE_TOO_LARGE')
        self.assertEqual(result['response_bytes'], runner.MAX_BODY + 1)
        self.assertEqual(result['error_code'], 1)

    def test_duplicate_json_fields_and_wrong_payload_fail(self):
        for raw, expected in ((b'{"code":0,"code":0}', 'INVALID_RESPONSE'),
                              (json.dumps(success(43)).encode(), 'RESULT_MISMATCH')):
            client, _ = self.client(Factory([Response(raw)]))
            self.assertEqual(self.execute(client)['error_class'], expected)

    def test_timeout_is_distinct_and_does_not_replay_request(self):
        client, factory = self.client(Factory([socket.timeout('secret')]))
        result = self.execute(client)
        self.assertEqual(result['error_class'], 'HTTP_TIMEOUT')
        self.assertEqual(len(factory.requests), 1)
        self.assertEqual(result['error_code'], 1)

    def test_credentials_exist_only_in_memory_headers_not_raw_receipts(self):
        with patch.dict(os.environ, {'P4_OFFLINE_ONLY_PASSWORD': 'canary-secret-123'}):
            client, factory = self.client()
            result = self.execute(client)
        self.assertIn('Authorization', factory.requests[0][3])
        encoded = json.dumps(result)
        self.assertNotIn('canary-secret-123', encoded)
        self.assertNotIn(factory.requests[0][3]['Authorization'], encoded)

    def test_single_watchdog_interrupts_blocked_socket_and_terminates(self):
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        registry = runner.DeadlineRegistry()
        self.addCleanup(registry.close)
        registry.arm(0, reader, time.monotonic() + .03)
        reader.settimeout(1)
        start = time.monotonic()
        self.assertEqual(reader.recv(1), b'')
        self.assertLess(time.monotonic() - start, .5)
        registry.close()
        self.assertFalse(registry.thread.is_alive())

    def test_absolute_header_wait_timeout_interrupts_socket_instead_of_idle_timeout_reset(self):
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        registry = runner.DeadlineRegistry()
        self.addCleanup(registry.close)
        factory = Factory()
        connection = factory('127.0.0.1', 123, 1)
        def connect():
            connection.sock = reader
        def blocked_headers():
            if not reader.recv(1):
                raise http.client.RemoteDisconnected('deadline interrupted headers')
        connection.connect, connection.getresponse = connect, blocked_headers
        client = runner.KeepAliveWorker(0, dict(workload(), request_timeout_seconds=.03), registry,
                                       lambda *args, **kwargs: connection)
        self.addCleanup(client.close)
        started = time.monotonic()
        result = self.execute(client)
        self.assertEqual(result['error_class'], 'HTTP_TIMEOUT')
        self.assertLess(time.monotonic() - started, .5)


class RawWindowAuditTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='p4-http-offline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workload = workload()
        self.pins = {name: runner.baseline.process_sample(os.getpid())['start_ticks'] for name in ('fe', 'be')}

    def vector(self, filename, values, width):
        path = self.root / filename
        path.write_bytes(b''.join(struct.pack('>q' if width == 8 else '>i', value) for value in values))
        path.with_name(path.name + '.sha256').write_text(runner.baseline.sha(path))

    def launch(self):
        warmup_arrivals, warmup_keys = getattr(self, 'warmup_vectors', ([], []))
        self.vector('warmup-arrivals.bin', warmup_arrivals, 8)
        self.vector('warmup-keys.bin', warmup_keys, 4)
        self.vector('measured-arrivals.bin', [1000000, 2000000, 3000000], 8)
        self.vector('measured-keys.bin', [42, 43, 44], 4)
        runner.save(self.root / 'workload.json', self.workload)
        launch = {'created_monotonic_ns': time.monotonic_ns(), 'boot_id': runner.statistics.boot_id(),
                  'phase': self.workload['phase'], 'variant': self.workload['variant'],
                  'business_binding': runner.business_binding(self.workload),
                  'workload_sha256': runner.baseline.sha(self.root / 'workload.json'), 'bindings': {},
                  'service_start_ticks': self.pins, 'vectors': {name: runner.statistics.reference(self.root / name)
                   for name in ('warmup-arrivals.bin', 'warmup-keys.bin', 'measured-arrivals.bin', 'measured-keys.bin')}}
        runner.save(self.root / 'launch.json', launch)
        return {'warmup': (warmup_arrivals, warmup_keys), 'measured': ([1000000, 2000000, 3000000], [42, 43, 44])}

    def run_window(self, factory=None):
        vectors = self.launch()
        return runner.execute_window(self.workload, self.root, vectors, self.pins, connection_factory=factory or Factory())

    def test_full_raw_oracle_boundaries_cleanup_and_normalized_window_are_recomputed(self):
        summary = self.run_window()
        self.assertEqual(summary['successful_requests'], 3)
        result = runner.audit_window(self.root)
        self.assertEqual(result['status'], 'DIAGNOSTIC_VERIFIED')
        window = result['window']
        self.assertEqual(window['monotonic_clock_domain'], 'controller_monotonic_exact')
        self.assertTrue(window['oracle_verified'] and window['cleanup_verified'] and window['cpu_boundary_verified'])
        self.assertEqual(window['effective_duration_seconds'], 1)
        self.assertEqual(window['scheduled_requests'], 3)
        self.assertTrue(result['raw_artifacts'])
        self.assertFalse(result['formal_performance_pass'])
        runner.save(self.root / 'audit.json', result)
        runner.save(self.root / 'window.json', window)
        self.assertEqual(runner.audit_window(self.root), result)

    def test_wrong_payload_not_hidden_by_successful_http_or_row_count(self):
        summary = self.run_window(Factory([Response(json.dumps(success(99)).encode())]))
        self.assertEqual(summary['successful_requests'], 2)
        self.assertEqual(summary['error_classes'], {'RESULT_MISMATCH': 1})
        with self.assertRaisesRegex(ValueError, 'Measured HTTP/oracle errors'):
            runner.audit_window(self.root)

    def test_raw_sample_mutation_cannot_be_replaced_by_green_summary(self):
        self.run_window()
        path = self.root / 'worker-0.csv'
        path.write_text(path.read_text().replace(hashlib.md5(b'42').hexdigest(), hashlib.md5(b'99').hexdigest()))
        with self.assertRaisesRegex(ValueError, 'full point oracle'):
            runner.audit_window(self.root)

    def test_duplicated_request_indices_are_rejected(self):
        self.run_window()
        path = self.root / 'worker-0.csv'
        lines = path.read_text().splitlines()
        lines[-1] = lines[-2]
        path.write_text('\n'.join(lines) + '\n')
        with self.assertRaisesRegex(ValueError, 'Duplicate/reordered'):
            runner.audit_window(self.root)

    def test_backlog_remains_in_end_to_end_latency(self):
        class SlowFactory(Factory):
            def __call__(self, *args, **kwargs):
                value = super().__call__(*args, **kwargs)
                original = value.getresponse
                def slow():
                    time.sleep(.03)
                    return original()
                value.getresponse = slow
                return value
        summary = self.run_window(SlowFactory())
        self.assertGreater(summary['client_queue_p99_ms'], 30)
        self.assertGreater(summary['p99_ms'], summary['service_p99_ms'])
        runner.audit_window(self.root)

    def test_sixteen_workers_keep_independent_fixed_connections_and_all_receipts(self):
        self.workload['concurrency'] = 16
        self.workload['business_workload_sha256'] = runner.business_binding(self.workload)['sha256']
        factory = Factory()
        self.run_window(factory)
        audit = runner.audit_window(self.root)
        self.assertEqual(len(factory.connections), 16)
        self.assertEqual(len(list(self.root.glob('worker-*.csv'))), 16)
        self.assertEqual(audit['window']['successful_requests'], 3)
        self.assertTrue(all(connection.sock is None for connection in factory.connections))

    def test_warmup_failures_remain_disqualifying_after_successful_measurement(self):
        self.workload['warmup_seconds'] = 1
        self.warmup_vectors = ([1000000], [42])
        summary = self.run_window(Factory([Response(json.dumps(success(99)).encode())]))
        self.assertEqual(summary['successful_requests'], 3)
        with self.assertRaisesRegex(ValueError, 'Warmup had HTTP/oracle errors'):
            runner.audit_window(self.root)

    def test_pid_lifetime_change_invalidates_cpu_cost_even_with_good_payloads(self):
        self.run_window()
        resources = runner.statistics.read_json(self.root / 'resources.json')
        resources['cpu']['end']['fe']['start_ticks'] += 1
        runner.save(self.root / 'resources.json', resources)
        with self.assertRaisesRegex(ValueError, 'changed process'):
            runner.audit_window(self.root)

    def test_warmup_boundary_cannot_exclude_raw_request_completion(self):
        self.warmup_vectors = ([0], [42])
        self.run_window()
        path = self.root / 'warmup-worker-0.csv'
        with path.open() as stream:
            rows = list(csv.DictReader(stream))
        rows[0]['end_ns'] = str(10**12)
        with path.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, runner.FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        with self.assertRaisesRegex(ValueError, 'Warmup boundary excludes'):
            runner.audit_window(self.root)

    def test_declared_summary_cannot_hide_raw_tail_latency(self):
        self.run_window()
        summary = runner.statistics.read_json(self.root / 'summary.json')
        summary['p99_ms'] = 0
        runner.save(self.root / 'summary.json', summary)
        with self.assertRaisesRegex(ValueError, 'Summary differs'):
            runner.audit_window(self.root)


class GeneratorTest(unittest.TestCase):
    def test_existing_java_schedule_and_key_generator_is_reused_without_network(self):
        javac = shutil.which('javac')
        if not javac:
            self.skipTest('JDK17 required')
        with tempfile.TemporaryDirectory(prefix='p4-http-vectors-') as directory:
            root = Path(directory)
            vectors = runner.generate_vectors(workload(), root, Path(javac).resolve().parent.parent)
            self.assertTrue(vectors['measured'][0])
            self.assertEqual(len(vectors['measured'][0]), len(vectors['measured'][1]))
            self.assertEqual(vectors['warmup'], ([], []))
            self.assertTrue(all(0 <= key < 1000000 for key in vectors['measured'][1]))
            self.assertEqual((root / 'measured-arrivals.bin.sha256').read_text().strip(), runner.baseline.sha(root / 'measured-arrivals.bin'))


class PublishedFreezeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='p4-http-freeze-offline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workload = dict(workload(), phase='AB', variant='B', freeze=str(self.root / 'freeze.json'))
        self.frozen = {'status': 'FROZEN_ELIGIBLE', 'boot_id': runner.statistics.boot_id(),
                       'identities': {'A': self.workload['identity'], 'B': self.workload['identity']},
                       'cell': {key: self.workload[key] for key in (
                           'rate', 'concurrency', 'connection_mode', 'warmup_seconds', 'duration_seconds', 'seed')}}
        self.frozen['cell'].update(workload_sha256=self.workload['business_workload_sha256'],
                                   arrival_schedule_sha256='a' * 64)
        self.publish()

    def publish(self):
        path = Path(self.workload['freeze'])
        runner.save(path, self.frozen)
        publication = {'freeze': runner.statistics.reference(path), 'boot_id': runner.statistics.boot_id(),
                       'published_monotonic_ns': time.monotonic_ns()}
        runner.save(path.with_suffix('.json.published.json'), publication)

    def test_candidate_requires_existing_published_matching_inputs_before_launch(self):
        result = runner.frozen_launch(self.workload)
        self.assertEqual(result['freeze'], runner.statistics.reference(self.workload['freeze']))
        self.assertEqual(result['frozen_arrival_schedule_sha256'], 'a' * 64)
        for field, value in (('rate', 6), ('concurrency', 16), ('connection_mode', 'per_request')):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'workload differs'):
                runner.frozen_launch(dict(self.workload, **{field: value}))

    def test_modified_or_future_publication_cannot_authorize_candidate(self):
        publication = Path(self.workload['freeze'] + '.published.json')
        value = runner.statistics.read_json(publication)
        value['published_monotonic_ns'] = time.monotonic_ns() + 10**12
        runner.save(publication, value)
        with self.assertRaisesRegex(ValueError, 'future freeze'):
            runner.frozen_launch(self.workload)
        self.publish()
        self.frozen['cell']['rate'] = 6
        runner.save(self.workload['freeze'], self.frozen)
        with self.assertRaisesRegex(ValueError, 'future freeze'):
            runner.frozen_launch(self.workload)

    def test_a_only_window_cannot_silently_consume_ab_freeze(self):
        with self.assertRaisesRegex(ValueError, 'A-only execution'):
            runner.frozen_launch(dict(self.workload, phase='AA', variant='A'))


class OwnedTargetTest(unittest.TestCase):
    def test_installed_lib_symlink_to_package_is_valid_for_both_variants(self):
        # The real checkout installations link fe/lib to their package's fe/lib.
        # Only /proc ownership reads are mocked; path resolution, PID/config and SHA checks are real.
        with tempfile.TemporaryDirectory(prefix='http-owned-offline-', dir=runner.ROOT / '.build-records') as directory:
            root = Path(directory)
            for variant in ('A', 'B'):
                installation = root / ('installation-' + variant)
                package_lib = root / ('package-' + variant) / 'fe/lib'
                package_lib.mkdir(parents=True)
                (package_lib / 'doris-fe.jar').write_bytes(('different-' + variant).encode())
                for name, pid in (('fe', 123), ('be', 456)):
                    (installation / name / 'bin').mkdir(parents=True)
                    (installation / name / 'bin' / (name + '.pid')).write_text(str(pid))
                (installation / 'fe/conf').mkdir()
                (installation / 'fe/conf/fe.conf').write_text('http_port=12345\nquery_port=12346\n')
                (installation / 'fe/lib').symlink_to(package_lib, target_is_directory=True)
                value = dict(workload(), phase='AB' if variant == 'B' else 'DIAGNOSTIC', variant=variant,
                             cluster_record=str(root / (variant + '.json')))
                value['services'] = {name: {'root': str(installation / name), 'pid': pid}
                                     for name, pid in (('fe', 123), ('be', 456))}
                value['build_identity'] = {'fe_artifact': str(installation / 'fe/lib/doris-fe.jar'),
                                          'be_artifact': sys.executable, 'baseline_source_commit': 'a' * 40}
                value['identity']['fe_sha256'] = runner.baseline.sha(value['build_identity']['fe_artifact'])
                value['identity']['be_sha256'] = runner.baseline.sha(sys.executable)
                state = {'installation': str(installation), 'query_port': 12346, 'http_port': 12345}
                with patch.object(runner, 'validate_cluster', return_value=(state, 12347)), \
                        patch.object(runner.baseline, 'check_workload'), \
                        patch.object(runner.os.path, 'samefile', return_value=True), \
                        patch.object(runner.baseline, 'process_sample', return_value={'start_ticks': 99}):
                    self.assertEqual(runner.validate_owned_target(value), {'fe': 99, 'be': 99})
                    value['build_identity']['fe_artifact'] = str(package_lib / 'other.jar')
                    with self.assertRaisesRegex(ValueError, 'installed FE JAR'):
                        runner.validate_owned_target(value)


if __name__ == '__main__':
    unittest.main()
