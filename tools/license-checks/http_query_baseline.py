#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""One audited G1 HTTP Query window. A/A or A/B scheduling and capacity are external decisions."""

import argparse
import base64
import csv
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

import calibrate_read_capacity as capacity
import metadata_fixture
import p4_statistics as statistics
import run_performance_baseline as baseline
import stream_load_fixture
from stream_load_fixture import ROOT, owned, save, validate_cluster

MAX_BODY = 65536
SEED = 20260922
FIELDS = ('index', 'query_index', 'scheduled_ns', 'start_ns', 'end_ns', 'rows', 'error_code', 'sql_state',
          'error_class', 'point_key', 'http_status', 'business_code', 'response_bytes', 'response_sha256',
          'request_sha256', 'actual_payload', 'column_name', 'column_type', 'connection_generation', 'transport_reused')


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def business_binding(workload):
    payload = {key: workload[key] for key in ('database', 'table', 'concurrency', 'seed', 'connection_mode',
               'request_timeout_seconds', 'query_timeout_seconds', 'expected_column_type')}
    payload.update(schema='license_http_point_v1', group='G1', endpoint='HTTP Query/default_cluster',
                   sql_template=sql_template(workload), http_stream=False, row_limit=1000,
                   arrival='java_random_strictmath_poisson_v1', key_model='java_random_uniform_0_999999',
                   payload_model='lowercase_md5_ascii_decimal_id')
    if 'fixture_sha256' in workload:
        payload['fixture_sha256'] = workload['fixture_sha256']
    return {'payload': payload, 'sha256': hashlib.sha256(canonical(payload)).hexdigest()}


def sql_template(workload):
    return ('SELECT /*+ SET_VAR(enable_sql_cache=false, enable_query_cache=false, '
            'enable_short_circuit_query=true, query_timeout=%d) */ payload FROM %s WHERE id = '
            % (workload['query_timeout_seconds'], workload['table']))


def request_body(workload, key):
    return canonical({'is_sync': True, 'limit': 1000, 'stmt': sql_template(workload) + str(key)})


def validate_shape(workload):
    allowed = {'group', 'seed', 'concurrency', 'connection_mode', 'phase', 'variant', 'warmup_seconds',
               'duration_seconds', 'query_timeout_seconds', 'request_timeout_seconds', 'drain_timeout_seconds',
               'rate', 'database', 'table', 'expected_column_type', 'window_id', 'pair_id', 'http_port', 'user',
               'password_env', 'services', 'identity', 'business_workload_sha256', 'cluster_record',
               'build_identity', 'identity_bindings', 'fixture_sha256', 'freeze'}
    require(set(workload) <= allowed, 'Unknown workload fields; use password_env rather than inline credentials')
    require(workload.get('group') == 'G1' and workload.get('seed') == SEED, 'Only current G1 / seed 20260922')
    require(workload.get('concurrency') in (1, 16) and type(workload['concurrency']) is int, 'G1 workers must be 1 or 16')
    require(workload.get('connection_mode') == 'http_keep_alive', 'Explicit HTTP keep-alive is required')
    require(workload.get('phase') in ('DIAGNOSTIC', 'AA', 'AB') and workload.get('variant') in ('A', 'B'),
            'Explicit phase and A/B variant required')
    require(workload['phase'] == 'AB' or workload['variant'] == 'A', 'Candidate measurement requires published A/B freeze')
    for field in ('warmup_seconds', 'duration_seconds', 'query_timeout_seconds', 'drain_timeout_seconds'):
        require(type(workload.get(field)) is int and 0 <= workload[field] <= 3600, 'Invalid ' + field)
    require(all(workload[key] > 0 for key in ('duration_seconds', 'query_timeout_seconds', 'drain_timeout_seconds')),
            'Positive duration/query/drain timeout required')
    for field in ('rate', 'request_timeout_seconds'):
        require(type(workload.get(field)) in (int, float) and math.isfinite(workload[field])
                and 0 < workload[field] <= (100000 if field == 'rate' else 60), 'Invalid ' + field)
    for field in ('database', 'table'):
        require(isinstance(workload.get(field), str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)?', workload[field]),
                'Simple isolated identifiers required')
    require('.' not in workload['database'], 'Database must be unqualified')
    require(workload.get('expected_column_type') in ('VARCHAR', 'CHAR', 'STRING'), 'Freeze actual HTTP payload column type')
    require(isinstance(workload.get('window_id'), str) and re.fullmatch(r'G1-[A-Za-z0-9_.-]+', workload['window_id']), 'Explicit G1 window ID required')
    require(type(workload.get('pair_id')) is int and workload['pair_id'] >= 0, 'Explicit independent pair ID required')
    require(type(workload.get('http_port')) is int and 1 <= workload['http_port'] <= 65535, 'Invalid HTTP port')
    require(isinstance(workload.get('user'), str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', workload['user']),
            'Simple test username required')
    require(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', workload.get('password_env', 'MASSDB_BASELINE_PASSWORD')),
            'Use an environment variable name for the password')
    require(set(workload['services']) == {'fe', 'be'}, 'Exactly FE/BE service identities required')
    require(workload.get('business_workload_sha256') == business_binding(workload)['sha256'], 'Canonical business input hash mismatch')
    statistics.validate_identity(workload['identity'])


def validate_owned_target(workload):
    """Reuse checkout namespace/PID ownership rules; separately bind actual FE HTTP port and executable paths."""
    state, _ = validate_cluster(workload['cluster_record'])
    jdbc_shape = dict(workload, profile='checkout_isolated', host='127.0.0.1', port=state['query_port'],
                      case_id='LP-001', pairs=1, timeout_seconds=workload['query_timeout_seconds'], connection_mode='reuse',
                      point_key_workload={'table': workload['table'], 'mode': 'text', 'seed': SEED})
    baseline.check_workload(jdbc_shape | {'business_workload_sha256': baseline.business_workload_binding(jdbc_shape)['sha256']})
    installation = owned(state['installation'])
    for name in ('fe', 'be'):
        require(Path(workload['services'][name]['root']).resolve() == installation / name, 'Service root differs from cluster record')
        require(int((installation / name / 'bin' / (name + '.pid')).read_text()) == workload['services'][name]['pid'],
                'Service PID differs from cluster record')
    config = (installation / 'fe/conf/fe.conf').read_text()
    ports = re.findall(r'(?m)^\s*http_port\s*=\s*(\d+)\s*(?:#.*)?$', config)
    require(len(ports) == 1 and int(ports[0]) == workload['http_port'] == state['http_port'], 'Owned FE HTTP port mismatch')
    require(Path(workload['build_identity']['fe_artifact']).resolve() == (installation / 'fe/lib/doris-fe.jar').resolve(),
            'Bind the installed FE JAR rather than a mutable package copy')
    require(os.path.samefile(workload['build_identity']['be_artifact'], '/proc/%s/exe' % workload['services']['be']['pid']),
            'BE artifact is not the live executable')
    require(baseline.sha(workload['build_identity']['fe_artifact']) == workload['identity']['fe_sha256']
            and baseline.sha(workload['build_identity']['be_artifact']) == workload['identity']['be_sha256'], 'Live artifact identity mismatch')
    require(workload['build_identity']['baseline_source_commit'] == workload['identity']['source_commit'],
            'Installed build source identity mismatch')
    return {name: baseline.process_sample(info['pid'])['start_ticks'] for name, info in workload['services'].items()}


def cpu_sample(workload, pins):
    values = {}
    for name, info in workload['services'].items():
        before = time.monotonic_ns()
        value = baseline.process_sample(info['pid'])
        value.update(sample_started_ns=before, sample_ended_ns=time.monotonic_ns())
        require(value['start_ticks'] == pins[name], 'Service lifecycle changed')
        values[name] = value
    return values


def generate_vectors(workload, output, java_home):
    """Use the existing Java generator so integer/fractional arrival and point-key bytes match JDBC."""
    classes = output / 'schedule-classes'
    classes.mkdir()
    java, javac = Path(java_home) / 'bin/java', Path(java_home) / 'bin/javac'
    subprocess.run([str(javac), '--release', '17', '-d', str(classes), str(baseline.SOURCE)], check=True, timeout=30,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    vectors = {}
    for phase, duration, arrival_seed, key_seed in (
            ('warmup', workload['warmup_seconds'], SEED ^ 0x5DEECE66D, SEED ^ 0x9E3779B97F4A7C15),
            ('measured', workload['duration_seconds'], SEED, SEED)):
        if key_seed >= 1 << 63:
            key_seed -= 1 << 64
        path = output / (phase + '-arrivals.bin')
        subprocess.run([str(java), '-cp', str(classes), 'LicenseJdbcBaseline', '--schedule-only', str(workload['rate']),
                        str(duration), str(arrival_seed), str(path)], check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        count = path.stat().st_size // 8
        keys = output / (phase + '-keys.bin')
        subprocess.run([str(java), '-cp', str(classes), 'LicenseJdbcBaseline', '--point-keys-only', str(count),
                        str(key_seed), str(keys)], check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        arrivals_data, _ = capacity.verify_vector(output, path.name, 8, max(1, duration * 10**9))
        keys_data, _ = capacity.verify_vector(output, keys.name, 4, 1000000, count)
        vectors[phase] = ([x[0] for x in struct.iter_unpack('>q', arrivals_data)],
                          [x[0] for x in struct.iter_unpack('>i', keys_data)])
    return vectors


class DeadlineRegistry:
    """One bounded watchdog for all workers; never one timer thread per request."""
    def __init__(self):
        self.condition = threading.Condition()
        self.active = {}
        self.stopping = False
        self.thread = threading.Thread(target=self._run, name='http-point-deadlines', daemon=True)
        self.thread.start()

    def arm(self, worker, transport, deadline):
        with self.condition:
            self.active[worker] = (transport, deadline)
            self.condition.notify()

    def disarm(self, worker):
        with self.condition:
            self.active.pop(worker, None)
            self.condition.notify()

    def _run(self):
        with self.condition:
            while not self.stopping:
                now = time.monotonic()
                for worker, (transport, deadline) in list(self.active.items()):
                    if deadline <= now:
                        self.active.pop(worker)
                        try:
                            transport.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                delay = min((deadline - now for _, deadline in self.active.values()), default=.1)
                self.condition.wait(max(.001, min(.1, delay)))

    def close(self):
        with self.condition:
            self.stopping = True
            self.condition.notify()
        self.thread.join(timeout=1)
        require(not self.thread.is_alive(), 'Deadline watchdog did not terminate')


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate response JSON field')
        result[key] = value
    return result


def verify_point_response(status, body, expected, column_type):
    """Reuse the established non-stream HTTP result shape, then enforce exact raw string/type/column oracle."""
    if status != 200:
        return 'HTTP_STATUS', None
    if not isinstance(body, dict) or type(body.get('code')) is not int:
        return 'INVALID_RESPONSE', None
    if body['code'] != 0:
        message = body.get('msg')
        reported_timeout = isinstance(message, str) and re.search(
            r'\b(?:SQLTimeoutException|QueryTimeoutException)\b|\bquery timeout\b|\bexecution timeout\b', message)
        return 'SERVER_TIMEOUT_REPORTED' if reported_timeout else 'HTTP_BUSINESS_ERROR', None
    try:
        result = metadata_fixture.http_result({'http_status': status, 'body': body})
        data = body['data']
        if (data['meta'] != [{'name': 'payload', 'type': column_type}]
                or result['columns'] != ['payload'] or data['data'] != [[expected]]):
            return 'RESULT_MISMATCH', None
    except (ValueError, KeyError, TypeError):
        return 'RESULT_MISMATCH', None
    return 'NONE', expected


class KeepAliveWorker:
    def __init__(self, worker, workload, deadlines, connection_factory=http.client.HTTPConnection):
        self.worker, self.workload, self.deadlines = worker, workload, deadlines
        self.factory, self.connection, self.generation = connection_factory, None, 0
        self.closed = False
        secret = os.environ.get(workload.get('password_env', 'MASSDB_BASELINE_PASSWORD'), '')
        token = base64.b64encode((workload['user'] + ':' + secret).encode()).decode()
        self.headers = {'Authorization': 'Basic ' + token, 'Content-Type': 'application/json',
                        'X-Doris-Stream': 'false', 'Connection': 'keep-alive'}

    def connect(self, timeout):
        if self.connection is None or self.connection.sock is None:
            if self.connection is not None:
                self.connection.close()
            self.connection = self.factory('127.0.0.1', self.workload['http_port'], timeout=timeout)
            self.connection.connect()
            self.generation += 1
            return False
        return True

    def close(self):
        self.deadlines.disarm(self.worker)
        if self.connection is not None:
            self.connection.close()
        self.closed = True

    def execute(self, index, key, scheduled, epoch):
        start = time.monotonic_ns()
        deadline = start / 1e9 + self.workload['request_timeout_seconds']
        body = request_body(self.workload, key)
        record = dict(zip(FIELDS, [''] * len(FIELDS)))
        record.update(index=index, query_index=0, scheduled_ns=scheduled - epoch, start_ns=start - epoch,
                      rows=-1, error_code=1, sql_state='HTTP', error_class='CLIENT_ERROR', point_key=key,
                      request_sha256=hashlib.sha256(body).hexdigest(), response_bytes=0, transport_reused=False)
        response, raw, transport = None, bytearray(), None
        try:
            record['transport_reused'] = self.connect(max(.001, deadline - time.monotonic()))
            transport = self.connection.sock
            self.deadlines.arm(self.worker, transport, deadline)
            transport.settimeout(max(.001, deadline - time.monotonic()))
            self.connection.request('POST', '/api/query/default_cluster/' + self.workload['database'], body, self.headers)
            response = self.connection.getresponse()
            record['http_status'] = response.status
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                transport.settimeout(remaining)
                chunk = response.read1(min(65536, MAX_BODY + 1 - len(raw)))
                raw.extend(chunk)
                if len(raw) > MAX_BODY:
                    record['error_class'] = 'RESPONSE_TOO_LARGE'
                    break
                if not chunk or response.isclosed():
                    if getattr(response, 'length', None) not in (None, 0):
                        raise http.client.IncompleteRead(bytes(raw), response.length)
                    if response.status != 200:
                        record['error_class'] = 'HTTP_STATUS'
                        break
                    data = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_json,
                                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Non-finite JSON')))
                    if isinstance(data, dict) and type(data.get('code')) is int:
                        record['business_code'] = data['code']
                    expected = hashlib.md5(str(key).encode('ascii')).hexdigest()
                    category, payload = verify_point_response(response.status, data, expected, self.workload['expected_column_type'])
                    record['error_class'] = category
                    if category == 'NONE':
                        record.update(rows=1, error_code=0, sql_state='00000', actual_payload=payload,
                                      column_name='payload', column_type=self.workload['expected_column_type'])
                    break
            if time.monotonic() >= deadline:
                raise TimeoutError()
        except (TimeoutError, socket.timeout):
            record['error_class'] = 'HTTP_TIMEOUT'
        except (ValueError, UnicodeError, json.JSONDecodeError):
            record['error_class'] = 'INVALID_RESPONSE'
        except (OSError, http.client.HTTPException):
            record['error_class'] = 'HTTP_TIMEOUT' if time.monotonic() >= deadline else 'CONNECTION_ERROR'
        finally:
            self.deadlines.disarm(self.worker)
            if response is not None:
                close_transport = response.will_close
                response.close()
            else:
                close_transport = True
            if close_transport or record['error_class'] != 'NONE':
                if self.connection is not None:
                    self.connection.close()
            if record['error_class'] != 'NONE':
                record.update(error_code=1, sql_state='HTTP')
            record.update(connection_generation=self.generation, response_bytes=len(raw),
                          response_sha256=hashlib.sha256(raw).hexdigest(), end_ns=time.monotonic_ns() - epoch)
            if epoch + record['end_ns'] >= int(deadline * 1e9) and record['error_class'] == 'NONE':
                record.update(error_class='HTTP_TIMEOUT', error_code=1, sql_state='HTTP')
        return record


def wait_until(deadline_ns, cancel):
    while True:
        remaining = (deadline_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            return
        if cancel.wait(min(remaining, .1)):
            raise InterruptedError()


def execute_window(workload, output, vectors, pins, *, connection_factory=http.client.HTTPConnection):
    """All request/boundary times share Python's monotonic clock. No process or JDBC clock conversion."""
    cancel, warm_start, measure_start, cleanup = [threading.Event() for _ in range(4)]
    ready, warmed, finished = queue.Queue(), queue.Queue(), queue.Queue()
    failures, clients, threads, last = [], [], [], [0] * workload['concurrency']
    epoch, deadlines = {}, DeadlineRegistry()
    def worker(number):
        client = KeepAliveWorker(number, workload, deadlines, connection_factory)
        clients.append(client)
        try:
            with (output / ('worker-%d.csv' % number)).open('w', newline='') as measured_file, \
                    (output / ('warmup-worker-%d.csv' % number)).open('w', newline='') as warm_file:
                measured_writer, warm_writer = csv.DictWriter(measured_file, FIELDS), csv.DictWriter(warm_file, FIELDS)
                measured_writer.writeheader()
                warm_writer.writeheader()
                client.connect(workload['request_timeout_seconds'])
                ready.put(number)
                for phase, gate, writer in (('warmup', warm_start, warm_writer), ('measured', measure_start, measured_writer)):
                    while not gate.wait(.1):
                        if cancel.is_set():
                            raise InterruptedError()
                    arrivals, keys = vectors[phase]
                    for index in range(number, len(arrivals), workload['concurrency']):
                        if cancel.is_set():
                            raise InterruptedError()
                        scheduled = epoch[phase] + arrivals[index]
                        wait_until(scheduled, cancel)
                        record = client.execute(index, keys[index], scheduled, epoch[phase])
                        writer.writerow(record)
                        if phase == 'measured':
                            last[number] = epoch[phase] + record['end_ns']
                    wait_until(epoch[phase] + workload[phase == 'warmup' and 'warmup_seconds' or 'duration_seconds'] * 10**9, cancel)
                    (warmed if phase == 'warmup' else finished).put(number)
                while not cleanup.wait(.1):
                    if cancel.is_set():
                        raise InterruptedError()
        except BaseException as error:
            failures.append({'worker': number, 'class': type(error).__name__})
        finally:
            client.close()
    def await_workers(mailbox, timeout):
        seen, deadline = set(), time.monotonic() + timeout
        while len(seen) != workload['concurrency']:
            require(not failures, 'Worker failed; retained classes in lifecycle')
            require(time.monotonic() < deadline, 'Worker phase deadline elapsed')
            try:
                seen.add(mailbox.get(timeout=.05))
            except queue.Empty:
                pass
    start_cpu, end_cpu, interval_end, boundary_end, error = None, None, None, None, None
    lifecycle = {'started_monotonic_ns': time.monotonic_ns(),
                 'launch_sha256': baseline.sha(output / 'launch.json')}
    try:
        for number in range(workload['concurrency']):
            thread = threading.Thread(target=worker, args=(number,), daemon=True, name='http-point-%d' % number)
            threads.append(thread)
            thread.start()
        await_workers(ready, workload['request_timeout_seconds'] + 5)
        epoch['warmup'] = time.monotonic_ns()
        warm_start.set()
        await_workers(warmed, workload['warmup_seconds'] + workload['drain_timeout_seconds'] + 5)
        lifecycle['warmup_end_monotonic_ns'] = time.monotonic_ns()
        start_cpu = cpu_sample(workload, pins)
        epoch['measured'] = time.monotonic_ns()
        measure_start.set()
        await_workers(finished, workload['duration_seconds'] + workload['drain_timeout_seconds'] + 5)
        interval_end = max([epoch['measured'] + workload['duration_seconds'] * 10**9, *last])
        end_cpu = cpu_sample(workload, pins)
        boundary_end = time.monotonic_ns()
    except BaseException as exception:
        error = type(exception).__name__
    finally:
        lifecycle['cleanup_start_ns'] = time.monotonic_ns()
        cleanup.set()
        if error:
            cancel.set()
            warm_start.set()
            measure_start.set()
            for client in clients:
                if client.connection is not None and client.connection.sock is not None:
                    try:
                        client.connection.sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        for thread in threads:
            thread.join(timeout=workload['request_timeout_seconds'] + 1)
        deadlines.close()
        lifecycle.update(cleanup_end_ns=time.monotonic_ns(), worker_failures=failures, controller_error=error,
                         workers_alive=[thread.name for thread in threads if thread.is_alive()],
                         connections_closed=all(client.closed for client in clients),
                         connection_generations={str(client.worker): client.generation for client in clients})
    lifecycle.update(warmup_start_monotonic_ns=epoch.get('warmup'), start_monotonic_ns=epoch.get('measured'),
                     end_monotonic_ns=interval_end, measurement_end_ns=boundary_end)
    resources = {'cpu': {'start': start_cpu or {}, 'end': end_cpu or {}}}
    save(output / 'resources.json', resources)
    save(output / 'lifecycle.json', lifecycle)
    summary = baseline.summarize(output, len(vectors['measured'][0]), workload['duration_seconds'], resources['cpu'])
    summary.update(retry_count=0, error_count=sum(summary['errors'].values()),
                   timeout_count=sum(summary['error_classes'].get(name, 0) for name in ('HTTP_TIMEOUT', 'SERVER_TIMEOUT_REPORTED')),
                   unclassified_business_error_count=summary['error_classes'].get('HTTP_BUSINESS_ERROR', 0),
                   oracle_verified=False, cleanup_verified=not lifecycle['workers_alive'] and lifecycle['connections_closed'],
                   timeout_contract={'request_dispatch_to_completion_seconds': workload['request_timeout_seconds'],
                                     'query_hint_timeout_seconds': workload['query_timeout_seconds'], 'queue_deadline_seconds': None},
                   phase=workload['phase'], variant=workload['variant'], performance_pass=False)
    save(output / 'summary.json', summary)
    return summary


def utc_anchor():
    before = time.monotonic_ns()
    wall = time.time_ns()
    return {'before_monotonic_ns': before, 'utc_ns': wall, 'after_monotonic_ns': time.monotonic_ns()}


def frozen_launch(workload):
    if workload['phase'] != 'AB':
        require('freeze' not in workload, 'A-only execution does not consume an A/B freeze')
        return {}
    path = Path(workload['freeze']).resolve()
    frozen = statistics.read_json(path)
    publication_path = path.with_suffix(path.suffix + '.published.json')
    publication = statistics.read_json(publication_path)
    reference = statistics.reference(path)
    require(frozen['status'] == 'FROZEN_ELIGIBLE' and frozen['boot_id'] == statistics.boot_id(), 'Eligible same-boot freeze required before B')
    require(publication['freeze'] == reference and publication['boot_id'] == statistics.boot_id()
            and publication['published_monotonic_ns'] <= time.monotonic_ns(), 'Invalid or future freeze publication')
    require(frozen['identities'][workload['variant']] == workload['identity'], 'A/B identity differs from freeze')
    cell = frozen['cell']
    for field in ('rate', 'concurrency', 'connection_mode', 'warmup_seconds', 'duration_seconds', 'seed'):
        require(cell[field] == workload[field], 'A/B workload differs from freeze: ' + field)
    require(cell['workload_sha256'] == workload['business_workload_sha256'], 'A/B business hash differs from freeze')
    return {'freeze': reference, 'publication': statistics.reference(publication_path),
            'frozen_arrival_schedule_sha256': cell['arrival_schedule_sha256']}


def launch_bindings(workload, java_home):
    paths = {'http_runner': Path(__file__), 'jdbc_generator': baseline.SOURCE,
             'shared_baseline': Path(baseline.__file__), 'raw_verifier': Path(capacity.__file__),
             'http_result_contract': Path(metadata_fixture.__file__), 'statistics': Path(statistics.__file__),
             'checkout_guard': Path(stream_load_fixture.__file__),
             'cluster_record': Path(workload['cluster_record']),
             'java': Path(java_home) / 'bin/java', 'javac': Path(java_home) / 'bin/javac',
             'fe_artifact': Path(workload['build_identity']['fe_artifact']),
             'be_artifact': Path(workload['build_identity']['be_artifact']),
             'fe_configuration': Path(workload['services']['fe']['root']) / 'conf/fe.conf',
             'be_configuration': Path(workload['services']['be']['root']) / 'conf/be.conf'}
    bindings = {name: statistics.reference(path) for name, path in paths.items()}
    for name, item in workload.get('identity_bindings', {}).items():
        require(name in ('environment', 'configuration', 'fixture', 'client'), 'Unexpected identity snapshot')
        statistics.verify_reference(item)
        require(item['sha256'] == workload['identity'][name + '_sha256'], 'Identity snapshot differs from frozen digest')
        bindings[name] = item
    if workload['phase'] != 'DIAGNOSTIC':
        require(set(workload.get('identity_bindings', {})) == {'environment', 'configuration', 'fixture', 'client'},
                'Formal windows need actual environment/configuration/fixture/client snapshot references')
    return bindings


def raw_window_bindings(output):
    excluded = {str((output / name).resolve()) for name in ('audit.json', 'window.json')}
    return [item for item in capacity.raw_artifact_bindings(output) if item['path'] not in excluded]


def audit_window(output):
    """Recompute every scheduled ID, key, oracle and metric from raw files; no summary boolean substitutes."""
    output = Path(output)
    before = raw_window_bindings(output)
    workload, launch = statistics.read_json(output / 'workload.json'), statistics.read_json(output / 'launch.json')
    validate_shape(workload)
    require(launch['workload_sha256'] == baseline.sha(output / 'workload.json'), 'Actual workload changed after launch')
    require(launch['phase'] == workload['phase'] and launch['variant'] == workload['variant']
            and launch['business_binding'] == business_binding(workload), 'Launch phase/business identity mismatch')
    require(launch['boot_id'] == statistics.boot_id(), 'Raw window is from another monotonic clock boot')
    for item in launch['bindings'].values():
        statistics.verify_reference(item)
    lifecycle, resources = statistics.read_json(output / 'lifecycle.json'), statistics.read_json(output / 'resources.json')
    require(lifecycle['launch_sha256'] == baseline.sha(output / 'launch.json'), 'Launch receipt changed after execution')
    for item in launch['vectors'].values():
        statistics.verify_reference(item)
    require(lifecycle['controller_error'] is None and not lifecycle['worker_failures'] and not lifecycle['workers_alive']
            and lifecycle['connections_closed'], 'Window workers/connections did not finish cleanly')
    require(lifecycle['cleanup_start_ns'] >= lifecycle['measurement_end_ns']
            and lifecycle['cleanup_end_ns'] >= lifecycle['cleanup_start_ns'], 'CPU cleanup ordering mismatch')
    require(lifecycle['warmup_start_monotonic_ns'] >= launch['created_monotonic_ns']
            and lifecycle['warmup_end_monotonic_ns'] - lifecycle['warmup_start_monotonic_ns']
            >= workload['warmup_seconds'] * 10**9, 'Actual warmup did not run')
    derived = {}
    for phase, duration in (('warmup', workload['warmup_seconds']), ('measured', workload['duration_seconds'])):
        arrivals, arrival_hash = capacity.verify_vector(output, phase + '-arrivals.bin', 8, max(1, duration * 10**9))
        count = len(arrivals) // 8
        keys, key_hash = capacity.verify_vector(output, phase + '-keys.bin', 4, 1000000, count)
        seen, errors, timeouts, last = bytearray(count), 0, 0, 0
        expected_files = {('warmup-' if phase == 'warmup' else '') + 'worker-%d.csv' % i for i in range(workload['concurrency'])}
        actual_files = {p.name for p in output.glob(('warmup-' if phase == 'warmup' else '') + 'worker-*.csv')}
        require(expected_files == actual_files, 'Missing or extra worker receipts')
        for worker in range(workload['concurrency']):
            previous = -1
            path = output / (('warmup-' if phase == 'warmup' else '') + 'worker-%d.csv' % worker)
            with path.open() as stream:
                for row in csv.DictReader(stream):
                    index = int(row['index'])
                    require(0 <= index < count and not seen[index] and index > previous
                            and index % workload['concurrency'] == worker, 'Duplicate/reordered/missing worker request index')
                    seen[index], previous = 1, index
                    scheduled, start, end = [int(row[name]) for name in ('scheduled_ns', 'start_ns', 'end_ns')]
                    require(scheduled == struct.unpack_from('>q', arrivals, index * 8)[0] and scheduled <= start <= end,
                            'Actual request timestamps differ from scheduled arrival')
                    key = struct.unpack_from('>i', keys, index * 4)[0]
                    require(int(row['point_key']) == key and int(row['query_index']) == 0
                            and row['request_sha256'] == hashlib.sha256(request_body(workload, key)).hexdigest(), 'Actual HTTP request/key differs from frozen workload')
                    require(int(row['connection_generation']) >= 1 and row['transport_reused'] in ('True', 'False'), 'Missing actual connection usage')
                    if row['error_code'] == '0':
                        require(row['error_class'] == 'NONE' and row['sql_state'] == '00000'
                                and row['http_status'] == '200' and row['business_code'] == '0' and row['rows'] == '1'
                                and row['column_name'] == 'payload' and row['column_type'] == workload['expected_column_type']
                                and row['actual_payload'] == hashlib.md5(str(key).encode('ascii')).hexdigest(),
                                'Successful HTTP result differs from the full point oracle')
                    else:
                        errors += 1
                        timeouts += row['error_class'] in ('HTTP_TIMEOUT', 'SERVER_TIMEOUT_REPORTED')
                    last = max(last, end)
        require(not seen.count(0), 'Scheduled HTTP requests disappeared')
        derived[phase] = {'scheduled_requests': count, 'observed_requests': count, 'error_count': errors,
                          'timeout_count': timeouts, 'last_ns': last, 'arrival_sha256': arrival_hash, 'keys_sha256': key_hash}
    measured = derived['measured']
    require(lifecycle['warmup_end_monotonic_ns'] >= lifecycle['warmup_start_monotonic_ns']
            + max(workload['warmup_seconds'] * 10**9, derived['warmup']['last_ns']),
            'Warmup boundary excludes a raw request completion')
    if workload['phase'] != 'DIAGNOSTIC':
        require(workload['warmup_seconds'] >= 120 and workload['duration_seconds'] >= 300
                and measured['scheduled_requests'] >= 10000, 'Formal G1 raw window too short or insufficient samples')
    start, end = lifecycle['start_monotonic_ns'], lifecycle['end_monotonic_ns']
    require(end == start + max(workload['duration_seconds'] * 10**9, measured['last_ns']), 'Request interval does not cover final completion')
    require(lifecycle['warmup_end_monotonic_ns'] <= start, 'Warmup and measured intervals overlap')
    for name in ('fe', 'be'):
        first, final = resources['cpu']['start'][name], resources['cpu']['end'][name]
        require(first['start_ticks'] == final['start_ticks'] == launch['service_start_ticks'][name], 'CPU counters span changed process')
        require(first['sample_started_ns'] <= first['sample_ended_ns'] <= start <= end
                <= final['sample_started_ns'] <= final['sample_ended_ns'] <= lifecycle['measurement_end_ns']
                and final['cpu_seconds'] >= first['cpu_seconds'], 'CPU sampling is outside the measured request boundary')
    recomputed = baseline.summarize(output, measured['scheduled_requests'], workload['duration_seconds'], resources['cpu'])
    reported = statistics.read_json(output / 'summary.json')
    for key, value in recomputed.items():
        require(reported.get(key) == value, 'Summary differs from raw HTTP requests: ' + key)
    require(reported['error_count'] == measured['error_count'] and reported['timeout_count'] == measured['timeout_count'],
            'Error/timeout counts differ from raw requests')
    require(not derived['warmup']['error_count'], 'Warmup had HTTP/oracle errors')
    require(not measured['error_count'], 'Measured HTTP/oracle errors are retained, not successful evidence')
    window = {'window_id': workload['window_id'], 'pair_id': workload['pair_id'], 'variant': workload['variant'],
              'boot_id': launch['boot_id'], 'identity': workload['identity'],
              'workload_sha256': workload['business_workload_sha256'], 'arrival_schedule_sha256': measured['arrival_sha256'],
              'rate': workload['rate'], 'warmup_seconds': workload['warmup_seconds'], 'duration_seconds': workload['duration_seconds'],
              'warmup_start_monotonic_ns': lifecycle['warmup_start_monotonic_ns'],
              'warmup_end_monotonic_ns': lifecycle['warmup_end_monotonic_ns'], 'start_monotonic_ns': start, 'end_monotonic_ns': end,
              'monotonic_clock_domain': 'controller_monotonic_exact', 'monotonic_mapping_uncertainty_ns': 0,
              'effective_duration_seconds': (end - start) / 1e9, 'scheduled_requests': measured['scheduled_requests'],
              'observed_requests': measured['observed_requests'], 'successful_requests': recomputed['successful_requests'],
              'error_count': measured['error_count'], 'timeout_count': measured['timeout_count'], 'retry_count': 0,
              'oracle_verified': True, 'cleanup_verified': True, 'cpu_boundary_verified': True,
              'metrics': {name: recomputed[name] for name in statistics.METRICS}}
    dependencies = list(launch['bindings'].values())
    if workload['phase'] == 'AB':
        require(all(launch.get(key) == value for key, value in frozen_launch(workload).items()),
                'Actual A/B launch differs from its published freeze')
        for key in ('freeze', 'publication'):
            statistics.verify_reference(launch[key])
            dependencies.append(launch[key])
        publication = statistics.read_json(launch['publication']['path'])
        require(publication['published_monotonic_ns'] <= launch['created_monotonic_ns'] <= lifecycle['warmup_start_monotonic_ns'], 'A/B started before freeze publication')
        window.update(freeze_sha256=launch['freeze']['sha256'], freeze_publication_sha256=launch['publication']['sha256'])
        require(measured['arrival_sha256'] == launch['frozen_arrival_schedule_sha256'], 'Actual A/B arrival schedule changed')
    after = raw_window_bindings(output)
    require(before == after, 'Raw HTTP evidence changed during independent audit')
    return {'status': 'DIAGNOSTIC_VERIFIED' if workload['phase'] == 'DIAGNOSTIC' else 'VERIFIED',
            'window': window, 'auditor': statistics.reference(__file__), 'raw_artifacts': after,
            'dependency_bindings': dependencies,
            'warmup': derived['warmup'], 'formal_performance_pass': False,
            'scope': 'One complete HTTP point window. Capacity, independent pairs, resource coverage and performance gates remain external.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workload', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    workload = statistics.read_json(args.workload)
    validate_shape(workload)
    pins = validate_owned_target(workload)
    freeze = frozen_launch(workload)
    bindings = launch_bindings(workload, args.java_home)
    if args.validate_only:
        print(json.dumps({'status': 'INPUTS_VALID_NO_REQUESTS', 'variant': workload['variant']}))
        return 0
    output = owned(args.output)
    output.mkdir(parents=True, exist_ok=False)
    save(output / 'workload.json', workload)
    vectors = generate_vectors(workload, output, args.java_home)
    if workload['phase'] != 'DIAGNOSTIC':
        require(workload['warmup_seconds'] >= 120 and workload['duration_seconds'] >= 300
                and len(vectors['measured'][0]) >= 10000, 'Formal G1 window too short or fewer than 10000 requests')
    if freeze:
        require(baseline.sha(output / 'measured-arrivals.bin') == freeze['frozen_arrival_schedule_sha256'], 'A/B schedule differs before first request')
    for item in bindings.values():
        statistics.verify_reference(item)
    launch = {'schema_version': 1, 'phase': workload['phase'], 'variant': workload['variant'], 'launch_token': uuid.uuid4().hex,
              'created_monotonic_ns': time.monotonic_ns(), 'utc_anchor': utc_anchor(), 'boot_id': statistics.boot_id(),
              'actual_client_affinity': sorted(os.sched_getaffinity(0)), 'service_start_ticks': pins, 'bindings': bindings,
              'business_binding': business_binding(workload), 'workload_sha256': baseline.sha(output / 'workload.json'),
              'vectors': {name: statistics.reference(output / name) for name in (
                  'warmup-arrivals.bin', 'warmup-keys.bin', 'measured-arrivals.bin', 'measured-keys.bin')}, **freeze}
    save(output / 'launch.json', launch)
    summary = execute_window(workload, output, vectors, pins)
    try:
        cpu_sample(workload, pins)
        audit = audit_window(output)
    except (ValueError, KeyError, OSError, TypeError) as error:
        save(output / 'audit.json', {'status': 'INCOMPLETE_OR_FAILED', 'class': type(error).__name__,
                                     'reason': str(error) if isinstance(error, ValueError) else None,
                                     'formal_performance_pass': False})
        print(json.dumps({'status': 'INCOMPLETE_OR_FAILED', 'summary': str(output / 'summary.json')}))
        return 2
    save(output / 'audit.json', audit)
    normalized = dict(audit['window'], evidence=statistics.reference(output / 'audit.json'))
    save(output / 'window.json', normalized)
    print(json.dumps({'status': audit['status'], 'successful_requests': summary['successful_requests'],
                      'window': str(output / 'window.json'), 'formal_performance_pass': False}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
