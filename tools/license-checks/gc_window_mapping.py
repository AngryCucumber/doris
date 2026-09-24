#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.
"""Pure bounded parser/mapper for future original GC log record timestamps. No file/process/service I/O."""
import bisect
import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import PurePosixPath
import re

LIBJVM_SHA256 = '00aeedfb518f774aad30c63fc43969fd29133ddc224ca81cccaf3b98185178c1'
SEMANTICS = 'temurin17.0.4+8-linux-timenanos-CLOCK_MONOTONIC-log-record-time'
MAX_ARCHIVE = 32 * 1024**2
MAX_LINE = 65536
MAX_EVENTS = 100000
MAX_WINDOWS = 10000
HEX = re.compile(r'[a-f0-9]{64}')
PAUSE = re.compile(r'\[([^]\r\n]+)\]\[([0-9]+(?:\.[0-9]+)?)s\](?:\[([0-9]+)ns\])? '
                   r'GC\(([0-9]+)\) Pause (.+) ([0-9]+(?:\.[0-9]+)?)ms')


class Unqualified(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Unqualified(reason)


def integer(value, label):
    require(type(value) is int and 0 <= value <= 2**63 - 1, 'invalid_' + label)
    return value


def digest_text(value, label):
    require(isinstance(value, str) and HEX.fullmatch(value) is not None, 'invalid_' + label)
    return value


def parse_pause_line(line):
    """Future reader hook; complete original time,uptime[,timenanos] top-level Pause lines only.

    The timenanos field is log-record construction time, never a promised STW end/start.
    Legacy two-decorator lines remain parseable but deliberately have no mapping timestamp.
    """
    require(isinstance(line, bytes) and len(line) <= MAX_LINE and line.endswith(b'\n'), 'incomplete_or_oversized_gc_line')
    try:
        text = line[:-1].decode('utf-8', errors='strict')
    except UnicodeDecodeError as error:
        raise Unqualified('invalid_gc_line_utf8') from error
    match = PAUSE.fullmatch(text)
    if match is None:
        if re.search(r'\] GC\([0-9]+\) Pause ', text) and re.search(r'(?:ms|NaN|Inf)\s*$', text):
            raise Unqualified('malformed_completed_pause')
        return None
    wall, uptime, mono, gc_id, description, duration = match.groups()
    require(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d{4}', wall) is not None,
            'unsupported_wall_timestamp')
    require(len(uptime.split('.')[0]) <= 19 and len(duration.split('.')[0]) <= 19
            and ('.' not in uptime or len(uptime.split('.')[1]) <= 9)
            and ('.' not in duration or len(duration.split('.')[1]) <= 6), 'unsupported_decimal_precision')
    try:
        datetime.datetime.strptime(wall, '%Y-%m-%dT%H:%M:%S.%f%z')
        uptime_ns = Decimal(uptime) * 1000000000
        duration_ns = Decimal(duration) * 1000000
        require(uptime_ns == uptime_ns.to_integral_value() and duration_ns == duration_ns.to_integral_value(),
                'unsupported_decimal_precision')
    except (ValueError, InvalidOperation) as error:
        raise Unqualified('invalid_timestamp_or_duration') from error
    category = description.split(' ', 1)[0].lower()
    require(category in {'young', 'full', 'remark', 'cleanup'}, 'unsupported_pause_category')
    require(0 <= duration_ns <= uptime_ns <= 2**63 - 1, 'invalid_duration_or_uptime')
    return {'wall_time_raw': wall, 'uptime_raw_seconds': uptime, 'duration_raw_ms': duration,
            'record_uptime_ns': int(uptime_ns), 'duration_ns': int(duration_ns), 'category': category,
            'gc_id': integer(int(gc_id), 'gc_id'),
            'log_record_monotonic_ns': integer(int(mono), 'log_monotonic_ns') if mono is not None else None,
            'timestamp_semantics': 'log_record_time_not_stw_boundary',
            'raw_line_sha256': hashlib.sha256(line).hexdigest()}


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate_json_field')
        value[key] = item
    return value


def file_key(value, event=False):
    names = ('source_device', 'source_inode', 'generation') if event else ('device', 'inode', 'generation')
    return tuple(integer(value[name], name) for name in names)


def clock_and_windows(context, binding):
    require(context['schema_version'] == 1 and context['jdk_runtime'] == '17.0.4+8'
            and context['libjvm_sha256'] == LIBJVM_SHA256 and context['timestamp_semantics_proof'] == SEMANTICS,
            'unproven_jdk_clock_semantics')
    names = ('source_before', 'source_after', 'workload_before', 'workload_after')
    clock = context[names[0]]
    require(clock['clock_id'] == 'CLOCK_MONOTONIC' and isinstance(clock['boot_id'], str) and clock['boot_id']
            and re.fullmatch(r'time:\[[0-9]+\]', clock['time_namespace']) is not None,
            'invalid_clock_identity')
    digest_text(clock['timens_offsets_sha256'], 'time_namespace_offsets_hash')
    require(all(context[name] == clock for name in names), 'boot_time_namespace_or_offsets_mismatch')
    require(context['fe_before'] == binding and context['fe_after'] == binding, 'fe_lifetime_or_log_binding_mismatch')
    for name in ('pid', 'start_ticks'):
        require(integer(binding[name], 'fe_' + name) > 0, 'invalid_fe_' + name)
    digest_text(binding['cmdline_sha256'], 'fe_command_hash')
    require(isinstance(binding['namespace'], str)
            and re.fullmatch(r'net:\[[0-9]+\]', binding['namespace']) is not None, 'invalid_fe_network_namespace')
    for name in ('executable', 'path'):
        path = binding[name]
        require(isinstance(path, str) and path.startswith('/') and len(path) <= 4096
                and '\x00' not in path and '\n' not in path and '\r' not in path
                and str(PurePosixPath(path)) == path and '..' not in PurePosixPath(path).parts,
                'invalid_fe_' + name)
    option = binding['log_option']
    match = re.fullmatch(r'-Xlog:gc\*,classhisto\*=trace:(?:file=)?([^:]+):time,uptime,timenanos:'
                         r'filecount=10,filesize=50M', option) if isinstance(option, str) else None
    require(binding['filecount'] == 10 and binding['filesize_bytes'] == 50 * 1024**2
            and match is not None and match[1] == binding['path'],
            'original_selection_path_rotation_or_future_decorators_not_bound')
    begin = integer(context['capture_start_monotonic_ns'], 'capture_start')
    frozen = integer(context['terminal_prefix_freeze_after_monotonic_ns'], 'terminal_prefix_freeze')
    require(begin <= frozen, 'reversed_capture_interval')
    windows = context['windows']
    require(isinstance(windows, list) and 0 < len(windows) <= MAX_WINDOWS, 'invalid_windows')
    ids, previous_end = set(), begin
    for window in windows:
        name = window['id']
        require(isinstance(name, str) and 0 < len(name) <= 128 and name not in ids, 'duplicate_or_invalid_window_id')
        start = integer(window['start_monotonic_ns'], 'window_start')
        end = integer(window['end_monotonic_ns'], 'window_end')
        require(previous_end <= start < end <= frozen, 'overlapping_unsorted_or_uncovered_windows')
        ids.add(name)
        previous_end = end
    return windows, begin, frozen


def map_archive(archive, summary, context):
    """Map only the archived observed prefix; any evidence gap makes the entire mapping unqualified.

    Inputs are bytes/dicts already independently collected and frozen by an owner. This function
    never reads live logs, invents clock anchors, imports the observer, or backfills legacy evidence.
    """
    result = {'schema_version': 1, 'status': 'UNQUALIFIED', 'reasons': [], 'events': [], 'windows': [],
              'observed_prefix_record_time_mapping_qualified': False, 'all_jvm_gc_pauses_proven': False,
              'complete_stw_window_distribution_proven': False, 'duration_is_log_recorded_pause_duration': True,
              'record_timestamp_is_stw_end_or_start': False, 'historical_backfill': False}
    try:
        require(isinstance(archive, bytes) and len(archive) <= MAX_ARCHIVE, 'event_archive_bound')
        require(not archive or archive.endswith(b'\n'), 'incomplete_event_archive_eof')
        require(summary['schema_version'] == 1 and summary['events_sha256'] == hashlib.sha256(archive).hexdigest()
                and summary['event_archive_actual_bytes'] == len(archive) and summary['event_archive_valid_eof'] is True,
                'event_archive_binding_mismatch')
        require(summary['errors'] == [] and summary['cleanup_errors'] == [] and summary['detected_gaps'] == []
                and summary['pending_bytes'] == 0 and summary['tail_complete'] is True and summary['files_closed'] is True
                and summary['observed_retained_prefix_continuity'] is True, 'incomplete_loss_rotation_cursor_or_cleanup')
        for name in ('events', 'events_flushed_confirmed', 'event_archive_actual_bytes', 'batches', 'pending_bytes'):
            integer(summary[name], 'summary_' + name)
        windows, capture_start, freeze_after = clock_and_windows(context, summary['binding'])
        terminal = summary['terminal_prefix']
        require(isinstance(terminal, dict) and terminal['detected_gaps'] == [], 'missing_or_gapped_terminal_prefix')
        drain_index = integer(terminal['batch_index'], 'terminal_batch_index')
        require(drain_index + 1 == summary['batches'], 'terminal_batch_count_mismatch')
        cursors = summary['final_cursors']
        require(isinstance(cursors, list) and 0 < len(cursors) <= 12, 'missing_or_oversized_cursor_set')
        cursor_map = {}
        for cursor in cursors:
            key = file_key(cursor)
            require(key not in cursor_map, 'duplicate_file_generation')
            baseline = integer(cursor['baseline_offset'], 'baseline_offset')
            confirmed = integer(cursor['event_archive_confirmed_offset'], 'confirmed_offset')
            for name in ('line_offset', 'read_offset', 'pending_bytes'):
                integer(cursor[name], 'cursor_' + name)
            require(baseline <= confirmed == cursor['line_offset'] == cursor['read_offset']
                    and cursor['pending_bytes'] == 0 and cursor['unconfirmed_read_range'] is None,
                    'read_cursor_not_fully_confirmed')
            cursor_map[key] = cursor
        segments = terminal['segments']
        require(isinstance(segments, list) and len(segments) == len(cursor_map), 'terminal_generation_count_mismatch')
        seen = set()
        for segment in segments:
            key = file_key(segment)
            require(key in cursor_map and key not in seen, 'terminal_generation_mismatch')
            seen.add(key)
            for name in ('end_offset', 'frozen_size', 'pending_bytes'):
                integer(segment[name], 'terminal_' + name)
            digest_text(segment['read_sha256'], 'terminal_read_hash')
            require(cursor_map[key]['baseline_offset'] <= integer(segment['start_offset'], 'terminal_start') <= segment['end_offset']
                    == segment['frozen_size'] == cursor_map[key]['read_offset'] and segment['pending_bytes'] == 0,
                    'terminal_frozen_prefix_not_drained')
        lines = archive.splitlines(keepends=True)
        require(len(lines) <= MAX_EVENTS and len(lines) == summary['events'] == summary['events_flushed_confirmed'],
                'event_count_or_flush_confirmation_mismatch')
        starts = [window['start_monotonic_ns'] for window in windows]
        aggregates = {w['id']: {'id': w['id'], 'count': 0, 'logged_pause_duration_ns': [], 'read_in_terminal_drain_count': 0}
                      for w in windows}
        final_offsets, file_times, drain_seqs = {}, {}, []
        previous_batch = -1
        for index, line in enumerate(lines):
            require(len(line) <= MAX_LINE, 'event_line_bound')
            event = json.loads(line, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(Unqualified('nonfinite_json')))
            require(event['seq'] == index and type(event['seq']) is int, 'event_sequence_mismatch')
            key = file_key(event, event=True)
            require(key in cursor_map, 'event_outside_frozen_generation')
            start = integer(event['line_start_offset'], 'event_line_start')
            end = integer(event['line_end_offset'], 'event_line_end')
            require(cursor_map[key]['baseline_offset'] <= start < end <= cursor_map[key]['event_archive_confirmed_offset']
                    and event['initial_partial'] is False and start >= final_offsets.get(key, 0), 'event_offset_overlap_or_partial')
            final_offsets[key] = end
            digest_text(event['raw_line_sha256'], 'event_raw_line_hash')
            require(integer(event['pid'], 'event_pid') == summary['binding']['pid']
                    and integer(event['start_ticks'], 'event_start_ticks') == summary['binding']['start_ticks'],
                    'event_fe_lifetime_mismatch')
            stamp = integer(event['log_record_monotonic_ns'], 'missing_or_invalid_record_timestamp')
            require(event['timestamp_semantics'] == 'log_record_time_not_stw_boundary', 'event_timestamp_semantics_mismatch')
            require(capture_start <= stamp <= freeze_after and stamp >= file_times.get(key, 0), 'record_time_outside_capture_or_reversed')
            file_times[key] = stamp
            duration = integer(event['duration_ns'], 'pause_duration')
            require(duration <= integer(event['record_uptime_ns'], 'record_uptime'), 'duration_exceeds_jvm_uptime')
            require(event['category'] in {'young', 'full', 'remark', 'cleanup'}, 'unsupported_pause_category')
            batch = integer(event['read_batch_index'], 'read_batch')
            require(previous_batch <= batch <= drain_index, 'event_read_batch_reversed_or_after_terminal')
            previous_batch = batch
            read_phase = 'terminal_drain' if batch == drain_index else 'regular'
            if batch == drain_index:
                drain_seqs.append(index)
            position = bisect.bisect_right(starts, stamp) - 1
            window = windows[position] if position >= 0 and stamp < windows[position]['end_monotonic_ns'] else None
            assignment = 'window' if window else ('before_windows' if stamp < starts[0] else
                         'after_windows' if stamp >= windows[-1]['end_monotonic_ns'] else 'between_windows')
            row = {'seq': index, 'gc_id': integer(event['gc_id'], 'gc_id'), 'category': event['category'],
                   'log_record_monotonic_ns': stamp, 'duration_ns': duration, 'window_id': window['id'] if window else None,
                   'record_assignment': assignment, 'read_phase': read_phase,
                   'source_generation': list(key), 'line_offsets': [start, end], 'raw_line_sha256': event['raw_line_sha256']}
            result['events'].append(row)
            if window:
                bucket = aggregates[window['id']]
                bucket['count'] += 1
                bucket['logged_pause_duration_ns'].append(duration)
                bucket['read_in_terminal_drain_count'] += read_phase == 'terminal_drain'
        require(terminal['first_event_seq'] == (min(drain_seqs) if drain_seqs else None)
                and terminal['last_event_seq'] == (max(drain_seqs) if drain_seqs else None), 'terminal_event_range_mismatch')
        result.update(status='OBSERVED_PREFIX_RECORD_TIME_MAPPING_QUALIFIED',
                      observed_prefix_record_time_mapping_qualified=True, windows=list(aggregates.values()),
                      timestamp_semantics='log_record_time_not_stw_boundary',
                      event_archive_sha256=hashlib.sha256(archive).hexdigest(),
                      read_phase_counts={'regular': len(lines) - len(drain_seqs), 'terminal_drain': len(drain_seqs)},
                      coverage_scope='Only confirmed observed retained log prefix; polling cannot exclude unseen truncate-regrow or upstream logging loss.')
    except (Unqualified, KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        result['reasons'].append(str(error) if isinstance(error, Unqualified) else 'malformed_input_' + type(error).__name__)
        result['events'] = []
        result['windows'] = []
    return result
