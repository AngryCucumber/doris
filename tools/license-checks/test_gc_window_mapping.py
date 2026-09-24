#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.
"""Static test draft only; never reads a JVM/log/service or executes a collector."""
import copy
import hashlib
import json
import unittest
import gc_window_mapping as subject

BASE = 100000000000


def gc_line(stamp, category='Young', gc_id=7, duration='0.001', wall='2026-09-24T12:45:06.123+0800'):
    tag = '' if stamp is None else '[%dns]' % (BASE + stamp)
    return ('[%s][10.001s]%s GC(%d) Pause %s (Test) %sms\n' % (wall, tag, gc_id, category, duration)).encode()


def inputs(stamps=(100,), drain=False):
    binding = {'pid': 123, 'start_ticks': 456, 'namespace': 'net:[1]', 'executable': '/exact/java',
               'cmdline_sha256': 'a' * 64, 'path': '/owned/fe/log/fe.gc.log.fixed', 'filecount': 10,
               'filesize_bytes': 50 * 1024**2,
               'log_option': '-Xlog:gc*,classhisto*=trace:/owned/fe/log/fe.gc.log.fixed:time,uptime,timenanos:filecount=10,filesize=50M'}
    clock = {'boot_id': 'same-boot', 'time_namespace': 'time:[1]', 'timens_offsets_sha256': 'b' * 64,
             'clock_id': 'CLOCK_MONOTONIC'}
    context = {'schema_version': 1, 'jdk_runtime': '17.0.4+8', 'libjvm_sha256': subject.LIBJVM_SHA256,
               'timestamp_semantics_proof': subject.SEMANTICS,
               **{name: copy.deepcopy(clock) for name in ('source_before', 'source_after', 'workload_before', 'workload_after')},
               'fe_before': copy.deepcopy(binding), 'fe_after': copy.deepcopy(binding),
               'capture_start_monotonic_ns': BASE + 50, 'terminal_prefix_freeze_after_monotonic_ns': BASE + 400,
               'windows': [{'id': 'A', 'start_monotonic_ns': BASE + 100, 'end_monotonic_ns': BASE + 200},
                           {'id': 'B', 'start_monotonic_ns': BASE + 200, 'end_monotonic_ns': BASE + 300}]}
    events = []
    for index, stamp in enumerate(stamps):
        line = gc_line(stamp)
        event = subject.parse_pause_line(line)
        event.update(seq=index, source_device=1, source_inode=2, generation=0, pid=123, start_ticks=456,
                     line_start_offset=index * 256, line_end_offset=index * 256 + len(line),
                     initial_partial=False, read_batch_index=1 if drain else 0)
        events.append(event)
    end = events[-1]['line_end_offset'] if events else 0
    summary = {'schema_version': 1, 'binding': binding, 'events': len(events), 'events_flushed_confirmed': len(events),
               'errors': [], 'cleanup_errors': [], 'detected_gaps': [], 'pending_bytes': 0, 'tail_complete': True,
               'files_closed': True, 'observed_retained_prefix_continuity': True, 'batches': 2,
               'final_cursors': [{'device': 1, 'inode': 2, 'generation': 0, 'baseline_offset': 0, 'read_offset': end,
                                  'line_offset': end, 'event_archive_confirmed_offset': end,
                                  'pending_bytes': 0, 'unconfirmed_read_range': None}],
               'terminal_prefix': {'batch_index': 1, 'detected_gaps': [],
                                   'segments': [{'device': 1, 'inode': 2, 'generation': 0, 'start_offset': 0,
                                                 'end_offset': end, 'frozen_size': end, 'pending_bytes': 0, 'read_sha256': 'c' * 64}],
                                   'first_event_seq': 0 if drain and events else None,
                                   'last_event_seq': len(events) - 1 if drain and events else None},
               'event_archive_valid_eof': True}
    return events, summary, context


def mapped(events, summary, context):
    archive = b''.join((json.dumps(event, separators=(',', ':')) + '\n').encode() for event in events)
    summary = copy.deepcopy(summary)
    summary.update(events_sha256=hashlib.sha256(archive).hexdigest(), event_archive_actual_bytes=len(archive))
    return subject.map_archive(archive, summary, context)


class GcWindowMappingTests(unittest.TestCase):
    def reject(self, result):
        self.assertEqual(result['status'], 'UNQUALIFIED')
        self.assertTrue(result['reasons'])
        self.assertFalse(result['observed_prefix_record_time_mapping_qualified'])
        self.assertEqual(result['windows'], [])

    def test_parser_retains_record_time_and_never_invents_stw_boundaries(self):
        event = subject.parse_pause_line(gc_line(100))
        self.assertEqual(event['log_record_monotonic_ns'], BASE + 100)
        self.assertEqual(event['duration_ns'], 1000)
        self.assertEqual(event['timestamp_semantics'], 'log_record_time_not_stw_boundary')
        self.assertNotIn('stw_end_monotonic_ns', event)
        self.assertNotIn('stw_start_monotonic_ns', event)

    def test_half_open_boundaries_and_after_window_are_exact(self):
        result = mapped(*inputs((99, 100, 199, 200, 299, 300)))
        self.assertTrue(result['observed_prefix_record_time_mapping_qualified'])
        self.assertEqual([x['window_id'] for x in result['events']], [None, 'A', 'A', 'B', 'B', None])
        self.assertEqual([x['count'] for x in result['windows']], [2, 2])
        self.assertFalse(result['complete_stw_window_distribution_proven'])
        self.assertFalse(result['all_jvm_gc_pauses_proven'])

    def test_between_windows_has_no_invented_assignment(self):
        events, summary, context = inputs((225,))
        context['windows'][1]['start_monotonic_ns'] = BASE + 250
        result = mapped(events, summary, context)
        self.assertEqual(result['events'][0]['record_assignment'], 'between_windows')
        self.assertIsNone(result['events'][0]['window_id'])

    def test_terminal_drain_is_separate_from_record_window(self):
        result = mapped(*inputs((150, 350), drain=True))
        self.assertEqual(result['read_phase_counts'], {'regular': 0, 'terminal_drain': 2})
        self.assertEqual(result['windows'][0]['read_in_terminal_drain_count'], 1)
        self.assertEqual(result['events'][1]['record_assignment'], 'after_windows')
        self.assertIsNone(result['events'][1]['window_id'])

    def test_legacy_time_uptime_has_no_timestamp_and_cannot_be_backfilled(self):
        event = subject.parse_pause_line(gc_line(None))
        self.assertIsNone(event['log_record_monotonic_ns'])
        events, summary, context = inputs((None,))
        self.reject(mapped(events, summary, context))

    def test_original_two_decorator_log_binding_is_unqualified(self):
        events, summary, context = inputs()
        summary['binding']['log_option'] = summary['binding']['log_option'].replace(',timenanos', '')
        context['fe_before'] = copy.deepcopy(summary['binding'])
        context['fe_after'] = copy.deepcopy(summary['binding'])
        self.reject(mapped(events, summary, context))

    def test_boot_time_namespace_and_offsets_mismatch_each_reject(self):
        for field, value in [('boot_id', 'reboot'), ('time_namespace', 'time:[2]'), ('timens_offsets_sha256', 'd' * 64)]:
            with self.subTest(field=field):
                events, summary, context = inputs()
                context['source_after'][field] = value
                self.reject(mapped(events, summary, context))

    def test_missing_fe_binding_fields_never_qualify_even_if_both_snapshots_match(self):
        for field in ('executable', 'path', 'namespace'):
            events, summary, context = inputs()
            del summary['binding'][field]
            context['fe_before'] = copy.deepcopy(summary['binding'])
            context['fe_after'] = copy.deepcopy(summary['binding'])
            self.reject(mapped(events, summary, context))

    def test_partial_log_option_match_and_wrong_path_are_rejected(self):
        for change in ('selection', 'path', 'trailing_option'):
            events, summary, context = inputs()
            if change == 'selection':
                summary['binding']['log_option'] = summary['binding']['log_option'].replace('gc*,classhisto*=trace', 'gc*=off')
            elif change == 'path':
                summary['binding']['path'] = '/owned/fe/log/another.log'
            else:
                summary['binding']['log_option'] += ':extra'
            context['fe_before'] = copy.deepcopy(summary['binding'])
            context['fe_after'] = copy.deepcopy(summary['binding'])
            self.reject(mapped(events, summary, context))

    def test_invalid_live_fe_identity_and_noncanonical_paths_are_rejected(self):
        for field, value in [('pid', 0), ('start_ticks', 0), ('namespace', 'time:[1]'),
                             ('executable', 'relative/java'), ('path', '/owned/../foreign/log'),
                             ('path', '/owned//log'), ('executable', '/exact/java\x00')]:
            events, summary, context = inputs()
            summary['binding'][field] = value
            context['fe_before'] = copy.deepcopy(summary['binding'])
            context['fe_after'] = copy.deepcopy(summary['binding'])
            self.reject(mapped(events, summary, context))

    def test_original_file_equals_log_option_prefix_is_supported(self):
        events, summary, context = inputs()
        summary['binding']['log_option'] = summary['binding']['log_option'].replace('trace:/', 'trace:file=/')
        context['fe_before'] = copy.deepcopy(summary['binding'])
        context['fe_after'] = copy.deepcopy(summary['binding'])
        self.assertTrue(mapped(events, summary, context)['observed_prefix_record_time_mapping_qualified'])

    def test_wall_clock_jump_does_not_move_record_assignment(self):
        events, summary, context = inputs((150, 250))
        events[1]['wall_time_raw'] = '2020-01-01T00:00:00.000+0800'
        result = mapped(events, summary, context)
        self.assertEqual([x['window_id'] for x in result['events']], ['A', 'B'])

    def test_exact_jdk_semantics_and_lifetime_are_required(self):
        for change in ['libjvm', 'proof', 'lifetime']:
            events, summary, context = inputs()
            if change == 'libjvm': context['libjvm_sha256'] = 'e' * 64
            elif change == 'proof': context['timestamp_semantics_proof'] = 'wall-clock-guess'
            else: context['fe_after']['start_ticks'] += 1
            self.reject(mapped(events, summary, context))

    def test_gap_error_pending_or_unclosed_file_never_qualifies(self):
        for field, value in [('detected_gaps', ['rotation_lost']), ('errors', ['read_error']),
                             ('cleanup_errors', ['close_error']), ('pending_bytes', 1), ('files_closed', False)]:
            events, summary, context = inputs()
            summary[field] = value
            self.reject(mapped(events, summary, context))

    def test_read_offset_is_not_archive_committed_offset(self):
        events, summary, context = inputs()
        summary['final_cursors'][0]['read_offset'] += 1
        summary['final_cursors'][0]['unconfirmed_read_range'] = [0, 1]
        self.reject(mapped(events, summary, context))

    def test_terminal_frozen_prefix_must_be_fully_drained(self):
        events, summary, context = inputs()
        summary['terminal_prefix']['segments'][0]['frozen_size'] += 1
        self.reject(mapped(events, summary, context))

    def test_unconfirmed_event_count_and_initial_partial_are_rejected(self):
        for change in ['count', 'partial']:
            events, summary, context = inputs()
            if change == 'count': summary['events_flushed_confirmed'] = 0
            else: events[0]['initial_partial'] = True
            self.reject(mapped(events, summary, context))

    def test_same_gc_id_multiple_pauses_are_not_deduplicated(self):
        events, summary, context = inputs((150, 160))
        events[0]['category'], events[1]['category'] = 'remark', 'cleanup'
        result = mapped(events, summary, context)
        self.assertEqual(result['windows'][0]['count'], 2)
        self.assertEqual([x['gc_id'] for x in result['events']], [7, 7])

    def test_duplicate_source_offsets_reject_even_different_gc_id(self):
        events, summary, context = inputs((150, 160))
        events[1]['gc_id'] = 8
        events[1]['line_start_offset'] = events[0]['line_start_offset']
        self.reject(mapped(events, summary, context))

    def test_rotation_generation_mismatch_is_not_silently_repaired(self):
        events, summary, context = inputs()
        events[0]['generation'] = 1
        self.reject(mapped(events, summary, context))

    def test_overlapping_windows_and_uncovered_end_are_rejected(self):
        for change in ['overlap', 'end']:
            events, summary, context = inputs()
            if change == 'overlap': context['windows'][1]['start_monotonic_ns'] = BASE + 199
            else: context['terminal_prefix_freeze_after_monotonic_ns'] = BASE + 299
            self.reject(mapped(events, summary, context))

    def test_read_after_terminal_or_regressing_batch_is_rejected(self):
        events, summary, context = inputs((150, 160), drain=True)
        events[1]['read_batch_index'] = 0
        self.reject(mapped(events, summary, context))

    def test_record_after_frozen_prefix_or_reversed_file_clock_is_rejected(self):
        for stamps in [(450,), (160, 150)]:
            self.reject(mapped(*inputs(stamps)))

    def test_zero_events_is_only_qualified_empty_observed_prefix(self):
        result = mapped(*inputs(()))
        self.assertTrue(result['observed_prefix_record_time_mapping_qualified'])
        self.assertEqual([x['count'] for x in result['windows']], [0, 0])
        self.assertFalse(result['all_jvm_gc_pauses_proven'])

    def test_incomplete_oversized_and_nonfinite_pause_lines_reject(self):
        for line in [gc_line(150)[:-1], b'x' * subject.MAX_LINE + b'\n', gc_line(150, duration='NaN'),
                     gc_line(150, duration='-1'), gc_line(150, duration='0.0000001')]:
            with self.subTest(line=line[:80]), self.assertRaises(subject.Unqualified):
                subject.parse_pause_line(line)

    def test_start_concurrent_and_nested_lines_are_not_pause_events(self):
        for line in [b'[wall][1.0s][100ns] GC(1) Pause Young (Start)\n',
                     b'[wall][1.0s][100ns] GC(1) Concurrent Mark Cycle 1.000ms\n',
                     b'[wall][1.0s][100ns] GC(1)   Evacuate Collection Set 1.000ms\n']:
            self.assertIsNone(subject.parse_pause_line(line))

    def test_event_archive_digest_and_eof_must_match(self):
        events, summary, context = inputs()
        archive = (json.dumps(events[0]) + '\n').encode()
        summary.update(events_sha256='f' * 64, event_archive_actual_bytes=len(archive))
        self.reject(subject.map_archive(archive, summary, context))
        summary['events_sha256'] = hashlib.sha256(archive[:-1]).hexdigest()
        summary['event_archive_actual_bytes'] -= 1
        self.reject(subject.map_archive(archive[:-1], summary, context))

    def test_boolean_counter_and_missing_timestamp_are_unqualified(self):
        events, summary, context = inputs()
        summary['events'] = True
        self.reject(mapped(events, summary, context))
        summary['events'] = 1
        del events[0]['log_record_monotonic_ns']
        self.reject(mapped(events, summary, context))


if __name__ == '__main__':
    unittest.main()
