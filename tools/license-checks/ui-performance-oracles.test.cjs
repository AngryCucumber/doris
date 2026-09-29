// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const api = require('./LicenseUiPerformance.cjs');
const fixture = () => ({ schema_version: 1, token: 'a'.repeat(32), variant: 'B', scenario: 'details', context_count: 50,
    duration_seconds: 300, refresh_interval_seconds: 10, preparation_concurrency: 1, role: 'admin', language: 'en',
    prefix: '/gateway/cluster/fe/default', origin: 'http://127.0.0.1:38031', action_timeout_seconds: 30,
    prepare_timeout_seconds: 300, deadline_monotonic_ns: '99999999999999999', chromium: '/explicit/chromium',
    playwright: '/explicit/playwright', output: '/explicit/output', accounts_file: '/explicit/accounts',
    allow_no_browser_sandbox: true });
const reject = (config, code) => assert.throws(() => api.validateConfig(config), error => error.fixtureCode === code);

test('A cannot fabricate a license page or import workload', () => {
    for (const scenario of ['details', 'imports']) reject({ ...fixture(), variant: 'A', scenario }, 'NO_LICENSE_PAGE_ON_A');
    assert.equal(api.validateConfig({ ...fixture(), variant: 'A', scenario: 'other-tabs' }).variant, 'A');
});
test('required context counts and serial preparation cannot silently shrink', () => {
    for (const context_count of [1, 10, 50]) assert.equal(api.validateConfig({ ...fixture(), context_count }).context_count, context_count);
    for (const context_count of [0, 2, 8, 49, 51]) reject({ ...fixture(), context_count }, 'CONFIG_CONTEXT_COUNT');
    reject({ ...fixture(), preparation_concurrency: 4 }, 'CONFIG_SERIAL_PREPARATION');
});
test('imports require exactly three certificate references and ADMIN', () => {
    const config = { ...fixture(), scenario: 'imports', context_count: 10,
        certificate_files: [1, 2, 3].map(n => ({ path: '/private/' + n, sha256: String(n).repeat(64) })) };
    assert.equal(api.validateConfig(config).certificate_files.length, 3);
    reject({ ...config, context_count: 50 }, 'CONFIG_CONTEXT_COUNT');
    reject({ ...config, role: 'ordinary' }, 'IMPORT_REQUIRES_ADMIN');
    reject({ ...config, certificate_files: config.certificate_files.slice(1) }, 'CONFIG_CERTIFICATE_REFERENCES');
    reject({ ...fixture(), certificate_files: config.certificate_files }, 'UNEXPECTED_CERTIFICATES');
});
test('window and refresh cadence are exact, no short test can become a formal window', () => {
    reject({ ...fixture(), duration_seconds: 30 }, 'CONFIG_WINDOW');
    reject({ ...fixture(), refresh_interval_seconds: 1 }, 'CONFIG_WINDOW');
    const schedule = api.schedule('details');
    assert.equal(schedule.length, 30);
    assert.deepEqual(schedule.map(item => item.offset_ms), Array.from({ length: 30 }, (_, n) => n * 10000));
    assert.deepEqual(api.schedule('imports').map(item => item.offset_ms), [0, 100000, 200000]);
    assert.equal(api.schedule('other-tabs').length, 3);
});
test('origin and prefix require explicit isolated destinations', () => {
    for (const origin of ['https://example.org', 'http://127.0.0.1:8080/path', 'http://root:secret@127.0.0.1:8080', 'http://172.32.1.1:8080']) {
        reject({ ...fixture(), origin }, 'CONFIG_OWNED_ORIGIN');
    }
    for (const prefix of ['/../x', '/a?x', '/a/', '//a']) reject({ ...fixture(), prefix }, 'CONFIG_PREFIX');
    assert.equal(api.validateConfig({ ...fixture(), prefix: '', origin: 'http://10.254.27.11:38031' }).prefix, '');
});
test('endpoints avoid archiving URL payloads and distinguish receipt from import', () => {
    const origin = 'http://127.0.0.1:8080', prefix = '/massdb';
    for (const [suffix, expected] of [['', 'status'], ['/validate', 'validate'], ['/import', 'import'],
        ['/imports/' + 'a'.repeat(64), 'receipt'], ['?certificate=do-not-record', 'license_query_string']]) {
        assert.equal(api.endpoint(origin + prefix + '/api/license' + suffix, origin, prefix), expected);
    }
    assert.equal(api.endpoint(origin + '/api/license', origin, prefix), 'wrong_prefix');
    assert.equal(api.endpoint('http://127.0.0.2:8080/api/license', origin, prefix), 'foreign');
});
test('receipt proof needs the same fingerprint and exact applied version', () => {
    const value = { submission_status: 'APPLIED', fingerprint: 'a'.repeat(64), committed_version: '9007199254740992', applied_version: '9007199254740993' };
    assert.equal(api.receiptApplied(value, 'a'.repeat(64)), true);
    assert.equal(api.receiptApplied(value, 'b'.repeat(64)), false);
    assert.equal(api.receiptApplied({ ...value, applied_version: '9007199254740991' }, value.fingerprint), false);
    assert.equal(api.receiptApplied({ ...value, applied_version: 9007199254740992 }, value.fingerprint), false);
    assert.equal(api.receiptApplied({ ...value, submission_status: 'COMMITTED' }, value.fingerprint), false);
});
test('safe response projection drops arbitrary server messages and certificate bodies', () => {
    const certificate = 'secret.header.signature';
    assert.deepEqual(api.safeBody({ certificate, message: certificate, committed_version: certificate, applied_version: true,
        status: 'VALID', administrator: true, reason: certificate, fingerprint: certificate }), { status: 'VALID', administrator: true });
    assert.equal(api.errorCode(new Error(certificate)), 'DRIVER_FAILURE');
    assert.equal(api.errorCode({ fixtureCode: 'SECRET_X'.repeat(30) }), 'DRIVER_FAILURE');
});
test('failed and never sent actions do not inflate success or P99', () => {
    const result = api.summary([{ events: [{ status: 'PASS', e2e_ms: 3 }, { status: 'FAIL', e2e_ms: 90 },
        { status: 'NOT_SENT' }, { status: 'PASS', e2e_ms: 1 }] }]);
    assert.equal(result.actions_successful, 2);
    assert.equal(result.actions_failed, 1);
    assert.equal(result.actions_not_sent, 1);
    assert.deepEqual(result.latency_ms.samples, [1, 3]);
    assert.equal(result.p99, null);
    assert.equal(result.formal_business_performance_pass, false);
});
test('release belongs to this Node clock and requires bridge evidence', () => {
    const now = 100000000000n, deadline = 900000000000n;
    const release = { token: 'a'.repeat(32), clock_domain: 'node_process_hrtime', node_pid: 123,
        epoch_monotonic_ns: '105000000000', epoch_unix_ms: 1790700000000, duration_seconds: 300,
        clock_bridge_sha256: 'b'.repeat(64) };
    assert.equal(api.releaseEpoch(release, release.token, 123, now, deadline), 105000000000n);
    for (const change of [{ node_pid: 124 }, { clock_domain: 'java_nanoTime' }, { clock_bridge_sha256: '' }, { duration_seconds: 30 }]) {
        assert.throws(() => api.releaseEpoch({ ...release, ...change }, release.token, 123, now, deadline), /RELEASE_FIELDS/);
    }
    for (const epoch_monotonic_ns of ['99000000000', '131000000000', '850000000000']) {
        assert.throws(() => api.releaseEpoch({ ...release, epoch_monotonic_ns }, release.token, 123, now, deadline), /RELEASE_EPOCH/);
    }
});
test('secret fixture permissions and byte bound are checked against actual files', () => {
    const base = path.resolve(__dirname, '../../.build-records/license-p4-20260929/ui');
    fs.mkdirSync(base, { recursive: true });
    const dir = fs.mkdtempSync(path.join(base, 'offline-fixtures-'));
    const file = path.join(dir, 'secret');
    try {
        fs.writeFileSync(file, 'test-not-a-certificate', { mode: 0o600 });
        assert.equal(api.secretFile(file, 64).toString(), 'test-not-a-certificate');
        assert.throws(() => api.secretFile(file, 1), /SECRET_FILE_MODE_OR_BOUND/);
        fs.chmodSync(file, 0o644);
        assert.throws(() => api.secretFile(file, 64), /SECRET_FILE_MODE_OR_BOUND/);
        assert.throws(() => api.secretFile('/etc/hosts', 65536), /PATH_OUTSIDE_RECORDS/);
    } finally { fs.rmSync(dir, { recursive: true }); }
});

test('one action deadline covers all steps and aborts a stalled request once', async () => {
    let aborted = 0;
    await assert.rejects(api.boundedOperation(new Promise(() => {}), 5, () => { aborted++; }), /ACTION_ABSOLUTE_TIMEOUT/);
    assert.equal(aborted, 1);
    assert.equal(await api.boundedOperation(Promise.resolve('complete'), 100, () => { aborted++; }), 'complete');
    await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(aborted, 1);
});
