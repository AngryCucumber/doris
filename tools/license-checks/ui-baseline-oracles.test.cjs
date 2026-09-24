// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
'use strict';

// Offline tests: requiring the driver does not load Playwright or launch a browser.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('node:crypto');
const fixture = require('./LicenseUiBaselineFixture.cjs');

test('visible button text permits only the original AntD two-Chinese-character spacing', () => {
    for (const [text, variants] of [['登录', ['登录', '登 录']], ['执行', ['执行', '执 行']],
        ['中文', ['中文', '中 文']], ['Execute', ['Execute']], ['Login', ['Login']]]) {
        for (const actual of variants) assert.equal(fixture.buttonTextPattern(text).test(actual), true);
        for (const actual of [text + ' fake', 'fake ' + text, text.toLowerCase() + ' ']) {
            assert.equal(fixture.buttonTextPattern(text).test(actual), false);
        }
    }
    assert.equal(fixture.buttonTextPattern('a.b').test('axb'), false);
});

test('early response rejection stays observable without an unhandled rejection', async () => {
    const events = [];
    const handler = error => events.push(error);
    process.on('unhandledRejection', handler);
    try {
        const error = new Error('private credential-like message');
        const waiting = fixture.observe(Promise.reject(error));
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(events, []);
        await assert.rejects(waiting, candidate => candidate === error);
    } finally {
        process.removeListener('unhandledRejection', handler);
    }
});

test('error diagnostics never preserve arbitrary error names or messages', () => {
    assert.equal(fixture.safeErrorName({ name: 'TimeoutError', message: 'password secret' }), 'TimeoutError');
    assert.equal(fixture.safeErrorName({ name: 'cookie secret', message: 'token secret' }), 'OtherError');
});

test('HTTP/JSON 401 or a signature-like success message is not business success', () => {
    assert.equal(fixture.business({ code: 0, msg: 'success' }), true);
    for (const code of [401, 200, '0', false, undefined]) {
        assert.equal(Boolean(fixture.business({ code, msg: 'success' })), false);
    }
    assert.equal(fixture.business({ code: 0, msg: 'Login success!' }), false);
});

test('only original permission reasons classify as authorization denials', () => {
    assert.equal(fixture.denial({ code: 401, msg: 'Unauthorized', data: 'Cookie is invalid' }), true);
    assert.equal(fixture.denial({ code: 401, msg: 'Unauthorized', data: 'Access denied; missing privilege' }), true);
    assert.equal(fixture.denial({ code: 401, msg: 'Unauthorized', data: 'license expired' }), false);
});

function data() {
    return { type: 'result_set', meta: ['id', 'grp', 'v', 'payload'].map(name => ({ name })),
        data: [0, 7, 999999].map(id => [id, id % 1024, id % 100000,
            crypto.createHash('md5').update(String(id)).digest('hex')]) };
}

test('point oracle compares every field, row, type and order', () => {
    assert.equal(fixture.pointRows(data()).length, 3);
    for (const mutate of [
        value => { value.data[2][3] = 'wrong'; },
        value => { value.data[1][1] = 8; },
        value => { value.data[0][2] = null; },
        value => { value.data.push(value.data[0]); },
        value => { value.data.reverse(); },
        value => { value.meta.reverse(); },
        value => { value.data[0][0] = false; },
    ]) {
        const value = data();
        mutate(value);
        assert.throws(() => fixture.pointRows(value));
    }
});

test('network labels never retain URL queries, credentials or unexpected path contents', () => {
    const origin = 'http://127.0.0.1:12345';
    assert.equal(fixture.label(origin + '/proxy/fe/home?password=secret', origin, '/proxy/fe'), 'home_page');
    assert.equal(fixture.label(origin + '/proxy/fe/secret-token', origin, '/proxy/fe'), 'unclassified_local');
    assert.equal(fixture.label('http://user:secret@example.invalid/home', origin, ''), 'blocked_external');
    assert.equal(fixture.label(origin + '/home', origin, '/proxy/fe'), 'wrong_prefix');
});

test('close receipt distinguishes successful graceful close, failure and timeout', async () => {
    assert.deepEqual(await fixture.closeContext(null), { attempted: false, closed: false });
    assert.deepEqual(await fixture.closeContext({ close: async () => {} }), { attempted: true, closed: true });
    assert.deepEqual(await fixture.closeContext({ close: async () => { throw new Error('secret must not escape'); } }),
        { attempted: true, closed: false });
    assert.deepEqual(await fixture.closeContext({ close: () => new Promise(() => {}) }, 5),
        { attempted: true, closed: false });
});

test('background gate only accepts the sibling directory and frozen full duration', () => {
    const config = { cell: { id: 'cell-001' }, output: '/owned/run/cell-001/browser.json',
        background: { directory: '/owned/run/cell-001-background', token: 'a'.repeat(32), duration_seconds: 300 } };
    assert.equal(fixture.backgroundPaths(config), config.background);
    for (const change of [{ directory: '/owned/other/cell-001-background' },
        { directory: '/owned/run/cell-002-background' }, { token: '../secret' }, { duration_seconds: 30 }]) {
        assert.throws(() => fixture.backgroundPaths({ ...config, background: { ...config.background, ...change } }));
    }
});

test('refresh cadence freezes 29 ten-second refreshes and two separate route changes', () => {
    const schedule = fixture.cadenceSchedule();
    const refreshes = schedule.events.filter(event => event.kind === 'refresh');
    assert.deepEqual(refreshes.map(event => event.offset_ms), Array.from({ length: 29 }, (_, index) => (index + 1) * 10000));
    assert.equal(refreshes.filter(event => event.target === 'Home' && event.operation === 'document_reload').length, 9);
    assert.equal(refreshes.filter(event => event.target === 'Playground' && event.operation === 'tree_button').length, 10);
    assert.equal(refreshes.filter(event => event.target === 'Configuration' && event.operation === 'document_reload').length, 10);
    assert.deepEqual(schedule.events.filter(event => event.kind === 'navigate').map(event => event.offset_ms), [95000, 195000]);
    assert.deepEqual(schedule.events.map(event => event.sequence), Array.from({ length: 31 }, (_, index) => index));
});

function virtualCadence(execute, waitUntil) {
    const clock = { value: 1000, aborts: 0 };
    const hooks = { now: () => clock.value, wall: () => 1700000000000 + clock.value,
        waitUntil: async due => { clock.value = Math.max(clock.value, due); if (waitUntil) waitUntil(clock, due); },
        execute: async (event, budget) => { await execute(clock, event, budget); },
        abort: async () => { clock.aborts++; return true; }, publish: () => {} };
    return { clock, hooks };
}

test('a slow refresh records queue time without shifting later arrivals', async () => {
    const { hooks } = virtualCadence(async (clock, event) => { clock.value += event.sequence === 0 ? 15000 : 100; });
    const result = await fixture.runCadence(fixture.cadenceSchedule(), hooks);
    assert.equal(result.status, 'PASS');
    assert.equal(result.events[0].scheduled_ms, 11000);
    assert.equal(result.events[1].scheduled_ms, 21000);
    assert.equal(result.events[1].started_ms, 26000);
    assert.equal(result.events[1].queue_ms, 5000);
    assert.equal(result.events[1].e2e_ms, 5100);
    assert.equal(result.events.at(-1).scheduled_ms, 291000);
});

test('scheduler delay retains a missed arrival instead of sending it late or rebasing', async () => {
    const sent = [];
    const { hooks } = virtualCadence(async (clock, event) => { sent.push(event.sequence); clock.value += 100; },
        (clock, due) => { if (due === 11000) clock.value = 32000; });
    const result = await fixture.runCadence(fixture.cadenceSchedule(), hooks);
    assert.equal(result.status, 'FAIL');
    assert.equal(result.events[0].status, 'QUEUE_DEADLINE_MISS');
    assert.equal(result.events[0].started_ms, null);
    assert.equal(sent.includes(0), false);
    assert.equal(result.events[1].scheduled_ms, 21000);
    assert.equal(result.events[1].queue_ms, 11000);
});

test('timeout closes the active page and records every remaining unsent event', async () => {
    const { clock, hooks } = virtualCadence(async (time, event, budget) => {
        time.value += budget;
        const error = new Error('private message must not escape');
        error.name = 'TimeoutError';
        throw error;
    });
    const result = await fixture.runCadence(fixture.cadenceSchedule(), hooks);
    assert.equal(result.status, 'FAIL');
    assert.equal(clock.aborts, 1);
    assert.equal(result.events[0].status, 'TIMEOUT');
    assert.equal(result.events[0].page_close_confirmed, true);
    assert.equal(result.events.slice(1).every(event => event.status === 'NOT_SENT_ABORTED'), true);
    assert.equal(JSON.stringify(result).includes('private message'), false);
});
