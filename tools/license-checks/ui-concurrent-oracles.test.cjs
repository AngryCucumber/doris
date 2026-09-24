// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fixture = require('./LicenseUiConcurrentFixture.cjs');

test('background receipt records the actual first action and context lifetime with its exact token', () => {
    const evidence = { token: 'owned', start_receipt: { unix_millis: 1000 } };
    fixture.recordBackgroundAction(evidence, 11500);
    fixture.recordBackgroundAction(evidence, 11503);
    fixture.recordBackgroundEnd(evidence, { token: 'owned', unix_millis: 301500, scheduled_window_complete: true }, 301510);
    assert.equal(evidence.browser_actions_started_unix_millis, 11500);
    assert.equal(evidence.browser_context_held_until_unix_millis, 301510);
    assert.equal(evidence.token, 'owned');
    for (const change of [{ token: 'other' }, { scheduled_window_complete: false }, { unix_millis: 11500 }]) {
        assert.throws(() => fixture.recordBackgroundEnd(evidence,
            { token: 'owned', unix_millis: 301500, scheduled_window_complete: true, ...change }, 301510));
    }
    assert.throws(() => fixture.recordBackgroundEnd(evidence,
        { token: 'owned', unix_millis: 301500, scheduled_window_complete: true }, 301499));
    assert.throws(() => fixture.recordBackgroundAction({ start_receipt: { unix_millis: 1000 } }, 999));
});

// Event-loop driven virtual time: concurrent awaiters at the same due time are
// released together. No browser, HTTP, SQL, real timer window or credentials.
function virtualClock() {
    let value = 0;
    let queued = false;
    const waiting = [];
    function pump() {
        if (queued || !waiting.length) return;
        queued = true;
        setImmediate(() => {
            queued = false;
            value = Math.max(value, Math.min(...waiting.map(item => item.due)));
            const ready = waiting.filter(item => item.due <= value);
            for (const item of ready) waiting.splice(waiting.indexOf(item), 1);
            for (const item of ready) item.resolve();
            pump();
        });
    }
    return { now: () => value, waitUntil: due => due <= value ? Promise.resolve()
        : new Promise(resolve => { waiting.push({ due, resolve }); pump(); }) };
}

function hooks(clock, count) {
    return { ...clock, preparationDeadline: 90000, checkPreparation: () => {}, prepare: async index => { await clock.waitUntil(index * 5); return clock.now(); },
        release: async ready => { assert.equal(ready.length, count); return clock.now() + 500; },
        execute: async (_index, event) => { event.expected_original_denial = false; },
        abort: async () => true, publish: () => {} };
}

for (const count of [1, 10, 50]) {
    test(`${count} real scheduler workers enter the same action concurrently after the readiness barrier`, async () => {
        const clock = virtualClock();
        const input = hooks(clock, count);
        let inFlight = 0;
        let maxInFlight = 0;
        let allEntered;
        const barrier = new Promise(resolve => { allEntered = resolve; });
        input.execute = async (_index, event) => {
            event.expected_original_denial = false;
            if (event.sequence !== 0) return;
            inFlight++;
            maxInFlight = Math.max(maxInFlight, inFlight);
            if (inFlight === count) allEntered();
            await barrier;
            inFlight--;
        };
        const result = await fixture.concurrentWindow(count, input);
        assert.equal(result.status, 'PASS');
        assert.equal(maxInFlight, count);
        assert.equal(new Set(result.receipts.map(row => row.epoch_ms)).size, 1);
        for (const row of result.receipts) {
            assert.equal(row.events.length, 31);
            assert.equal(row.events.filter(event => event.kind === 'refresh').length, 29);
            assert.ok(row.finished_ms >= result.epoch_ms + 300000);
            assert.ok(row.ready_ms <= result.epoch_ms);
        }
    });
}

test('a failed login prevents release for every context rather than running a reduced matrix', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 10);
    let released = false;
    input.prepare = async index => { if (index === 4) throw new Error('private error'); return clock.now(); };
    input.release = async () => { released = true; return 1; };
    await assert.rejects(fixture.concurrentWindow(10, input), /CONTEXT_READINESS_FAILED/);
    assert.equal(released, false);
});

test('one failed context retains its unsent events and does not stop the other nine contexts', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 10);
    const aborted = [];
    input.execute = async (index, event) => {
        if (index === 3 && event.sequence === 0) throw new Error('private failure');
        event.expected_original_denial = false;
    };
    input.abort = async index => { aborted.push(index); return true; };
    const result = await fixture.concurrentWindow(10, input);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(aborted, [3]);
    assert.equal(result.receipts[3].events[0].status, 'FAIL');
    assert.equal(result.receipts[3].events.filter(event => event.status === 'NOT_SENT_ABORTED').length, 30);
    assert.equal(result.receipts.filter(row => row.status === 'PASS').length, 9);
    assert.ok(result.receipts.every(row => row.finished_ms >= result.epoch_ms + 300000));
});

test('sample report separates pages, navigation and denied traffic without claiming page P99', () => {
    const event = (target, kind, denied, delay, status = 'PASS') => ({ target, kind,
        expected_original_denial: denied, e2e_ms: delay, status });
    const samples = fixture.descriptiveSamples([{ events: [event('Home', 'refresh', true, 3),
        event('Playground', 'refresh', false, 4), event('Playground', 'navigate', false, 5),
        event('Home', 'refresh', false, undefined, 'NOT_SENT_ABORTED')] }]);
    assert.deepEqual(samples['Home:refresh'].denial_e2e_ms, [3]);
    assert.equal(samples['Home:refresh'].successful, 0);
    assert.equal(samples['Home:refresh'].failed_or_unsent, 1);
    assert.deepEqual(samples['Playground:refresh'].success_e2e_ms, [4]);
    assert.deepEqual(samples['Playground:navigate'].success_e2e_ms, [5]);
    assert.ok(Object.values(samples).every(value => value.p99_ms === null && !value.formal_performance_pass));
});

test('unsupported concurrency is rejected before invoking any preparation hook', async () => {
    await assert.rejects(fixture.concurrentWindow(5, { prepare: () => { throw new Error('must not run'); } }), /CONTEXT_COUNT/);
});

test('release cannot precede the final successful readiness observation', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 10);
    input.release = async () => 1;
    await assert.rejects(fixture.concurrentWindow(10, input), /SHARED_EPOCH_PRECEDES_READINESS/);
});

test('owned first context is closed even if no later handle registration succeeds', async () => {
    const first = {};
    const attempts = [];
    const close = fixture.ownedCloser([first], async context => { attempts.push(context); return { closed: true }; });
    await close();
    assert.deepEqual(attempts, [first]);
});

test('concurrent cleanup callers await the same actual close and close persistent context last', async () => {
    const owned = [{ id: 0 }, { id: 1 }, { id: 2 }];
    let release;
    const pending = new Promise(resolve => { release = resolve; });
    const order = [];
    const close = fixture.ownedCloser(owned, async context => {
        if (context.id) await pending;
        order.push(context.id);
        return { closed: true };
    });
    const signalClose = close();
    const finallyClose = close();
    assert.equal(signalClose, finallyClose);
    assert.deepEqual(order, []);
    release();
    await finallyClose;
    assert.equal(order.at(-1), 0);
    assert.equal(order.length, 3);
});

test('bounded cleanup attempts all 50 contexts despite individual failures', async () => {
    let active = 0;
    let peak = 0;
    const attempted = [];
    const result = await fixture.boundedAll(Array.from({ length: 50 }, (_, index) => index), 10, async index => {
        attempted.push(index); active++; peak = Math.max(peak, active);
        await new Promise(resolve => setImmediate(resolve));
        active--;
        if (index % 7 === 0) throw new Error('must not leak');
        return true;
    });
    assert.equal(attempted.length, 50);
    assert.equal(peak, 10);
    assert.equal(result.filter(item => item.status === 'rejected').length, 8);
    assert.ok(result.filter(item => item.status === 'rejected').every(item => item.error_code === 'DRIVER_FAILURE'));
});

test('cancelled waits stop all workers without waiting for the whole 300-second window', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 10);
    let cancelled = false;
    input.waitUntil = async due => { if (cancelled) throw new Error('cancelled'); await clock.waitUntil(due); };
    input.execute = async () => { cancelled = true; };
    await assert.rejects(fixture.concurrentWindow(10, input), /CONTEXT_WINDOW_INTERRUPTED/);
    assert.ok(clock.now() < 300000);
});


test('fixed four setup slots retain all fifty contexts and still release fifty concurrent action loops', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 50);
    const retained = new Set(Array.from({ length: 50 }, (_, index) => ({ index })));
    let inflight = 0;
    let peak = 0;
    let timedInflight = 0;
    let timedPeak = 0;
    let releaseTimed;
    const timedBarrier = new Promise(resolve => { releaseTimed = resolve; });
    const snapshots = [];
    input.prepare = async index => {
        inflight++; peak = Math.max(peak, inflight);
        await clock.waitUntil(clock.now() + 10);
        inflight--;
        assert.equal(retained.size, 50);
        return clock.now();
    };
    input.preparationProgress = state => snapshots.push(state);
    input.release = async ready => {
        assert.equal(ready.length, 50);
        assert.ok(ready.every(item => item.status === 'fulfilled'));
        assert.equal(retained.size, 50);
        return clock.now() + 500;
    };
    input.execute = async (_index, event) => {
        event.expected_original_denial = false;
        if (event.sequence !== 0) return;
        timedInflight++; timedPeak = Math.max(timedPeak, timedInflight);
        if (timedInflight === 50) releaseTimed();
        await timedBarrier;
        timedInflight--;
    };
    const result = await fixture.concurrentWindow(50, input);
    assert.equal(peak, 4);
    assert.equal(timedPeak, 50);
    assert.equal(retained.size, 50);
    assert.equal(result.receipts.length, 50);
    assert.ok(result.receipts.every(item => item.events.length === 31 && item.finished_ms >= result.epoch_ms + 300000));
    assert.ok(snapshots.every(item => item.inflight <= 4 && item.records.length === 50));
    assert.equal(snapshots.at(-1).ready_count, 50);
});

test('a setup failure stops unstarted setup work and never releases a smaller context matrix', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 50);
    const attempted = [];
    const snapshots = [];
    let released = false;
    input.prepare = async index => {
        attempted.push(index);
        await clock.waitUntil(10);
        if (index === 0) throw new Error('private login detail must not be copied');
        return clock.now();
    };
    input.preparationProgress = state => snapshots.push(state);
    input.release = async () => { released = true; return 500; };
    await assert.rejects(fixture.concurrentWindow(50, input), /CONTEXT_READINESS_FAILED/);
    assert.equal(released, false);
    assert.ok(attempted.length <= 4);
    assert.equal(snapshots.at(-1).records.length, 50);
    assert.ok(snapshots.at(-1).records.some(item => item.status === 'NOT_STARTED'));
    assert.ok(!JSON.stringify(snapshots).includes('private login'));
});

test('preparation cancellation prevents new setup jobs and release while retaining all outcomes', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 50);
    let cancelled = false;
    let released = false;
    let started = 0;
    const snapshots = [];
    input.checkPreparation = () => {
        if (cancelled) { const error = new Error('private'); error.fixtureCode = 'PREPARATION_INTERRUPTED'; throw error; }
    };
    input.prepare = async () => { started++; await clock.waitUntil(10); cancelled = true; return clock.now(); };
    input.preparationProgress = state => snapshots.push(state);
    input.release = async () => { released = true; return 500; };
    await assert.rejects(fixture.concurrentWindow(50, input), /PREPARATION_INTERRUPTED/);
    assert.ok(started <= 4);
    assert.equal(released, false);
    assert.equal(snapshots.at(-1).records.length, 50);
});

test('one absolute ninety-second preparation deadline is never restarted per group', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 50);
    input.preparationDeadline = 90000;
    let released = false;
    let started = 0;
    const snapshots = [];
    input.prepare = async () => { started++; await clock.waitUntil(clock.now() + 30000); return clock.now(); };
    input.preparationProgress = state => snapshots.push(state);
    input.release = async () => { released = true; return 100000; };
    await assert.rejects(fixture.concurrentWindow(50, input), /PREPARATION_DEADLINE/);
    assert.equal(released, false);
    assert.ok(started <= 12);
    assert.ok(snapshots.every(item => item.deadline_ms === 90000));
    assert.equal(clock.now(), 90000);
});

test('preparation evidence writer failure waits for active peers and never starts the timed window', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 50);
    let active = 0;
    let released = false;
    let writes = 0;
    input.prepare = async () => { active++; await clock.waitUntil(10); active--; return clock.now(); };
    input.preparationProgress = () => { if (++writes > 4) throw new Error('private disk detail'); };
    input.release = async () => { released = true; return 500; };
    await assert.rejects(fixture.concurrentWindow(50, input));
    assert.equal(active, 0);
    assert.equal(released, false);
});


test('a single transient preparation receipt failure stops queued jobs immediately', async () => {
    const clock = virtualClock();
    const input = hooks(clock, 50);
    let writes = 0;
    let started = 0;
    let active = 0;
    let released = false;
    input.prepare = async () => { started++; active++; await clock.waitUntil(10); active--; return clock.now(); };
    input.preparationProgress = () => { if (++writes === 5) throw new Error('single private save error'); };
    input.release = async () => { released = true; return 500; };
    await assert.rejects(fixture.concurrentWindow(50, input), /CONTEXT_READINESS_FAILED/);
    assert.ok(started <= 4);
    assert.equal(active, 0);
    assert.equal(released, false);
});


for (const firstCode of ['PREPARATION_DEADLINE', 'REAL_LOGIN_FAILED']) {
    test(`persistent receipt failure preserves the earlier ${firstCode} and joins active preparation`, async () => {
        const clock = virtualClock();
        const input = hooks(clock, 50);
        let active = 0;
        let started = 0;
        let writes = 0;
        let released = false;
        const snapshots = [];
        input.prepare = async index => {
            started++; active++;
            try {
                await clock.waitUntil(10);
                if (index === 0) {
                    const error = new Error('private preparation detail');
                    error.fixtureCode = firstCode;
                    throw error;
                }
                return clock.now();
            } finally { active--; }
        };
        input.preparationProgress = state => {
            snapshots.push(state);
            if (++writes > 4) throw new Error('private persistent disk detail');
        };
        input.release = async () => { released = true; return 500; };
        await assert.rejects(fixture.concurrentWindow(50, input), error => {
            assert.equal(error.fixtureCode, firstCode === 'PREPARATION_DEADLINE'
                ? firstCode : 'CONTEXT_READINESS_FAILED');
            assert.equal(error.firstPreparationFailure, firstCode);
            assert.equal(error.preparationEvidenceError, 'PREPARATION_RECEIPT_WRITE_FAILED');
            assert.ok(!JSON.stringify(error).includes('private'));
            return true;
        });
        assert.equal(active, 0);
        assert.equal(started, 4);
        assert.equal(released, false);
        assert.ok(writes > 5);
        assert.equal(snapshots.at(-1).first_preparation_failure, firstCode);
        assert.equal(snapshots.at(-1).records.length, 50);
        assert.ok(snapshots.at(-1).records.slice(4).every(item => item.status === 'NOT_STARTED'));
        assert.ok(!JSON.stringify(snapshots).includes('private'));
    });
}
