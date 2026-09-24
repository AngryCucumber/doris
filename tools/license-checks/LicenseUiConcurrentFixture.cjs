// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
'use strict';

// Importing this module performs no network access and does not load Playwright.
const fs = require('node:fs');
const path = require('node:path');
const base = require('./LicenseUiBaselineFixture.cjs');
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function check(value, code) {
    if (!value) { const error = new Error(code); error.fixtureCode = code; throw error; }
}
const safeCode = error => /^[A-Z0-9_]+$/.test(error?.fixtureCode || '') ? error.fixtureCode : 'DRIVER_FAILURE';
const PREPARATION_CONCURRENCY = 4;
const PREPARATION_CAP_MILLIS = 90000;

async function boundedAll(items, concurrency, operation) {
    let next = 0;
    const results = new Array(items.length);
    await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
        while (next < items.length) {
            const index = next++;
            try { results[index] = { status: 'fulfilled', value: await operation(items[index], index) }; }
            catch (error) { results[index] = { status: 'rejected', error_code: safeCode(error) }; }
        }
    }));
    return results;
}

function ownedCloser(ownedContexts, operation) {
    let closePromise;
    return () => {
        if (!closePromise) closePromise = (async () => {
            const others = await boundedAll(ownedContexts.slice(1), 10, operation);
            // Persistent context owns Chromium; close it after every secondary attempt.
            const first = ownedContexts.length ? await boundedAll([ownedContexts[0]], 1, operation) : [];
            return [...first, ...others];
        })();
        return closePromise;
    };
}

async function prepareContexts(count, hooks) {
    check([1, 10, 50].includes(count), 'CONTEXT_COUNT');
    const deadline = hooks.preparationDeadline;
    check(Number.isFinite(deadline), 'PREPARATION_DEADLINE_REQUIRED');
    const prepared = Array.from({ length: count }, (_, context) => ({ context, status: 'NOT_STARTED' }));
    let next = 0;
    let active = 0;
    let maximum = 0;
    let stopCode = null;
    const checkpoint = () => {
        hooks.checkPreparation();
        check(hooks.now() < deadline, 'PREPARATION_DEADLINE');
    };
    const publish = () => hooks.preparationProgress?.({ concurrency_limit: PREPARATION_CONCURRENCY,
        maximum_inflight: maximum, inflight: active, deadline_ms: deadline, first_preparation_failure: stopCode,
        ready_count: prepared.filter(item => item.status === 'fulfilled').length,
        records: prepared.map(item => ({ ...item })) });
    const workers = await Promise.allSettled(Array.from({ length: Math.min(count, PREPARATION_CONCURRENCY) }, async () => {
        while (next < count) {
            if (stopCode) break;
            try { checkpoint(); } catch (error) { stopCode ||= safeCode(error); break; }
            const index = next++;
            active++;
            maximum = Math.max(maximum, active);
            prepared[index] = { context: index, status: 'PREPARING', started_ms: hooks.now() };
            try {
                publish();
                const ready = await hooks.prepare(index);
                checkpoint();
                check(Number.isFinite(ready) && ready <= hooks.now(), 'PREPARATION_READY_CLOCK');
                prepared[index] = { ...prepared[index], status: 'fulfilled', ready_ms: ready };
            } catch (error) {
                prepared[index] = { ...prepared[index], status: 'rejected', error_code: safeCode(error) };
                stopCode ||= safeCode(error);
            } finally {
                active--;
                try { publish(); } catch (error) { stopCode ||= safeCode(error); throw error; }
            }
        }
    }));
    const failedWorker = workers.find(item => item.status === 'rejected');
    if (failedWorker) stopCode ||= safeCode(failedWorker.reason);
    for (let index = next; index < count; index++) {
        prepared[index] = { context: index, status: 'NOT_STARTED', error_code: stopCode || 'PREPARATION_NOT_STARTED' };
    }
    let finalEvidenceError = null;
    try { publish(); } catch (error) {
        finalEvidenceError = 'PREPARATION_RECEIPT_WRITE_FAILED';
        stopCode ||= safeCode(error);
    }
    if (stopCode || !prepared.every(item => item.status === 'fulfilled')) {
        const code = ['PREPARATION_INTERRUPTED', 'PREPARATION_DEADLINE'].includes(stopCode)
            ? stopCode : 'CONTEXT_READINESS_FAILED';
        const failure = new Error(code);
        failure.fixtureCode = code;
        failure.firstPreparationFailure = stopCode || code;
        failure.preparationEvidenceError = finalEvidenceError;
        throw failure;
    }
    checkpoint();
    return prepared;
}

async function concurrentWindow(count, hooks) {
    check([1, 10, 50].includes(count), 'CONTEXT_COUNT');
    const schedule = base.cadenceSchedule();
    // Only setup is bounded. All retained contexts enter the unchanged timed loops together.
    const prepared = await prepareContexts(count, hooks);
    const epoch = await hooks.release(prepared);
    check(Number.isFinite(epoch) && prepared.every(item => item.ready_ms <= epoch), 'SHARED_EPOCH_PRECEDES_READINESS');
    const settled = await Promise.allSettled(Array.from({ length: count }, async (_, index) => {
        let aborted = false;
        const receipt = { context: index, epoch_ms: epoch, ready_ms: prepared[index].ready_ms,
            status: 'RUNNING', events: [], window_seconds: 300 };
        for (const item of schedule.events) {
            const event = { ...item, context: index, scheduled_ms: epoch + item.offset_ms,
                deadline_ms: Math.min(epoch + 300000, epoch + item.offset_ms + 20000),
                started_ms: null, matched_network_ids: [] };
            receipt.events.push(event);
            if (aborted) { event.status = 'NOT_SENT_ABORTED'; continue; }
            await hooks.waitUntil(event.scheduled_ms);
            if (hooks.now() >= event.deadline_ms) { event.status = 'QUEUE_DEADLINE_MISS'; continue; }
            event.started_ms = hooks.now();
            event.queue_ms = event.started_ms - event.scheduled_ms;
            try {
                await hooks.execute(index, event, event.deadline_ms - event.started_ms);
                event.finished_ms = hooks.now();
                check(event.finished_ms <= event.deadline_ms, 'ACTION_DEADLINE_OVERRUN');
                event.status = 'PASS';
            } catch (error) {
                event.finished_ms = hooks.now();
                event.status = error?.name === 'TimeoutError' ? 'TIMEOUT' : 'FAIL';
                event.error_code = safeCode(error);
                aborted = true;
                try { event.page_closed_after_failure = await hooks.abort(index); }
                catch (_) { event.page_closed_after_failure = false; }
            }
            event.e2e_ms = event.finished_ms - event.scheduled_ms;
            hooks.publish(index, receipt);
        }
        // A fast final action does not shorten the shared 300-second interval.
        await hooks.waitUntil(epoch + 300000);
        receipt.finished_ms = hooks.now();
        receipt.status = receipt.events.every(event => event.status === 'PASS') ? 'PASS' : 'FAIL';
        hooks.publish(index, receipt);
        return receipt;
    }));
    check(settled.every(value => value.status === 'fulfilled'), 'CONTEXT_WINDOW_INTERRUPTED');
    const receipts = settled.map(value => value.value);
    return { contexts: count, epoch_ms: epoch, ready: prepared, receipts,
        status: receipts.every(item => item.status === 'PASS') ? 'PASS' : 'FAIL',
        actual_windows_concurrent: true, formal_AA_qualified: false };
}

function descriptiveSamples(receipts) {
    const groups = {};
    for (const receipt of receipts) {
        for (const event of receipt.events) {
            const key = event.target + ':' + event.kind;
            const group = groups[key] ||= { planned: 0, successful: 0, original_denials: 0,
                failed_or_unsent: 0, success_e2e_ms: [], denial_e2e_ms: [] };
            group.planned++;
            if (event.status !== 'PASS') { group.failed_or_unsent++; continue; }
            if (event.expected_original_denial) {
                group.original_denials++;
                group.denial_e2e_ms.push(event.e2e_ms);
            } else {
                group.successful++;
                group.success_e2e_ms.push(event.e2e_ms);
            }
        }
    }
    for (const group of Object.values(groups)) {
        group.p99_ms = null;
        group.p99_status = 'not_claimed_insufficient_page_samples';
        group.formal_performance_pass = false;
    }
    return groups;
}

async function body(response) {
    check(Number(response.headers()['content-length'] || 0) <= 2097152, 'API_BODY_BOUND');
    const raw = await response.body();
    check(raw.length <= 2097152 && /json/i.test(response.headers()['content-type'] || ''), 'API_BODY_TYPE_OR_BOUND');
    return JSON.parse(raw.toString('utf8'));
}

async function receiptFile(background, name, now, waitUntil) {
    const deadline = now() + 60000;
    const file = path.join(background.directory, name);
    while (!fs.existsSync(file)) {
        check(now() < deadline, 'BACKGROUND_RECEIPT_TIMEOUT');
        await waitUntil(now() + 50);
    }
    check(fs.statSync(file).size <= 8192, 'BACKGROUND_RECEIPT_BOUND');
    const value = JSON.parse(fs.readFileSync(file, 'utf8').replace(
        /("(?:java_monotonic_ns|epoch_java_monotonic_ns)"\s*:\s*)(-?\d+)/g, '$1"$2"'));
    check(value.token === background.token, 'BACKGROUND_TOKEN');
    return value;
}

function recordBackgroundAction(evidence, at) {
    check(Number.isSafeInteger(at) && at >= evidence.start_receipt.unix_millis, 'BACKGROUND_ACTION_CLOCK');
    if (evidence.browser_actions_started_unix_millis === undefined) {
        evidence.browser_actions_started_unix_millis = at;
    }
}

function recordBackgroundEnd(evidence, end, heldUntil) {
    check(end.token === evidence.token && end.scheduled_window_complete === true, 'BACKGROUND_END_IDENTITY');
    check(Number.isSafeInteger(heldUntil) && heldUntil >= end.unix_millis
        && evidence.browser_actions_started_unix_millis >= evidence.start_receipt.unix_millis
        && evidence.browser_actions_started_unix_millis < end.unix_millis, 'BACKGROUND_BROWSER_INTERVAL');
    evidence.end_receipt = end;
    evidence.browser_context_held_until_unix_millis = heldUntil;
}

async function run(config) {
    check([1, 10, 50].includes(config.cell.contexts), 'CONTEXT_COUNT');
    check(config.preparation_concurrency === PREPARATION_CONCURRENCY, 'FROZEN_PREPARATION_CONCURRENCY');
    check(config.origins.length === config.cell.contexts
        && new Set(config.origins).size === config.origins.length
        && config.origins.every(origin => /^http:\/\/127\.0\.0\.1:\d+$/.test(origin)), 'OWNED_ORIGINS');
    check(path.dirname(config.profile) === path.dirname(config.output), 'OWNED_PROFILE_PATH');
    check(['', '/proxy/fe', '/gateway/cluster/fe/default'].includes(config.cell.prefix)
        && ['zh-CN', 'en'].includes(config.cell.language)
        && ['admin', 'reader', 'unprivileged'].includes(config.cell.role), 'CELL_SCOPE');
    const { chromium } = require(config.runtime.playwright);
    const started = process.hrtime.bigint();
    const now = () => Number(process.hrtime.bigint() - started) / 1e6;
    const waitUntil = async due => {
        while (now() < due) {
            check(!interruption, 'WINDOW_INTERRUPTED');
            await new Promise(resolve => setTimeout(resolve, Math.min(100, due - now())));
        }
        check(!interruption, 'WINDOW_INTERRUPTED');
    };
    const report = { schema_version: 1, status: 'RUNNING', cell: config.cell, runtime: { node: process.version },
        preparation: { concurrency_limit: PREPARATION_CONCURRENCY, local_cap_millis: PREPARATION_CAP_MILLIS,
            deadline_origin: 'node_start_additional_cap_original_java_90s_deadline_unchanged',
            stage: 'BEFORE_BROWSER_LAUNCH', created_contexts: 0, ready_count: 0, maximum_inflight: 0, records: [] },
        contexts: [], AA_qualified: false, LP021_complete: false, LP022_complete: false,
        background_business_precision_qualified: false, full_goal_complete: false,
        deep_link_history_query_navigation: 'separate_existing_navigation_fixture',
        performance_scope: 'concurrent_page_functional_observation_not_formal_business_AA' };
    let lastPublished = -Infinity;
    const publish = (force = false) => {
        if (!force && now() - lastPublished < 1000) return;
        const temporary = config.output + '.tmp';
        fs.writeFileSync(temporary, JSON.stringify(report) + '\n', { mode: 0o600 });
        fs.renameSync(temporary, config.output);
        lastPublished = now();
    };
    const handles = [];
    const ownedContexts = [];
    let browser;
    let interruption = false;
    const preparationDeadline = PREPARATION_CAP_MILLIS;
    let preparationTimer;
    let preparationEvidenceError = null;
    const publishPreparation = stage => {
        if (stage) report.preparation.stage = stage;
        report.preparation.created_contexts = ownedContexts.length;
        report.preparation.observed_ms = now();
        report.preparation.interrupted = interruption;
        const raw = JSON.stringify({ schema_version: 1, cell: config.cell, ...report.preparation }) + '\n';
        check(Buffer.byteLength(raw) <= 65536, 'PREPARATION_RECEIPT_BOUND');
        const file = path.join(path.dirname(config.output), 'preparation.json');
        fs.writeFileSync(file + '.tmp', raw, { mode: 0o600 });
        fs.renameSync(file + '.tmp', file);
    };
    const closeAll = ownedCloser(ownedContexts, async context => {
        const result = await base.closeContext(context, 3000);
        const handle = handles.find(item => item.context === context);
        if (handle) handle.record.context_closed = result.closed;
        return result;
    });
    const stop = () => {
        interruption = true;
        try { publishPreparation('CANCELLED'); } catch (_) { preparationEvidenceError = 'PREPARATION_RECEIPT_WRITE_FAILED'; }
        // Abort active Playwright operations, keeping contexts available for their
        // independent logout attempts in finally. All waits observe cancellation.
        boundedAll(handles.filter(handle => handle.page), 10, handle => base.closeContext(handle.page, 1000)).catch(() => {});
    };
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
    try {
        publishPreparation('BEFORE_BROWSER_LAUNCH');
        // This local cap never replaces or extends the background Java deadline.
        preparationTimer = setTimeout(stop, Math.max(0, preparationDeadline - now()));
        const options = { executablePath: config.runtime.chromium, headless: true,
            chromiumSandbox: !config.runtime.allow_no_browser_sandbox,
            viewport: { width: 1440, height: 1000 }, locale: config.cell.language,
            timezoneId: 'UTC', serviceWorkers: 'block', acceptDownloads: false,
            args: ['--disable-background-networking', ...(config.runtime.allow_no_browser_sandbox ? ['--no-sandbox'] : [])] };
        const first = await chromium.launchPersistentContext(config.profile, options);
        ownedContexts.push(first);
        publishPreparation('CONTEXT_CREATED');
        check(!interruption, 'CANCELLED_DURING_BROWSER_LAUNCH');
        browser = first.browser();
        check(browser, 'BROWSER_HANDLE');
        report.runtime.chromium = browser.version();
        for (let index = 0; index < config.cell.contexts; index++) {
            const context = index === 0 ? first : await browser.newContext({
                viewport: options.viewport, locale: options.locale, timezoneId: 'UTC',
                serviceWorkers: 'block', acceptDownloads: false });
            if (index) { ownedContexts.push(context); publishPreparation('CONTEXT_CREATED'); }
            check(!interruption, 'CANCELLED_DURING_CONTEXT_CREATION');
            const record = { context: index, network: [], blocked_requests: 0, page_error_events: 0,
                session_established: false, status: 'PREPARING' };
            report.contexts.push(record);
            handles.push({ context, record, origin: config.origins[index], action: 'prepare', pending: new Set() });
        }
        check(browser.contexts().length === config.cell.contexts, 'ACTUAL_CONTEXT_COUNT');
        publishPreparation('ALL_CONTEXTS_CREATED');
        const group = await concurrentWindow(config.cell.contexts, {
            now, waitUntil, preparationDeadline,
            checkPreparation: () => {
                check(!interruption, 'PREPARATION_INTERRUPTED');
                check(!preparationEvidenceError, preparationEvidenceError || 'PREPARATION_RECEIPT_WRITE_FAILED');
            },
            preparationProgress: state => { Object.assign(report.preparation, state); publishPreparation('PREPARING'); },
            prepare: async index => {
                const handle = handles[index];
                check(!interruption, 'CANCELLED_DURING_PREPARATION');
                const { context, record, origin } = handle;
                const preparationCheckpoint = () => {
                    check(!interruption, 'PREPARATION_INTERRUPTED');
                    check(now() < preparationDeadline, 'PREPARATION_DEADLINE');
                };
                const preparationStep = async operation => {
                    preparationCheckpoint();
                    const remaining = Math.max(1, Math.min(20000, preparationDeadline - now()));
                    context.setDefaultTimeout(remaining);
                    context.setDefaultNavigationTimeout(remaining);
                    if (handle.page) { handle.page.setDefaultTimeout(remaining); handle.page.setDefaultNavigationTimeout(remaining); }
                    const value = await operation();
                    preparationCheckpoint();
                    return value;
                };
                const prefix = config.cell.prefix;
                const tracked = new Map();
                await context.addInitScript(language => {
                    if (localStorage.getItem('I18N_LANGUAGE') === null) localStorage.setItem('I18N_LANGUAGE', language);
                }, config.cell.language);
                await context.route('**/*', route => {
                    if (route.request().url().startsWith(origin + '/')) return route.continue();
                    record.blocked_requests++;
                    return route.abort('blockedbyclient');
                });
                context.on('request', request => {
                    if (record.network.length >= 2000) { record.network_overflow = true; return; }
                    const item = { id: record.network.length + 1, action: handle.action, start_ms: now(),
                        endpoint: base.label(request.url(), origin, prefix), method: request.method() === 'GET' ? 'GET' : 'POST' };
                    record.network.push(item);
                    tracked.set(request, item);
                });
                context.on('response', response => {
                    const item = tracked.get(response.request());
                    if (!item) return;
                    item.http_status = response.status();
                    item.content_type = base.contentType(response.headers()['content-type'] || '');
                });
                context.on('requestfinished', request => {
                    const item = tracked.get(request);
                    if (item) { item.finished_ms = now(); item.failed = false; }
                });
                context.on('requestfailed', request => {
                    const item = tracked.get(request);
                    if (item) { item.finished_ms = now(); item.failed = true; }
                });
                handle.page = context.pages()[0] || await preparationStep(() => context.newPage());
                preparationCheckpoint();
                const page = handle.page;
                page.on('pageerror', () => record.page_error_events++);
                page.setDefaultTimeout(20000);
                page.setDefaultNavigationTimeout(20000);
                handle.response = async (endpoint, trigger) => {
                    const waiting = page.waitForResponse(response => base.label(response.url(), origin, prefix) === endpoint);
                    waiting.catch(() => {});
                    await trigger();
                    const response = await waiting;
                    check(response.status() === 200, 'API_HTTP_STATUS');
                    const value = await body(response);
                    check(await response.finished() === null, 'API_BODY_COMPLETION');
                    const item = tracked.get(response.request());
                    check(item, 'REQUEST_NOT_OBSERVED');
                    item.business_code = Number.isInteger(value.code) ? value.code : null;
                    item.business_success = base.business(value);
                    item.original_permission_denial = base.denial(value);
                    return value;
                };
                handle.observe = async (target, trigger) => {
                    const endpoint = { Home: 'hardware', Playground: 'databases', Configuration: 'configuration' }[target];
                    const value = await handle.response(endpoint, trigger);
                    const denied = config.cell.role !== 'admin' && (target !== 'Playground' || config.expected.auth_all);
                    if (denied) {
                        check(base.denial(value), 'ORIGINAL_PERMISSION_DENIAL');
                        if (value.data === 'Cookie is invalid') {
                            await page.locator('.ant-modal-confirm-btns button').first().click();
                            await page.locator('.ant-modal-confirm').waitFor({ state: 'hidden' });
                        }
                    } else {
                        check(base.business(value), 'API_BUSINESS_FAILURE');
                        if (target === 'Home') {
                            check(value.data?.VersionInfo?.Version === config.expected.version
                                && value.data?.VersionInfo?.Git === config.expected.git, 'HOME_BUILD_IDENTITY');
                            await page.getByText('Version : ' + config.expected.version, { exact: true }).waitFor();
                            check(await page.locator('footer').count() === 1, 'HOME_FOOTER');
                        } else if (target === 'Playground') {
                            check(Array.isArray(value.data) && value.data.includes('license_perf'), 'DATABASES_MODEL');
                            await page.locator('.CodeMirror').waitFor();
                            await page.getByText('license_perf', { exact: true }).waitFor();
                        } else {
                            check(equal(value.data?.column_names, ['Name', 'Value']), 'CONFIG_COLUMNS');
                            const ports = value.data.rows.filter(row => row.Name === 'http_port');
                            check(ports.length === 1 && String(ports[0].Value) === String(config.expected.http_port), 'CONFIG_PORT');
                            const rows = page.locator('table tbody tr.ant-table-row');
                            await rows.first().waitFor();
                            const actual = await rows.evaluateAll(items => items.map(row => [...row.querySelectorAll('td')].map(td => td.textContent)));
                            const wanted = value.data.rows.slice(0, 30).map(row => ['Name', 'Value'].map(key => row[key] === '\\N' ? '-' : String(row[key] ?? '')));
                            check(equal(actual, wanted), 'CONFIG_VISIBLE_VALUES');
                        }
                    }
                    return denied;
                };
                await preparationStep(() => page.goto(origin + prefix + '/home'));
                await preparationStep(() => page.waitForURL(origin + prefix + '/login'));
                await preparationStep(() => page.locator('#basic_username').fill(config.account.username));
                await preparationStep(() => page.locator('#basic_password').fill(config.account.password));
                const login = await preparationStep(() => handle.response('login', () => page.getByRole('button').filter({
                    hasText: base.buttonTextPattern(config.cell.language === 'en' ? 'Login' : '登录') }).click()));
                check(login.code === 200, 'REAL_LOGIN_FAILED');
                record.session_established = (await context.cookies()).some(cookie => cookie.name === 'PALO_SESSION_ID');
                check(record.session_established, 'REAL_COOKIE_MISSING');
                await preparationStep(() => page.waitForURL(origin + prefix + '/home'));
                await preparationStep(() => handle.observe('Home', () => page.reload()));
                context.setDefaultTimeout(20000);
                context.setDefaultNavigationTimeout(20000);
                page.setDefaultTimeout(20000);
                page.setDefaultNavigationTimeout(20000);
                record.ready_ms = now();
                record.status = 'READY';
                publish();
                return record.ready_ms;
            },
            release: async ready => {
                check(now() < preparationDeadline, 'PREPARATION_DEADLINE');
                check(!interruption, 'CANCELLED_BEFORE_RELEASE');
                check(browser.contexts().length === config.cell.contexts
                    && handles.every(handle => browser.contexts().includes(handle.context)), 'CONTEXT_EXITED_BEFORE_RELEASE');
                report.contexts_alive_at_release = browser.contexts().length;
                report.ready_contexts = ready;
                publishPreparation('ALL_CONTEXTS_READY');
                clearTimeout(preparationTimer);
                if (config.background) {
                    const background = base.backgroundPaths(config);
                    fs.writeFileSync(path.join(background.directory, 'browser-ready.json'), JSON.stringify({
                        token: background.token, ready_contexts: ready.length, unix_millis: Date.now(),
                        browser_monotonic_ns: process.hrtime.bigint().toString() }), { flag: 'wx', mode: 0o600 });
                    const start = await receiptFile(background, 'window-start.json', now, waitUntil);
                    check(start.duration_seconds === 300 && start.epoch_delay_millis === 500, 'BACKGROUND_WINDOW');
                    report.background = { token: background.token, start_receipt: start, clocks_have_separate_origins: true };
                    const epoch = now() + start.unix_millis + 500 - Date.now();
                    report.window_epoch_unix_millis = start.unix_millis + 500;
                    return epoch;
                }
                report.window_epoch_unix_millis = Date.now() + 500;
                return now() + 500;
            },
            execute: async (index, event, budget) => {
                check(!interruption, 'WINDOW_INTERRUPTED');
                if (report.background) recordBackgroundAction(report.background, Date.now());
                const handle = handles[index];
                const { page, record, origin } = handle;
                handle.action = `cadence-${event.sequence}`;
                const route = { Home: '/home', Playground: '/Playground', Configuration: '/Configuration' }[event.target];
                const endpoint = { Home: 'hardware', Playground: 'databases', Configuration: 'configuration' }[event.target];
                event.expected_endpoint = endpoint;
                page.setDefaultTimeout(Math.max(1, Math.floor(budget)));
                page.setDefaultNavigationTimeout(Math.max(1, Math.floor(budget)));
                let timer;
                try {
                    await Promise.race([(async () => {
                        if (event.kind === 'refresh') check(new URL(page.url()).pathname === config.cell.prefix + route, 'ROUTE_CHANGED');
                        const trigger = event.kind === 'navigate' ? () => page.goto(origin + config.cell.prefix + route)
                            : event.operation === 'document_reload' ? () => page.reload()
                                : () => page.getByRole('button', { name: config.cell.language === 'en' ? 'Refresh' : '刷新', exact: true }).click();
                        event.expected_original_denial = await handle.observe(event.target, trigger);
                        check(new URL(page.url()).pathname === config.cell.prefix + route, 'PREFIX_OR_ROUTE_CHANGED');
                        check(await page.evaluate(() => localStorage.getItem('I18N_LANGUAGE')) === config.cell.language, 'LANGUAGE_CHANGED');
                        event.oracle_verified = true;
                    })(), new Promise((_, reject) => { timer = setTimeout(() => {
                        const error = new Error('ACTION_TIMEOUT'); error.name = 'TimeoutError'; reject(error);
                    }, budget); })]);
                } finally {
                    clearTimeout(timer);
                    event.matched_network_ids = record.network.filter(item => item.action === handle.action && item.endpoint === endpoint).map(item => item.id);
                }
                check(event.matched_network_ids.length === 1, 'DUPLICATE_OR_MISSING_REFRESH_REQUEST');
            },
            abort: async index => (await base.closeContext(handles[index].page)).closed,
            publish: (index, receipt) => { handles[index].record.window = receipt; publish(); },
        });
        report.window = group;
        for (const handle of handles) delete handle.record.window;
        report.contexts_alive_after_window = handles.filter(handle => browser.contexts().includes(handle.context)).length;
        check(report.contexts_alive_after_window === config.cell.contexts, 'CONTEXT_EXITED_DURING_WINDOW');
        report.page_samples = descriptiveSamples(group.receipts);
        if (config.background) {
            const end = await receiptFile(config.background, 'window-end.json', now, waitUntil);
            check(end.scheduled_window_complete === true, 'BACKGROUND_INCOMPLETE');
            check(handles.every(handle => browser.contexts().includes(handle.context)), 'CONTEXT_EXITED_BEFORE_BACKGROUND_END');
            recordBackgroundEnd(report.background, end, Date.now());
        }
        check(group.status === 'PASS', 'CONTEXT_WINDOW_FAILURE');
        check(handles.every(handle => !handle.record.network_overflow && handle.record.blocked_requests === 0
            && handle.record.page_error_events === 0 && !handle.record.network.some(item => item.endpoint === 'wrong_prefix')),
            'UNEXPECTED_BROWSER_ERROR_OR_REQUEST');
        report.status = 'PASS';
    } catch (error) {
        report.status = 'FAIL'; report.failure_code = safeCode(error);
        if (error.firstPreparationFailure) {
            report.preparation.first_preparation_failure = safeCode({ fixtureCode: error.firstPreparationFailure });
        }
        if (error.preparationEvidenceError === 'PREPARATION_RECEIPT_WRITE_FAILED') {
            preparationEvidenceError = error.preparationEvidenceError;
        }
    } finally {
        clearTimeout(preparationTimer);
        try { publishPreparation('CLEANUP'); } catch (_) { preparationEvidenceError = 'PREPARATION_RECEIPT_WRITE_FAILED'; }
        // Context request clients share that context's real cookie jar; values are never archived.
        report.logout_attempts = await boundedAll(handles, 10, async handle => {
            if (!handle.record.session_established) return { needed: false };
            try {
                const response = await handle.context.request.post(handle.origin + config.cell.prefix + '/rest/v1/logout', { timeout: 5000 });
                check(response.status() === 200 && base.business(await body(response)), 'REAL_LOGOUT_FAILED');
                handle.record.server_session_logout_confirmed = true;
            } catch (_) { handle.record.server_session_logout_confirmed = false; report.status = 'FAIL'; }
            return { context: handle.record.context, confirmed: handle.record.server_session_logout_confirmed };
        });
        report.context_close_attempts = await closeAll();
        report.browser_context_closed = handles.length === config.cell.contexts && handles.every(handle => handle.record.context_closed);
        report.server_session_logout_confirmed = handles.every(handle => !handle.record.session_established
            || handle.record.server_session_logout_confirmed);
        if (!report.browser_context_closed || !report.server_session_logout_confirmed) report.status = 'FAIL';
        if (preparationEvidenceError) { report.status = 'FAIL'; report.preparation_evidence_error = preparationEvidenceError; }
        report.finished_ms = now();
        try { publishPreparation('FINISHED'); } catch (_) { report.status = 'FAIL'; report.preparation_evidence_error = 'PREPARATION_RECEIPT_WRITE_FAILED'; }
        publish(true);
        process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
    }
    return report.status === 'PASS' ? 0 : 2;
}

async function main() {
    const chunks = []; let size = 0;
    for await (const chunk of process.stdin) { size += chunk.length; check(size <= 2097152, 'CONFIG_BOUND'); chunks.push(chunk); }
    return run(JSON.parse(Buffer.concat(chunks).toString('utf8')));
}
if (require.main === module) main().then(code => { process.exitCode = code; }).catch(() => { process.exitCode = 2; });
module.exports = { prepareContexts, PREPARATION_CONCURRENCY, PREPARATION_CAP_MILLIS, concurrentWindow, descriptiveSamples, boundedAll, ownedCloser, run, recordBackgroundAction, recordBackgroundEnd };
