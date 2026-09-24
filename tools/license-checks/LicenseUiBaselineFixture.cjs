// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
'use strict';

// Controller supplies credentials through stdin only. No HAR, traces, console text or screenshots.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

function check(condition, code) {
    if (!condition) {
        const error = new Error(code);
        error.fixtureCode = code;
        throw error;
    }
}

function eq(first, second) {
    return isDeepStrictEqual(first, second);
}

function buttonTextPattern(text) {
    // AntD inserts a space between two Chinese characters. Icon aria-labels are
    // separate accessible-name content, so match the complete visible button text.
    const escaped = text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp('^' + (/^[\u4e00-\u9fa5]{2}$/.test(text) ? text.split('').join('\\s*') : escaped) + '$');
}

function observe(promise) {
    // A second waiter can reject while the triggering click or first waiter is pending.
    promise.catch(() => {});
    return promise;
}

function safeErrorName(error) {
    return ['Error', 'TimeoutError', 'TypeError', 'RangeError', 'SyntaxError'].includes(error?.name)
        ? error.name : 'OtherError';
}

function business(body) {
    return body && Number.isInteger(body.code) && body.code === 0 && body.msg === 'success';
}

function denial(body) {
    return body && body.code === 401 && body.msg === 'Unauthorized'
        && typeof body.data === 'string'
        && (body.data === 'Cookie is invalid' || body.data.startsWith('Access denied'));
}

function pointRows(data) {
    check(data && data.type === 'result_set' && Array.isArray(data.meta) && Array.isArray(data.data), 'POINT_RESULT_SHAPE');
    check(eq(data.meta.map(column => column.name), ['id', 'grp', 'v', 'payload']), 'POINT_COLUMN_ORDER');
    const expected = [0, 7, 999999].map(id => [String(id), String(id % 1024), String(id % 100000),
        crypto.createHash('md5').update(String(id), 'ascii').digest('hex')]);
    check(data.data.every(row => Array.isArray(row) && row.length === 4
        && row.every(value => typeof value === 'number' || typeof value === 'string')), 'POINT_TYPES_OR_NULL');
    check(eq(data.data.map(row => row.map(String)), expected), 'POINT_COMPLETE_VALUES');
    return expected;
}

function label(raw, origin, prefix) {
    try {
        const url = new URL(raw);
        if (url.origin !== origin) return 'blocked_external';
        if (!url.pathname.startsWith(prefix + '/')) return 'wrong_prefix';
        const name = url.pathname.slice(prefix.length);
        const known = {
            '/login': 'login_page', '/home': 'home_page', '/Configuration': 'configuration_page',
            '/Playground': 'playground_page', '/legal-notices': 'legal_page',
            '/rest/v1/login': 'login', '/rest/v1/logout': 'logout',
            '/rest/v1/hardware_info/fe/': 'hardware', '/rest/v1/config/fe/': 'configuration',
            '/api/meta/namespaces/default_cluster/databases': 'databases',
            '/api/meta/namespaces/default_cluster/databases/license_perf/tables': 'tables',
            '/api/meta/namespaces/default_cluster/databases/license_perf/tables/point_rows/schema': 'schema',
            '/api/query/internal/license_perf': 'query',
            '/Playground/structure/license_perf-point_rows': 'structure_page',
            '/Playground/result/license_perf-point_rows': 'result_page',
        };
        if (known[name]) return known[name];
        if (/^\/[a-zA-Z0-9_.-]+\.(js|css|png|ico|svg|woff2?|ttf)$/.test(name)) return 'asset';
        if (name.startsWith('/legal/')) return 'legal_resource';
        return 'unclassified_local';
    } catch (_) {
        return 'invalid_url';
    }
}

function contentType(value) {
    if (/json/i.test(value)) return 'json';
    if (/html/i.test(value)) return 'html';
    if (/javascript/i.test(value)) return 'javascript';
    if (/css/i.test(value)) return 'css';
    return 'other';
}

async function boundedBody(response) {
    const length = Number(response.headers()['content-length'] || 0);
    check(!length || length <= 2097152, 'API_CONTENT_LENGTH_BOUND');
    const bytes = await response.body();
    check(bytes.length <= 2097152, 'API_BODY_BOUND');
    check(contentType(response.headers()['content-type'] || '') === 'json', 'API_JSON_MIME');
    try {
        return JSON.parse(bytes.toString('utf8'));
    } catch (_) {
        check(false, 'API_INVALID_JSON');
    }
}

async function closeContext(context, timeoutMs = 5000) {
    if (!context) return { attempted: false, closed: false };
    let timer;
    try {
        const timeout = new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('close timeout')), timeoutMs);
        });
        await Promise.race([context.close(), timeout]);
        return { attempted: true, closed: true };
    } catch (_) {
        return { attempted: true, closed: false };
    } finally {
        clearTimeout(timer);
    }
}

function backgroundPaths(config) {
    const value = config.background;
    check(value && /^[a-f0-9]{32}$/.test(value.token) && value.duration_seconds === 300, 'BACKGROUND_IDENTITY');
    check(path.dirname(value.directory) === path.dirname(path.dirname(config.output))
        && path.basename(value.directory) === config.cell.id + '-background', 'BACKGROUND_DIRECTORY');
    return value;
}

async function backgroundReceipt(background, name, timeoutMs) {
    const deadline = process.hrtime.bigint() + BigInt(timeoutMs) * 1000000n;
    const file = path.join(background.directory, name);
    while (!fs.existsSync(file)) {
        check(process.hrtime.bigint() < deadline, 'BACKGROUND_COORDINATION_TIMEOUT');
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    check(fs.statSync(file).size <= 8192, 'BACKGROUND_RECEIPT_BOUND');
    const raw = fs.readFileSync(file, 'utf8');
    // Preserve JVM nanoseconds exactly; JSON numbers can exceed JavaScript's safe integer range.
    const value = JSON.parse(raw.replace(/("(?:java_monotonic_ns|epoch_java_monotonic_ns)"\s*:\s*)(-?\d+)/g,
        '$1"$2"'));
    check(value.token === background.token, 'BACKGROUND_RECEIPT_TOKEN');
    return value;
}

function cadenceSchedule() {
    const events = [];
    for (let offset = 10000; offset < 300000; offset += 10000) {
        const target = offset < 100000 ? 'Home' : offset < 200000 ? 'Playground' : 'Configuration';
        events.push({ offset_ms: offset, kind: 'refresh', target,
            operation: target === 'Playground' ? 'tree_button' : 'document_reload' });
    }
    for (const [offset, target] of [[95000, 'Playground'], [195000, 'Configuration']]) {
        events.push({ offset_ms: offset, kind: 'navigate', target, operation: 'route_navigation' });
    }
    events.sort((first, second) => first.offset_ms - second.offset_ms);
    return { schema_version: 1, duration_ms: 300000, refresh_interval_ms: 10000,
        action_timeout_ms: 20000, initial_page: 'Home', scope: 'single_context_original_A_refresh_subset',
        events: events.map((event, sequence) => ({ ...event, sequence })) };
}

async function runCadence(schedule, hooks) {
    check(eq(schedule, cadenceSchedule()), 'FROZEN_CADENCE_SCHEDULE');
    const epoch = hooks.now();
    const events = schedule.events.map(event => ({ ...event, scheduled_ms: epoch + event.offset_ms,
        deadline_ms: Math.min(epoch + schedule.duration_ms, epoch + event.offset_ms + schedule.action_timeout_ms),
        status: 'PLANNED', started_ms: null, matched_network_ids: [] }));
    const receipt = { schedule, epoch_ms: epoch, epoch_unix_millis: hooks.wall(), events,
        status: 'RUNNING', scope: schedule.scope, formal_performance_pass: false };
    hooks.publish(receipt);
    let aborted = false;
    for (const event of events) {
        if (aborted) {
            event.status = 'NOT_SENT_ABORTED';
            event.recorded_ms = hooks.now();
            continue;
        }
        await hooks.waitUntil(event.scheduled_ms);
        const started = hooks.now();
        if (started >= event.deadline_ms) {
            event.status = 'QUEUE_DEADLINE_MISS';
            event.recorded_ms = started;
            continue;
        }
        event.started_ms = started;
        event.started_unix_millis = hooks.wall();
        event.queue_ms = started - event.scheduled_ms;
        try {
            await hooks.execute(event, Math.max(1, event.deadline_ms - started));
            event.finished_ms = hooks.now();
            event.finished_unix_millis = hooks.wall();
            check(event.finished_ms <= event.deadline_ms, 'CADENCE_ACTION_OVERRAN_DEADLINE');
            event.status = 'PASS';
        } catch (error) {
            event.finished_ms = hooks.now();
            event.finished_unix_millis = hooks.wall();
            event.error_code = error.name === 'TimeoutError' ? 'CADENCE_ACTION_TIMEOUT'
                : /^[A-Z0-9_]+$/.test(error.fixtureCode || '') ? error.fixtureCode : 'CADENCE_ACTION_FAILURE';
            event.status = event.error_code === 'CADENCE_ACTION_TIMEOUT' ? 'TIMEOUT' : 'FAIL';
            // Never start the next action while a rejected Playwright operation may still be in flight.
            aborted = true;
            try {
                event.page_close_confirmed = await hooks.abort();
            } catch (_) {
                event.page_close_confirmed = false;
            }
        }
        event.e2e_ms = event.finished_ms - event.scheduled_ms;
        hooks.publish(receipt);
    }
    receipt.status = events.every(event => event.status === 'PASS') ? 'PASS' : 'FAIL';
    receipt.finished_ms = hooks.now();
    receipt.finished_unix_millis = hooks.wall();
    hooks.publish(receipt);
    return receipt;
}

async function run(config) {
    const { chromium } = require(config.runtime.playwright);
    const { cell, origin, expected } = config;
    const prefix = cell.prefix;
    check(['', '/proxy/fe', '/gateway/cluster/fe/default'].includes(prefix), 'PREFIX');
    check(['zh-CN', 'en'].includes(cell.language), 'LANGUAGE');
    check(['admin', 'reader', 'unprivileged'].includes(cell.role), 'ROLE');
    check(/^http:\/\/127\.0\.0\.1:\d+$/.test(origin), 'LOCAL_PROXY');
    check(path.dirname(config.output) === path.dirname(config.profile), 'OWNED_PROFILE_PATH');
    const started = process.hrtime.bigint();
    const now = () => Number(process.hrtime.bigint() - started) / 1e6;
    const report = { schema_version: 1, cell, status: 'RUNNING', runtime: { node: process.version },
        actions: [], network: [], page_error_events: [], console_event_counts: {}, blocked_requests: 0,
        limitations: [], LP021_complete: false, LP022_complete: false, full_goal_complete: false,
        missing: ['background_read_write', 'formal_windows', 'all_viewports', 'visibility_and_session_negatives', 'B_P2U'] };
    let context;
    let background;
    let permissionModalExpected = false;
    let activeAction = 'bootstrap';
    let actionNumber = 0;
    const requestRecords = new Map();
    const pending = new Set();
    const track = promise => {
        pending.add(promise);
        promise.finally(() => pending.delete(promise)).catch(() => {});
    };
    const publish = () => {
        fs.writeFileSync(config.output, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    };
    publish();
    const close = () => closeContext(context);
    const stop = () => { report.interrupted = true; close().finally(() => process.exit(2)); };
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
    try {
        const argumentsForBrowser = ['--disable-background-networking'];
        if (config.runtime.allow_no_browser_sandbox) argumentsForBrowser.push('--no-sandbox');
        context = await chromium.launchPersistentContext(config.profile, {
            executablePath: config.runtime.chromium, headless: true,
            chromiumSandbox: !config.runtime.allow_no_browser_sandbox,
            viewport: { width: 1440, height: 1000 }, locale: cell.language, timezoneId: 'UTC',
            serviceWorkers: 'block', acceptDownloads: false, args: argumentsForBrowser,
        });
        report.runtime.chromium = context.browser().version();
        await context.addInitScript(language => {
            if (localStorage.getItem('I18N_LANGUAGE') === null) localStorage.setItem('I18N_LANGUAGE', language);
        }, cell.language);
        await context.route('**/*', route => {
            if (route.request().url().startsWith(origin + '/')) return route.continue();
            report.blocked_requests++;
            return route.abort('blockedbyclient');
        });
        context.on('request', request => {
            if (report.network.length >= 2000) {
                report.network_overflow = true;
                return;
            }
            const record = { id: report.network.length + 1, action: activeAction, start_ms: now(),
                method: ['GET', 'POST'].includes(request.method()) ? request.method() : 'other',
                endpoint: label(request.url(), origin, prefix), resource: request.resourceType(),
                redirected_from: request.redirectedFrom() ? requestRecords.get(request.redirectedFrom())?.id : null };
            report.network.push(record);
            requestRecords.set(request, record);
        });
        context.on('response', response => track((async () => {
            const record = requestRecords.get(response.request());
            if (!record) return;
            record.response_ms = now();
            record.http_status = response.status();
            record.content_type = contentType(response.headers()['content-type'] || '');
            if (['login', 'logout', 'hardware', 'configuration', 'databases', 'tables', 'schema', 'query'].includes(record.endpoint)) {
                try {
                    const body = await boundedBody(response);
                    record.business_code = Number.isInteger(body.code) ? body.code : null;
                    record.business_success = business(body);
                    record.original_permission_denial = denial(body);
                    record.login_success = record.endpoint === 'login' && body.code === 200;
                } catch (_) {
                    record.parse_failed = true;
                }
            }
        })()));
        context.on('requestfinished', request => track((async () => {
            const record = requestRecords.get(request);
            if (!record) return;
            record.finished_ms = now();
            record.failed = false;
            try {
                const size = await request.sizes();
                record.response_body_bytes = size.responseBodySize;
                record.request_body_bytes = size.requestBodySize;
            } catch (_) {
                record.byte_count_unavailable = true;
            }
        })()));
        context.on('requestfailed', request => {
            const record = requestRecords.get(request);
            if (record) { record.finished_ms = now(); record.failed = true; }
        });
        const page = context.pages()[0] || await context.newPage();
        const button = text => page.getByRole('button').filter({ hasText: buttonTextPattern(text) });
        page.setDefaultTimeout(config.timeout_ms);
        page.setDefaultNavigationTimeout(config.timeout_ms);
        page.on('pageerror', () => report.page_error_events.push({ action: activeAction, at_ms: now() }));
        page.on('console', event => {
            const type = event.type();
            report.console_event_counts[type] = (report.console_event_counts[type] || 0) + 1;
        });
        async function beginBackground() {
            background = backgroundPaths(config);
            fs.writeFileSync(path.join(background.directory, 'browser-ready.json'), JSON.stringify({
                token: background.token, browser_monotonic_ns: process.hrtime.bigint().toString(),
                unix_millis: Date.now(), at_utc: new Date().toISOString(),
            }), { flag: 'wx', mode: 0o600 });
            const start = await backgroundReceipt(background, 'window-start.json', 60000);
            check(start.duration_seconds === 300 && start.epoch_delay_millis === 500, 'BACKGROUND_WINDOW');
            await new Promise(resolve => setTimeout(resolve, 500));
            report.background = { token: background.token, start_receipt: start,
                browser_actions_started_ms: now(), browser_actions_started_unix_millis: Date.now(),
                all_clocks_have_separate_origins: true, formal_performance_pass: false };
            report.missing = report.missing.filter(item => item !== 'background_read_write');
        }
        if (config.background && !config.refresh_cadence) await beginBackground();

        async function action(name, callback) {
            activeAction = `${++actionNumber}-${name}`;
            const result = { id: activeAction, started_ms: now(), status: 'RUNNING' };
            report.actions.push(result);
            try {
                await callback(result);
                result.status = 'PASS';
            } catch (error) {
                result.status = 'FAIL';
                result.error_code = /^[A-Z0-9_]+$/.test(error.fixtureCode || '') ? error.fixtureCode : 'BROWSER_ACTION_FAILURE';
                result.error_name = safeErrorName(error);
                throw error;
            } finally {
                result.finished_ms = now();
                publish();
            }
        }

        async function responseFor(endpoint, trigger) {
            const waiting = page.waitForResponse(response => label(response.url(), origin, prefix) === endpoint);
            waiting.catch(() => {}); // Trigger failure must not leave an unhandled response-wait rejection.
            await trigger();
            const response = await waiting;
            check(response.status() === 200, 'API_HTTP_STATUS');
            const body = await boundedBody(response);
            check(await response.finished() === null, 'API_BODY_COMPLETION');
            return body;
        }

        async function home(trigger) {
            const body = await responseFor('hardware', trigger);
            permissionModalExpected = denial(body) && body.data === 'Cookie is invalid';
            if (cell.role !== 'admin') {
                check(denial(body), 'REST_NONADMIN_COOKIE_DENIAL');
                return;
            }
            check(business(body), 'HOME_BUSINESS');
            check(body.data?.VersionInfo?.Version === expected.version && body.data?.VersionInfo?.Git === expected.git,
                'HOME_BUILD_IDENTITY');
            await page.getByRole('heading', { name: 'Version', exact: true }).waitFor();
            await page.getByRole('heading', { name: 'Hardware Info', exact: true }).waitFor();
            await page.getByText('Version : ' + expected.version, { exact: true }).waitFor();
            check(await page.locator('footer').count() === 1, 'HOME_FOOTER');
        }

        async function configuration(trigger) {
            const body = await responseFor('configuration', trigger);
            permissionModalExpected = denial(body) && body.data === 'Cookie is invalid';
            if (cell.role !== 'admin') {
                check(denial(body), 'CONFIG_NONADMIN_COOKIE_DENIAL');
                return;
            }
            check(business(body) && eq(body.data?.column_names, ['Name', 'Value']), 'CONFIG_TABLE_SHAPE');
            const port = body.data.rows.filter(row => row.Name === 'http_port');
            check(port.length === 1 && String(port[0].Value) === String(expected.http_port), 'CONFIG_ACTUAL_PORT');
            await page.getByRole('heading', { name: 'Configure Info', exact: true }).waitFor();
            await page.getByRole('columnheader', { name: 'Name', exact: true }).waitFor();
            const visibleRows = page.locator('table tbody tr.ant-table-row');
            await visibleRows.first().waitFor();
            const rendered = await visibleRows.evaluateAll(rows => rows.map(row =>
                [...row.querySelectorAll('td')].map(cell => cell.textContent)));
            const visibleExpected = body.data.rows.slice(0, 30).map(row => ['Name', 'Value'].map(name =>
                row[name] === '\\N' ? '-' : String(row[name] ?? '')));
            check(eq(rendered, visibleExpected), 'CONFIG_VISIBLE_ROWS');
        }

        async function databases(trigger) {
            const body = await responseFor('databases', trigger);
            permissionModalExpected = denial(body) && body.data === 'Cookie is invalid';
            if (cell.role !== 'admin' && expected.auth_all) {
                check(denial(body), 'TREE_AUTH_ALL_DENIAL');
                return false;
            }
            check(business(body) && Array.isArray(body.data) && body.data.includes('license_perf'), 'DATABASES_ORACLE');
            report.dom_wait_stage = 'PLAYGROUND_EDITOR';
            await page.locator('.CodeMirror').waitFor();
            report.dom_wait_stage = 'PLAYGROUND_DATABASE';
            await page.getByText('license_perf', { exact: true }).waitFor();
            report.dom_wait_stage = 'PLAYGROUND_EXECUTE';
            await button(cell.language === 'en' ? 'Execute' : '执行').waitFor();
            report.dom_wait_stage = null;
            return true;
        }

        async function dismissPermissionModal() {
            const cancel = page.locator('.ant-modal-confirm-btns button').first();
            await cancel.waitFor({ state: 'visible' });
            await cancel.click();
            await page.locator('.ant-modal-confirm').waitFor({ state: 'hidden' });
        }

        async function cadence() {
            check(config.background, 'CADENCE_REQUIRES_BACKGROUND');
            check(eq(config.refresh_cadence, cadenceSchedule()), 'FROZEN_CADENCE_SCHEDULE');
            // Login and the initial page oracle are outside the fixed refresh/background window.
            await home(() => page.reload());
            if (permissionModalExpected) await dismissPermissionModal();
            await beginBackground();
            report.default_functional_navigation = 'not_run_in_refresh_subcase';
            report.missing.push('default_functional_navigation_in_this_run');
            const result = await runCadence(config.refresh_cadence, {
                now, wall: () => Date.now(),
                waitUntil: async scheduled => {
                    while (now() < scheduled) await new Promise(resolve => setTimeout(resolve, Math.min(100, scheduled - now())));
                },
                publish: receipt => { report.refresh_cadence = receipt; publish(); },
                abort: async () => (await closeContext(page)).closed,
                execute: async (event, budget) => {
                    activeAction = `cadence-${event.sequence}`;
                    event.action_id = activeAction;
                    event.expected_endpoint = { Home: 'hardware', Playground: 'databases', Configuration: 'configuration' }[event.target];
                    event.expected_original_denial = cell.role !== 'admin' && (event.target !== 'Playground' || expected.auth_all);
                    const expectedPath = { Home: '/home', Playground: '/Playground', Configuration: '/Configuration' }[event.target];
                    page.setDefaultTimeout(Math.max(1, Math.floor(budget)));
                    page.setDefaultNavigationTimeout(Math.max(1, Math.floor(budget)));
                    let timer;
                    const operation = (async () => {
                        if (event.kind === 'refresh') {
                            check(new URL(page.url()).pathname === prefix + expectedPath, 'CADENCE_ROUTE_CHANGED');
                        }
                        const trigger = event.kind === 'navigate' ? () => page.goto(origin + prefix + expectedPath)
                            : event.operation === 'document_reload' ? () => page.reload()
                                : () => page.getByRole('button', {
                                    name: cell.language === 'en' ? 'Refresh' : '刷新', exact: true }).click();
                        if (event.target === 'Home') await home(trigger);
                        else if (event.target === 'Configuration') await configuration(trigger);
                        else await databases(trigger);
                        if (permissionModalExpected) await dismissPermissionModal();
                        check(new URL(page.url()).pathname === prefix + expectedPath, 'CADENCE_PREFIX_OR_ROUTE');
                        check(await page.evaluate(() => localStorage.getItem('I18N_LANGUAGE')) === cell.language,
                            'CADENCE_LANGUAGE_CHANGED');
                        event.oracle_verified = true;
                    })();
                    try {
                        await Promise.race([operation, new Promise((_, reject) => {
                            timer = setTimeout(() => {
                                const error = new Error('CADENCE_ACTION_TIMEOUT');
                                error.fixtureCode = 'CADENCE_ACTION_TIMEOUT';
                                reject(error);
                            }, budget);
                        })]);
                    } finally {
                        clearTimeout(timer);
                        event.matched_network_ids = report.network.filter(record => record.action === activeAction
                            && record.endpoint === event.expected_endpoint).map(record => record.id);
                    }
                    check(event.matched_network_ids.length === 1, 'CADENCE_API_REQUEST_COUNT');
                },
            });
            try {
                check(result.status === 'PASS', 'CADENCE_INCOMPLETE');
                const end = await backgroundReceipt(background, 'window-end.json', 60000);
                check(end.scheduled_window_complete === true, 'CADENCE_BACKGROUND_INCOMPLETE');
                check(result.events.every(event => event.started_unix_millis >= report.background.start_receipt.unix_millis
                    && event.finished_unix_millis <= end.unix_millis), 'CADENCE_OUTSIDE_BACKGROUND');
                result.background_window_verified = true;
            } catch (error) {
                result.status = 'FAIL';
                result.background_window_verified = false;
                throw error;
            }
            page.setDefaultTimeout(config.timeout_ms);
            page.setDefaultNavigationTimeout(config.timeout_ms);
        }

        await action('login_redirect_and_real_basic', async result => {
            await page.goto(origin + prefix + '/home');
            await page.waitForURL(origin + prefix + '/login');
            await page.locator('#basic_username').fill(config.account.username);
            await page.locator('#basic_password').fill(config.account.password);
            const waiting = observe(page.waitForResponse(response => label(response.url(), origin, prefix) === 'login'));
            const homeWaiting = observe(page.waitForResponse(response => label(response.url(), origin, prefix) === 'hardware'));
            await button(cell.language === 'en' ? 'Login' : '登录').click();
            const response = await waiting;
            check(response.status() === 200 && (await boundedBody(response)).code === 200, 'REAL_LOGIN_FAILED');
            await page.waitForURL(origin + prefix + '/home');
            const initial = await boundedBody(await homeWaiting);
            check(cell.role === 'admin' ? business(initial) : denial(initial), 'POST_LOGIN_COOKIE_BEHAVIOR');
            const cookies = await context.cookies();
            result.session_cookie_present = cookies.some(cookie => cookie.name === 'PALO_SESSION_ID');
            check(result.session_cookie_present, 'REAL_SESSION_COOKIE_MISSING');
            result.username_marker_matches = await page.evaluate(username => localStorage.getItem('username') === username,
                config.account.username);
            check(result.username_marker_matches, 'LOGIN_USERNAME_MARKER');
        });
        if (config.refresh_cadence) {
            await cadence();
        } else {
            report.default_functional_navigation = 'executed';
            await action('home_direct_reload', async () => home(() => page.goto(origin + prefix + '/home')));
            await action('configuration_direct', async () => configuration(() => page.goto(origin + prefix + '/Configuration')));
            let treeAllowed = false;
            await action('playground_initial', async () => {
                treeAllowed = await databases(() => page.goto(origin + prefix + '/Playground'));
            });
            if (treeAllowed) {
                await action('tree_manual_refresh', async () => {
                    await databases(() => page.getByRole('button', { name: cell.language === 'en' ? 'Refresh' : '刷新', exact: true }).click());
                });
                await action('tree_expand_and_object_permission', async () => {
                    const treeNode = page.locator('.ant-tree-treenode').filter({ has: page.getByText('license_perf', { exact: true }) });
                    const body = await responseFor('tables', () => treeNode.locator('.ant-tree-switcher').click());
                    check(business(body) && Array.isArray(body.data), 'TABLES_BUSINESS');
                    const wanted = cell.role === 'admin' ? expected.tables : cell.role === 'reader' ? ['point_rows'] : [];
                    check(eq([...body.data].sort(), wanted), 'TABLES_PRIVILEGE_ORACLE');
                });
                await action('schema_direct_deep_link', async () => {
                    const body = await responseFor('schema', () => page.goto(origin + prefix + '/Playground/structure/license_perf-point_rows'));
                    if (cell.role === 'unprivileged') {
                        check(denial(body), 'SCHEMA_ORIGINAL_PERMISSION_DENIAL');
                        return;
                    }
                    check(business(body), 'SCHEMA_BUSINESS');
                    const base = body.data?.point_rows;
                    check(base?.is_base === true && eq(base.schema, expected.schema), 'SCHEMA_DESCRIBE_ORACLE');
                    for (const column of ['id', 'grp', 'v', 'payload']) {
                        await page.locator('table').getByText(column, { exact: true }).first().waitFor();
                    }
                });
            }
            if (cell.role === 'admin' || (cell.role === 'reader' && !expected.auth_all)) {
                let wantedRows;
                await action('execute_three_row_query', async () => {
                    await page.locator('.CodeMirror').click();
                    await page.keyboard.press('Control+A');
                    await page.keyboard.insertText(config.point_sql);
                    const body = await responseFor('query', () => button(cell.language === 'en' ? 'Execute' : '执行').click());
                    check(business(body), 'QUERY_BUSINESS');
                    wantedRows = pointRows(body.data);
                    await page.waitForURL(origin + prefix + '/Playground/result/license_perf-point_rows');
                    await page.waitForFunction(() => document.querySelectorAll('table tbody tr').length === 3);
                    const actualRows = await page.locator('table tbody tr').evaluateAll(rows =>
                        rows.map(row => Array.from(row.querySelectorAll('td')).map(cell => cell.textContent.trim())));
                    check(eq(actualRows, wantedRows), 'QUERY_COMPLETE_DOM_VALUES');
                });
                await action('result_history_back_forward', async () => {
                    await page.goBack();
                    await page.waitForURL(origin + prefix + '/Playground/structure/license_perf-point_rows');
                    await page.goForward();
                    await page.waitForURL(origin + prefix + '/Playground/result/license_perf-point_rows');
                    await page.waitForFunction(() => document.querySelectorAll('table tbody tr').length === 3);
                    const actualRows = await page.locator('table tbody tr').evaluateAll(rows =>
                        rows.map(row => Array.from(row.querySelectorAll('td')).map(cell => cell.textContent.trim())));
                    check(eq(actualRows, wantedRows), 'HISTORY_RESULT_VALUES');
                });
                await action('result_fresh_deep_link_risk', async result => {
                    // A fresh page has no React Router location.state; do not inject state to hide a baseline defect.
                    const fresh = await context.newPage();
                    fresh.setDefaultTimeout(config.timeout_ms);
                    let errors = 0;
                    fresh.on('pageerror', () => errors++);
                    try {
                        await fresh.goto(origin + prefix + '/Playground/result/license_perf-point_rows');
                        await fresh.waitForTimeout(500);
                        result.page_error_count = errors;
                        result.result_rows = await fresh.locator('table tbody tr').count();
                        if (errors || result.result_rows !== 3) {
                            report.limitations.push('ORIGINAL_RESULT_DEEP_LINK_WITHOUT_HISTORY_STATE');
                            result.observation = 'BASELINE_LIMITATION';
                        } else {
                            const rows = await fresh.locator('table tbody tr').evaluateAll(items =>
                                items.map(row => Array.from(row.querySelectorAll('td')).map(cell => cell.textContent.trim())));
                            check(eq(rows, wantedRows), 'FRESH_DEEP_LINK_VALUES');
                            result.observation = 'RESULT_RESTORED_WITHOUT_INJECTED_STATE';
                        }
                    } finally {
                        await fresh.close();
                    }
                });
            }
            if (cell.role === 'admin') {
                await action('menu_to_configuration', async () => configuration(() =>
                    page.getByRole('menuitem', { name: 'Configuration', exact: true }).click()));
                await action('logo_home_and_history', async () => {
                    await home(() => page.locator('header > div').first().click());
                    await page.waitForURL(origin + prefix + '/home');
                    // Logo uses history.replace; direct navigation supplies a predictable separate history entry.
                    await configuration(() => page.goto(origin + prefix + '/Configuration'));
                    await page.goBack();
                    await page.waitForURL(origin + prefix + '/home');
                    await page.getByText('Version : ' + expected.version, { exact: true }).waitFor();
                    await page.goForward();
                    await page.waitForURL(origin + prefix + '/Configuration');
                    await page.getByRole('heading', { name: 'Configure Info', exact: true }).waitFor();
                    check(await page.locator('table tbody tr').count() > 0, 'HISTORY_CONFIG_ROWS');
                });
                await action('language_real_reload', async result => {
                    await configuration(() => button(cell.language === 'en' ? '中文' : 'English').click());
                    const wanted = cell.language === 'en' ? 'zh-CN' : 'en';
                    result.language_key_matches = await page.evaluate(value => localStorage.getItem('I18N_LANGUAGE') === value, wanted);
                    check(result.language_key_matches, 'LANGUAGE_PERSISTENCE');
                    check(new URL(page.url()).pathname === prefix + '/Configuration', 'LANGUAGE_PREFIX_ROUTE');
                });
            }
        }
        await action('logout', async () => {
            // Use direct navigation, not databases(), because language may already have changed.
            const bodyBeforeLogout = await responseFor('databases', () => page.goto(origin + prefix + '/Playground'));
            if (cell.role !== 'admin' && expected.auth_all) {
                check(denial(bodyBeforeLogout), 'LOGOUT_SETUP_PERMISSION');
                if (bodyBeforeLogout.data === 'Cookie is invalid') await dismissPermissionModal();
            } else {
                check(business(bodyBeforeLogout), 'LOGOUT_SETUP_TREE');
            }
            await page.locator('.ant-dropdown-link').hover();
            // Select the only dropdown menu item by its existing logout icon, independent of missing locale keys.
            const item = page.locator('.ant-dropdown-menu-item').filter({ has: page.locator('.anticon-logout') });
            const body = await responseFor('logout', () => item.click());
            check(business(body), 'LOGOUT_BUSINESS');
            await page.waitForURL(origin + prefix + '/login');
            check(await page.evaluate(() => localStorage.getItem('username') === null), 'LOGOUT_MARKER');
        });
        check(!report.network_overflow, 'NETWORK_EVENT_BOUND');
        check(report.blocked_requests === 0, 'UNEXPECTED_EXTERNAL_REQUEST');
        check(!report.network.some(record => record.endpoint === 'wrong_prefix'), 'REQUEST_PREFIX_ESCAPE');
        check(report.page_error_events.length === 0, 'UNEXPECTED_PAGE_ERROR');
        report.status = report.limitations.length ? 'PARTIAL' : 'PASS';
    } catch (error) {
        report.status = 'FAIL';
        report.failure_code = /^[A-Z0-9_]+$/.test(error.fixtureCode || '') ? error.fixtureCode : 'BROWSER_FIXTURE_FAILURE';
        report.failure_name = safeErrorName(error);
    } finally {
        if (background) {
            try {
                const end = await backgroundReceipt(background, 'window-end.json', 360000);
                check(end.scheduled_window_complete === true, 'BACKGROUND_WINDOW_INCOMPLETE');
                report.background = { ...report.background, end_receipt: end,
                    browser_context_held_until_ms: now(), browser_context_held_until_unix_millis: Date.now() };
            } catch (_) {
                report.status = 'FAIL';
                report.background_failure_code = 'BACKGROUND_WINDOW_UNCONFIRMED';
            }
        }
        report.server_session_logout_confirmed = false;
        if (context) {
            try {
                // A failed page action must also invalidate its FE session, not merely delete local cookies.
                const response = await context.request.post(origin + prefix + '/rest/v1/logout', { timeout: 5000 });
                report.server_session_logout_confirmed = response.status() === 200 && business(await boundedBody(response));
            } catch (_) {
                // Only the fixed failure marker is retained; the request may carry HttpOnly credentials.
            }
        }
        const cleanup = await close();
        await Promise.allSettled([...pending]);
        report.elapsed_ms = now();
        report.browser_context_close_attempted = cleanup.attempted;
        report.browser_context_closed = cleanup.closed;
        if (!cleanup.closed || !report.server_session_logout_confirmed) {
            report.status = 'FAIL';
            report.cleanup_failure_code = 'SESSION_OR_GRACEFUL_CLOSE_UNCONFIRMED';
        }
        publish();
    }
    return report.status === 'FAIL' ? 2 : 0;
}

async function main() {
    const chunks = [];
    let length = 0;
    for await (const chunk of process.stdin) {
        length += chunk.length;
        check(length <= 2097152, 'CONFIG_BOUND');
        chunks.push(chunk);
    }
    const config = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return run(config);
}

if (require.main === module) {
    main().then(code => { process.exitCode = code; }).catch(error => {
        process.stderr.write(JSON.stringify({ status: 'FAIL', error_name: safeErrorName(error) }) + '\n');
        process.exitCode = 2;
    });
}

module.exports = { business, denial, pointRows, label, contentType, closeContext, backgroundPaths, cadenceSchedule,
    runCadence, buttonTextPattern, observe, safeErrorName };
