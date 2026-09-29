// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

'use strict';
// Real G7 browser workload. Importing this module never starts a browser or sends a request.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ROOT = path.resolve(__dirname, '../..');
const RECORDS = path.join(ROOT, '.build-records');
const STATUSES = new Set(['VALID', 'EXPIRING', 'MISSING', 'NOT_YET_VALID', 'EXPIRED', 'INVALID',
    'FEATURE_NOT_LICENSED', 'LICENSE_NOT_READY', 'CLOCK_SUSPECT', 'LIMIT_EXCEEDED']);
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const monotonic = () => process.hrtime.bigint();
function releaseEpoch(value, token, nodePid, now, deadline) {
    check(value.token === token && value.clock_domain === 'node_process_hrtime' && value.node_pid === nodePid
        && /^[0-9]{1,20}$/.test(value.epoch_monotonic_ns) && value.duration_seconds === 300
        && Number.isSafeInteger(value.epoch_unix_ms) && /^[a-f0-9]{64}$/.test(value.clock_bridge_sha256 || ''), 'RELEASE_FIELDS');
    const epoch = BigInt(value.epoch_monotonic_ns);
    check(epoch >= now && epoch <= now + 30000000000n && epoch + 300000000000n < deadline, 'RELEASE_EPOCH');
    return epoch;
}
const errorCode = error => /^[A-Z][A-Z0-9_]{0,95}$/.test(error?.fixtureCode || '')
    ? error.fixtureCode : 'DRIVER_FAILURE';
function check(value, code) {
    if (!value) { const error = new Error(code); error.fixtureCode = code; throw error; }
}
function validateConfig(config) {
    check(config && config.schema_version === 1 && /^[a-f0-9]{32}$/.test(config.token), 'CONFIG_IDENTITY');
    check(['A', 'B'].includes(config.variant) && ['details', 'imports', 'other-tabs'].includes(config.scenario), 'CONFIG_SCENARIO');
    check(config.variant !== 'A' || config.scenario === 'other-tabs', 'NO_LICENSE_PAGE_ON_A');
    check((config.scenario === 'imports' ? [1, 10] : [1, 10, 50]).includes(config.context_count), 'CONFIG_CONTEXT_COUNT');
    check(config.duration_seconds === 300 && config.refresh_interval_seconds === 10, 'CONFIG_WINDOW');
    check(config.preparation_concurrency === 1, 'CONFIG_SERIAL_PREPARATION');
    check(['admin', 'ordinary'].includes(config.role) && ['en', 'zh-CN'].includes(config.language), 'CONFIG_ROLE_LANGUAGE');
    check(config.scenario !== 'imports' || config.role === 'admin', 'IMPORT_REQUIRES_ADMIN');
    check(typeof config.prefix === 'string' && /^(?:\/[A-Za-z0-9_-]+)*$/.test(config.prefix), 'CONFIG_PREFIX');
    const origin = new URL(config.origin);
    check(['http:', 'https:'].includes(origin.protocol) && origin.origin === config.origin
        && !origin.username && !origin.password
        && /^(?:127\.0\.0\.1|10(?:\.[0-9]{1,3}){3}|192\.168(?:\.[0-9]{1,3}){2}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2})$/.test(origin.hostname), 'CONFIG_OWNED_ORIGIN');
    check(Number.isInteger(config.action_timeout_seconds) && config.action_timeout_seconds >= 10
        && config.action_timeout_seconds <= 150, 'CONFIG_ACTION_TIMEOUT');
    check(Number.isInteger(config.prepare_timeout_seconds) && config.prepare_timeout_seconds >= 90
        && config.prepare_timeout_seconds <= 600, 'CONFIG_PREPARE_TIMEOUT');
    check(/^[0-9]{1,20}$/.test(config.deadline_monotonic_ns), 'CONFIG_ABSOLUTE_DEADLINE');
    check(typeof config.chromium === 'string' && typeof config.playwright === 'string'
        && typeof config.output === 'string' && typeof config.accounts_file === 'string', 'CONFIG_PATHS');
    check(typeof config.allow_no_browser_sandbox === 'boolean', 'CONFIG_SANDBOX');
    if (config.scenario === 'imports') {
        check(Array.isArray(config.certificate_files) && config.certificate_files.length === 3
            && config.certificate_files.every(item => typeof item.path === 'string' && /^[a-f0-9]{64}$/.test(item.sha256)), 'CONFIG_CERTIFICATE_REFERENCES');
    } else check(!config.certificate_files, 'UNEXPECTED_CERTIFICATES');
    return config;
}
function schedule(scenario) {
    if (scenario === 'details') return Array.from({ length: 30 }, (_, index) => ({ sequence: index, offset_ms: index * 10000, kind: 'refresh' }));
    if (scenario === 'imports') return [0, 100000, 200000].map((offset_ms, sequence) => ({ sequence, offset_ms, kind: 'import' }));
    check(scenario === 'other-tabs', 'UNKNOWN_SCHEDULE');
    return ['home', 'Configuration', 'Session'].map((route, sequence) => ({ sequence, offset_ms: sequence * 100000, kind: 'navigate', route }));
}
function owned(input) {
    const resolved = fs.realpathSync(input);
    check(resolved.startsWith(RECORDS + path.sep), 'PATH_OUTSIDE_RECORDS');
    return resolved;
}
function secretFile(input, limit) {
    const resolved = owned(input);
    const stat = fs.statSync(resolved);
    check(stat.isFile() && (stat.mode & 0o777) === 0o600 && stat.size <= limit, 'SECRET_FILE_MODE_OR_BOUND');
    return fs.readFileSync(resolved);
}
function endpoint(raw, origin, prefix) {
    const url = new URL(raw);
    if (url.origin !== origin) return 'foreign';
    if (url.search && url.pathname.startsWith(prefix + '/api/license')) return 'license_query_string';
    const relative = url.pathname.slice(prefix.length);
    if (prefix && !url.pathname.startsWith(prefix + '/')) return 'wrong_prefix';
    if (relative === '/api/license') return 'status';
    if (relative === '/api/license/validate') return 'validate';
    if (relative === '/api/license/import') return 'import';
    if (/^\/api\/license\/imports\/[a-f0-9]{64}$/.test(relative)) return 'receipt';
    if (relative.startsWith('/api/license')) return 'unknown_license';
    if (relative === '/rest/v1/login') return 'login';
    if (relative === '/rest/v1/logout') return 'logout';
    return 'other';
}
function receiptApplied(value, fingerprint) {
    const decimal = value => /^(0|[1-9][0-9]*)$/.test(String(value))
        && (typeof value === 'string' || Number.isSafeInteger(value));
    return value && value.submission_status === 'APPLIED' && value.fingerprint === fingerprint
        && decimal(value.committed_version) && decimal(value.applied_version)
        && BigInt(value.applied_version) >= BigInt(value.committed_version);
}
function safeBody(body) {
    const result = {};
    if (STATUSES.has(body.status)) result.status = body.status;
    if (typeof body.administrator === 'boolean') result.administrator = body.administrator;
    if (['NOT_SUBMITTED', 'COMMITTED', 'APPLIED', 'UNKNOWN'].includes(body.submission_status)) result.submission_status = body.submission_status;
    if (/^LICENSE_[A-Z0-9_]+$/.test(body.reason || '')) result.reason = body.reason;
    if (/^[a-f0-9]{64}$/.test(body.fingerprint || '')) result.fingerprint = body.fingerprint;
    for (const field of ['committed_version', 'applied_version']) {
        if ((typeof body[field] === 'string' && /^(0|[1-9][0-9]{0,20})$/.test(body[field]))
            || (Number.isSafeInteger(body[field]) && body[field] >= 0)) result[field] = body[field];
    }
    return result;
}
async function boundedOperation(operation, timeoutMillis, abort) {
    let timer;
    try {
        return await Promise.race([operation, new Promise((_, reject) => {
            timer = setTimeout(() => {
                try { Promise.resolve(abort()).catch(() => {}); } catch (_) { /* Preserve the timeout cause. */ }
                const error = new Error('ACTION_ABSOLUTE_TIMEOUT');
                error.fixtureCode = 'ACTION_ABSOLUTE_TIMEOUT'; reject(error);
            }, Math.max(1, timeoutMillis));
        })]);
    } finally { clearTimeout(timer); }
}
function summary(records) {
    const events = records.flatMap(record => record.events);
    const latencies = events.filter(item => item.status === 'PASS').map(item => item.e2e_ms).sort((a, b) => a - b);
    return { actions_scheduled: events.length, actions_successful: latencies.length,
        actions_failed: events.filter(item => item.status === 'FAIL').length,
        actions_not_sent: events.filter(item => item.status === 'NOT_SENT').length,
        latency_ms: { samples: latencies, minimum: latencies[0] ?? null, maximum: latencies.at(-1) ?? null,
            mean: latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : null },
        p99: null, p99_status: 'NOT_QUALIFIED_INSUFFICIENT_BROWSER_SAMPLES', formal_business_performance_pass: false };
}
async function run(input) {
    const config = validateConfig(input);
    const output = owned(config.output);
    check(fs.statSync(output).isDirectory() && !(fs.statSync(output).mode & 0o077), 'OUTPUT_MUST_BE_PRIVATE');
    for (const name of ['ready.json', 'release.json', 'done.json', 'finish.json', 'terminal.json']) {
        check(!fs.existsSync(path.join(output, name)), 'OUTPUT_ALREADY_USED');
    }
    const accountsRaw = secretFile(config.accounts_file, 65536);
    const accounts = JSON.parse(accountsRaw);
    check(Array.isArray(accounts) && accounts.length === config.context_count && accounts.every(account =>
        /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(account.username) && typeof account.password === 'string'
        && account.password.length <= 1024), 'ACCOUNT_REFERENCES');
    check(config.scenario !== 'imports' || new Set(accounts.map(item => item.username)).size === config.context_count,
        'IMPORT_REQUIRES_DISTINCT_PRINCIPALS');
    const certificates = (config.certificate_files || []).map(item => {
        const raw = secretFile(item.path, 65536);
        check(raw.length > 0 && sha(raw) === item.sha256, 'CERTIFICATE_FINGERPRINT');
        const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
        check(Buffer.from(text, 'utf8').equals(raw), 'CERTIFICATE_UTF8_BYTES');
        return { text, fingerprint: item.sha256, path: fs.realpathSync(item.path), bytes: raw.length };
    });
    const secrets = certificates.flatMap(item => [item.text, ...item.text.split('.')]).filter(item => item.length >= 12);
    const deadline = BigInt(config.deadline_monotonic_ns);
    const started = monotonic();
    const prepareDeadline = started + BigInt(config.prepare_timeout_seconds) * 1000000000n;
    const report = { schema_version: 1, token: config.token, variant: config.variant, scenario: config.scenario,
        context_count: config.context_count, duration_seconds: 300, refresh_interval_seconds: 10,
        role: config.role, language: config.language, prefix: config.prefix, origin: config.origin,
        status: 'RUNNING', source_sha256: sha(fs.readFileSync(__filename)), config_sha256: sha(Buffer.from(JSON.stringify(config))),
        accounts_sha256: sha(accountsRaw), certificate_fingerprints: certificates.map(item => item.fingerprint),
        started_monotonic_ns: String(started), started_unix_ms: Date.now(), contexts: [],
        maximum_license_inflight: 0, foreign_requests: 0, secret_violations: 0, page_errors: 0,
        formal_business_performance_pass: false, complete_G7_qualified: false };
    const publish = (name, body) => {
        const raw = JSON.stringify(body, null, 2) + '\n';
        check(Buffer.byteLength(raw) <= 16 * 1024 * 1024, 'REPORT_BOUND');
        fs.writeFileSync(path.join(output, name + '.tmp'), raw, { mode: 0o600 });
        fs.renameSync(path.join(output, name + '.tmp'), path.join(output, name));
    };
    const stamp = () => ({ token: config.token, monotonic_ns: String(monotonic()), unix_ms: Date.now() });
    let interrupted = false;
    const stop = () => { interrupted = true; };
    process.on('SIGTERM', stop);
    process.on('SIGINT', stop);
    const guard = () => {
        check(!interrupted && !fs.existsSync(path.join(output, 'stop.json')), 'EXTERNAL_STOP');
        check(monotonic() < deadline, 'ABSOLUTE_DEADLINE');
    };
    const waitUntil = async due => {
        while (monotonic() < due) { guard(); await new Promise(resolve => setTimeout(resolve, 50)); }
        guard();
    };
    const control = async name => {
        while (!fs.existsSync(path.join(output, name))) { guard(); await new Promise(resolve => setTimeout(resolve, 50)); }
        const file = path.join(output, name);
        check(fs.statSync(file).size <= 4096, 'CONTROL_BOUND');
        const value = JSON.parse(fs.readFileSync(file, 'utf8'));
        check(value.token === config.token, 'CONTROL_TOKEN');
        return value;
    };
    let browser;
    let watchdogFailure = null;
    const watchdog = setInterval(() => {
        try { guard(); } catch (error) {
            if (watchdogFailure) return;
            watchdogFailure = errorCode(error);
            if (browser) browser.close().catch(() => {});
        }
    }, 100);
    let licenseInflight = 0;
    const handles = [];
    const pending = new Set();
    const tracked = new Map();
    const consume = promise => { pending.add(promise); promise.finally(() => pending.delete(promise)).catch(() => {}); };
    const isLicense = kind => ['status', 'validate', 'import', 'receipt', 'unknown_license', 'license_query_string'].includes(kind);
    const scan = text => { if (secrets.some(secret => text.includes(secret))) report.secret_violations++; };
    const entry = config.origin + config.prefix;
    async function responseAction(handle, kind, trigger) {
        const response = handle.page.waitForResponse(response => endpoint(response.url(), config.origin, config.prefix) === kind);
        response.catch(() => {});
        await trigger();
        const received = await response;
        check(await received.finished() === null, 'RESPONSE_TRANSPORT_FAILURE');
        const raw = await received.body();
        check(raw.length <= 1024 * 1024, 'RESPONSE_BOUND');
        scan(raw.toString('utf8'));
        const value = JSON.parse(raw.toString('utf8'));
        return { status: received.status(), value };
    }
    async function statusAction(handle, trigger) {
        const result = await responseAction(handle, 'status', trigger);
        check(result.status === 200 && STATUSES.has(result.value.status)
            && result.value.administrator === (config.role === 'admin'), 'STATUS_OR_ROLE_ORACLE');
        await handle.page.getByTestId('license-status').waitFor();
        check(await handle.page.getByTestId('license-status').getAttribute('data-status') === result.value.status, 'STATUS_DISPLAY_ORACLE');
        if (config.role === 'ordinary') {
            check(JSON.stringify(Object.keys(result.value).sort()) === JSON.stringify(['administrator', 'expires_at', 'status']), 'ORDINARY_RESPONSE_FIELDS');
            check(await handle.page.getByTestId('license-import-open').count() === 0
                && await handle.page.getByTestId('license-deployment').count() === 0, 'ORDINARY_DETAILS_VISIBLE');
        }
    }
    async function privacy(handle, requireEmpty) {
        const evidence = await handle.page.evaluate(({ values, requireEmpty }) => {
            const valuesIn = value => values.some(secret => String(value).includes(secret));
            return { url: valuesIn(location.href), storage: [...Object.values(localStorage), ...Object.values(sessionStorage)].some(valuesIn),
                inputs: requireEmpty && [...document.querySelectorAll('input,textarea')].some(item => valuesIn(item.value)),
                body: requireEmpty && valuesIn(document.body.innerText) };
        }, { values: secrets, requireEmpty });
        check(!Object.values(evidence).some(Boolean), 'BROWSER_SECRET_LEAK');
    }
    async function importAction(handle, event) {
        const certificate = certificates[event.sequence];
        const page = handle.page;
        const before = handle.record.network.length;
        await page.getByTestId('license-import-open').click();
        const input = page.getByTestId('license-certificate-input');
        check(await input.inputValue() === '', 'PREVIOUS_CERTIFICATE_NOT_CLEARED');
        if (event.sequence % 2) await page.getByTestId('license-certificate-file').setInputFiles(certificate.path);
        else await input.fill(certificate.text);
        await privacy(handle, false);
        const validation = await responseAction(handle, 'validate', () => page.getByTestId('license-validate').click());
        check(validation.status === 200 && validation.value.reason === 'LICENSE_VALIDATED'
            && validation.value.fingerprint === certificate.fingerprint, 'VALIDATION_ORACLE');
        check(!handle.record.network.slice(before).some(item => item.endpoint === 'import'), 'IMPORTED_BEFORE_CONFIRM');
        await page.getByTestId('license-validation').waitFor();
        const result = await responseAction(handle, 'import', () => page.getByTestId('license-confirm-import').click());
        event.import_http_status = result.status;
        check([200, 202].includes(result.status) && result.value.fingerprint === certificate.fingerprint, 'IMPORT_RESPONSE_ORACLE');
        if (result.status === 200) check(receiptApplied(result.value, certificate.fingerprint), 'APPLIED_VERSION_ORACLE');
        else check(['COMMITTED', 'UNKNOWN'].includes(result.value.submission_status), 'PENDING_RESPONSE_ORACLE');
        await page.locator('[data-testid="license-poll-status"][data-poll-status="complete"]').waitFor();
        await page.getByTestId('license-import-dialog').waitFor({ state: 'hidden' });
        event.fingerprint = certificate.fingerprint;
        event.automatic_receipt_requests = handle.record.network.slice(before).filter(item => item.endpoint === 'receipt').length;
        // Read the original receipt explicitly even after synchronous success. No resubmission.
        const queried = await responseAction(handle, 'receipt', () => page.getByTestId('license-receipt-query').click());
        check(queried.status === 200 && receiptApplied(queried.value, certificate.fingerprint), 'RECEIPT_ORACLE');
        await privacy(handle, true);
        const requests = handle.record.network.slice(before);
        check(requests.filter(item => item.endpoint === 'validate').length === 1
            && requests.filter(item => item.endpoint === 'import').length === 1, 'DUPLICATE_SUBMISSION');
    }
    try {
        guard();
        const { chromium } = require(config.playwright);
        browser = await chromium.launch({ executablePath: config.chromium, headless: true,
            chromiumSandbox: !config.allow_no_browser_sandbox,
            args: ['--disable-background-networking', ...(config.allow_no_browser_sandbox ? ['--no-sandbox'] : [])] });
        report.chromium_version = browser.version();
        report.node_version = process.version;
        // Sequential preparation preserves every context and measures its readiness; no contexts are recycled.
        for (let index = 0; index < config.context_count; index++) {
            guard(); check(monotonic() < prepareDeadline, 'PREPARATION_DEADLINE');
            const context = await browser.newContext({ viewport: { width: 1440, height: 1000 },
                locale: config.language === 'en' ? 'en-US' : 'zh-CN', timezoneId: 'UTC', serviceWorkers: 'block', acceptDownloads: false });
            const record = { context: index, phase: 'preparation', network: [], events: [], maximum_license_inflight: 0,
                created_monotonic_ns: String(monotonic()), session_established: false, context_closed: false };
            report.contexts.push(record);
            const handle = { context, record, inflight: 0, page: null };
            handles.push(handle);
            await context.addInitScript(language => {
                if (localStorage.getItem('I18N_LANGUAGE') === null) localStorage.setItem('I18N_LANGUAGE', language);
            }, config.language);
            // Observation only: no route interception, API synthesis, cache disabling, or request rewriting.
            context.on('request', request => {
                const kind = endpoint(request.url(), config.origin, config.prefix);
                scan(request.url());
                if (kind === 'foreign' || kind === 'wrong_prefix') report.foreign_requests++;
                if (record.network.length >= 3000) { record.network_overflow = true; return; }
                const item = { id: record.network.length, phase: record.phase, endpoint: kind, method: request.method(),
                    started_monotonic_ns: String(monotonic()), action: handle.action ?? null };
                if (isLicense(kind)) {
                    item.request_body_bytes = request.postDataBuffer()?.length || 0;
                    item.request_body_sha256 = request.postDataBuffer() ? sha(request.postDataBuffer()) : null;
                    handle.inflight++; licenseInflight++;
                    record.maximum_license_inflight = Math.max(record.maximum_license_inflight, handle.inflight);
                    report.maximum_license_inflight = Math.max(report.maximum_license_inflight, licenseInflight);
                }
                record.network.push(item); tracked.set(request, { item, handle, license: isLicense(kind) });
            });
            context.on('response', response => {
                const observed = tracked.get(response.request());
                if (!observed) return;
                observed.item.http_status = response.status();
                if (observed.license) consume((async () => {
                    try {
                        const bytes = await response.body();
                        check(bytes.length <= 1024 * 1024, 'RESPONSE_BOUND');
                        scan(bytes.toString('utf8'));
                        observed.item.response = safeBody(JSON.parse(bytes.toString('utf8')));
                        observed.item.response_complete = true;
                    } catch (_) { observed.item.response_complete = false; }
                })());
            });
            const finished = (request, failed) => {
                const observed = tracked.get(request);
                if (!observed || observed.item.finished_monotonic_ns) return;
                observed.item.finished_monotonic_ns = String(monotonic()); observed.item.transport_failed = failed;
                if (observed.license) { observed.handle.inflight--; licenseInflight--; }
            };
            context.on('requestfinished', request => finished(request, false));
            context.on('requestfailed', request => finished(request, true));
            const page = await context.newPage(); handle.page = page;
            page.setDefaultTimeout(config.action_timeout_seconds * 1000);
            page.on('console', message => scan(message.text()));
            page.on('pageerror', () => report.page_errors++);
            await page.goto(entry + '/login');
            await page.locator('#basic_username').fill(accounts[index].username);
            await page.locator('#basic_password').fill(accounts[index].password);
            await page.locator('button[type="submit"]').click();
            await page.waitForURL(entry + '/home');
            check((await context.cookies()).some(cookie => cookie.name === 'PALO_SESSION_ID' && cookie.httpOnly), 'COOKIE_LOGIN');
            record.session_established = true;
            check(!record.network.some(item => isLicense(item.endpoint)), 'LICENSE_REQUEST_OUTSIDE_PAGE');
            if (config.scenario !== 'other-tabs') await statusAction(handle, () => page.goto(entry + '/License'));
            record.ready_monotonic_ns = String(monotonic());
            check(monotonic() < prepareDeadline, 'PREPARATION_DEADLINE');
            publish('progress.json', { ...stamp(), created_contexts: handles.length,
                ready_contexts: handles.filter(item => item.record.ready_monotonic_ns).length, maximum_preparation_inflight: 1 });
        }
        check(browser.contexts().length === config.context_count, 'CONTEXT_COUNT_BEFORE_RELEASE');
        publish('ready.json', { ...stamp(), context_count: handles.length, all_contexts_ready: true,
            node_pid: process.pid, clock_domain: 'node_process_hrtime',
            host_boot_id: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
            preparation_concurrency: 1, source_sha256: report.source_sha256 });
        const release = await control('release.json');
        const epoch = releaseEpoch(release, config.token, process.pid, monotonic(), deadline);
        report.release = release;
        const runContext = async handle => {
            handle.record.phase = 'measurement';
            let failed = false;
            for (const planned of schedule(config.scenario)) {
                const due = epoch + BigInt(planned.offset_ms) * 1000000n;
                const event = { ...planned, status: 'NOT_SENT', scheduled_monotonic_ns: String(due) };
                handle.record.events.push(event);
                if (failed) continue;
                try {
                    await waitUntil(due);
                    handle.action = planned.sequence;
                    const at = monotonic(); event.started_monotonic_ns = String(at);
                    event.queue_ms = Number(at - due) / 1e6;
                    const remaining = Number(epoch + 300000000000n - at) / 1e6;
                    check(remaining > 0, 'WINDOW_ENDED_BEFORE_ACTION');
                    handle.page.setDefaultTimeout(Math.max(1, Math.min(config.action_timeout_seconds * 1000, remaining)));
                    await boundedOperation((async () => {
                        if (planned.kind === 'refresh') await statusAction(handle, () => handle.page.getByTestId('license-refresh').click());
                        else if (planned.kind === 'import') await importAction(handle, event);
                        else await handle.page.goto(entry + '/' + planned.route);
                    })(), Math.min(config.action_timeout_seconds * 1000, remaining), () => handle.page.close());
                    check(monotonic() <= epoch + 300000000000n, 'ACTION_AFTER_WINDOW');
                    event.status = 'PASS';
                } catch (error) { event.status = 'FAIL'; event.failure_code = errorCode(error); failed = true; }
                finally {
                    event.finished_monotonic_ns = String(monotonic());
                    event.e2e_ms = Number(BigInt(event.finished_monotonic_ns) - due) / 1e6;
                    handle.action = null;
                }
            }
            await waitUntil(epoch + 300000000000n);
            handle.record.held_through_monotonic_ns = String(monotonic());
            handle.record.phase = 'holding';
        };
        const results = await Promise.allSettled(handles.map(runContext));
        check(results.every(item => item.status === 'fulfilled'), 'WINDOW_INTERRUPTED');
        check(browser.contexts().length === config.context_count, 'CONTEXT_EXITED_DURING_WINDOW');
        await Promise.allSettled([...pending]);
        report.summary = summary(report.contexts);
        for (const handle of handles) {
            const record = handle.record;
            const measured = record.network.filter(item => item.phase === 'measurement' && isLicense(item.endpoint));
            if (config.scenario === 'details') check(measured.length === 30 && measured.every(item => item.endpoint === 'status'
                && item.http_status === 200 && item.response_complete && !item.transport_failed), 'DETAILS_REQUEST_COUNT_OR_RESULT');
            if (config.scenario === 'other-tabs') check(!record.network.some(item => isLicense(item.endpoint)), 'OTHER_TABS_LICENSE_REQUEST');
            check(!record.network_overflow && record.maximum_license_inflight <= 1, 'CONTEXT_REQUEST_CONCURRENCY');
        }
        check(report.summary.actions_failed === 0 && report.summary.actions_not_sent === 0, 'ACTION_WINDOW_FAILED');
        check(report.foreign_requests === 0 && report.secret_violations === 0 && report.page_errors === 0, 'BROWSER_ERROR_OR_LEAK');
        report.measurement_status = 'PASS';
        publish('done.json', { ...stamp(), status: 'BROWSER_WINDOW_PASS', all_contexts_alive: true,
            context_count: handles.length, summary: report.summary });
        await control('finish.json');
        check(!report.contexts.some(record => record.network.some(item => item.phase === 'holding'
            && isLicense(item.endpoint))), 'UNEXPECTED_IDLE_LICENSE_REQUEST');
        for (const handle of handles) {
            handle.record.phase = 'after_unmount';
            await handle.page.goto(entry + '/Configuration');
            const unmounted = monotonic();
            await waitUntil(unmounted + 2000000000n);
            check(!handle.record.network.some(item => isLicense(item.endpoint)
                && BigInt(item.started_monotonic_ns) >= unmounted), 'REQUEST_AFTER_UNMOUNT');
            await privacy(handle, true);
        }
        check(!watchdogFailure, watchdogFailure || 'WATCHDOG_FAILURE');
        report.status = 'PASS';
    } catch (error) {
        report.status = 'FAIL'; report.failure_code = watchdogFailure || errorCode(error);
        if (!fs.existsSync(path.join(output, 'done.json'))) publish('done.json', { ...stamp(), status: 'BROWSER_WINDOW_FAILED', failure_code: report.failure_code });
    } finally {
        clearInterval(watchdog);
        for (const handle of handles) {
            handle.record.phase = 'cleanup';
            try {
                if (handle.record.session_established) {
                    const response = await handle.context.request.post(entry + '/rest/v1/logout', { timeout: 5000 });
                    const value = await response.json();
                    check(response.status() === 200 && value.code === 0, 'LOGOUT_FAILED');
                    handle.record.logout_confirmed = true;
                }
            } catch (_) { handle.record.logout_confirmed = false; report.status = 'FAIL'; }
            try { await boundedOperation(handle.context.close(), 5000, () => {}); handle.record.context_closed = true; }
            catch (_) { report.status = 'FAIL'; }
        }
        try { if (browser) await boundedOperation(browser.close(), 5000, () => {}); report.browser_closed = true; }
        catch (_) { report.browser_closed = false; report.status = 'FAIL'; }
        await Promise.allSettled([...pending]);
        report.finished_monotonic_ns = String(monotonic()); report.finished_unix_ms = Date.now();
        report.summary = summary(report.contexts);
        publish('terminal.json', report);
        process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
    }
    return report.status === 'PASS' ? 0 : 2;
}
module.exports = { validateConfig, schedule, endpoint, receiptApplied, safeBody, summary, errorCode, secretFile, releaseEpoch, boundedOperation, run };
if (require.main === module) {
    (async () => {
        check(process.argv.length === 3, 'ONE_CONFIG_REQUIRED');
        const raw = secretFile(process.argv[2], 65536);
        process.exitCode = await run(JSON.parse(raw.toString('utf8')));
    })().catch(error => { process.stderr.write(errorCode(error) + '\n'); process.exitCode = 2; });
}
