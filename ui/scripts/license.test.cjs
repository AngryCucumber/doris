// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

// Browser contract tests against the production bundle and deliberately controlled API responses.
// These fixtures do not issue certificates or prove FE authorization, persistence, or signature checks.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const ts = require('typescript');
const { chromium } = require('playwright');

const dist = path.resolve(process.env.MASSDB_LICENSE_TEST_DIST || path.join(__dirname, '../dist'));
const artifacts = path.resolve(process.env.MASSDB_LICENSE_TEST_ARTIFACTS
    || path.join(__dirname, '../../.build-records/license-p2u-20260929/tests/browser'));
const CANARY = 'P2U_BROWSER_ONLY_CERTIFICATE_CANARY';
const certificate = `${CANARY}.mock_payload.mock_signature`;
const fingerprint = input => crypto.createHash('sha256').update(input).digest('hex');
const expectedFingerprint = fingerprint(certificate);
const fixedEpoch = 1790683200;
const selectedCases = process.env.MASSDB_LICENSE_TEST_CASES
    ? new Set(process.env.MASSDB_LICENSE_TEST_CASES.split(',')) : null;

test('P2U independent SHA-256 and lossless receipt-version oracles', () => {
    const source = fs.readFileSync(path.join(__dirname, '../src/pages/license/model.ts'), 'utf8');
    const compiled = ts.transpileModule(source, { compilerOptions: {
        target: ts.ScriptTarget.ES2019, module: ts.ModuleKind.CommonJS,
    } }).outputText;
    const exports = {};
    vm.runInNewContext(compiled, { exports, TextEncoder, Uint8Array, DataView, Int32Array, Date, Number });
    const vectors = ['', 'abc', ' leading and trailing whitespace\r\n', '证书内容🙂é',
        ...[55, 56, 63, 64, 65, 65536].map(size => 'a'.repeat(size)), 'é'.repeat(32768)];
    for (const value of vectors) {
        assert.equal(exports.certificateFingerprint(value), fingerprint(value),
            `SHA-256 oracle mismatch for ${Buffer.byteLength(value)} UTF-8 bytes`);
        assert.equal(exports.utf8Bytes(value).length, Buffer.byteLength(value));
    }
    assert.equal(exports.appliedReceipt(receipt('APPLIED', {
        committed_version: '9007199254740993', applied_version: '9007199254740992',
    })), false, 'adjacent signed-64-bit versions above JS safe integer must remain distinct');
    assert.equal(exports.appliedReceipt(receipt('APPLIED', {
        committed_version: '9007199254740993', applied_version: '9007199254740993',
    })), true);
    assert.equal(exports.appliedReceipt(receipt('APPLIED', {
        committed_version: '9223372036854775806', applied_version: '9223372036854775807',
    })), true);
    for (const value of [receipt('COMMITTED'), receipt('UNKNOWN'), receipt('APPLIED', { committed_version: 0 }),
        receipt('APPLIED', { applied_version: null }), receipt('APPLIED', { applied_version: 'unknown' })]) {
        assert.equal(exports.appliedReceipt(value), false, 'only a valid APPLIED version pair is complete');
    }
});

function details(sequence = 11) {
    return {
        license_id: `browser-license-${sequence}`, fingerprint: expectedFingerprint,
        customer_id: `private-customer-${sequence}`, issuer: 'browser-test-issuer', edition: 'Enterprise',
        sequence, not_before: fixedEpoch - 86400, expires_at: fixedEpoch + 86400,
        max_fe_nodes: 4, max_be_nodes: 8, features: ['QUERY'],
    };
}

function snapshot(status = 'VALID', administrator = true) {
    if (!administrator) return { status, administrator: false, expires_at: fixedEpoch + 86400 };
    return {
        status, administrator: true, expires_at: fixedEpoch + 86400,
        deployment_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', activated: true, recovery_ready: true,
        reasons: status === 'VALID' ? [] : [status], warnings: [], trusted_utc: fixedEpoch,
        clock_epoch: 2, registered_fe_nodes: 2, registered_be_nodes: 3,
        max_fe_nodes: 4, max_be_nodes: 8, base_max_fe_nodes: 4, base_max_be_nodes: 8,
        active: details(), pending: null, highest_sequence: 11, applied_version: 18,
    };
}

function receipt(submission = 'APPLIED', options = {}) {
    return {
        reason: submission === 'APPLIED' ? 'LICENSE_APPLIED' : submission === 'COMMITTED'
            ? 'LICENSE_COMMITTED_PENDING_APPLY' : 'LICENSE_COMMIT_UNCERTAIN',
        submission_status: submission, fingerprint: expectedFingerprint,
        committed_version: submission === 'UNKNOWN' ? 0 : 19,
        applied_version: submission === 'APPLIED' ? 19 : 18,
        retryable: submission !== 'APPLIED', ...options,
    };
}

function errorBody(reason, submission = 'NOT_SUBMITTED', options = {}) {
    return { reason, message: reason, retryable: false, submission_status: submission,
        committed_version: 0, applied_version: 18, ...options };
}

async function eventually(condition, description, timeout = 10000) {
    const deadline = performance.now() + timeout;
    while (performance.now() < deadline) {
        if (await condition()) return;
        await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.fail(description);
}

async function fixture(browser, name, options = {}) {
    const prefix = options.prefix || '';
    const model = {
        status: snapshot(), statusCode: 200,
        validate: { status: 200, body: { ...receipt('NOT_SUBMITTED'), reason: 'LICENSE_VALIDATED',
            committed_version: 0, coverage_gap_seconds: 0, expected_license_version: 18,
            expected_membership_version: 3, idempotent: false } },
        imported: { status: 200, body: receipt() },
        received: { status: 200, body: receipt() },
        requests: [], activeReceipts: 0, maxActiveReceipts: 0, releaseReceipt: null,
        holdReceipt: false, closedReceipts: 0, holdStatus: false, releaseStatus: null,
        holdImport: false, releaseImport: null,
    };
    const server = http.createServer(async (request, response) => {
        try {
            const url = new URL(request.url, 'http://unused');
            let pathname = decodeURIComponent(url.pathname);
            if (prefix && !pathname.startsWith(prefix + '/')) {
                response.writeHead(404); response.end('wrong proxy prefix'); return;
            }
            pathname = pathname.slice(prefix.length);
            if (pathname.startsWith('/api/license')) {
                const chunks = [];
                for await (const chunk of request) chunks.push(chunk);
                const raw = Buffer.concat(chunks).toString('utf8');
                let submitted;
                try { submitted = raw && JSON.parse(raw); } catch (_) { submitted = undefined; }
                const record = { path: pathname, method: request.method, query: url.search,
                    bodyBytes: Buffer.byteLength(raw), headers: request.headers,
                    certificate: submitted && submitted.certificate, started: performance.now() };
                model.requests.push(record);
                const isReceipt = pathname.startsWith('/api/license/imports/');
                const requestedStatus = JSON.parse(JSON.stringify(model.status));
                if (pathname === '/api/license' && model.holdStatus) {
                    await new Promise(resolve => { model.releaseStatus = resolve; });
                }
                if (pathname === '/api/license/import' && model.holdImport) {
                    await new Promise(resolve => { model.releaseImport = resolve; });
                }
                if (isReceipt) {
                    model.activeReceipts++;
                    model.maxActiveReceipts = Math.max(model.maxActiveReceipts, model.activeReceipts);
                    let finished = false;
                    const finish = () => {
                        if (finished) return;
                        finished = true;
                        model.activeReceipts--;
                        if (!response.writableEnded) model.closedReceipts++;
                    };
                    response.on('close', finish);
                    response.on('finish', finish);
                    if (model.holdReceipt) await new Promise(resolve => { model.releaseReceipt = resolve; });
                }
                let answer = pathname === '/api/license' ? { status: model.statusCode, body: requestedStatus }
                    : pathname.endsWith('/validate') ? model.validate
                    : pathname.endsWith('/import') ? model.imported
                    : isReceipt ? model.received
                    : { status: 404, body: errorBody('NOT_FOUND') };
                if (typeof answer === 'function') answer = answer(record);
                if (answer.disconnect) { response.destroy(); return; }
                if (response.destroyed) return;
                response.writeHead(answer.status, { 'Content-Type': 'application/json',
                    'Cache-Control': 'no-store', ...answer.headers });
                if (answer.partial) {
                    response.flushHeaders();
                    response.write('{"submission_status":"COMMITTED",');
                    setTimeout(() => response.destroy(), 50);
                    return;
                }
                response.end(answer.rawBody || JSON.stringify(answer.body));
                return;
            }
            if (pathname.startsWith('/rest/') || pathname.startsWith('/api/')) {
                let data = { column_names: [], rows: [] };
                if (pathname.includes('/hardware_info/')) data = { VersionInfo: {}, HardwareInfo: {} };
                if (pathname.endsWith('/databases')) data = ['information_schema'];
                response.writeHead(200, { 'Content-Type': 'application/json' });
                response.end(JSON.stringify({ code: pathname.endsWith('/login') ? 200 : 0,
                    msg: 'success', data }));
                return;
            }
            let file = path.resolve(dist, '.' + pathname);
            if (!file.startsWith(dist + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
                file = path.join(dist, 'index.html');
            }
            const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css',
                '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain' };
            response.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' });
            response.end(fs.readFileSync(file));
        } catch (_) {
            if (!response.headersSent) response.writeHead(500);
            if (!response.destroyed) response.end('fixture failed');
        }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const host = options.insecure ? 'massdb-p2u.test' : '127.0.0.1';
    const origin = `http://${host}:${server.address().port}`;
    const context = await browser.newContext({ viewport: options.viewport || { width: 1440, height: 1000 },
        timezoneId: 'Asia/Shanghai' });
    await context.addInitScript(({ authenticated, language }) => {
        if (!localStorage.getItem('p2u_browser_initialized')) {
            if (authenticated) localStorage.setItem('username', 'p2u-browser-admin');
            localStorage.setItem('I18N_LANGUAGE', language);
            localStorage.setItem('p2u_browser_initialized', '1');
        }
        window.__licenseRequests = [];
        const originalFetch = window.fetch;
        window.fetch = function(resource, init) {
            const url = typeof resource === 'string' ? resource : resource.url;
            const item = { path: new URL(url, location.href).pathname,
                method: (init && init.method) || 'GET', started: performance.now(), ended: null };
            if (item.path.includes('/api/license')) window.__licenseRequests.push(item);
            return originalFetch.apply(this, arguments).then(response => {
                item.ended = performance.now(); item.status = response.status; return response;
            }, error => { item.ended = performance.now(); item.error = error.name; throw error; });
        };
    }, { authenticated: options.authenticated !== false, language: options.language || 'en' });
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const consoleText = [], errors = [], urls = [];
    page.on('console', message => consoleText.push(message.text()));
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => urls.push(request.url()));
    const id = value => page.getByTestId(value);
    const count = suffix => model.requests.filter(record => record.path === '/api/license' + suffix).length;
    const receipts = () => model.requests.filter(record => record.path.startsWith('/api/license/imports/'));
    const enter = async () => {
        await page.goto(origin + prefix + '/License');
        await id('license-status').waitFor();
    };
    const open = async input => {
        await id('license-import-open').click();
        await id('license-certificate-input').fill(input === undefined ? certificate : input);
    };
    const validate = async () => {
        await id('license-validate').click();
        await id('license-validation').waitFor();
    };
    const confirm = async () => {
        const importsBefore = count('/import');
        await id('license-confirm-import').click({ force: true });
        await eventually(() => count('/import') > importsBefore, 'confirm must make a new import request');
        await id('license-receipt').waitFor();
        await eventually(async () => await page.evaluate(() => {
            const records = window.__licenseRequests.filter(r => r.path.endsWith('/api/license/import'));
            const record = records[records.length - 1];
            return record && record.ended !== null;
        }), 'import response must finish or fail');
        await new Promise(resolve => setTimeout(resolve, 40));
    };
    const stopSecrets = async () => {
        assert.ok(!urls.some(url => url.includes(CANARY)), 'certificate must never enter request/navigation URLs');
        const storage = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
        assert.ok(!storage.includes(CANARY), 'certificate must never enter browser storage');
        assert.ok(!consoleText.some(text => text.includes(CANARY)), 'certificate must never enter the console');
        assert.ok(!errors.some(text => text.includes(CANARY)), 'certificate must never enter uncaught errors');
        assert.deepEqual(errors, [], 'License scenarios must not produce uncaught browser errors');
    };
    const clock = async () => {
        await page.clock.install({ time: new Date(fixedEpoch * 1000) });
        await page.clock.pauseAt(new Date(fixedEpoch * 1000 + 1000));
    };
    const advance = async milliseconds => {
        await page.clock.runFor(milliseconds);
        // Network responses and React promise callbacks use the real event loop, not the virtual clock.
        await new Promise(resolve => setTimeout(resolve, 40));
    };
    return { model, page, context, id, count, receipts, enter, open, validate, confirm,
        stopSecrets, clock, advance, origin, prefix,
        async close() {
            if (model.releaseReceipt) model.releaseReceipt();
            if (model.releaseStatus) model.releaseStatus();
            if (model.releaseImport) model.releaseImport();
            const trace = await page.evaluate(() => window.__licenseRequests || []).catch(() => []);
            fs.mkdirSync(artifacts, { recursive: true });
            fs.writeFileSync(path.join(artifacts, name + '.json'), JSON.stringify({ name,
                proofScope: 'production UI bundle / real Chromium / controlled mock API',
                requests: model.requests.map(({ path, method, query, bodyBytes, certificate: value }) => ({
                    path, method, query, bodyBytes, certificateSha256: value ? fingerprint(value) : null,
                })), browserTiming: trace, maxActiveReceipts: model.maxActiveReceipts,
                closedReceipts: model.closedReceipts, measurements: model.measurements,
                uncaughtErrors: errors }, null, 2));
            await context.close();
            server.closeAllConnections();
            await new Promise(resolve => server.close(resolve));
        } };
}

test('P2U License browser contracts (controlled API, not FE integration)', { timeout: 300000 }, async t => {
    assert.ok(fs.existsSync(path.join(dist, 'index.html')), 'build the UI before running License tests');
    fs.mkdirSync(artifacts, { recursive: true });
    const browser = await chromium.launch({ headless: true, args: [
        '--host-resolver-rules=MAP massdb-p2u.test 127.0.0.1', '--no-proxy-server',
    ] });
    const executedCases = new Set();
    const run = async (name, body, options) => {
        if (selectedCases && !selectedCases.has(name)) return;
        executedCases.add(name);
        return t.test(name, async () => {
            const f = await fixture(browser, name, options);
            try { await body(f); await f.stopSecrets(); } finally { await f.close(); }
        });
    };
    try {
        for (const prefix of ['', '/proxy/fe', '/gateway/cluster/fe/default']) {
            await run('U01-navigation-' + (prefix.replaceAll('/', '-') || 'root'), async f => {
                await f.page.goto(f.origin + prefix + '/home');
                await f.page.locator('header').waitFor();
                assert.equal(f.count(''), 0, 'Home must not load license details');
                for (const tab of ['/System?path=/', '/QueryProfile', '/Session', '/Playground']) {
                    await f.page.goto(f.origin + prefix + tab);
                    await f.page.locator('header').waitFor();
                    assert.equal(f.model.requests.length, 0, `${tab} must not call license APIs`);
                }
                await f.page.getByRole('menuitem', { name: 'Configuration', exact: true }).click();
                await f.page.waitForURL(f.origin + prefix + '/Configuration');
                assert.equal(f.model.requests.length, 0, 'other tabs must not call license APIs');
                await f.id('license-tab').click();
                await f.id('license-status').waitFor();
                assert.equal(f.count(''), 1, 'entering License must issue exactly one status GET');
                assert.match(await f.id('license-tab').getAttribute('class'), /ant-menu-item-selected/);
                const menu = await f.page.getByRole('menuitem').allTextContents();
                assert.equal(menu.indexOf('License'), menu.indexOf('Configuration') + 1);
                await f.page.reload();
                await f.id('license-status').waitFor();
                assert.equal(f.count(''), 2, 'reload must issue exactly one new status GET');
                await f.page.getByRole('menuitem', { name: 'Configuration', exact: true }).click();
                await f.page.goBack();
                await f.id('license-status').waitFor();
                assert.match(await f.id('license-tab').getAttribute('class'), /ant-menu-item-selected/);
                await f.page.goForward();
                await f.page.waitForURL(f.origin + prefix + '/Configuration');
                assert.doesNotMatch(await f.id('license-tab').getAttribute('class'), /ant-menu-item-selected/);
                const beforeLanguage = f.count('');
                await f.id('license-tab').click();
                await f.id('license-status').waitFor();
                await f.page.getByRole('button', { name: '中文', exact: true }).click();
                await f.id('license-status').waitFor();
                await eventually(() => f.count('') === beforeLanguage + 2, 'language reload must make one details GET');
                assert.match(await f.id('license-tab').innerText(), /证书/);
                if (!prefix) await f.page.screenshot({ path: path.join(artifacts, 'license-zh-desktop.png'), fullPage: true });
                await f.page.getByRole('button', { name: 'English', exact: true }).click();
                await f.id('license-status').waitFor();
                assert.equal(await f.id('license-tab').innerText(), 'License');
                await f.page.screenshot({ path: path.join(artifacts, 'license' + (prefix.replaceAll('/', '-') || '-root') + '.png'), fullPage: true });
            }, { prefix });
        }

        await run('U01-existing-login-boundary', async f => {
            await f.page.goto(f.origin + '/License');
            await f.page.waitForURL(f.origin + '/login');
            assert.equal(f.model.requests.length, 0, 'unauthenticated routing must not call license APIs');
            await f.page.locator('#basic_username').fill('p2u-browser-admin');
            await f.page.getByRole('button', { name: 'Login', exact: true }).click();
            await f.page.waitForURL(f.origin + '/home');
            await f.id('license-tab').click();
            await f.id('license-status').waitFor();
            assert.equal(f.count(''), 1);
        }, { authenticated: false });

        await run('U01-other-tab-remains-free-of-license-work', async f => {
            await f.page.goto(f.origin + '/Configuration');
            await f.page.getByRole('heading', { name: 'Configure Info', exact: true }).waitFor();
            await f.clock(); await f.advance(300000);
            assert.equal(f.model.requests.length, 0, 'five virtual idle minutes outside License must do no license work');
        });

        for (const language of ['en', 'zh-CN']) {
            await run('U01-narrow-layout-' + language, async f => {
                await f.enter();
                assert.ok(await f.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
                    'license details must fit a narrow viewport');
                const heading = await f.id('license-page').locator('h1').boundingBox();
                const headerBottom = await f.page.locator('header').evaluate(header => Math.max(...[header,
                    ...header.querySelectorAll('*')].filter(element => {
                    const style = getComputedStyle(element);
                    const rect = element.getBoundingClientRect();
                    return style.visibility !== 'hidden' && style.display !== 'none'
                        && !element.closest('[aria-hidden="true"]') && rect.width > 0 && rect.height > 0;
                }).map(element => element.getBoundingClientRect().bottom)));
                f.model.measurements = { viewportWidth: 375, heading, visibleHeaderBottom: headerBottom };
                assert.ok(heading.y >= headerBottom, 'wrapped navigation must not obscure the License title');
                await f.page.screenshot({ path: path.join(artifacts, `license-${language}-375.png`), fullPage: true });
            }, { language, viewport: { width: 375, height: 1000 } });
        }

        await run('U04-server-state-and-browser-clock', async f => {
            f.model.status.pending = { ...details(12), not_before: fixedEpoch + 3600, expires_at: fixedEpoch + 172800 };
            await f.enter();
            assert.match(await f.id('license-active').innerText(), /private-customer-11/);
            assert.match(await f.id('license-pending').innerText(), /private-customer-12/);
            assert.match(await f.id('license-fe-usage').innerText(), /2\s*\/\s*4/);
            assert.match(await f.id('license-be-usage').innerText(), /3\s*\/\s*8/);
            const detail = await f.id('license-active').innerText();
            assert.match(detail, /2026-09-30/);
            assert.match(detail, /UTC/);
            await f.page.clock.setFixedTime(new Date('2049-01-01T00:00:00Z'));
            assert.equal(await f.id('license-status').getAttribute('data-status'), 'VALID');
            for (const status of ['EXPIRED', 'LICENSE_NOT_READY', 'LIMIT_EXCEEDED', 'CLOCK_SUSPECT', 'MISSING']) {
                f.model.status = snapshot(status);
                await f.id('license-refresh').click();
                await eventually(async () => (await f.id('license-status').getAttribute('data-status')) === status,
                    'UI must display the server-provided license state');
            }
            await f.page.clock.setFixedTime(new Date('2000-01-01T00:00:00Z'));
            assert.equal(await f.id('license-status').getAttribute('data-status'), 'MISSING');
            const reads = f.count('');
            await f.clock(); await f.advance(300000);
            assert.equal(f.count(''), reads, 'idle details page must never refresh automatically');
        });

        await run('U04-role-change-clears-private-details', async f => {
            await f.enter();
            await f.open(); await f.validate();
            f.model.status = snapshot('EXPIRED', false);
            await f.id('license-import-cancel').click();
            await f.id('license-refresh').click();
            await eventually(async () => await f.id('license-import-open').count() === 0,
                'ordinary user must not see the import action');
            assert.equal(await f.id('license-active').count(), 0);
            assert.equal(await f.id('license-pending').count(), 0);
            assert.ok(!(await f.page.locator('body').innerText()).includes('private-customer-11'));
            assert.equal(await f.id('license-confirm-import').count(), 0);
            f.model.status = snapshot();
            await f.id('license-refresh').click();
            await f.id('license-import-open').waitFor();
            await f.id('license-import-open').click();
            assert.equal(await f.id('license-certificate-input').inputValue(), '');
            assert.equal(await f.id('license-validation').count(), 0);
        });

        await run('U04-late-admin-response-after-session-change', async f => {
            await f.enter();
            f.model.holdStatus = true;
            await f.id('license-refresh').click();
            await eventually(() => f.model.releaseStatus !== null, 'old administrator request must be in flight');
            await f.page.evaluate(() => {
                localStorage.setItem('username', 'p2u-browser-reader');
                window.dispatchEvent(new StorageEvent('storage', { key: 'username', newValue: 'p2u-browser-reader' }));
            });
            f.model.releaseStatus();
            await new Promise(resolve => setTimeout(resolve, 100));
            assert.equal(await f.id('license-active').count(), 0, 'late previous-role response must never restore details');
            assert.equal(await f.id('license-import-open').count(), 0);
            f.model.holdStatus = false;
            f.model.status = snapshot('VALID', false);
            await f.id('license-refresh').click();
            await f.id('license-status').waitFor();
            assert.equal(await f.id('license-active').count(), 0);
        });

        await run('U02-late-file-read-after-close-and-session-change', async f => {
            await f.enter();
            await f.page.evaluate(() => {
                const Reader = window.FileReader;
                window.FileReader = class extends Reader {
                    readAsArrayBuffer(file) {
                        window.__releaseLicenseFile = () => super.readAsArrayBuffer(file);
                    }
                };
            });
            await f.id('license-import-open').click();
            await f.id('license-certificate-file').setInputFiles({ name: 'delayed.txt', mimeType: 'text/plain',
                buffer: Buffer.from(certificate) });
            await f.id('license-import-cancel').click();
            await f.id('license-import-open').click();
            await f.id('license-certificate-input').fill('replacement-input');
            await f.page.evaluate(() => window.__releaseLicenseFile());
            await new Promise(resolve => setTimeout(resolve, 100));
            assert.equal(await f.id('license-certificate-input').inputValue(), 'replacement-input',
                'a late file read must never restore a closed certificate input');
            await f.page.evaluate(() => {
                localStorage.setItem('username', 'p2u-browser-reader');
                window.dispatchEvent(new StorageEvent('storage', { key: 'username', newValue: 'p2u-browser-reader' }));
            });
            await f.id('license-import-dialog').waitFor({ state: 'hidden' });
            assert.equal(await f.id('license-active').count(), 0);
            f.model.status = snapshot();
            await f.id('license-refresh').click();
            await f.id('license-import-open').click();
            assert.equal(await f.id('license-certificate-input').inputValue(), '');
        });

        await run('U02-logout-clears-an-open-certificate', async f => {
            await f.enter(); await f.open(); await f.validate();
            const otherTab = await f.context.newPage();
            await otherTab.goto(f.origin + '/home');
            await otherTab.locator('.ant-dropdown-link').hover();
            await otherTab.getByText('Sign out', { exact: true }).click();
            await otherTab.waitForURL(f.origin + '/login');
            await f.id('license-import-dialog').waitFor({ state: 'hidden' });
            assert.equal(await f.id('license-certificate-input').count(), 0);
            assert.equal(await f.page.evaluate(() => localStorage.getItem('username')), null);
            assert.equal(await f.id('license-active').count(), 0);
            await otherTab.close();
        });

        await run('U02-text-validate-confirm-and-sensitive-lifetime', async f => {
            await f.enter(); await f.open();
            assert.equal(f.count('/import'), 0);
            assert.equal(await f.id('license-confirm-import').isEnabled(), false, 'no import before validation');
            await f.validate();
            assert.equal(f.count('/import'), 0, 'validation must not persist');
            assert.equal(f.count('/validate'), 1);
            assert.ok(f.model.requests.find(r => r.path.endsWith('/validate')).certificate === certificate,
                'validation must preserve exact certificate bytes');
            await f.id('license-certificate-input').fill(certificate + 'edited');
            assert.equal(await f.id('license-confirm-import').isEnabled(), false, 'editing invalidates prior validation');
            await f.id('license-certificate-input').fill(certificate);
            await f.validate();
            await f.confirm();
            await f.id('license-import-dialog').waitFor({ state: 'hidden' });
            assert.equal(f.count('/import'), 1, 'confirmation submits once');
            for (const request of f.model.requests.filter(r => r.method === 'POST')) {
                assert.equal(request.headers['x-massdb-license-csrf'], '1');
                assert.equal(request.query, '');
                assert.ok(request.certificate === certificate, 'POST is the sole intended certificate transport');
            }
            await f.id('license-import-open').click();
            assert.equal(await f.id('license-certificate-input').inputValue(), '', 'success clears temporary input');
            await f.id('license-certificate-input').fill(certificate);
            await f.id('license-import-cancel').click();
            await f.id('license-import-open').click();
            assert.equal(await f.id('license-certificate-input').inputValue(), '', 'closing clears temporary input');
        });

        await run('U02-file-utf8-limit-and-invalid-preserves-active', async f => {
            await f.enter(); await f.id('license-import-open').click();
            await f.id('license-certificate-file').setInputFiles({ name: 'license.txt', mimeType: 'text/plain',
                buffer: Buffer.from(certificate) });
            await eventually(async () => await f.id('license-certificate-input').inputValue() === certificate,
                'UTF-8 file must populate temporary input');
            await f.validate();
            assert.equal(f.count('/validate'), 1);
            await f.id('license-certificate-input').fill('é'.repeat(32769));
            const before = f.count('/validate');
            if (await f.id('license-validate').isEnabled()) await f.id('license-validate').click();
            assert.equal(f.count('/validate'), before, 'limit is 64 KiB UTF-8 bytes, not character count');
            await f.id('license-certificate-file').setInputFiles({ name: 'too-large.txt', mimeType: 'text/plain',
                buffer: Buffer.alloc(65537, 65) });
            assert.equal(f.count('/validate'), before, 'oversized file must never reach API');
            await f.id('license-certificate-file').setInputFiles({ name: 'invalid-utf8.txt', mimeType: 'text/plain',
                buffer: Buffer.from([0xc3, 0x28]) });
            await eventually(async () => (await f.id('license-error').innerText()).includes('LICENSE_INVALID_FILE'),
                'invalid UTF-8 must not be replaced or silently accepted');
            assert.equal(f.count('/validate'), before);
            await f.id('license-certificate-input').fill(certificate);
            f.model.validate = { status: 400, body: errorBody('LICENSE_INVALID_SIGNATURE', 'NOT_SUBMITTED',
                { message: certificate }) };
            await f.id('license-validate').click();
            await f.id('license-error').waitFor();
            assert.ok(!(await f.id('license-error').innerText()).includes(CANARY), 'untrusted server messages must not echo input');
            assert.equal(f.count('/import'), 0);
            await f.id('license-import-cancel').click();
            assert.equal(await f.id('license-status').getAttribute('data-status'), 'VALID');
            assert.match(await f.id('license-active').innerText(), /browser-license-11/);
        });

        await run('U02-insecure-http-sha256-and-boundary', async f => {
            await f.enter();
            assert.equal(await f.page.evaluate(() => isSecureContext), false);
            assert.equal(await f.page.evaluate(() => typeof crypto.subtle), 'undefined');
            const exactLimit = 'é'.repeat(32768);
            f.model.validate.body.fingerprint = fingerprint(exactLimit);
            f.model.imported = { disconnect: true };
            await f.open(exactLimit); await f.validate(); await f.confirm();
            assert.equal(f.count('/validate'), 1, 'exactly 64 KiB must be accepted for server validation');
            assert.ok(f.model.requests.find(r => r.path.endsWith('/import')).certificate === exactLimit);
            assert.equal(await f.id('license-receipt-fingerprint').inputValue(), fingerprint(exactLimit),
                'non-secure HTTP fallback must match independent Node SHA-256 including UTF-8');
        }, { insecure: true });

        await run('U03-exact-backoff-monotonic-budget', async f => {
            f.model.imported = { status: 202, body: receipt('COMMITTED') };
            f.model.received = { status: 202, body: receipt('COMMITTED') };
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            const initial = await f.page.evaluate(() => performance.now());
            const expected = [2000, 6000, 14000, 30000, 60000, 90000];
            let elapsed = 0;
            for (let index = 0; index < expected.length; index++) {
                await f.advance(expected[index] - elapsed - 1);
                assert.equal(f.receipts().length, index, 'no receipt request before its deadline');
                await f.advance(1);
                await eventually(() => f.receipts().length === index + 1, 'receipt request must run at backoff deadline');
                await eventually(() => f.model.activeReceipts === 0, 'receipt request must finish before next delay');
                elapsed = expected[index];
            }
            await f.page.clock.setFixedTime(new Date('1990-01-01T00:00:00Z'));
            await f.advance(30000);
            assert.equal(f.receipts().length, 6, '120 second budget disallows a request starting at its deadline');
            await f.advance(300000);
            assert.equal(f.receipts().length, 6, 'budget exhaustion must remain stopped');
            assert.equal(f.model.maxActiveReceipts, 1);
            assert.equal(f.count('/import'), 1, 'polling must never resubmit');
            const trace = await f.page.evaluate(() => window.__licenseRequests.filter(r => r.path.includes('/imports/')));
            assert.deepEqual(trace.map(item => Math.round(item.started - initial)), expected,
                'poll deadlines must use monotonic time despite wall-clock changes');
            await f.id('license-receipt-query').click();
            await eventually(() => f.receipts().length === 7, 'explicit manual receipt query remains available');
            await f.advance(300000);
            assert.equal(f.receipts().length, 7, 'manual query must not restart automatic polling');
        });

        await run('U03-polling-is-serial-and-aborts-inflight', async f => {
            f.model.imported = { status: 202, body: receipt('COMMITTED') };
            f.model.received = { status: 202, body: receipt('COMMITTED') };
            f.model.holdReceipt = true;
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            await f.advance(2000);
            await eventually(() => f.receipts().length === 1, 'first receipt must start');
            await f.advance(20000);
            assert.equal(f.receipts().length, 1, 'slow receipt must never overlap another request');
            assert.equal(f.model.maxActiveReceipts, 1);
            await f.page.getByRole('menuitem', { name: 'Configuration', exact: true }).click();
            await eventually(() => f.model.closedReceipts === 1, 'leaving page must abort in-flight receipt');
            f.model.releaseReceipt();
            await f.advance(300000);
            assert.equal(f.receipts().length, 1);
        });

        await run('U03-budget-aborts-final-inflight-request', async f => {
            f.model.imported = { status: 202, body: receipt('COMMITTED') };
            f.model.received = { status: 202, body: receipt('COMMITTED') };
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            for (const delay of [2000, 4000, 8000, 16000, 30000]) {
                const count = f.receipts().length;
                await f.advance(delay);
                await eventually(() => f.receipts().length === count + 1 && f.model.activeReceipts === 0,
                    'each completed request starts the next backoff');
            }
            f.model.holdReceipt = true;
            await f.advance(30000);
            await eventually(() => f.receipts().length === 6 && f.model.activeReceipts === 1,
                'last allowed receipt request must be in flight at 90 seconds');
            await f.advance(29999);
            assert.equal(f.model.closedReceipts, 0);
            await f.advance(1);
            await eventually(() => f.model.closedReceipts === 1,
                '120 second total budget must abort the remaining network request');
            assert.equal(await f.id('license-poll-status').getAttribute('data-poll-status'), 'exhausted');
            f.model.releaseReceipt();
            await f.advance(300000);
            assert.equal(f.receipts().length, 6);
        });

        for (const stop of ['hidden', 'offline', 'logout']) {
            await run('U03-stop-no-resume-' + stop, async f => {
                f.model.imported = { status: 202, body: receipt('COMMITTED') };
                f.model.received = { status: 202, body: receipt('COMMITTED') };
                await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
                if (stop === 'hidden') {
                    await f.page.evaluate(() => {
                        Object.defineProperty(document, 'hidden', { configurable: true, value: true });
                        Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
                        document.dispatchEvent(new Event('visibilitychange'));
                    });
                } else if (stop === 'offline') {
                    await f.page.evaluate(() => window.dispatchEvent(new Event('offline')));
                } else {
                    // Clock-controlled tests must let the real modal's closing animation finish first.
                    await f.advance(500);
                    await f.id('license-import-dialog').waitFor({ state: 'hidden' });
                    await f.page.locator('.ant-dropdown-link').hover();
                    await f.advance(250);
                    await f.page.getByText('Sign out', { exact: true }).click({ force: true });
                    await f.page.waitForURL(f.origin + '/login');
                }
                await f.advance(10000);
                assert.equal(f.receipts().length, 0, 'stop event must cancel scheduled request');
                if (stop === 'hidden') {
                    await f.page.evaluate(() => {
                        Object.defineProperty(document, 'hidden', { configurable: true, value: false });
                        Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
                        document.dispatchEvent(new Event('visibilitychange'));
                    });
                } else if (stop === 'offline') {
                    await f.page.evaluate(() => window.dispatchEvent(new Event('online')));
                }
                await f.advance(300000);
                assert.equal(f.receipts().length, 0, 'stop must not automatically resume');
                assert.equal(f.count('/import'), 1);
                if (stop !== 'logout') {
                    await f.id('license-receipt-query').click();
                    await eventually(() => f.receipts().length === 1, 'manual query is allowed after stop');
                } else {
                    assert.equal(await f.page.evaluate(() => localStorage.getItem('username')), null);
                    assert.equal(await f.id('license-certificate-input').count(), 0);
                }
            });
        }

        await run('U03-lost-response-and-network-failure', async f => {
            // Headers arrive, then the peer interrupts the body before the outcome is readable.
            // This avoids the browser's own pre-header socket retransmissions retained in v2 evidence.
            f.model.imported = { status: 200, partial: true };
            f.model.received = { status: 200, partial: true };
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            assert.equal(await f.id('license-receipt-fingerprint').inputValue(), expectedFingerprint);
            const importTransmissions = f.count('/import');
            await f.advance(300000);
            await f.id('license-import-dialog').waitFor({ state: 'hidden' });
            assert.equal(f.receipts().length, 0, 'a network failure stops automatic requests');
            await f.id('license-receipt-query').click();
            await eventually(() => f.receipts().length >= 1 && f.model.activeReceipts === 0,
                'lost response leaves a fingerprint for manual receipt lookup');
            await eventually(async () => await f.page.evaluate(() => window.__licenseRequests
                .some(r => r.path.includes('/imports/') && r.ended !== null)), 'failed manual request must settle');
            const receiptTransmissions = f.receipts().length;
            await f.advance(300000);
            assert.equal(f.receipts().length, receiptTransmissions, 'network failure must stop polling');
            assert.equal(f.count('/import'), importTransmissions, 'no later submission may be sent');
            const failedTrace = await f.page.evaluate(() => window.__licenseRequests);
            assert.equal(importTransmissions, 1, 'one interrupted POST must cause exactly one wire submission');
            assert.equal(failedTrace.filter(r => r.path.endsWith('/api/license/import')).length, 1,
                'lost response must never trigger a second application submission');
            assert.equal(failedTrace.filter(r => r.path.includes('/imports/')).length, 1);
            f.model.received = { status: 200, body: receipt() };
            await f.id('license-receipt-query').click();
            await eventually(() => f.receipts().length === receiptTransmissions + 1,
                'manual retry can recover after network repair');
            await f.advance(300000);
            assert.equal(f.receipts().length, receiptTransmissions + 1);
            assert.equal((await f.page.evaluate(() => window.__licenseRequests)).filter(r => r.path.includes('/imports/')).length, 2);
        });

        await run('U03-applied-receipt-and-explicit-refresh', async f => {
            f.model.imported = { status: 202, body: receipt('COMMITTED') };
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            f.model.status.active = details(12);
            await f.advance(2000);
            await eventually(async () => (await f.id('license-poll-status').getAttribute('data-poll-status')) === 'complete',
                'APPLIED receipt must finish confirmation');
            assert.equal(f.count(''), 1, 'details remain explicitly refreshed');
            assert.match(await f.id('license-active').innerText(), /browser-license-11/);
            await f.advance(300000);
            assert.equal(f.receipts().length, 1);
            assert.equal(f.count(''), 1);
            await f.id('license-refresh').click({ force: true });
            await eventually(() => f.count('') === 2, 'manual refresh must issue exactly one details request');
            await eventually(async () => (await f.id('license-active').innerText()).includes('browser-license-12'),
                'manual refresh must show the new server snapshot');
        });

        for (const outcome of ['unknown', 'network']) {
            await run('U03-next-receipt-target-clears-success-' + outcome, async f => {
                await f.enter(); await f.clock();
                const success = f.page.getByText('The submission is applied on this FE. Refresh to view its current license status.',
                    { exact: true });
                await f.id('license-receipt-fingerprint').fill(expectedFingerprint);
                await f.id('license-receipt-query').click();
                await eventually(async () => (await f.id('license-poll-status').getAttribute('data-poll-status')) === 'complete',
                    'receipt A must first be successfully applied');
                await success.waitFor();
                const nextFingerprint = fingerprint(certificate + '-renewal');
                await f.id('license-receipt-fingerprint').fill(nextFingerprint);
                assert.equal(await success.count(), 0, 'editing receipt target must remove prior success announcement');
                assert.notEqual(await f.id('license-poll-status').getAttribute('data-poll-status'), 'complete',
                    'an unqueried fingerprint must not inherit the prior completed state');
                assert.equal(await f.id('license-receipt').getAttribute('data-submission-status'), '');
                f.model.received = outcome === 'unknown'
                    ? { status: 503, body: receipt('UNKNOWN', { fingerprint: nextFingerprint }) }
                    : { status: 200, partial: true };
                await f.id('license-receipt-query').click();
                await eventually(() => f.receipts().length === 2 && f.model.activeReceipts === 0,
                    'receipt B request must finish or lose its response body');
                await f.id('license-error').waitFor();
                assert.equal(await success.count(), 0, 'unknown or failed receipt B must not announce A success');
                assert.notEqual(await f.id('license-poll-status').getAttribute('data-poll-status'), 'complete');
                assert.equal(await f.id('license-receipt-fingerprint').inputValue(), nextFingerprint);
                assert.ok(!(await f.id('license-receipt').innerText()).includes('LICENSE_APPLIED'),
                    'old APPLIED receipt must not survive a new target or its network failure');
                if (outcome === 'unknown') {
                    assert.equal(await f.id('license-receipt').getAttribute('data-submission-status'), 'UNKNOWN');
                } else {
                    assert.match(await f.id('license-error').innerText(), /LICENSE_NETWORK_ERROR/);
                }
                await f.advance(300000);
                assert.equal(f.receipts().length, 2, 'manual receipt lookup must stay manual after failure');
                assert.equal(f.count('/import'), 0);
            });
        }

        await run('U03-next-import-clears-prior-receipt-success', async f => {
            await f.enter(); await f.clock();
            const success = f.page.getByText('The submission is applied on this FE. Refresh to view its current license status.',
                { exact: true });
            await f.id('license-receipt-fingerprint').fill(expectedFingerprint);
            await f.id('license-receipt-query').click();
            await success.waitFor();
            const nextCertificate = certificate + '-renewal';
            const nextFingerprint = fingerprint(nextCertificate);
            f.model.validate.body.fingerprint = nextFingerprint;
            f.model.imported = { status: 202, body: receipt('COMMITTED', { fingerprint: nextFingerprint }) };
            f.model.received = { status: 503, body: receipt('UNKNOWN', { fingerprint: nextFingerprint }) };
            f.model.holdImport = true;
            await f.open(nextCertificate); await f.validate();
            await f.id('license-confirm-import').click();
            await eventually(() => f.model.releaseImport !== null, 'new import B must be in flight');
            assert.equal(await success.count(), 0, 'starting import B must immediately clear old A success');
            assert.notEqual(await f.id('license-poll-status').getAttribute('data-poll-status'), 'complete');
            assert.equal(await f.id('license-receipt').getAttribute('data-submission-status'), 'UNKNOWN');
            assert.equal(await f.id('license-receipt-fingerprint').inputValue(), nextFingerprint);
            f.model.releaseImport();
            await eventually(async () => (await f.id('license-poll-status').getAttribute('data-poll-status')) === 'waiting',
                'B committed response must enter confirmation');
            await f.advance(2000);
            await eventually(() => f.receipts().length === 2 && f.model.activeReceipts === 0,
                'confirmation must query B after A historical receipt');
            assert.equal(await f.id('license-receipt').getAttribute('data-submission-status'), 'UNKNOWN');
            assert.equal(await success.count(), 0);
            assert.notEqual(await f.id('license-poll-status').getAttribute('data-poll-status'), 'complete');
            assert.equal(f.count('/import'), 1);
            assert.ok(f.receipts()[1].path.endsWith('/' + nextFingerprint), 'confirmation must stay bound to B');
        });

        await run('U03-inconsistent-applied-version-is-not-success', async f => {
            f.model.imported = { status: 200, rawBody: JSON.stringify(receipt('APPLIED'))
                .replace('"committed_version":19', '"committed_version":9007199254740993')
                .replace('"applied_version":19', '"applied_version":9007199254740992') };
            f.model.received = { status: 202, body: receipt('COMMITTED') };
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            assert.equal(f.count(''), 1, 'applied below committed version must not announce successful import');
            assert.notEqual(await f.id('license-poll-status').getAttribute('data-poll-status'), 'complete');
            assert.equal(await f.id('license-receipt').getAttribute('data-submission-status'), 'UNKNOWN');
            assert.match(await f.id('license-receipt').innerText(), /LICENSE_INVALID_RESPONSE/);
        });

        await run('U03-partial-body-network-failure-stops', async f => {
            f.model.imported = { status: 202, partial: true };
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            await eventually(async () => (await f.id('license-poll-status').getAttribute('data-poll-status')) === 'stopped',
                'failure reading response body must stop automatic work');
            const trace = await f.page.evaluate(() => window.__licenseRequests.find(r => r.path.endsWith('/api/license/import')));
            assert.equal(trace.status, 202, 'test must prove headers arrived before the body was interrupted');
            await f.advance(300000);
            assert.equal(f.receipts().length, 0, 'half-response transport error must not become UNKNOWN auto-polling');
            assert.equal(f.count('/import'), 1);
            assert.equal(await f.id('license-receipt-fingerprint').inputValue(), expectedFingerprint);
            await f.id('license-receipt-query').click();
            await eventually(() => f.receipts().length === 1, 'manual confirmation remains available after partial response');
        });

        for (const stage of ['import', 'receipt']) {
            await run('U03-wrong-fingerprint-' + stage, async f => {
                const wrong = { status: 200, body: receipt('APPLIED', { fingerprint: 'b'.repeat(64) }) };
                f.model.imported = stage === 'import' ? wrong : { status: 202, body: receipt('COMMITTED') };
                f.model.received = wrong;
                await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
                if (stage === 'receipt') {
                    await f.advance(2000);
                    await eventually(() => f.receipts().length === 1, 'first receipt must be queried');
                }
                assert.notEqual(await f.id('license-poll-status').getAttribute('data-poll-status'), 'complete',
                    'APPLIED for another certificate cannot confirm this submission');
                assert.equal(await f.id('license-receipt-fingerprint').inputValue(), expectedFingerprint);
                assert.equal(f.count('/import'), 1);
            });
        }

        await run('U02-untrusted-receipt-fields-never-echo-input', async f => {
            f.model.imported = { status: 200, body: receipt('APPLIED', {
                committed_version: certificate, applied_version: certificate, message: certificate,
            }) };
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            await f.advance(500);
            assert.notEqual(await f.id('license-poll-status').getAttribute('data-poll-status'), 'complete');
            assert.ok(!(await f.page.locator('body').innerText()).includes(CANARY),
                'malformed response fields must not reveal raw certificate text');
        });

        await run('U03-receipt-rate-limit-honors-retry-after', async f => {
            f.model.imported = { status: 202, body: receipt('COMMITTED') };
            f.model.received = { status: 429, body: errorBody('LICENSE_RATE_LIMITED'), headers: { 'Retry-After': '7' } };
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            await f.advance(2000);
            await eventually(() => f.receipts().length === 1, 'first receipt request must run');
            await f.id('license-error').waitFor();
            assert.match(await f.id('license-error').innerText(), /429/);
            await f.advance(6999);
            assert.equal(f.receipts().length, 1, 'server Retry-After must extend shorter exponential delay');
            f.model.received = { status: 200, body: receipt() };
            await f.advance(1);
            await eventually(() => f.receipts().length === 2, 'receipt may retry after server cooldown');
            await eventually(async () => (await f.id('license-poll-status').getAttribute('data-poll-status')) === 'complete',
                'applied receipt completes after rate limit');
        });

        for (const status of [401, 403, 503]) {
            await run('U03-receipt-http-stop-' + status, async f => {
                f.model.imported = { status: 202, body: receipt('COMMITTED') };
                f.model.received = { status, body: errorBody(status === 401 ? 'UNAUTHENTICATED'
                    : status === 403 ? 'ACCESS_DENIED' : 'LICENSE_NOT_READY') };
                await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
                await f.advance(2000);
                await eventually(() => f.receipts().length === 1, 'first receipt request must run');
                await f.id('license-error').waitFor();
                assert.match(await f.id('license-error').innerText(), new RegExp(String(status)));
                await f.advance(300000);
                assert.equal(f.receipts().length, 1, 'non-confirmation HTTP failures must stop polling');
                assert.equal(f.count('/import'), 1);
                if (status !== 503) {
                    assert.equal(await f.id('license-active').count(), 0);
                    assert.equal(await f.id('license-import-open').count(), 0);
                }
            });
        }

        for (const status of [401, 403, 429, 503]) {
            await run('U03-http-' + status, async f => {
                const reason = { 401: 'UNAUTHENTICATED', 403: 'ACCESS_DENIED',
                    429: 'LICENSE_RATE_LIMITED', 503: 'LICENSE_NOT_READY' }[status];
                f.model.validate = { status, body: errorBody(reason), headers: { 'Retry-After': '7' } };
                await f.enter(); await f.open();
                await f.id('license-validate').click();
                await f.id('license-error').waitFor();
                assert.match(await f.id('license-error').innerText(), new RegExp(String(status)));
                assert.equal(f.count('/import'), 0);
                if (status === 401 || status === 403) {
                    assert.equal(await f.id('license-active').count(), 0);
                    assert.equal(await f.id('license-import-open').count(), 0);
                    if (status === 401) assert.equal(await f.id('license-error').locator('a[href$="/login"]').count(), 1);
                } else {
                    assert.equal(await f.id('license-confirm-import').isEnabled(), false);
                }
                await f.clock(); await f.advance(300000);
                assert.equal(f.count('/validate'), 1, 'HTTP error must not automatically retry certificate body');
            });
        }

        await run('U03-unknown-submission-receipt', async f => {
            f.model.imported = { status: 503, body: receipt('UNKNOWN') };
            f.model.received = { status: 503, body: receipt('UNKNOWN') };
            await f.enter(); await f.clock(); await f.open(); await f.validate(); await f.confirm();
            await f.advance(2000);
            await eventually(() => f.receipts().length === 1, 'UNKNOWN result uses receipt confirmation');
            assert.equal(f.count('/import'), 1);
            assert.equal(f.count(''), 1, 'UNKNOWN must not refresh details as a successful import');
            assert.match(await f.id('license-receipt').innerText(), /UNKNOWN|unknown|无法确认/);
        });
    } finally {
        await browser.close();
    }
    if (selectedCases) assert.deepEqual([...executedCases].sort(), [...selectedCases].sort(),
        'every requested targeted case must exist and execute');
});
