// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { chromium } = require('playwright');

const dist = process.env.MASSDB_LEGAL_TEST_DIST
    ? path.resolve(process.env.MASSDB_LEGAL_TEST_DIST) : path.resolve(__dirname, '../dist');
const metadata = JSON.parse(fs.readFileSync(process.env.MASSDB_LEGAL_TEST_MANIFEST
    || path.join(dist, 'legal/manifest.json'))).metadata;
const screenshots = process.env.MASSDB_LEGAL_TEST_SCREENSHOTS
    ? path.resolve(process.env.MASSDB_LEGAL_TEST_SCREENSHOTS) : path.resolve(__dirname, '../../.build-records/ui/screenshots');
const prefixes = ['', '/proxy/fe', '/gateway/cluster/fe/default',
    '/system/team', '/home/team', '/System/home/team'];
const routeNames = ['login', 'legal-notices', 'home', 'Playground', 'System', 'QueryProfile', 'Session',
    'Configuration', 'License'];

// Serves dist under every deployment prefix, unknown paths fall back to index.html like the FE.
function serveDist(request, response) {
    let pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    const prefix = prefixes.find(prefix => prefix &&
        (pathname === prefix || pathname.startsWith(prefix + '/')));
    if (prefix) pathname = pathname.slice(prefix.length);
    if (pathname.startsWith('/rest/') || pathname.startsWith('/api/')) {
        response.setHeader('Content-Type', 'application/json');
        const data = pathname.endsWith('/databases')
            ? ['information_schema', 'mysql', ...Array.from({ length: 60 }, (_, i) => `database_${i}`)]
            : { VersionInfo: {}, HardwareInfo: {} };
        return response.end(JSON.stringify({ code: pathname.endsWith('/login') ? 200 : 0,
            msg: 'success', data }));
    }
    let file = path.resolve(dist, '.' + pathname);
    if (!file.startsWith(dist + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
        file = path.join(dist, 'index.html');
    }
    const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css',
        '.json': 'application/json', '.txt': 'text/plain', '.png': 'image/png', '.ico': 'image/x-icon' };
    response.setHeader('Content-Type', types[path.extname(file)] || 'application/octet-stream');
    response.end(fs.readFileSync(file));
}

async function startServer() {
    const server = http.createServer(serveDist);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return server;
}

// Runs the inline script of an index.html for one location and returns the path of the <base> it sets.
function appRoot(html, pathname) {
    const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
    const appended = [];
    vm.runInNewContext(script, {
        location: { origin: 'http://fe.test', pathname },
        document: {
            createElement: () => ({ setAttribute(name, value) { this[name] = value; } }),
            getElementsByTagName: () => [{ appendChild: element => appended.push(element) }],
        },
    });
    assert.equal(appended.length, 1, 'index.html must add exactly one <base>');
    return new URL(appended[0].href).pathname;
}

// Review U1: a database named like a route must not become part of the application root, and a proxy prefix
// that itself contains route names must keep working.
test('index.html finds the application root for route-named databases and proxy prefixes', () => {
    for (const file of [path.resolve(__dirname, '../src/index.html'), path.join(dist, 'index.html')]) {
        const html = fs.readFileSync(file, 'utf8');
        for (const prefix of ['/proxy', ...prefixes]) {
            const root = prefix + '/';
            const expect = (pathname, why) => assert.equal(appRoot(html, pathname), root, `${file}: ${pathname} ${why}`);
            for (const name of routeNames) {
                expect(prefix + '/' + name, 'is a page');
                expect(prefix + '/Playground/structure/' + name, 'is the database ' + name);
                expect(prefix + '/Playground/structure/' + name + '-' + name, 'is a table');
                expect(prefix + '/Playground/import/' + name + '-t1', 'is a table import');
            }
            expect(prefix + '/home/', 'has a trailing slash');
            expect(prefix + '/QueryProfile/', 'lists profiles');
            expect(prefix + '/QueryProfile/0123abcd', 'is one profile');
        }
        assert.equal(appRoot(html, '/'), '/');
        assert.equal(appRoot(html, '/a/b/c/d/e'), '/a/b/c/d/', 'unknown paths keep the upstream rule');
    }
});

test('Playground database pages load and reload under every deployment prefix', { timeout: 300000 }, async () => {
    const server = await startServer();
    const origin = `http://127.0.0.1:${server.address().port}`;
    const browser = await chromium.launch({ headless: true });
    try {
        const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
        await context.addInitScript(() => localStorage.setItem('username', 'notice-test'));
        const page = await context.newPage();
        page.setDefaultTimeout(10000);
        for (const prefix of prefixes) {
            for (const name of routeNames) {
                const url = origin + prefix + '/Playground/structure/' + name;
                for (const load of [() => page.goto(url), () => page.reload()]) {
                    await load();
                    await page.locator('aside').waitFor();
                    assert.equal(await page.evaluate(() => document.baseURI), origin + prefix + '/', url);
                    assert.equal(new URL(page.url()).pathname, prefix + '/Playground/structure/' + name);
                }
            }
        }
        await page.goto(origin + '/Playground/structure/home');
        await page.locator('aside').waitFor();
        await page.screenshot({ path: path.join(screenshots, 'playground-database-home-reload.png') });
        await context.close();
    } finally {
        await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
});

// Review U3: 480 px or 40% of the Playground row, whichever is smaller, is the sidebar's only upper limit, so the
// panel follows the pointer back as soon as a drag starts from its visible edge.
test('Playground sidebar width follows the pointer up to one upper limit', { timeout: 120000 }, async () => {
    const server = await startServer();
    const origin = `http://127.0.0.1:${server.address().port}`;
    const browser = await chromium.launch({ headless: true });
    try {
        const context = await browser.newContext({ viewport: { width: 1920, height: 900 } });
        await context.addInitScript(() => localStorage.setItem('username', 'notice-test'));
        const page = await context.newPage();
        page.setDefaultTimeout(10000);
        const side = page.locator('aside');
        const width = async () => (await side.boundingBox()).width;
        const limit = () => side.evaluate(element => {
            const row = element.parentElement;
            const style = getComputedStyle(row);
            const content = row.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
            return Math.max(220, Math.min(480, Math.floor(content * 0.4)));
        });
        // One drag from the visible handle; returns the width after the mouse is released.
        const drag = async dx => {
            const handle = await side.locator('.react-resizable-handle-e').boundingBox();
            const x = handle.x + handle.width / 2;
            const y = handle.y + handle.height / 2;
            const viewport = page.viewportSize().width;
            await page.mouse.move(x, y);
            await page.mouse.down();
            await page.mouse.move(Math.max(5, Math.min(viewport - 5, x + dx)), y, { steps: 12 });
            await page.mouse.up();
            return width();
        };
        const near = (actual, expected, why) => assert.ok(Math.abs(actual - expected) <= 2,
            `${why}: width ${actual}, expected ${expected}`);
        for (const viewport of [1000, 1920]) {
            await page.setViewportSize({ width: viewport, height: 900 });
            await page.goto(origin + '/Playground');
            await page.locator('.CodeMirror').waitFor();
            const max = await limit();
            near(await drag(700), max, `${viewport} px: dragged past the limit`);
            near(await drag(-60), max - 60, `${viewport} px: the next drag back must move at once`);
            near(await drag(-1000), 220, `${viewport} px: the minimum still applies`);
            await page.screenshot({ path: path.join(screenshots, `playground-sidebar-${viewport}.png`) });
        }
        // A narrower window lowers the limit; the width must follow it, not stay above it.
        near(await drag(700), await limit(), '1920 px: at the limit');
        await page.setViewportSize({ width: 1000, height: 900 });
        const narrowed = await limit();
        await page.waitForFunction(max => document.querySelector('aside').getBoundingClientRect().width <= max + 2,
            narrowed);
        // Recheck F5: the narrower window only limits what is drawn; widening it brings the chosen width back.
        await page.setViewportSize({ width: 1920, height: 900 });
        const widened = await limit();
        await page.waitForFunction(max => document.querySelector('aside').getBoundingClientRect().width >= max - 2,
            widened).catch(() => {});
        near(await width(), widened, 'after widening the window the sidebar returns to the width that was chosen');
        await page.setViewportSize({ width: 1000, height: 900 });
        await page.waitForFunction(max => document.querySelector('aside').getBoundingClientRect().width <= max + 2,
            narrowed);
        near(await drag(-60), narrowed - 60, 'after narrowing the window the next drag back must move at once');
        // A drag is a new choice: it is kept when the window widens again.
        await page.setViewportSize({ width: 1920, height: 900 });
        await page.waitForTimeout(300);
        near(await width(), narrowed - 60, 'a width chosen in the narrow window is kept when it widens');
        await context.close();
    } finally {
        await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
});

test('legal notices remain public, local and usable under deployment prefixes', { timeout: 180000 }, async () => {
    const server = await startServer();
    const origin = `http://127.0.0.1:${server.address().port}`;
    const browser = await chromium.launch({ headless: true });
    fs.mkdirSync(screenshots, { recursive: true });
    try {
        for (const prefix of prefixes) {
            const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
            const page = await context.newPage();
            const errors = [];
            const businessRequests = [];
            page.on('pageerror', error => { errors.push(error.message); process.stderr.write(error.stack + '\n'); });
            page.on('request', request => { if (/\/(api|rest)\//.test(request.url())) businessRequests.push(request.url()); });
            await page.goto(origin + prefix + '/legal-notices');
            await page.getByRole('heading', { name: /MassDB SQL/ }).waitFor();
            assert.equal(businessRequests.length, 0, 'public notices must not call business APIs');
            assert.match(await page.locator('main').innerText(), /2012-2014 Monty Program Ab/);
            await page.reload();
            await page.getByRole('heading', { name: /MassDB SQL/ }).waitFor();
            const lgpl = await page.request.get(origin + prefix + '/legal/licenses/LICENSE-LGPL.txt');
            assert.match(await lgpl.text(), /GNU LESSER GENERAL PUBLIC LICENSE/);
            await page.getByRole('button', { name: 'Read the full LGPL 2.1 license', exact: true }).click();
            await page.getByText('GNU LESSER GENERAL PUBLIC LICENSE', { exact: false }).last().waitFor();
            const downloaded = page.waitForEvent('download');
            await page.getByRole('link', { name: 'Download', exact: true }).first().click();
            const download = await downloaded;
            assert.match(fs.readFileSync(await download.path(), 'utf8'), /GNU LESSER GENERAL PUBLIC LICENSE/);
            assert.equal(await page.getByRole('button', { name: 'Read company proprietary license and scope', exact: true }).count(), 0);
            assert.equal(await page.locator('a[href$="/legal/LICENSE-MASSDB.txt"]').count(), 0);
            assert.doesNotMatch(await page.locator('main').innerText(), /company proprietary commercial notice/);
            const noticeButton = page.getByRole('button', { name: 'Read NOTICE attributions', exact: true });
            for (const response of [
                { contentType: 'text/html', body: '<html>SPA fallback</html>' },
                { contentType: 'application/json;charset=UTF-8', body: '{"code":404,"msg":"Not Found","data":null}' },
                { contentType: 'application/problem+json', body: '{"status":404,"title":"Not Found"}' },
                { contentType: 'text/plain;charset=UTF-8', body: '   ' },
            ]) {
                await page.route('**/legal/NOTICE.txt', route => route.fulfill({ status: 200, ...response }));
                await noticeButton.click();
                await page.getByRole('alert').waitFor();
                await noticeButton.click();
                await page.unroute('**/legal/NOTICE.txt');
            }
            await noticeButton.click();
            await noticeButton.locator('xpath=../..').locator('pre').filter({ hasText: 'Apache Doris' }).waitFor();
            if (metadata.companyCopyrightConfirmed) {
                const attributions = await noticeButton.locator('xpath=../..').locator('pre').innerText();
                assert.ok(attributions.includes(`Copyright (c) ${metadata.copyrightYears} ${metadata.companyZh}`));
                assert.ok(attributions.includes(metadata.companyEn));
                assert.match(attributions, /The Apache Software Foundation/);
            }
            assert.equal(await page.getByRole('alert').count(), 0, 'a restored plain-text notice must load');
            await page.goto(origin + prefix + '/home');
            await page.waitForURL(origin + prefix + '/login');
            assert.equal(await page.locator('footer').count(), 1);
            await page.locator('input[id="basic_username"]').fill('notice-test');
            await page.getByRole('button', { name: 'Login', exact: true }).click();
            await page.waitForURL(origin + prefix + '/home');
            await page.getByRole('menuitem', { name: 'Playground', exact: true }).waitFor();
            assert.equal(await page.locator('footer').count(), 1);
            await page.getByRole('link', { name: 'Copyright and Open-source Notices', exact: true }).click();
            await page.getByRole('heading', { name: /MassDB SQL/ }).waitFor();
            await page.goBack();
            await page.waitForURL(origin + prefix + '/home');
            await page.goForward();
            await page.waitForURL(origin + prefix + '/legal-notices');
            await page.getByRole('button', { name: '中文', exact: true }).click();
            await page.getByRole('heading', { name: 'MassDB SQL — 版权与开源声明', exact: true }).waitFor();
            assert.equal(await page.getByRole('button', { name: '阅读公司专有许可与适用范围', exact: true }).count(), 0);
            assert.equal(await page.locator('a[href$="/legal/LICENSE-MASSDB.txt"]').count(), 0);
            assert.doesNotMatch(await page.locator('main').innerText(), /公司专有商业许可/);
            await page.getByRole('button', { name: 'English', exact: true }).click();
            await page.getByRole('link', { name: 'Back to product', exact: true }).click();
            await page.waitForURL(origin + prefix + '/home');
            await page.evaluate(() => localStorage.removeItem('username'));
            await page.goto(origin + prefix + '/Configuration');
            await page.waitForURL(origin + prefix + '/login');
            assert.deepEqual(errors, []);
            await context.close();
        }
        for (const language of ['en', 'zh-CN']) {
            for (const width of [375, 768, 1440]) {
                const context = await browser.newContext({ viewport: { width, height: 1000 } });
                await context.addInitScript(language => localStorage.setItem('I18N_LANGUAGE', language), language);
                const page = await context.newPage();
                await page.route('**/*', route => route.request().url().startsWith(origin) ? route.continue() : route.abort());
                await page.goto(origin + '/login');
                await page.locator('footer').waitFor();
                assert.equal(await page.locator('footer').count(), 1);
                if (metadata.companyCopyrightConfirmed) {
                    assert.match(await page.locator('footer').innerText(), new RegExp(language === 'en' ? 'Xiamen Meiya Pico' : '厦门市美亚柏科'));
                } else {
                    assert.doesNotMatch(await page.locator('footer').innerText(), /自有修改与新增部分|modifications and original additions/i);
                    assert.match(await page.locator('footer').innerText(), /MariaDB Connector\/J/);
                }
                const form = await page.locator('form').boundingBox();
                const footer = await page.locator('footer').boundingBox();
                assert.ok(form.y + form.height <= footer.y, 'footer must not cover the sign-in form');
                assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
                await page.screenshot({ path: path.join(screenshots, `login-${language}-${width}.png`), fullPage: true });
                await page.goto(origin + '/legal-notices');
                await page.getByRole('heading', { name: /MassDB SQL/ }).waitFor();
                assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
                await page.screenshot({ path: path.join(screenshots, `legal-${language}-${width}.png`), fullPage: true });
                await page.evaluate(() => localStorage.setItem('username', 'notice-test'));
                await page.goto(origin + '/home');
                await page.locator('header').waitFor();
                assert.equal(await page.locator('footer').count(), 1);
                if (metadata.companyCopyrightConfirmed) {
                    const company = language === 'en' ? metadata.companyEn : metadata.companyZh;
                    assert.ok((await page.locator('footer').innerText()).includes(`© ${metadata.copyrightYears} ${company}`));
                }
                await page.screenshot({ path: path.join(screenshots, `business-${language}-${width}.png`), fullPage: true });
                await page.setViewportSize({ width, height: width === 1440 ? 720 : 1000 });
                await page.goto(origin + '/Playground');
                await page.locator('.CodeMirror').waitFor();
                await page.getByText('information_schema', { exact: true }).waitFor();
                const side = page.locator('aside');
                const editor = page.locator('.site-layout-background main');
                const toolbar = page.locator('.playground-tree-toolbar');
                const search = toolbar.getByRole('textbox');
                const refresh = toolbar.getByRole('button', { name: language === 'en' ? 'Refresh' : '刷新' });
                const sideBounds = await side.boundingBox();
                const editorBounds = await editor.boundingBox();
                const noticeBounds = await page.locator('footer').boundingBox();
                assert.ok(editorBounds.y + editorBounds.height <= noticeBounds.y,
                    'the editor and footer must not overlap');
                assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
                    'Playground must fit the window horizontally');
                assert.ok(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight + 1),
                    'Playground must reserve footer height instead of adding another viewport');
                if (width >= 768) {
                    assert.ok(Math.abs(sideBounds.y - editorBounds.y) < 1, 'panel tops must align');
                    assert.ok(Math.abs(sideBounds.height - editorBounds.height) < 1, 'panel bottoms must align');
                    const searchBounds = await search.boundingBox();
                    const titleBounds = await page.getByText(language === 'en' ? 'Editor' : '编辑器', { exact: true }).boundingBox();
                    assert.ok(Math.abs(searchBounds.y + searchBounds.height / 2 - titleBounds.y - titleBounds.height / 2) < 2,
                        'search and editor toolbar controls must align');
                } else {
                    assert.ok(sideBounds.y + sideBounds.height < editorBounds.y,
                        'narrow windows must stack the database tree above the editor');
                }
                const toolbarBeforeScroll = await toolbar.boundingBox();
                await page.locator('.playground-tree-body').evaluate(el => { el.scrollTop = el.scrollHeight; });
                assert.deepEqual(await toolbar.boundingBox(), toolbarBeforeScroll, 'tree scrolling must leave search in place');
                await search.fill('mysql');
                await page.locator('.site-tree-search-value').filter({ hasText: /^mysql$/ }).waitFor({ state: 'attached' });
                await search.fill('');
                await Promise.all([
                    page.waitForResponse(response => response.url().endsWith('/databases')),
                    refresh.click(),
                ]);
                await page.locator('.playground-tree-body').evaluate(el => { el.scrollTop = 0; });
                if (width === 1440) {
                    const handle = await side.locator('.react-resizable-handle-e').boundingBox();
                    await page.mouse.move(handle.x + handle.width / 2, handle.y + handle.height / 2);
                    await page.mouse.down();
                    await page.mouse.move(handle.x + handle.width / 2 + 120, handle.y + handle.height / 2, { steps: 10 });
                    await page.mouse.up();
                    const resizedSide = await side.boundingBox();
                    const resizedEditor = await editor.boundingBox();
                    const codeBounds = await page.locator('.CodeMirror').boundingBox();
                    assert.ok(resizedSide.width > sideBounds.width + 100, 'sidebar dragging must resize its layout column');
                    assert.ok(codeBounds.x + codeBounds.width <= resizedEditor.x + resizedEditor.width,
                        'the SQL editor must shrink with the remaining column');
                    assert.ok((await toolbar.boundingBox()).width <= resizedSide.width,
                        'search must follow the resized sidebar');
                }
                await page.screenshot({ path: path.join(screenshots, `playground-${language}-${width}.png`), fullPage: true });
                await context.close();
            }
        }
    } finally {
        await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
});
