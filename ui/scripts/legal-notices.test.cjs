// MassDB SQL implementation.
// Licensing decision pending (A02); see dist/source-headers.json.
// This file does not assert an ASF contributor agreement.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const dist = process.env.MASSDB_LEGAL_TEST_DIST
    ? path.resolve(process.env.MASSDB_LEGAL_TEST_DIST) : path.resolve(__dirname, '../dist');
const metadata = JSON.parse(fs.readFileSync(process.env.MASSDB_LEGAL_TEST_MANIFEST
    || path.join(dist, 'legal/manifest.json'))).metadata;
const screenshots = process.env.MASSDB_LEGAL_TEST_SCREENSHOTS
    ? path.resolve(process.env.MASSDB_LEGAL_TEST_SCREENSHOTS) : path.resolve(__dirname, '../../.build-records/ui/screenshots');
const prefixes = ['', '/proxy/fe', '/gateway/cluster/fe/default',
    '/system/team', '/home/team', '/System/home/team'];

test('legal notices remain public, local and usable under deployment prefixes', { timeout: 180000 }, async () => {
    const server = http.createServer((request, response) => {
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
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
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
