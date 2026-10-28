// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Runs the inline <base> script of the page template, or of a built page, against a request path.
const html = fs.readFileSync(process.env.MASSDB_BASE_HREF_TEST_HTML
    ? path.resolve(process.env.MASSDB_BASE_HREF_TEST_HTML) : path.resolve(__dirname, '../src/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const origin = 'http://fe.example:8030';

function baseFor(pathname) {
    const appended = [];
    const element = { attributes: {}, setAttribute(name, value) { this.attributes[name] = value; } };
    vm.runInNewContext(script, {
        location: { pathname, origin },
        document: {
            createElement: () => element,
            getElementsByTagName: () => [{ appendChild: child => appended.push(child) }],
        },
    });
    assert.equal(appended.length, 1);
    return appended[0].attributes.href.slice(origin.length);
}

// Database and table names equal to route names, in single-segment and db-table forms.
const routes = ['/login', '/legal-notices', '/home', '/home/', '/Playground', '/Playground/default',
    '/Playground/result/home', '/Playground/result/Session', '/Playground/result/login',
    '/Playground/structure/System', '/Playground/structure/home-Configuration',
    '/Playground/import/QueryProfile-home', '/Playground/result/Playground', '/System', '/QueryProfile',
    '/QueryProfile/', '/QueryProfile/home', '/QueryProfile/0f5e2a-9c1d', '/Session', '/Configuration'];
const prefixes = ['', '/proxy/fe', '/gateway/cluster/fe/default', '/system/team', '/home/team',
    '/System/home/team', '/Playground/team', '/QueryProfile/team/login'];

test('routes whose database or table names match route names keep the deployment prefix', () => {
    for (const prefix of prefixes) {
        for (const route of routes) {
            assert.equal(baseFor(prefix + route), prefix + '/', prefix + route);
        }
    }
});

test('encoded names and empty segments do not move the prefix', () => {
    for (const prefix of ['', '/proxy/fe', '/home/team']) {
        for (const route of ['/Playground/structure/%E4%B8%AD%E6%96%87-%E8%A1%A8', '/Playground/result/home%20db',
            '/Playground/structure/Session%2Dorders', '/QueryProfile/%E4%B8%AD']) {
            assert.equal(baseFor(prefix + route), prefix + '/', prefix + route);
        }
    }
    assert.equal(baseFor('/proxy//fe/home'), '/proxy//fe/');
    assert.equal(baseFor('//home'), '//');
    assert.equal(baseFor('/home//'), '/');
});

test('paths without a known route keep the upstream four-segment prefix rule', () => {
    assert.equal(baseFor('/'), '/');
    assert.equal(baseFor('/unknown'), '/');
    assert.equal(baseFor('/a/b/c'), '/');
    assert.equal(baseFor('/gateway/cluster/fe/default/'), '/gateway/cluster/fe/default/');
    assert.equal(baseFor('/gateway/cluster/fe/default/unknown'), '/gateway/cluster/fe/default/');
    assert.equal(baseFor('/a/b/c/d/e'), '/a/b/c/d/');
});
