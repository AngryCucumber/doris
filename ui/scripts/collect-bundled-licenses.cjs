// MassDB SQL implementation.
// Licensing decision pending (A02); see dist/source-headers.json.
// This file does not assert an ASF contributor agreement.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const root = path.resolve(__dirname, '../..');
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const json = value => JSON.stringify(value, null, 2) + '\n';

function productInputs(flag) {
    return JSON.parse(execFileSync(process.env.MASSDB_NOTICE_PYTHON || 'python3',
        [path.join(root, 'build-support/prepare-product-notices.py'), flag],
        { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }));
}

function packageRoot(resource) {
    let directory = path.dirname(resource.split('?')[0]);
    while (directory.includes('node_modules')) {
        const manifest = path.join(directory, 'package.json');
        if (fs.existsSync(manifest)) {
            const pkg = JSON.parse(fs.readFileSync(manifest, 'utf8'));
            if (pkg.name && pkg.version) return directory;
        }
        directory = path.dirname(directory);
    }
    return null;
}

function collectComponents(modules, evidence = path.join(root, '.build-records/ui')) {
    const directories = new Set();
    const visited = new Set();
    function visit(module) {
        if (visited.has(module)) return;
        visited.add(module);
        if (module.resource && module.resource.includes('node_modules')) {
            const directory = packageRoot(module.resource);
            if (directory) directories.add(directory);
        }
        for (const child of module.modules || []) visit(child);
    }
    for (const module of modules) visit(module);
    fs.mkdirSync(evidence, { recursive: true });
    fs.writeFileSync(path.join(evidence, 'ui-bundled-packages.json'), json([...directories].sort()));
    const lock = JSON.parse(fs.readFileSync(path.join(root, 'ui/package-lock.json'), 'utf8'));
    const supplementsDirectory = path.join(root, 'dist/ui-licenses');
    const supplements = JSON.parse(fs.readFileSync(path.join(supplementsDirectory, 'overrides.json'), 'utf8'));
    return [...directories].map(directory => {
        const pkg = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
        const location = path.relative(path.join(root, 'ui'), directory).split(path.sep).join('/');
        const resolved = lock.packages && lock.packages[location];
        if (!resolved || resolved.version !== pkg.version || !resolved.integrity) {
            throw new Error(`Lockfile does not identify bundled package ${location}`);
        }
        const files = fs.readdirSync(directory).filter(name =>
            /^(licen[sc]e|copying|notice|copyright|authors)([._-].*)?$/i.test(name) &&
            fs.statSync(path.join(directory, name)).isFile());
        const notices = files.sort().map(name => {
            const text = fs.readFileSync(path.join(directory, name), 'utf8');
            if (!text.trim()) throw new Error(`Empty license/notice: ${pkg.name}/${name}`);
            return { name, text, sha256: sha256(text) };
        });
        if (!files.some(name => /^(licen[sc]e|copying)/i.test(name))) {
            const supplement = supplements[`${pkg.name}@${pkg.version}`];
            if (supplement) {
                const text = fs.readFileSync(path.join(supplementsDirectory, supplement.file), 'utf8');
                if (sha256(text) !== supplement.sha256 || resolved.integrity !== supplement.integrity) {
                    throw new Error(`License supplement does not match ${pkg.name}@${pkg.version}`);
                }
                notices.push({ name: supplement.file, text, sha256: supplement.sha256, sources: supplement.sources });
            } else {
                const readme = fs.readdirSync(directory).find(name => /^readme(?:\.md|\.markdown|\.txt)?$/i.test(name));
                const text = readme && fs.readFileSync(path.join(directory, readme), 'utf8');
                const section = text && text.match(/^#{1,6}\s+licen[sc]e\b[^\n]*\n([\s\S]*)/im);
                if (!section || !/copyright/i.test(section[1]) || !/permission is hereby granted/i.test(section[1])) {
                    throw new Error(`Missing original license text for bundled package ${pkg.name}@${pkg.version}`);
                }
                notices.push({ name: readme + '#license', text: section[1], sha256: sha256(section[1]) });
            }
        }
        const license = typeof pkg.license === 'string' ? pkg.license :
            (pkg.license && pkg.license.type) || (pkg.licenses && pkg.licenses.length === 1 && pkg.licenses[0].type);
        if (!license) throw new Error(`Missing license expression: ${pkg.name}@${pkg.version}`);
        return { name: pkg.name, version: pkg.version, license, location,
            resolved: resolved.resolved, integrity: resolved.integrity, notices };
    }).sort((a, b) => a.location < b.location ? -1 : a.location > b.location ? 1 : 0);
}

class ProductNoticesPlugin {
    apply(compiler) {
        const evidence = path.join(root, '.build-records/ui',
            compiler.options.mode === 'development' ? 'ui-development' : '');
        compiler.hooks.done.tap('ProductNoticesEvidence', stats => {
            fs.mkdirSync(evidence, { recursive: true });
            fs.writeFileSync(path.join(evidence, 'ui-webpack-stats.json'), json(stats.toJson({
                all: false, assets: true, chunks: true, chunkModules: true,
                modules: true, children: true, errors: true, warnings: true,
            })));
        });
        // Emit after normal assets are generated, so cleaning cannot remove legal resources.
        compiler.hooks.emit.tap('ProductNoticesPlugin', compilation => {
            const inputs = productInputs('--inputs');
            const modules = [...compilation.modules];
            for (const child of compilation.children) modules.push(...child.modules);
            const components = collectComponents(modules, evidence);
            const files = {};
            for (const [name, text] of Object.entries(inputs.files)) files['legal/' + name] = text;
            files['legal/THIRD-PARTY-NOTICES.txt'] = components.map(component =>
                `${component.name} ${component.version}\nLicense: ${component.license}\n` +
                component.notices.map(notice => `\n--- ${notice.name} ---\n${notice.text}`).join('\n')
            ).join('\n\n' + '='.repeat(72) + '\n\n') + '\n';
            const inventory = components.map(({ notices, ...component }) => ({ ...component,
                noticeFiles: notices.map(({ name, sha256, sources }) => ({ name, sha256, sources })) }));
            files['legal/components.json'] = json(inventory);
            files['legal/sbom.cdx.json'] = json({ bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
                metadata: { component: { type: 'application', name: 'MassDB SQL UI',
                    version: inputs.metadata.productVersion } },
                components: inventory.map(component => ({ type: 'library', name: component.name,
                    version: component.version, 'bom-ref': component.location,
                    licenses: [{ expression: component.license }],
                    properties: [{ name: 'npm:integrity', value: component.integrity }] })) });
            const assets = Object.entries(compilation.assets).filter(([name]) => !name.startsWith('legal/'))
                .map(([name, asset]) => ({ path: name, sha256: sha256(asset.source()) }))
                .sort((a, b) => a.path.localeCompare(b.path));
            files['legal/manifest.json'] = json({ schemaVersion: 1, metadata: inputs.metadata,
                components: inventory, assets,
                files: Object.entries(files).map(([name, text]) => ({ path: name, sha256: sha256(text) })) });
            for (const [name, text] of Object.entries(files)) {
                compilation.assets[name] = { source: () => text, size: () => Buffer.byteLength(text) };
            }
        });
    }
}

module.exports = { collectComponents, productInputs, ProductNoticesPlugin };
