// node --test test-unit/*.test.mjs
// Fails if the web UI's generated API clients stop being built from pinned inputs: the generator
// jar must be a fixed version with a sha256 that is checked, and nothing may be installed
// unpinned inside the generated client directories.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { sha256File, verifyJar } from '../scripts/openapi-client.mjs'

const read = (rel) =>
    fs.readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8')
const pin = JSON.parse(read('openapi-generator.pin.json'))
const pkg = JSON.parse(read('package.json'))
const lock = JSON.parse(read('package-lock.json'))

test('the generator pin is an exact version with a sha256 and a versioned Maven URL', () => {
    assert.match(pin.version, /^\d+\.\d+\.\d+$/)
    assert.match(pin.sha256, /^[0-9a-f]{64}$/)
    assert.ok(
        pin.url.startsWith(
            'https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/',
        ),
    )
    assert.ok(pin.url.includes(`/${pin.version}/`))
    assert.ok(pin.url.endsWith(`-${pin.version}.jar`))
})

test('openapitools.json names the same generator version as the pin', () => {
    const cfg = JSON.parse(read('openapitools.json'))
    assert.equal(cfg['generator-cli'].version, pin.version)
})

test('the client scripts go through the checked wrapper and install nothing', () => {
    for (const target of ['admin', 'gateway']) {
        const script = pkg.scripts[`openapi:client:${target}`]
        assert.equal(script, `node scripts/openapi-client.mjs ${target}`)
    }
    for (const [name, script] of Object.entries(pkg.scripts)) {
        if (name === 'openapi:tests-sdk') continue // not part of the shipped UI
        assert.doesNotMatch(script, /openapi-generator-cli/, name)
        assert.doesNotMatch(script, /\bnpm (i|install|add|ci)\b/, name)
        assert.doesNotMatch(script, /\b(pnpm|yarn) (dlx|add|install|i)\b/, name)
        assert.doesNotMatch(script, /\b(npx|bunx|pnpx)\b/, name)
        assert.doesNotMatch(script, /\bbun (x|add|install|i)\b/, name)
    }
})

test('the wrapper verifies the jar and compiles with the locked TypeScript', () => {
    const wrapper = read('scripts/openapi-client.mjs')
        .split('\n')
        .filter((line) => !line.trim().startsWith('//'))
        .join('\n')
    // The call sites, not the definition: both the cached jar and a fresh
    // download are checked against the pin before anything runs them.
    assert.match(wrapper, /verifyJar\(jarPath, pin\.sha256\)/)
    assert.match(wrapper, /verifyJar\(partial, pin\.sha256\)/)
    assert.match(wrapper, /node_modules.*typescript.*tsc/s)
    assert.doesNotMatch(wrapper, /\bnpm\b.*\b(install|i)\b/)
    assert.ok(lock.packages['node_modules/typescript'].integrity)
})

test('a jar whose sha256 differs is refused', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-pin-'))
    try {
        const jar = path.join(dir, 'g.jar')
        fs.writeFileSync(jar, 'not the generator')
        assert.throws(() => verifyJar(jar, pin.sha256), /refusing to run it/)
        verifyJar(jar, sha256File(jar))
    } finally {
        fs.rmSync(dir, { recursive: true, force: true })
    }
})
