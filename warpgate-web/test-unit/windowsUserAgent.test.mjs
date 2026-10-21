// node --test test-unit/*.test.mjs   (Node 22.18 or later: it imports the .ts module directly)
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { test } from 'node:test'
import { isWindowsUserAgent } from '../src/gateway/lib/windowsUserAgent.ts'

const fixtures = JSON.parse(
    fs.readFileSync(new URL('../test-fixtures/ua-parser-1.0.41/os-test.json', import.meta.url), 'utf8'),
)

// ua-parser-js 1.x names this one "Windows"; 2.x and this check call it Windows CE.
const DEPARTURES = new Set(['Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 7.11)'])

test('agrees with ua-parser-js 1.0.41 on every user agent in its OS tests', () => {
    assert.ok(fixtures.length >= 100, `only ${fixtures.length} fixtures`)
    let windows = 0
    for (const { ua, expect } of fixtures) {
        const want = expect.name === 'Windows' && !DEPARTURES.has(ua)
        if (want) windows++
        assert.equal(isWindowsUserAgent(ua), want, `${expect.name}: ${ua}`)
    }
    assert.ok(windows >= 10, `only ${windows} Windows fixtures`)
})

test('a Windows browser that sends its user agent in lower case is Windows', () => {
    for (const ua of [
        'mozilla/5.0 (windows nt 6.1; wow64) applewebkit/537.36 (khtml, like gecko) chrome/81.0.4044.138 safari/537.36 nettype/wifi micromessenger/7.0.20.1781(0x6700143b) windowswechat',
        'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/112.0.0.0 safari/537.36 quarkpc/1.5.5.75',
        'mozilla/5.0 (windows nt 10.0; wow64) applewebkit/537.36 (khtml, like gecko) chrome/53.0.2785.116 safari/537.36 qbcore/4.0.1301.400 qqbrowser/9.0.2524.400',
    ]) {
        assert.equal(isWindowsUserAgent(ua), true, ua)
    }
})

test('Windows devices with no desktop shell are not Windows', () => {
    for (const ua of [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19041',
        'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586',
        'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; HTC_Touch2_T3333; Windows Phone 6.5)',
        'Mozilla/5.0 (Windows IoT 10.0; Android 6.0.1; WebView/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Mobile Safari/537.36 Edge/18.17763',
    ]) {
        assert.equal(isWindowsUserAgent(ua), false, ua)
    }
})

test("Chromium's userAgentData platform decides when present", () => {
    const mac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'
    const win = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'
    assert.equal(isWindowsUserAgent(win, 'Windows'), true)
    assert.equal(isWindowsUserAgent(mac, 'macOS'), false)
    assert.equal(isWindowsUserAgent(win, 'Linux'), false)
    assert.equal(isWindowsUserAgent(mac), false)
    assert.equal(isWindowsUserAgent(win), true)
})
