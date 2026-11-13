// node --test test-unit/*.test.mjs   (Node 22.18 or later: it imports the .ts module directly)
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { sanitizeRedirect } from '../src/gateway/lib/redirect.ts'

const HTTPS_PAGE = {
    origin: 'https://warp.example.com',
    protocol: 'https:',
}
const HTTP_PAGE = { origin: 'http://localhost:8888', protocol: 'http:' }
const DOMAIN = 'warp.example.com'

const check = (next, domain = DOMAIN, page = HTTPS_PAGE) =>
    sanitizeRedirect(next, page, domain)

test('a same-origin next is kept, relative or absolute', () => {
    assert.equal(
        check('/@warpgate#/profile'),
        'https://warp.example.com/@warpgate#/profile',
    )
    assert.equal(
        check('https://warp.example.com/x?y=1'),
        'https://warp.example.com/x?y=1',
    )
    assert.equal(
        sanitizeRedirect('/x', HTTPS_PAGE, undefined),
        'https://warp.example.com/x',
    )
})

test('an https next on the cookie domain or a subdomain is accepted', () => {
    assert.equal(
        check('https://app.warp.example.com/path?q=1#h'),
        'https://app.warp.example.com/path?q=1#h',
    )
    assert.equal(
        check('HTTPS://A.B.Warp.Example.COM:8443/'),
        'https://a.b.warp.example.com:8443/',
    )
    assert.equal(
        check('https://app.warp.example.com/', '.warp.example.com'),
        'https://app.warp.example.com/',
    )
    assert.equal(
        check('https://app.warp.example.com/', 'Warp.Example.com'),
        'https://app.warp.example.com/',
    )
})

test('the cookie domain itself is accepted from a bound host', () => {
    const boundPage = {
        origin: 'https://app.warp.example.com',
        protocol: 'https:',
    }
    assert.equal(
        check('https://warp.example.com/@warpgate#/', DOMAIN, boundPage),
        'https://warp.example.com/@warpgate#/',
    )
    assert.equal(
        check('https://warp.example.com:8443/', DOMAIN, HTTPS_PAGE),
        'https://warp.example.com:8443/',
    )
})

test('another domain is rejected', () => {
    assert.equal(check('https://evil.com/'), undefined)
    assert.equal(check('https://example.com/'), undefined)
    assert.equal(check('https://other.example.com/'), undefined)
    assert.equal(check('https://warp.example.com.evil.com/'), undefined)
})

test('a look-alike suffix is rejected', () => {
    assert.equal(check('https://evil-warp.example.com/'), undefined)
    assert.equal(check('https://evilwarp.example.com/'), undefined)
    assert.equal(check('https://app.evil-warp.example.com/'), undefined)
})

test('userinfo is rejected', () => {
    assert.equal(check('https://user@app.warp.example.com/'), undefined)
    assert.equal(check('https://user:pw@app.warp.example.com/'), undefined)
    assert.equal(check('https://:pw@app.warp.example.com/'), undefined)
    assert.equal(check('https://evil.com@app.warp.example.com/'), undefined)
})

test('javascript: and other schemes are rejected', () => {
    assert.equal(check('javascript:alert(1)'), undefined)
    assert.equal(
        check('JavaScript://app.warp.example.com/%0aalert(1)'),
        undefined,
    )
    assert.equal(check('data:text/html,hi'), undefined)
    assert.equal(check('ftp://app.warp.example.com/'), undefined)
})

test('a protocol-relative or backslash next to another origin is rejected', () => {
    assert.equal(check('//evil.com/'), undefined)
    assert.equal(check('//app.warp.example.com/'), undefined)
    assert.equal(check('/\\app.warp.example.com/'), undefined)
    assert.equal(check('\\\\app.warp.example.com/'), undefined)
    assert.equal(check(' https://app.warp.example.com/'), undefined)
})

test('plain http is accepted only from a plain-http page', () => {
    assert.equal(check('http://app.warp.example.com/'), undefined)
    assert.equal(
        check('http://app.warp.example.com/', DOMAIN, HTTP_PAGE),
        'http://app.warp.example.com/',
    )
    assert.equal(
        check('https://app.warp.example.com/', DOMAIN, HTTP_PAGE),
        'https://app.warp.example.com/',
    )
})

test('without a cookie domain no other origin is accepted', () => {
    for (const domain of [undefined, null, '', '.', '  ']) {
        assert.equal(
            sanitizeRedirect(
                'https://app.warp.example.com/',
                HTTPS_PAGE,
                domain,
            ),
            undefined,
        )
        // A host with a trailing dot must not match an empty domain.
        assert.equal(
            sanitizeRedirect('https://evil.com./', HTTPS_PAGE, domain),
            undefined,
        )
    }
})

test('an unparsable next is dropped', () => {
    assert.equal(check('https://'), undefined)
    assert.equal(check('http://[::1'), undefined)
})
