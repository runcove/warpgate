// Where the login page may send the browser after sign-in (`?next=`).
//
// A `next` on this page's own origin is always accepted. A `next` on another
// origin is accepted only when it is written as an absolute http(s) URL, its
// scheme is https (or http when this page is itself http), it carries no
// userinfo, and its host is the session cookie's domain or a subdomain of it:
// the hosts the server shares the session with, such as a target bound to its
// own subdomain. Anything else is dropped and the caller falls back to home.
//
// `cookieDomain` is the domain the server scopes the session cookie to
// (`cookieDomain` in the instance info); without it no other origin is accepted.

const ABSOLUTE_HTTP_URL = /^https?:\/\//i

function hostIsUnder(hostname: string, domain: string): boolean {
    const base = domain.trim().replace(/^\./, '').toLowerCase()
    if (!base) {
        return false
    }
    // `hostname` comes from `URL`, which has already lower-cased it.
    return hostname === base || hostname.endsWith(`.${base}`)
}

export function sanitizeRedirect(
    url: string,
    page: { origin: string; protocol: string },
    cookieDomain?: string | null,
): string | undefined {
    let resolved: URL
    try {
        resolved = new URL(url, page.origin)
    } catch {
        return undefined
    }
    if (resolved.origin === page.origin) {
        return resolved.href
    }
    if (!cookieDomain || !ABSOLUTE_HTTP_URL.test(url)) {
        return undefined
    }
    const schemeAllowed =
        resolved.protocol === 'https:' ||
        (resolved.protocol === 'http:' && page.protocol === 'http:')
    if (
        !schemeAllowed ||
        resolved.username !== '' ||
        resolved.password !== '' ||
        !hostIsUnder(resolved.hostname, cookieDomain)
    ) {
        return undefined
    }
    return resolved.href
}
