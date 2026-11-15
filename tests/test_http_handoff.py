"""A host bound to an HTTP target gets its own browser session through a
one-time handoff from the control-plane host (`/@warpgate/handoff/start`,
then `/@warpgate/handoff` on the bound host), and only through it.

Each browser here keeps host-only cookies to the host that set them, as a
browser does; Python's cookie jar would otherwise send them to subdomains.
"""

from contextlib import contextmanager
from http.cookiejar import DefaultCookiePolicy
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest
import requests

from tests.conftest import SERVE_UNBOUND_HTTP_TARGETS, ProcessManager, WarpgateProcess

from .api_client import admin_client, sdk
from .test_http_common import *  # noqa
from .test_http_user_auth_oidc import _resolve_hosts_to_localhost
from .util import wait_port


MAIN_HOST = "warpgate.handoff.test"
SESSION_COOKIE = "__Host-warpgate-http-session"
LEGACY_SESSION_COOKIE = "warpgate-http-session"
HANDOFF_COOKIE = "__Host-warpgate-handoff"
# What a refused redeem adds to the page it sends the browser back to.
RETRY_MARKER = "warpgate-handoff-retry=1"
# A top-level navigation, as a browser sends it.
NAVIGATE = {"Accept": "text/html", "Sec-Fetch-Mode": "navigate"}
# A background request: never sent through a handoff.
FETCH = {"Accept": "application/json"}


def _echo_target(api, echo_server_port, role, label, external_host=None):
    """An HTTP target in front of the echo server that stamps `X-Test-Target:
    <label>` on what it forwards, so a response says which target served it."""
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"echo-{label}-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    headers={"X-Test-Target": label},
                    url=f"http://localhost:{echo_server_port}",
                    tls=sdk.Tls(
                        mode=sdk.TlsMode.DISABLED,
                        verify=False,
                    ),
                    external_host=external_host,
                    public=False,
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return target


def _served_by(response):
    assert response.status_code == 200, response.text
    return [value for name, value in response.json()["headers"] if name == "X-Test-Target"]


def _refused(response):
    """No target served it: the request was sent to the target list."""
    assert response.status_code == 307, response.text
    assert response.headers["location"] == "/@warpgate"


def _browser():
    browser = requests.Session()
    browser.verify = False
    browser.cookies.set_policy(
        DefaultCookiePolicy(strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain)
    )
    return browser


def _cookie(browser, name, url):
    host = urlsplit(url).hostname
    values = [c.value for c in browser.cookies if c.name == name and c.domain == host]
    assert len(values) == 1, (name, host, values)
    return values[0]


def _bare(url, cookie=None, headers=FETCH):
    """One request with exactly the `Cookie` header given, from no browser."""
    headers = dict(headers)
    if cookie is not None:
        headers["Cookie"] = cookie
    return requests.get(url, headers=headers, verify=False, allow_redirects=False)


def _on_host(url, base_url):
    """`url` with its scheme and authority replaced by `base_url`'s."""
    parts, base = urlsplit(url), urlsplit(base_url)
    return urlunsplit((base.scheme, base.netloc, parts.path, parts.query, ""))


def _username(browser_or_cookie, main_url):
    if isinstance(browser_or_cookie, requests.Session):
        response = browser_or_cookie.get(f"{main_url}/@warpgate/api/info")
    else:
        response = _bare(f"{main_url}/@warpgate/api/info", browser_or_cookie)
    assert response.status_code == 200, response.text
    return response.json()["username"]


def hand_off(browser, main_url, bound_url, path="/"):
    """The whole handoff for a `browser` signed in on `main_url`: a
    navigation on the bound host is sent to the control plane, which sends
    the browser back with a token that gives it a session there. For other
    modules' tests; `Setup.hand_off` checks more on the way."""
    response = browser.get(f"{bound_url}{path}", headers=NAVIGATE, allow_redirects=False)
    assert response.status_code == 303, response.text
    start = response.headers["location"]
    assert start.startswith(f"{main_url}/@warpgate/handoff/start?"), start
    response = browser.get(start, headers=NAVIGATE, allow_redirects=False)
    assert response.status_code == 303, response.text
    redeem = response.headers["location"]
    assert redeem.startswith(f"{bound_url}/@warpgate/handoff?"), redeem
    response = browser.get(redeem, headers=NAVIGATE, allow_redirects=False)
    assert response.status_code == 303, response.text
    assert response.headers["location"] == f"{bound_url}{path}"


@pytest.fixture(scope="module")
def handoff_wg(processes: ProcessManager):
    # Its own gateway with a dotted external host, so target hosts can sit
    # under it as a deployment binds them.
    wg = processes.start_wg(config_patch={"external_host": MAIN_HOST})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


@pytest.fixture(scope="module")
def default_wg(processes: ProcessManager):
    # The shipped default: a web target with no hostname is not served.
    wg = processes.start_wg()
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


@pytest.fixture(scope="module")
def unbound_wg(processes: ProcessManager):
    # `http.serve_unbound_http_targets` switched on.
    wg = processes.start_wg(
        config_patch={"external_host": MAIN_HOST, **SERVE_UNBOUND_HTTP_TARGETS}
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


class Setup:
    def __init__(self, echo_server_port, wg: WarpgateProcess):
        port = wg.http_port
        tag = uuid4().hex[:8]
        self.names = [MAIN_HOST, f"a-{tag}.{MAIN_HOST}", f"b-{tag}.{MAIN_HOST}"]
        self.main_url = f"https://{MAIN_HOST}:{port}"
        self.a_url = f"https://{self.names[1]}:{port}"
        self.b_url = f"https://{self.names[2]}:{port}"
        self.echo_server_port = echo_server_port

    @contextmanager
    def hosts(self):
        with _resolve_hosts_to_localhost(*self.names):
            with admin_client(self.main_url) as api:
                self.role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
                self.a = _echo_target(
                    api, self.echo_server_port, self.role, "a", urlsplit(self.a_url).netloc
                )
                self.b = _echo_target(
                    api, self.echo_server_port, self.role, "b", urlsplit(self.b_url).netloc
                )
            yield self

    def user(self):
        with admin_client(self.main_url) as api:
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, self.role.id)
        return user

    def signed_in(self, user=None):
        """A browser signed in on the control-plane host."""
        user = user or self.user()
        browser = _browser()
        response = browser.post(
            f"{self.main_url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code == 201, response.text
        return browser, user

    def open(self, browser, bound_url, path="/page"):
        """A navigation on a bound host with no session there: the handoff is
        opened and the browser sent to the control plane's start."""
        response = browser.get(f"{bound_url}{path}", headers=NAVIGATE, allow_redirects=False)
        assert response.status_code == 303, response.text
        start = response.headers["location"]
        assert start.startswith(f"{self.main_url}/@warpgate/handoff/start?"), start
        assert response.headers["referrer-policy"] == "no-referrer"
        return start

    def start(self, browser, start, bound_url):
        """The control plane mints a token and sends the browser back."""
        response = browser.get(start, headers=NAVIGATE, allow_redirects=False)
        assert response.status_code == 303, response.text
        redeem = response.headers["location"]
        assert redeem.startswith(f"{bound_url}/@warpgate/handoff?"), redeem
        assert response.headers["referrer-policy"] == "no-referrer"
        return redeem

    def hand_off(self, browser, bound_url, label, path="/page"):
        """The whole handoff; the page is then served from the bound host."""
        redeem = self.start(browser, self.open(browser, bound_url, path), bound_url)
        response = browser.get(redeem, headers=NAVIGATE, allow_redirects=False)
        assert response.status_code == 303, response.text
        assert response.headers["location"] == f"{bound_url}{path}"
        response = browser.get(f"{bound_url}{path}", headers=FETCH, allow_redirects=False)
        assert _served_by(response) == [label]
        assert response.json()["path"] == path


@pytest.fixture
def setup(echo_server_port, handoff_wg: WarpgateProcess):
    with Setup(echo_server_port, handoff_wg).hosts() as setup:
        yield setup


def _redeem_refused(response, bound_url, page="/", spent=True):
    """A refused redeem sends the browser back to `page` on `bound_url` to
    retry once, marked as a retry. One that spent a handoff (the token was
    real) also clears the nonce cookie; one that spent nothing changes
    nothing in the browser."""
    assert response.status_code == 303, response.text
    separator = "&" if "?" in page else "?"
    assert response.headers["location"] == f"{bound_url}{page}{separator}{RETRY_MARKER}"
    assert response.headers["referrer-policy"] == "no-referrer"
    removals = response.raw.headers.getlist("Set-Cookie")
    cleared = any(
        c.startswith(f"{HANDOFF_COOKIE}=;") and "Max-Age=0" in c for c in removals
    )
    assert cleared == spent, removals


class Test:
    def test_full_flow(self, setup):
        browser, _ = setup.signed_in()
        # Before the handoff the bound host serves nothing to this browser:
        # the control-plane session never reaches it.
        response = browser.get(f"{setup.a_url}/page", headers=FETCH, allow_redirects=False)
        assert response.status_code == 401, response.text

        start = setup.open(browser, setup.a_url, "/page?x=1")
        nonce = _cookie(browser, HANDOFF_COOKIE, setup.a_url)
        assert nonce
        redeem = setup.start(browser, start, setup.a_url)
        response = browser.get(redeem, headers=NAVIGATE, allow_redirects=False)
        assert response.status_code == 303, response.text
        assert response.headers["location"] == f"{setup.a_url}/page?x=1"
        assert response.headers["referrer-policy"] == "no-referrer"
        # The nonce is spent with the token.
        assert not [c for c in browser.cookies if c.name == HANDOFF_COOKIE]

        response = browser.get(f"{setup.a_url}/page?x=1", headers=FETCH)
        assert _served_by(response) == ["a"]
        # The target sees neither the token nor a Warpgate cookie.
        echoed = response.json()
        assert "warpgate-handoff" not in echoed["args"]
        cookies = [v for n, v in echoed["headers"] if n.lower() == "cookie"]
        assert not any("warpgate" in c for c in cookies), cookies

        # The second target host needs its own handoff.
        response = browser.get(f"{setup.b_url}/page", headers=FETCH, allow_redirects=False)
        assert response.status_code == 401, response.text
        setup.hand_off(browser, setup.b_url, "b")

    def test_a_used_token_is_refused(self, setup):
        browser, _ = setup.signed_in()
        redeem = setup.start(browser, setup.open(browser, setup.a_url), setup.a_url)
        nonce = _cookie(browser, HANDOFF_COOKIE, setup.a_url)
        response = browser.get(redeem, headers=NAVIGATE, allow_redirects=False)
        assert response.status_code == 303, response.text

        # The same token again, even with the right nonce, gets nothing.
        response = _bare(redeem, f"{HANDOFF_COOKIE}={nonce}", NAVIGATE)
        _redeem_refused(response, setup.a_url, spent=False)
        assert SESSION_COOKIE not in response.cookies

        # The browser that redeemed it first keeps its session.
        response = browser.get(f"{setup.a_url}/page", headers=FETCH)
        assert _served_by(response) == ["a"]

    def test_a_token_on_the_wrong_host_is_refused(self, setup):
        # The user may use both targets and holds an opened handoff on each.
        browser, _ = setup.signed_in()
        redeem_a = setup.start(browser, setup.open(browser, setup.a_url), setup.a_url)
        setup.open(browser, setup.b_url)

        response = browser.get(
            _on_host(redeem_a, setup.b_url), headers=NAVIGATE, allow_redirects=False
        )
        _redeem_refused(response, setup.b_url)
        response = browser.get(f"{setup.b_url}/page", headers=FETCH, allow_redirects=False)
        assert response.status_code == 401, response.text

        # The token is gone after the refusal: not even its own host takes it.
        _redeem_refused(
            browser.get(redeem_a, headers=NAVIGATE, allow_redirects=False),
            setup.a_url,
            spent=False,
        )
        response = browser.get(f"{setup.a_url}/page", headers=FETCH, allow_redirects=False)
        assert response.status_code == 401, response.text

    def test_a_redeem_without_the_nonce_cookie_is_refused(self, setup):
        browser, _ = setup.signed_in()
        redeem = setup.start(browser, setup.open(browser, setup.a_url), setup.a_url)

        _redeem_refused(_bare(redeem, None, NAVIGATE), setup.a_url, "/page")

        # Refused once, refused for good.
        _redeem_refused(
            browser.get(redeem, headers=NAVIGATE, allow_redirects=False),
            setup.a_url,
            spent=False,
        )
        response = browser.get(f"{setup.a_url}/page", headers=FETCH, allow_redirects=False)
        assert response.status_code == 401, response.text

    def test_someone_elses_link_is_refused(self, setup):
        # Another browser opens a handoff and passes its start link on.
        other = _browser()
        start = setup.open(other, setup.a_url)
        other_nonce = _cookie(other, HANDOFF_COOKIE, setup.a_url)

        # The signed-in victim holds a nonce of its own for that host.
        victim, _ = setup.signed_in()
        setup.open(victim, setup.a_url)
        redeem = setup.start(victim, start, setup.a_url)
        _redeem_refused(
            victim.get(redeem, headers=NAVIGATE, allow_redirects=False),
            setup.a_url,
            "/page",
        )
        response = victim.get(f"{setup.a_url}/page", headers=FETCH, allow_redirects=False)
        assert response.status_code == 401, response.text

        # Nor does the token minted for the victim work in the browser that
        # started the handoff.
        response = _bare(redeem, f"{HANDOFF_COOKIE}={other_nonce}", NAVIGATE)
        _redeem_refused(response, setup.a_url, spent=False)
        assert SESSION_COOKIE not in response.cookies

    def test_logout_on_a_host_ends_that_host_only(self, setup):
        browser, user = setup.signed_in()
        setup.hand_off(browser, setup.a_url, "a")
        setup.hand_off(browser, setup.b_url, "b")

        response = browser.post(
            f"{setup.a_url}/@warpgate/api/auth/logout",
            headers={"Origin": setup.a_url, "Sec-Fetch-Site": "same-origin"},
        )
        assert response.status_code // 100 == 2, response.text
        response = browser.get(f"{setup.a_url}/page", headers=FETCH, allow_redirects=False)
        assert response.status_code == 401, response.text
        response = browser.get(f"{setup.b_url}/page", headers=FETCH)
        assert _served_by(response) == ["b"]
        assert _username(browser, setup.main_url) == user.username

        # Still signed in on the control plane: a new visit hands off again
        # with no sign-in.
        setup.hand_off(browser, setup.a_url, "a")

    def test_logout_on_the_control_plane_ends_every_host(self, setup):
        browser, _ = setup.signed_in()
        setup.hand_off(browser, setup.a_url, "a")
        setup.hand_off(browser, setup.b_url, "b")

        response = browser.post(
            f"{setup.main_url}/@warpgate/api/auth/logout",
            headers={"Origin": setup.main_url, "Sec-Fetch-Site": "same-origin"},
        )
        assert response.status_code // 100 == 2, response.text
        assert _username(browser, setup.main_url) is None
        for bound_url in (setup.a_url, setup.b_url):
            response = browser.get(f"{bound_url}/page", headers=FETCH, allow_redirects=False)
            assert response.status_code == 401, (bound_url, response.text)

        # A new visit is sent to sign in, not handed a session.
        start = setup.open(browser, setup.a_url)
        response = browser.get(start, headers=NAVIGATE, allow_redirects=False)
        assert response.status_code // 100 == 3, response.text
        assert "/@warpgate/handoff?" not in response.headers["location"]

    def test_a_session_counts_only_where_it_was_handed_off(self, setup):
        browser, _ = setup.signed_in()
        main_session = _cookie(browser, SESSION_COOKIE, setup.main_url)
        # The control-plane session, presented on a bound host, is not served.
        response = _bare(f"{setup.a_url}/page", f"{SESSION_COOKIE}={main_session}")
        assert response.status_code == 401, response.text

        setup.hand_off(browser, setup.a_url, "a")
        a_session = _cookie(browser, SESSION_COOKIE, setup.a_url)
        # The host's session, presented on another bound host or on the
        # control plane, is not served there either.
        response = _bare(f"{setup.b_url}/page", f"{SESSION_COOKIE}={a_session}")
        assert response.status_code == 401, response.text
        assert _username(f"{SESSION_COOKIE}={a_session}", setup.main_url) is None
        # On its own host it is.
        response = _bare(f"{setup.a_url}/page", f"{SESSION_COOKIE}={a_session}")
        assert _served_by(response) == ["a"]

    @pytest.mark.parametrize(
        "encoded_name",
        ["%77arpgate-http-session", "%5F%5FHost-warpgate-http-session"],
    )
    def test_an_encoded_cookie_name_is_never_the_session(self, setup, encoded_name):
        planted_browser, planted_user = setup.signed_in()
        planted = _cookie(planted_browser, SESSION_COOKIE, setup.main_url)
        victim_browser, victim = setup.signed_in()
        own = _cookie(victim_browser, SESSION_COOKIE, setup.main_url)

        # Alone, it signs nobody in.
        assert _username(f"{encoded_name}={planted}", setup.main_url) is None
        # Ahead of the browser's own cookie, it changes nothing.
        cookie = f"{encoded_name}={planted}; {SESSION_COOKIE}={own}"
        assert _username(cookie, setup.main_url) == victim.username
        assert _username(planted_browser, setup.main_url) == planted_user.username

    def test_the_legacy_domain_cookie_is_expired_and_never_read(self, setup):
        browser, _ = setup.signed_in()
        session = _cookie(browser, SESSION_COOKIE, setup.main_url)

        response = _bare(
            f"{setup.main_url}/@warpgate/api/info",
            f"{LEGACY_SESSION_COOKIE}={session}",
        )
        assert response.status_code == 200, response.text
        assert response.json()["username"] is None
        removals = [
            c
            for c in response.raw.headers.getlist("Set-Cookie")
            if c.startswith(f"{LEGACY_SESSION_COOKIE}=;")
        ]
        assert removals, response.raw.headers.getlist("Set-Cookie")
        assert all("Max-Age=0" in c for c in removals), removals
        assert any(f"Domain=.{MAIN_HOST}" in c for c in removals), removals


class TestUnboundTargets:
    def _unbound(self, url, echo_server_port):
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            target = _echo_target(api, echo_server_port, role, "unbound")
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(target_name=target.name, username=user.username)
            ).secret
        session = requests.Session()
        session.verify = False
        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code == 201
        return session, target, ticket

    def test_a_target_with_no_hostname_is_refused_by_default(
        self, echo_server_port, default_wg: WarpgateProcess
    ):
        url = f"https://localhost:{default_wg.http_port}"
        session, target, ticket = self._unbound(url, echo_server_port)
        _refused(session.get(f"{url}/?warpgate-target={target.name}", allow_redirects=False))
        ticket_session = requests.Session()
        ticket_session.verify = False
        _refused(
            ticket_session.get(f"{url}/?warpgate-ticket={ticket}", allow_redirects=False)
        )

    def test_a_target_with_no_hostname_is_served_when_switched_on(
        self, echo_server_port, unbound_wg: WarpgateProcess
    ):
        url = f"https://{MAIN_HOST}:{unbound_wg.http_port}"
        with _resolve_hosts_to_localhost(MAIN_HOST):
            session, target, _ = self._unbound(url, echo_server_port)
            response = session.get(
                f"{url}/?warpgate-target={target.name}", allow_redirects=False
            )
            assert _served_by(response) == ["unbound"]
