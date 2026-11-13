"""A public HTTP target, as an anonymous visitor reaches it.

A target bound to its own host with `public` on, and no approval required, is
served to anyone without a sign-in. The visitor has no cookie and keeps none:
every request is proxied on its own, the second as the first. Turning `public`
off, or requiring approval, puts the target back behind the login; Warpgate's
own routes stay what they are on any target host.
"""

import ssl
from uuid import uuid4

import pytest
import requests
from websocket import WebSocketBadStatusException, create_connection

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_http_common import *  # noqa
from .test_http_user_auth_oidc import _resolve_hosts_to_localhost
from .util import wait_port

MAIN_HOST = "warpgate.public-target.test"
BROWSER_NAVIGATION = {
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Sec-Fetch-Mode": "navigate",
}


@pytest.fixture(scope="module")
def public_wg(processes: ProcessManager):
    # Its own gateway with a dotted external host: a cookie scoped to a
    # single-label domain is one a client's cookie jar refuses to store.
    wg = processes.start_wg(config_patch={"external_host": MAIN_HOST})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


def _echo_target(
    api, echo_server_port, role, label, external_host, *, public, require_approval
):
    """An HTTP target in front of the echo server, bound to `external_host`,
    that stamps `X-Test-Target: <label>` on what it forwards."""
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"public-{label}-{uuid4()}",
            require_approval=require_approval,
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
                    public=public,
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return target


class _Setup:
    """A target bound to a host of its own, reached from a client with no
    session."""

    def __init__(
        self, wg: WarpgateProcess, echo_server_port, label, *, public, require_approval
    ):
        port = wg.http_port
        self.host = f"{label}-{uuid4().hex[:8]}.{MAIN_HOST}"
        self.label = label
        self.port = port
        self.url = f"https://{self.host}:{port}"
        with admin_client(f"https://localhost:{port}") as api:
            # A role the target is granted to, and nobody holds: what lets the
            # visitor in is `public`, not a role.
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            self.target = _echo_target(
                api,
                echo_server_port,
                role,
                label,
                f"{self.host}:{port}",
                public=public,
                require_approval=require_approval,
            )

    def get(self, path, **kwargs):
        """One request with no cookie, as a visitor's first."""
        return requests.get(
            f"{self.url}{path}", verify=False, allow_redirects=False, **kwargs
        )

    def assert_proxied(self, response, path):
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["path"] == path
        assert [
            value for name, value in body["headers"] if name == "X-Test-Target"
        ] == [self.label]

    def assert_not_proxied(self, path="/some/page"):
        """Neither a plain request nor a browser's page load reaches the
        target: the first is refused, the second is sent to the login page."""
        response = self.get(path)
        assert response.status_code == 401, response.text
        assert "X-Test-Target" not in response.text

        response = self.get(path, headers=BROWSER_NAVIGATION)
        assert response.status_code == 307, response.text
        assert response.headers["location"] == "/@warpgate#/login?next=%2Fsome%2Fpage"

    def websocket(self):
        """An anonymous upgrade to the echo server's `/socket`."""
        return create_connection(
            f"wss://{self.host}:{self.port}/socket",
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )


def test_anonymous_visitors_of_a_public_target_are_proxied_every_time(
    echo_server_port,
    public_wg: WarpgateProcess,
):
    """Guards a visitor's later requests: each anonymous request is proxied, none is refused 401."""
    setup = _Setup(
        public_wg, echo_server_port, "open", public=True, require_approval=False
    )

    with _resolve_hosts_to_localhost(MAIN_HOST, setup.host):
        # Each request carries no cookie, whatever the one before it was sent.
        for _ in range(3):
            response = setup.get("/some/page?x=1")
            setup.assert_proxied(response, "/some/page")


def test_a_target_that_is_not_public_is_not_proxied_to_anonymous_visitors(
    echo_server_port,
    public_wg: WarpgateProcess,
):
    """Guards the bypass staying off: a target with `public` off is behind the login."""
    setup = _Setup(
        public_wg, echo_server_port, "closed", public=False, require_approval=False
    )

    with _resolve_hosts_to_localhost(MAIN_HOST, setup.host):
        # Twice, as the public target is: the answer is the same every time.
        setup.assert_not_proxied()
        setup.assert_not_proxied()


def test_a_public_target_that_requires_approval_is_not_proxied_to_anonymous_visitors(
    echo_server_port,
    public_wg: WarpgateProcess,
):
    """Guards approval over `public`: one approval must not let every anonymous visitor in."""
    setup = _Setup(
        public_wg, echo_server_port, "approval", public=True, require_approval=True
    )

    with _resolve_hosts_to_localhost(MAIN_HOST, setup.host):
        setup.assert_not_proxied()
        setup.assert_not_proxied()


def test_warpgate_routes_on_a_public_targets_host_do_not_answer_as_signed_in(
    echo_server_port,
    public_wg: WarpgateProcess,
):
    """Guards the bypass stopping at the proxy: Warpgate's own API is not opened up on a public host."""
    setup = _Setup(
        public_wg, echo_server_port, "routes", public=True, require_approval=False
    )

    with _resolve_hosts_to_localhost(MAIN_HOST, setup.host):
        # The target is served, so the bypass is on for this host ...
        setup.assert_proxied(setup.get("/some/page"), "/some/page")

        # ... and the visitor is still nobody to Warpgate.
        response = setup.get("/@warpgate/api/info")
        assert response.status_code == 200, response.text
        assert response.json()["username"] is None

        # Nothing of the management or the signed-in user's API is served.
        for path in [
            "/@warpgate/admin/api/users",
            "/@warpgate/admin/api/targets",
            "/@warpgate/admin",
            "/@warpgate/api/targets",
            "/@warpgate/api/profile/credentials",
        ]:
            response = setup.get(path)
            assert response.status_code in (
                401,
                403,
                404,
            ), f"{path}: {response.status_code}"


def test_anonymous_websocket_upgrades_follow_the_public_flag(
    echo_server_port,
    public_wg: WarpgateProcess,
):
    """Guards WebSocket use of a public route: an anonymous upgrade is proxied on a public target and refused on a non-public one."""
    public = _Setup(
        public_wg, echo_server_port, "wsopen", public=True, require_approval=False
    )
    closed = _Setup(
        public_wg, echo_server_port, "wsclosed", public=False, require_approval=False
    )

    with _resolve_hosts_to_localhost(MAIN_HOST, public.host, closed.host):
        # Twice, with no cookie either time.
        for _ in range(2):
            ws = public.websocket()
            try:
                ws.send("test")
                assert ws.recv() == "test"
                ws.send_binary(b"test")
                assert ws.recv() == b"test"
            finally:
                ws.close()

        with pytest.raises(WebSocketBadStatusException) as refused:
            closed.websocket()
        assert refused.value.status_code == 401
