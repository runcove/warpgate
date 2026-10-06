"""The Origin check on state-changing management requests.

A state-changing request under `/@warpgate` or `/_warpgate` (and a websocket
upgrade there) that carries an `Origin` must come from the main host's
origin, or from the request's own origin on a login-flow route. Clients that
send no browser headers - the SDK, the CLI, cove - are not affected, and the
IdP's form_post to the SSO return route is exempt.
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

MAIN_HOST = "warpgate.origin.test"
FOREIGN_ORIGIN = "https://elsewhere.example"
ADMIN_TOKEN = {"X-Warpgate-Token": "token-value"}


@pytest.fixture(scope="module")
def origin_wg(processes: ProcessManager):
    wg = processes.start_wg(config_patch={"external_host": MAIN_HOST})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


class _Setup:
    """A user with a password, and an echo target bound to its own host
    under the main host."""

    def __init__(self, wg: WarpgateProcess, echo_server_port: int, target_host: str):
        self.port = wg.http_port
        self.main_url = f"https://{MAIN_HOST}:{self.port}"
        self.main_origin = self.main_url
        self.target_url = f"https://{target_host}:{self.port}"
        with admin_client(self.main_url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            self.user = api.create_user(
                sdk.CreateUserRequest(username=f"user-{uuid4()}")
            )
            api.create_password_credential(
                self.user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(self.user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"echo-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            headers={},
                            url=f"http://localhost:{echo_server_port}",
                            external_host=f"{target_host}:{self.port}",
                            tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

    def login(self, base_url, origin=None):
        session = requests.Session()
        session.verify = False
        headers = {"Origin": origin} if origin else {}
        response = session.post(
            f"{base_url}/@warpgate/api/auth/login",
            json={"username": self.user.username, "password": "123"},
            headers=headers,
        )
        return session, response

    def create_role(self, origin=None):
        headers = dict(ADMIN_TOKEN)
        if origin:
            headers["Origin"] = origin
        return requests.post(
            f"{self.main_url}/@warpgate/admin/api/roles",
            json={"name": f"role-{uuid4()}"},
            headers=headers,
            verify=False,
        )


@pytest.fixture
def setup(origin_wg, echo_server_port):
    target_host = f"app-{uuid4().hex[:8]}.{MAIN_HOST}"
    with _resolve_hosts_to_localhost(MAIN_HOST, target_host):
        yield _Setup(origin_wg, echo_server_port, target_host)


def _cookie_header(session):
    return "; ".join(f"{c.name}={c.value}" for c in session.cookies)


class TestHTTPOriginCheck:
    def test_state_change_with_foreign_origin_is_refused(self, setup):
        response = setup.create_role(origin=FOREIGN_ORIGIN)
        assert response.status_code == 403, response.status_code

        session, response = setup.login(setup.main_url)
        assert response.status_code // 100 == 2, response.text
        for method, path in [
            ("POST", "/@warpgate/api/auth/logout"),
            ("POST", "/_warpgate/api/auth/logout"),
            ("DELETE", "/@warpgate/api/auth/state"),
            ("POST", "/@warpgate/api/profile/api-tokens"),
        ]:
            response = session.request(
                method,
                f"{setup.main_url}{path}",
                headers={"Origin": FOREIGN_ORIGIN},
                json={},
            )
            assert response.status_code == 403, (
                f"{method} {path}: {response.status_code}"
            )

        # Fetch Metadata stands in for a missing Origin.
        response = session.post(
            f"{setup.main_url}/@warpgate/api/auth/logout",
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert response.status_code == 403, response.status_code

        # Still logged in: none of the refused requests reached the handler.
        response = session.get(f"{setup.main_url}/@warpgate/api/info")
        assert response.json()["username"] == setup.user.username

    def test_state_change_with_main_origin_is_allowed(self, setup):
        response = setup.create_role(origin=setup.main_origin)
        assert response.status_code // 100 == 2, response.status_code

        session, response = setup.login(setup.main_url, origin=setup.main_origin)
        assert response.status_code // 100 == 2, response.text
        response = session.post(
            f"{setup.main_url}/@warpgate/api/auth/logout",
            headers={"Origin": setup.main_origin, "Sec-Fetch-Site": "same-origin"},
        )
        assert response.status_code // 100 == 2, response.status_code

    def test_login_post_with_own_origin_on_target_host_is_allowed(self, setup):
        own_origin = setup.target_url
        session, response = setup.login(setup.target_url, origin=own_origin)
        assert response.status_code // 100 == 2, response.text

        response = session.get(f"{setup.target_url}/@warpgate/api/info")
        assert response.json()["username"] == setup.user.username

        response = session.post(
            f"{setup.target_url}/@warpgate/api/auth/logout",
            headers={"Origin": own_origin},
        )
        assert response.status_code // 100 == 2, response.status_code

        # Another origin is refused even on a login route.
        _, response = setup.login(setup.target_url, origin=FOREIGN_ORIGIN)
        assert response.status_code == 403, response.status_code

    def test_sdk_client_without_origin_is_allowed(self, setup):
        response = setup.create_role()
        assert response.status_code // 100 == 2, response.status_code

        with admin_client(setup.main_url) as api:
            api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))

    def test_websocket_stream_with_foreign_origin_is_refused(self, setup):
        session, response = setup.login(setup.main_url)
        assert response.status_code // 100 == 2, response.text
        url = (
            f"wss://{MAIN_HOST}:{setup.port}"
            "/@warpgate/api/auth/web-auth-requests/stream"
        )
        sslopt = {"cert_reqs": ssl.CERT_NONE}
        cookie = _cookie_header(session)

        with pytest.raises(WebSocketBadStatusException) as refused:
            create_connection(
                url, cookie=cookie, origin=FOREIGN_ORIGIN, sslopt=sslopt
            )
        assert refused.value.status_code == 403

        ws = create_connection(
            url, cookie=cookie, origin=setup.main_origin, sslopt=sslopt
        )
        ws.close()
