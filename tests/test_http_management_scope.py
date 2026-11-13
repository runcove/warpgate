"""Warpgate's management routes on hosts bound to an HTTP target.

A host that is some target's `external_host` serves only the gateway's assets
and the SSO return under `/@warpgate` and `/_warpgate`. The login page, the
login steps, `info`, logout, the user API and the admin API answer 404 there
and are served on every other host as before; a visitor without a session is
sent to sign in on the control-plane host.
"""

import re
from urllib.parse import unquote, urlparse
from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_http_common import *  # noqa
from .test_http_user_auth_oidc import _resolve_hosts_to_localhost
from .util import wait_port

MAIN_HOST = "warpgate.scope.test"
ADMIN_TOKEN = {"X-Warpgate-Token": "token-value"}


@pytest.fixture(scope="module")
def scoped_wg(processes: ProcessManager):
    wg = processes.start_wg(config_patch={"external_host": MAIN_HOST})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


class _Setup:
    """A user with a password, and an echo target bound to its own host
    under the main host, as cove binds a VM."""

    def __init__(self, wg: WarpgateProcess, echo_server_port: int, target_host: str):
        self.port = wg.http_port
        self.main_url = f"https://{MAIN_HOST}:{self.port}"
        self.target_host = target_host
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
            self.target = api.create_target(
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
                            external_host=f"{self.target_host}:{self.port}",
                            tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                        )
                    ),
                )
            )
            api.add_target_role(self.target.id, role.id)

    def login(self, base_url):
        session = requests.Session()
        session.verify = False
        response = session.post(
            f"{base_url}/@warpgate/api/auth/login",
            json={"username": self.user.username, "password": "123"},
        )
        assert response.status_code // 100 == 2, response.text
        return session


@pytest.fixture
def setup(scoped_wg, echo_server_port):
    target_host = f"app-{uuid4().hex[:8]}.{MAIN_HOST}"
    with _resolve_hosts_to_localhost(MAIN_HOST, target_host):
        yield _Setup(scoped_wg, echo_server_port, target_host)


class TestHTTPManagementScope:
    def test_admin_api_is_404_on_target_host(self, setup):
        for path in [
            "/@warpgate/admin/api/users",
            "/_warpgate/admin/api/users",
            "/@warpgate/admin/api/targets",
            "/@warpgate/admin",
        ]:
            response = requests.get(
                f"{setup.target_url}{path}", headers=ADMIN_TOKEN, verify=False
            )
            assert response.status_code == 404, f"{path}: {response.status_code}"

        response = requests.post(
            f"{setup.target_url}/@warpgate/admin/api/roles",
            headers=ADMIN_TOKEN,
            json={"name": f"role-{uuid4()}"},
            verify=False,
        )
        assert response.status_code == 404, response.status_code

    def test_user_api_is_404_on_target_host(self, setup):
        session = setup.login(setup.main_url)
        for method, path in [
            ("GET", "/@warpgate/api/targets"),
            ("GET", "/@warpgate/api/profile/credentials"),
            ("GET", "/@warpgate/api/profile/api-tokens"),
            ("POST", "/@warpgate/api/profile/api-tokens"),
            ("POST", "/@warpgate/api/profile/credentials/otp"),
            ("GET", "/@warpgate/api/auth/web-auth-requests"),
            ("GET", "/_warpgate/api/targets"),
        ]:
            response = session.request(method, f"{setup.target_url}{path}", json={})
            assert response.status_code == 404, (
                f"{method} {path}: {response.status_code}"
            )

    def test_session_from_main_host_works_on_target_host(self, setup):
        session = setup.login(setup.main_url)

        response = session.get(
            f"{setup.target_url}/some/path?a=b", allow_redirects=False
        )
        assert response.status_code // 100 == 2, response.status_code
        assert response.json()["path"] == "/some/path"

    def test_sign_in_routes_are_404_on_target_host(self, setup):
        # A page on the target host shares its origin: it must not read who
        # is signed in, sign the browser out, or sign it in as someone else.
        session = setup.login(setup.main_url)
        for method, path in [
            ("GET", "/@warpgate"),
            ("GET", "/@warpgate/api/info"),
            ("GET", "/_warpgate/api/info"),
            ("POST", "/@warpgate/api/auth/logout"),
            ("POST", "/@warpgate/api/auth/login"),
            ("GET", "/@warpgate/api/sso/providers"),
            ("POST", "/@warpgate/api/sso/logout"),
        ]:
            response = session.request(
                method,
                f"{setup.target_url}{path}",
                json={"username": setup.user.username, "password": "123"},
                allow_redirects=False,
            )
            assert response.status_code == 404, (
                f"{method} {path}: {response.status_code}"
            )

        # None of them reached the session: still signed in.
        response = session.get(f"{setup.main_url}/@warpgate/api/info")
        assert response.json()["username"] == setup.user.username
        response = session.get(f"{setup.target_url}/x", allow_redirects=False)
        assert response.status_code // 100 == 2, response.status_code

    def test_assets_load_on_target_host(self, setup):
        shell = requests.get(f"{setup.main_url}/@warpgate", verify=False)
        assert shell.status_code == 200
        asset = re.search(r'(?:src|href)="(/@warpgate/assets/[^"]+)"', shell.text)
        assert asset, shell.text
        response = requests.get(f"{setup.target_url}{asset.group(1)}", verify=False)
        assert response.status_code == 200, response.status_code

    def test_signed_out_visitor_is_sent_to_the_main_host_to_sign_in(self, setup):
        def sign_in_redirect(path):
            response = requests.get(
                f"{setup.target_url}{path}",
                headers={"Accept": "text/html", "Sec-Fetch-Mode": "navigate"},
                allow_redirects=False,
                verify=False,
            )
            assert response.status_code == 307, response.status_code
            login, _, next_url = response.headers["location"].partition("?next=")
            assert login == f"{setup.main_url}/@warpgate#/login", login
            return urlparse(unquote(next_url))

        next_url = sign_in_redirect("/some/page?x=1")
        assert next_url.geturl() == f"{setup.target_url}/some/page?x=1"

        # An attacker-chosen path stays a page on the target host.
        next_url = sign_in_redirect("//evil.example/x")
        assert next_url.netloc == f"{setup.target_host}:{setup.port}", next_url

    def test_admin_api_by_token_works_on_non_target_host(self, setup):
        # Cove's daemon reaches the admin API by a token on a host no target
        # is bound to.
        for url, headers in [
            (f"https://localhost:{setup.port}", ADMIN_TOKEN),
            (
                f"https://localhost:{setup.port}",
                {**ADMIN_TOKEN, "Host": f"node.scope.test:{setup.port}"},
            ),
        ]:
            response = requests.get(
                f"{url}/@warpgate/admin/api/users", headers=headers, verify=False
            )
            assert response.status_code == 200, (headers, response.status_code)

    def test_main_host_routes_unchanged(self, setup):
        response = requests.get(
            f"{setup.main_url}/@warpgate/admin/api/users",
            headers=ADMIN_TOKEN,
            verify=False,
        )
        assert response.status_code == 200

        session = setup.login(setup.main_url)
        for path in [
            "/@warpgate",
            "/@warpgate/admin",
            "/@warpgate/api/targets",
            "/_warpgate/api/targets",
        ]:
            response = session.get(f"{setup.main_url}{path}")
            assert response.status_code == 200, f"{path}: {response.status_code}"
