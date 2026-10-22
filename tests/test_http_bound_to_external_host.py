"""An HTTP target bound to Warpgate's own external host.

The layout where a deployment's bare host is the whole site: the target's
`external_host` is the gateway's own host (the global `external_host`, plus the
port, which a binding compares as part of the Host header). A user opens the
bare host, signs in once and lands in the target without seeing the target
list; Warpgate's own management routes stay out of reach there, and are
reached on a host bound to nothing.
"""

from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_http_common import *  # noqa
from .test_http_host_binding import _echo_target, _served_by
from .test_http_user_auth_oidc import _resolve_hosts_to_localhost
from .util import wait_port

MAIN_HOST = "warpgate.whole-site.test"
ADMIN_TOKEN = {"X-Warpgate-Token": "token-value"}
BROWSER_NAVIGATION = {
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Sec-Fetch-Mode": "navigate",
}


@pytest.fixture(scope="module")
def whole_site_wg(processes: ProcessManager):
    # Its own gateway: a target bound to the main host makes that host a bound
    # host for every test sharing the gateway.
    wg = processes.start_wg(config_patch={"external_host": MAIN_HOST})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


def test_a_target_bound_to_the_external_host_itself_is_the_whole_site(
    echo_server_port,
    whole_site_wg: WarpgateProcess,
):
    port = whole_site_wg.http_port
    main_host = f"{MAIN_HOST}:{port}"
    url = f"https://{main_host}"
    # `localhost`, which no target is bound to; setup goes through here
    # because the main host serves no admin API.
    setup_url = f"https://localhost:{port}"
    # Another name for the same Warpgate, bound to nothing.
    admin_host = f"admin-{uuid4().hex[:8]}.{MAIN_HOST}:{port}"

    with admin_client(setup_url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        api.add_user_role(user.id, role.id)
        # The user is authorized for both; one is bound to the main host.
        bound = _echo_target(api, echo_server_port, role, "bound", main_host)
        other = _echo_target(api, echo_server_port, role, "other")

    with _resolve_hosts_to_localhost(MAIN_HOST):
        # Signed out, a browser's page load is sent to the login page on the
        # same host, carrying the page it asked for.
        response = requests.get(
            f"{url}/some/page?x=1",
            headers=BROWSER_NAVIGATION,
            verify=False,
            allow_redirects=False,
        )
        assert response.status_code == 307, response.text
        assert (
            response.headers["location"]
            == "/@warpgate#/login?next=%2Fsome%2Fpage%3Fx%3D1"
        )

        # Logging in on the host (the login flow is served there) ...
        session = requests.Session()
        session.verify = False
        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code == 201, response.text

        # ... and asking for the page again is answered by the target, not
        # the target list.
        response = session.get(f"{url}/some/page?x=1", allow_redirects=False)
        assert _served_by(response) == ["bound"]
        assert response.json()["path"] == "/some/page"

        # The bound target is the whole site: another target named in the
        # query parameter is ignored.
        response = session.get(
            f"{url}/some/page?warpgate-target={other.name}",
            allow_redirects=False,
        )
        assert _served_by(response) == ["bound"]
        response = session.get(f"{url}/", allow_redirects=False)
        assert _served_by(response) == ["bound"]

        # The login flow stays served there: the session is visible.
        response = session.get(f"{url}/@warpgate/api/info")
        assert response.status_code == 200, response.text
        assert response.json()["username"] == user.username

        # Warpgate's own management routes are not: they answer 404 on the
        # bound host, whether the request carries the session, the admin
        # token or both.
        for path in [
            "/@warpgate/admin/api/users",
            "/@warpgate/admin/api/targets",
            "/@warpgate/admin",
        ]:
            for headers in [{}, ADMIN_TOKEN]:
                response = session.get(
                    f"{url}{path}", headers=headers, allow_redirects=False
                )
                assert response.status_code == 404, (
                    f"{path} {sorted(headers)}: {response.status_code}"
                )
        response = requests.get(
            f"{url}/@warpgate/admin/api/users", headers=ADMIN_TOKEN, verify=False
        )
        assert response.status_code == 404, response.status_code
        for path in [
            "/@warpgate/api/targets",
            "/@warpgate/api/profile/credentials",
        ]:
            response = session.get(f"{url}{path}", allow_redirects=False)
            assert response.status_code == 404, f"{path}: {response.status_code}"

    # On a name bound to nothing, the admin API works for an admin.
    response = requests.get(
        f"{setup_url}/@warpgate/admin/api/users",
        headers={**ADMIN_TOKEN, "Host": admin_host},
        verify=False,
    )
    assert response.status_code == 200, response.status_code
    assert bound.name in [
        target["name"]
        for target in requests.get(
            f"{setup_url}/@warpgate/admin/api/targets",
            headers={**ADMIN_TOKEN, "Host": admin_host},
            verify=False,
        ).json()
    ]


SPLIT_MAIN_HOST = "warpgate.split-site.test"
SPLIT_ADMIN_HOST = f"admin.{SPLIT_MAIN_HOST}"


@pytest.fixture(scope="module")
def split_site_wg(processes: ProcessManager):
    # The shipped layout: the global `external_host` is the bound site, and
    # `http.external_host` names the control plane, a subdomain of it. Its own
    # gateway, so it shares no target with the test above.
    wg = processes.start_wg(
        config_patch={
            "external_host": SPLIT_MAIN_HOST,
            "http": {"external_host": SPLIT_ADMIN_HOST},
        }
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


def test_an_admin_session_works_on_the_control_plane_host_and_not_on_the_bound_site(
    echo_server_port,
    split_site_wg: WarpgateProcess,
):
    port = split_site_wg.http_port
    main_host = f"{SPLIT_MAIN_HOST}:{port}"
    main_url = f"https://{main_host}"
    admin_url = f"https://{SPLIT_ADMIN_HOST}:{port}"
    setup_url = f"https://localhost:{port}"

    with admin_client(setup_url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        admin = api.create_user(sdk.CreateUserRequest(username=f"admin-{uuid4()}"))
        api.create_password_credential(
            admin.id, sdk.NewPasswordCredential(password="123")
        )
        (admin_role,) = [
            admin_role
            for admin_role in api.get_admin_roles()
            if admin_role.name == "warpgate:admin"
        ]
        api.add_user_admin_role(admin.id, admin_role.id)
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        api.add_user_role(user.id, role.id)
        _echo_target(api, echo_server_port, role, "bound", main_host)

    def login(base_url, username):
        session = requests.Session()
        session.verify = False
        response = session.post(
            f"{base_url}/@warpgate/api/auth/login",
            json={"username": username, "password": "123"},
        )
        assert response.status_code == 201, response.text
        return session

    with _resolve_hosts_to_localhost(SPLIT_MAIN_HOST, SPLIT_ADMIN_HOST):
        # An admin signs in on the control plane host; the session cookie is
        # scoped to the external host, so it is also sent to the bound site.
        session = login(admin_url, admin.username)
        response = session.get(
            f"{admin_url}/@warpgate/admin/api/users", allow_redirects=False
        )
        assert response.status_code == 200, response.text
        assert admin.username in [entry["username"] for entry in response.json()]

        # The same session does not reach the admin API on the bound site.
        response = session.get(
            f"{main_url}/@warpgate/admin/api/users", allow_redirects=False
        )
        assert response.status_code == 404, response.status_code

        # The bound site serves the target to a logged-in user.
        session = login(main_url, user.username)
        response = session.get(f"{main_url}/some/page?x=1", allow_redirects=False)
        assert _served_by(response) == ["bound"]
        assert response.json()["path"] == "/some/page"
