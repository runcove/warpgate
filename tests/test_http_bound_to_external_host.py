"""HTTP targets and Warpgate's own external host.

A target may not be bound to the control-plane host, at any port: that host
would share its cookies with the target's pages. The supported layout binds
the site to the global `external_host` and names the control plane with
`http.external_host`, a different hostname (the split layout below).
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


@pytest.fixture(scope="module")
def whole_site_wg(processes: ProcessManager):
    # The control plane is the global `external_host` (no `http.external_host`).
    wg = processes.start_wg(config_patch={"external_host": MAIN_HOST})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


def test_a_target_cannot_be_bound_to_the_control_plane_host(
    echo_server_port,
    whole_site_wg: WarpgateProcess,
):
    port = whole_site_wg.http_port
    setup_url = f"https://localhost:{port}"
    with admin_client(setup_url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        for binding in [f"{MAIN_HOST}:{port}", MAIN_HOST, f"{MAIN_HOST.upper()}:8443"]:
            with pytest.raises(sdk.ApiException) as e:
                _echo_target(api, echo_server_port, role, "bound", binding)
            assert e.value.status == 409, binding
            assert "own host" in e.value.body, binding


def test_a_hostname_is_bound_to_one_target_whatever_the_port(
    echo_server_port,
    whole_site_wg: WarpgateProcess,
):
    port = whole_site_wg.http_port
    setup_url = f"https://localhost:{port}"
    name = f"vm-{uuid4().hex[:8]}.{MAIN_HOST}"
    with admin_client(setup_url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        first = _echo_target(api, echo_server_port, role, "first", f"{name}:{port}")
        for binding in [f"{name}:{port}", f"{name}:8443", name, name.upper()]:
            with pytest.raises(sdk.ApiException) as e:
                _echo_target(api, echo_server_port, role, "second", binding)
            assert e.value.status == 409, binding
            assert first.name in e.value.body, binding


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
