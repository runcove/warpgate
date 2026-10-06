from uuid import uuid4

import requests

from tests.conftest import WarpgateProcess

from .api_client import admin_client, sdk
from .test_http_common import *  # noqa


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


class Test:
    def test_a_bound_target_is_served_on_its_own_host_only(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        # The full Host header, port included, is what a binding matches.
        bound_host = f"bound-{uuid4().hex[:8]}.example:{shared_wg.http_port}"
        second_host = f"second-{uuid4().hex[:8]}.example:{shared_wg.http_port}"
        # A host no target is bound to.
        free_host = f"free-{uuid4().hex[:8]}.example:{shared_wg.http_port}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            # The user is authorized for both targets.
            bound = _echo_target(api, echo_server_port, role, "bound", bound_host)
            second = _echo_target(api, echo_server_port, role, "second", second_host)
            other = _echo_target(api, echo_server_port, role, "other")

        session = requests.Session()
        session.verify = False
        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code == 201

        on_bound_host = {"Host": bound_host}

        # Another target named in the query parameter: the bound target answers.
        response = session.get(
            f"{url}/?warpgate-target={other.name}",
            headers=on_bound_host,
            allow_redirects=False,
        )
        assert _served_by(response) == ["bound"]

        # The bound target named in the query parameter: honoured.
        response = session.get(
            f"{url}/?warpgate-target={bound.name}",
            headers=on_bound_host,
            allow_redirects=False,
        )
        assert _served_by(response) == ["bound"]

        # No query parameter: the binding.
        response = session.get(f"{url}/", headers=on_bound_host, allow_redirects=False)
        assert _served_by(response) == ["bound"]

        # Another bound target named on the bound host: the bound target.
        response = session.get(
            f"{url}/?warpgate-target={second.name}",
            headers=on_bound_host,
            allow_redirects=False,
        )
        assert _served_by(response) == ["bound"]

        # A bound target is served on its own host only: not on the main host,
        # whether named in the query parameter or remembered in the session
        # (the last request above left the bound target there).
        response = session.get(f"{url}/", allow_redirects=False)
        _refused(response)
        response = session.get(
            f"{url}/?warpgate-target={bound.name}",
            allow_redirects=False,
        )
        _refused(response)

        # Nor on a host bound to nothing.
        response = session.get(
            f"{url}/?warpgate-target={second.name}",
            headers={"Host": free_host},
            allow_redirects=False,
        )
        _refused(response)

        # On its own host it is served.
        response = session.get(
            f"{url}/?warpgate-target={second.name}",
            headers={"Host": second_host},
            allow_redirects=False,
        )
        assert _served_by(response) == ["second"]

        # A ticket for a bound target, too, is served on that target's host
        # only.
        with admin_client(url) as api:
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(target_name=bound.name, username=user.username)
            ).secret
        for host, served in ((None, False), (free_host, False), (bound_host, True)):
            ticket_session = requests.Session()
            ticket_session.verify = False
            response = ticket_session.get(
                f"{url}/?warpgate-ticket={ticket}",
                headers={"Host": host} if host else {},
                allow_redirects=False,
            )
            if served:
                assert _served_by(response) == ["bound"]
            else:
                _refused(response)

        # A target bound to no host is served on any host by the query
        # parameter, the main host included.
        response = session.get(
            f"{url}/?warpgate-target={other.name}",
            allow_redirects=False,
        )
        assert _served_by(response) == ["other"]
        response = session.get(
            f"{url}/?warpgate-target={other.name}",
            headers={"Host": free_host},
            allow_redirects=False,
        )
        assert _served_by(response) == ["other"]
