from uuid import uuid4

import pytest
import requests

from tests.conftest import SERVE_UNBOUND_HTTP_TARGETS, ProcessManager, WarpgateProcess

from .api_client import admin_client, sdk
from .test_http_common import *  # noqa
from .test_http_handoff import FETCH, _browser, hand_off as _hand_off
from .test_http_user_auth_oidc import _resolve_hosts_to_localhost
from .util import wait_port


def _echo_request(echo_server_port, name, label, external_host=None):
    return sdk.TargetDataRequest(
        name=name,
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


def _echo_target(api, echo_server_port, role, label, external_host=None):
    """An HTTP target in front of the echo server that stamps `X-Test-Target:
    <label>` on what it forwards, so a response says which target served it."""
    target = api.create_target(
        _echo_request(echo_server_port, f"echo-{label}-{uuid4()}", label, external_host)
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


MAIN_HOST = "warpgate.binding.test"


@pytest.fixture(scope="module")
def binding_wg(processes: ProcessManager):
    # Its own gateway with a dotted external host: a cookie scoped to a
    # single-label domain (shared_wg's `external-host`) is one a client's
    # cookie jar refuses to store.
    # It opens a target with no hostname by name.
    wg = processes.start_wg(
        config_patch={"external_host": MAIN_HOST, **SERVE_UNBOUND_HTTP_TARGETS}
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


class Test:
    def test_a_bound_target_is_served_on_its_own_host_only(
        self,
        echo_server_port,
        binding_wg: WarpgateProcess,
    ):
        port = binding_wg.http_port
        # Target hosts sit under Warpgate's external host, as a deployment
        # binds them, and every host is reached by its own URL, as a browser
        # reaches it: the user logs in on the main host (a bound host serves
        # no login), and each target host gets its own session through a
        # handoff. The full Host header, port included, is what a binding
        # matches.
        tag = uuid4().hex[:8]
        bound_name = f"bound-{tag}.{MAIN_HOST}"
        second_name = f"second-{tag}.{MAIN_HOST}"
        # A host under the external host that no target is bound to.
        free_name = f"free-{tag}.{MAIN_HOST}"
        bound_host = f"{bound_name}:{port}"
        second_host = f"{second_name}:{port}"
        free_host = f"{free_name}:{port}"
        url = f"https://{MAIN_HOST}:{port}"
        bound_url = f"https://{bound_host}"
        second_url = f"https://{second_host}"
        free_url = f"https://{free_host}"

        with _resolve_hosts_to_localhost(MAIN_HOST, bound_name, second_name, free_name):
            self._check(echo_server_port, url, bound_url, second_url, free_url)

    def _check(self, echo_server_port, url, bound_url, second_url, free_url):
        bound_host = bound_url.removeprefix("https://")
        second_host = second_url.removeprefix("https://")

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

        session = _browser()
        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code == 201

        # The main host's session counts there only: a bound host serves
        # nothing to it until the browser hands off.
        response = session.get(f"{bound_url}/", headers=FETCH, allow_redirects=False)
        assert response.status_code == 401, response.text
        _hand_off(session, url, bound_url)
        _hand_off(session, url, second_url)

        # Another target named in the query parameter: the bound target answers.
        response = session.get(
            f"{bound_url}/?warpgate-target={other.name}",
            allow_redirects=False,
        )
        assert _served_by(response) == ["bound"]

        # The bound target named in the query parameter: honoured.
        response = session.get(
            f"{bound_url}/?warpgate-target={bound.name}",
            allow_redirects=False,
        )
        assert _served_by(response) == ["bound"]

        # No query parameter: the binding.
        response = session.get(f"{bound_url}/", allow_redirects=False)
        assert _served_by(response) == ["bound"]

        # Another bound target named on the bound host: the bound target.
        response = session.get(
            f"{bound_url}/?warpgate-target={second.name}",
            allow_redirects=False,
        )
        assert _served_by(response) == ["bound"]

        # A bound target is served on its own host only: not on the main host,
        # whether remembered in the session or named in the query parameter.
        # The main host's session remembers a target only once it served it
        # there, so `late` is served unbound first, then bound.
        late_name = f"echo-late-{uuid4()}"
        late_host = f"late-{uuid4().hex[:8]}.{MAIN_HOST}"
        with admin_client(url) as api:
            late = api.create_target(_echo_request(echo_server_port, late_name, "late"))
            api.add_target_role(late.id, role.id)
        response = session.get(f"{url}/?warpgate-target={late.name}", allow_redirects=False)
        assert _served_by(response) == ["late"]
        with admin_client(url) as api:
            api.update_target(
                late.id, _echo_request(echo_server_port, late_name, "late", late_host)
            )
        response = session.get(f"{url}/", allow_redirects=False)
        _refused(response)
        response = session.get(
            f"{url}/?warpgate-target={bound.name}",
            allow_redirects=False,
        )
        _refused(response)

        # Nor on a host bound to nothing, where the browser has no session.
        response = session.get(
            f"{free_url}/?warpgate-target={second.name}",
            headers=FETCH,
            allow_redirects=False,
        )
        assert response.status_code == 401, response.text

        # On its own host it is served.
        response = session.get(
            f"{second_url}/?warpgate-target={second.name}",
            allow_redirects=False,
        )
        assert _served_by(response) == ["second"]

        # A ticket for a bound target, too, is served on that target's host
        # only.
        with admin_client(url) as api:
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(target_name=bound.name, username=user.username)
            ).secret
        for base_url, served in ((url, False), (free_url, False), (bound_url, True)):
            ticket_session = requests.Session()
            ticket_session.verify = False
            response = ticket_session.get(
                f"{base_url}/?warpgate-ticket={ticket}",
                allow_redirects=False,
            )
            if served:
                assert _served_by(response) == ["bound"]
            else:
                _refused(response)

        # With `http.serve_unbound_http_targets` on, a ticket for a target
        # bound to no host is served on a host no target
        # is bound to, and not on a bound host, whose origin it would share.
        with admin_client(url) as api:
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(target_name=other.name, username=user.username)
            ).secret
        for base_url, served in ((url, True), (free_url, True), (bound_url, False)):
            ticket_session = requests.Session()
            ticket_session.verify = False
            response = ticket_session.get(
                f"{base_url}/?warpgate-ticket={ticket}",
                allow_redirects=False,
            )
            if served:
                assert _served_by(response) == ["other"]
            else:
                _refused(response)

        # A target bound to no host is served by the query parameter on the
        # main host, with `http.serve_unbound_http_targets` on. A host bound
        # to nothing holds no session of the main host's.
        response = session.get(
            f"{url}/?warpgate-target={other.name}",
            allow_redirects=False,
        )
        assert _served_by(response) == ["other"]
        response = session.get(
            f"{free_url}/?warpgate-target={other.name}",
            headers=FETCH,
            allow_redirects=False,
        )
        assert response.status_code == 401, response.text
