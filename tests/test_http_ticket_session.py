import time
from datetime import datetime, timedelta, timezone

import requests

from .api_client import admin_client, sdk
from .test_http_common import *  # noqa
from .test_login_protection import _create_test_user, _post_login


def _info_username(url, session):
    resp = session.get(f"{url}/@warpgate/api/info")
    resp.raise_for_status()
    return resp.json()["username"]


def _open_ticket_link(url, secret, session=None):
    s = session or requests.Session()
    s.verify = False
    resp = s.get(f"{url}/some/path?warpgate-ticket={secret}", allow_redirects=False)
    return resp, s


def _make_ticket(api, user, target, **kwargs):
    return api.create_ticket(
        sdk.CreateTicketRequest(
            target_name=target.name, username=user.username, **kwargs
        )
    ).secret


def test_ticket_link_does_not_replace_another_users_login(shared_wg, echo_server_port):
    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        alice, _ = _create_test_user(api, echo_server_port)
        bob, bob_target = _create_test_user(api, echo_server_port)
        secret = _make_ticket(api, bob, bob_target, number_of_uses=1)

    _, session = _post_login(url, alice.username, "correct_password")
    assert _info_username(url, session) == alice.username

    resp, _ = _open_ticket_link(url, secret, session)
    assert resp.status_code == 403
    assert _info_username(url, session) == alice.username

    # The refused link spent no use: it still opens for someone with no session.
    resp, fresh = _open_ticket_link(url, secret)
    assert resp.status_code // 100 in (2, 3)
    assert _info_username(url, fresh) == bob.username


def test_ticket_link_does_not_replace_another_tickets_session(
    shared_wg, echo_server_port
):
    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        alice, alice_target = _create_test_user(api, echo_server_port)
        bob, bob_target = _create_test_user(api, echo_server_port)
        alice_secret = _make_ticket(api, alice, alice_target)
        bob_secret = _make_ticket(api, bob, bob_target, number_of_uses=1)

    resp, session = _open_ticket_link(url, alice_secret)
    assert resp.status_code // 100 in (2, 3)
    assert _info_username(url, session) == alice.username

    resp, _ = _open_ticket_link(url, bob_secret, session)
    assert resp.status_code == 403
    assert _info_username(url, session) == alice.username

    resp, fresh = _open_ticket_link(url, bob_secret)
    assert resp.status_code // 100 in (2, 3)
    assert _info_username(url, fresh) == bob.username


def test_own_ticket_link_still_opens_for_a_signed_in_user(shared_wg, echo_server_port):
    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        alice, alice_target = _create_test_user(api, echo_server_port)
        secret = _make_ticket(api, alice, alice_target)

    _, session = _post_login(url, alice.username, "correct_password")
    resp, _ = _open_ticket_link(url, secret, session)
    assert resp.status_code // 100 in (2, 3)
    assert _info_username(url, session) == alice.username


def test_ticket_session_ends_when_its_ticket_expires(shared_wg, echo_server_port):
    url = f"https://localhost:{shared_wg.http_port}"
    expiry = datetime.now(timezone.utc) + timedelta(seconds=4)
    with admin_client(url) as api:
        alice, alice_target = _create_test_user(api, echo_server_port)
        secret = _make_ticket(api, alice, alice_target, expiry=expiry)

    resp, session = _open_ticket_link(url, secret)
    assert resp.status_code // 100 in (2, 3)
    assert session.get(f"{url}/some/path").status_code == 200

    # The ticket expires, and the expiry sweep runs every few seconds.
    deadline = time.time() + 30
    status = 200
    while time.time() < deadline and status == 200:
        time.sleep(1)
        status = session.get(f"{url}/some/path", allow_redirects=False).status_code
    assert status != 200, "the session outlived its ticket"


def _anonymous_after(url, session):
    """The cookie session answers `info` without a username and no longer
    proxies, and the same holds for the proxied path."""
    info = session.get(f"{url}/@warpgate/api/info")
    info.raise_for_status()
    assert info.json().get("username") in (None, ""), info.json()
    assert session.get(f"{url}/some/path", allow_redirects=False).status_code != 200


def test_ticket_session_is_anonymous_for_the_api_after_its_ticket_is_deleted(
    shared_wg, echo_server_port
):
    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        alice, alice_target = _create_test_user(api, echo_server_port)
        ticket = api.create_ticket(
            sdk.CreateTicketRequest(
                target_name=alice_target.name, username=alice.username
            )
        )

        resp, session = _open_ticket_link(url, ticket.secret)
        assert resp.status_code // 100 in (2, 3)
        assert _info_username(url, session) == alice.username

        api.delete_ticket(ticket.ticket.id)

    # Straight away, with no wait for the sweep.
    _anonymous_after(url, session)


def test_ticket_session_is_anonymous_for_the_api_after_its_ticket_expires(
    shared_wg, echo_server_port
):
    url = f"https://localhost:{shared_wg.http_port}"
    expiry = datetime.now(timezone.utc) + timedelta(seconds=4)
    with admin_client(url) as api:
        alice, alice_target = _create_test_user(api, echo_server_port)
        secret = _make_ticket(api, alice, alice_target, expiry=expiry)

    resp, session = _open_ticket_link(url, secret)
    assert resp.status_code // 100 in (2, 3)
    assert _info_username(url, session) == alice.username

    time.sleep(6)
    _anonymous_after(url, session)
