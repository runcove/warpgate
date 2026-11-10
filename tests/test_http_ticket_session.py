import time
from datetime import datetime, timedelta, timezone

import pyotp
import requests
from base64 import b64decode

from .api_client import admin_client, sdk
from .test_http_common import *  # noqa
from .conftest import ProcessManager
from .test_login_protection import _create_test_user, _lp_wg, _post_login


def _info_username(url, session):
    resp = session.get(f"{url}/@warpgate/api/info")
    resp.raise_for_status()
    return resp.json()["username"]


def _open_ticket_link(url, secret, session=None):
    s = session or requests.Session()
    s.verify = False
    resp = s.get(f"{url}/some/path?warpgate-ticket={secret}", allow_redirects=False)
    return resp, s


def _signed_in(url, user):
    _, session = _post_login(url, user.username, "correct_password")
    return session


def _same_answer(a, b):
    """Two responses a client cannot tell apart: status, redirect target,
    whether a session cookie is set, and the referrer policy."""
    return _answer_shape(a) == _answer_shape(b)


def _answer_shape(resp):
    return (
        resp.status_code,
        resp.headers.get("Location"),
        "Set-Cookie" in resp.headers,
        resp.headers.get("Referrer-Policy"),
    )


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
    unknown, _ = _open_ticket_link(url, "not-a-real-ticket", _signed_in(url, alice))
    assert _same_answer(resp, unknown)
    assert _info_username(url, session) == alice.username

    # The ignored link spent no use: it still opens for someone with no session.
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
    resp_unknown, _ = _open_ticket_link(url, "not-a-real-ticket", session)
    assert _same_answer(resp, resp_unknown)
    assert _info_username(url, session) == alice.username

    resp, fresh = _open_ticket_link(url, bob_secret)
    assert resp.status_code // 100 in (2, 3)
    assert _info_username(url, fresh) == bob.username


PAGE_LOAD = {
    "Accept": "text/html",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
}


def _page_load_with_ticket(url, secret, session):
    return session.get(
        f"{url}/some/path?a=1&warpgate-ticket={secret}",
        headers=PAGE_LOAD,
        allow_redirects=False,
    )


def test_another_users_ticket_is_answered_like_an_unknown_one(
    shared_wg, echo_server_port
):
    """A signed-in browser opening a real ticket of someone else gets the
    answer an unknown ticket gets, so the page does not confirm the ticket."""
    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        alice, _ = _create_test_user(api, echo_server_port)
        bob, bob_target = _create_test_user(api, echo_server_port)
        real = _make_ticket(api, bob, bob_target, number_of_uses=1)

    def answer(secret):
        _, session = _post_login(url, alice.username, "correct_password")
        resp = _page_load_with_ticket(url, secret, session)
        assert _info_username(url, session) == alice.username
        return _answer_shape(resp), resp.text

    assert answer(real) == answer("not-a-real-ticket")

    # A browser page load is sent to the address without the ticket, so the
    # other user's unspent ticket stays out of this browser's history.
    (status, location, _, policy), _ = answer(real)
    assert status == 303
    assert location == "/some/path?a=1"
    assert policy == "no-referrer"

    # No use was spent.
    resp, fresh = _open_ticket_link(url, real)
    assert resp.status_code // 100 in (2, 3)
    assert _info_username(url, fresh) == bob.username


def test_ticket_link_does_not_replace_a_login_waiting_on_its_second_factor(
    shared_wg, echo_server_port, otp_key_base32, otp_key_base64
):
    """A sign-in that has passed the password and waits for the one-time code
    is kept when another user's ticket is opened in that browser, and the
    answer is the one an unknown ticket gets."""
    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        alice, _ = _create_test_user(api, echo_server_port)
        api.create_otp_credential(
            alice.id,
            sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64))),
        )
        api.update_user(
            alice.id,
            sdk.UserDataRequest(
                username=alice.username,
                credential_policy=sdk.UserRequireCredentialsPolicy(
                    http=["Password", "Totp"]
                ),
            ),
        )
        bob, bob_target = _create_test_user(api, echo_server_port)
        secret = _make_ticket(api, bob, bob_target, number_of_uses=1)

    def waiting_on_code():
        resp, session = _post_login(url, alice.username, "correct_password")
        assert resp.status_code // 100 != 2
        return session

    session = waiting_on_code()
    resp = _page_load_with_ticket(url, secret, session)
    other_session = waiting_on_code()
    unknown = _page_load_with_ticket(url, "not-a-real-ticket", other_session)
    assert _same_answer(resp, unknown)

    # The sign-in is still waiting, and finishes as its own user.
    resp = session.post(
        f"{url}/@warpgate/api/auth/otp", json={"otp": pyotp.TOTP(otp_key_base32).now()}
    )
    assert resp.status_code // 100 == 2
    assert _info_username(url, session) == alice.username

    # No use was spent.
    resp, fresh = _open_ticket_link(url, secret)
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
    proxies: a request with no auth to a target answers 401 (`page_auth` hands
    it to `gateway_redirect`, which redirects only navigations, those that
    accept text/html; requests sends `Accept: */*`, so it gets the 401)."""
    info = session.get(f"{url}/@warpgate/api/info")
    info.raise_for_status()
    assert info.json().get("username") in (None, ""), info.json()
    assert session.get(f"{url}/some/path", allow_redirects=False).status_code == 401


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
    expiry = datetime.now(timezone.utc) + timedelta(seconds=6)
    with admin_client(url) as api:
        alice, alice_target = _create_test_user(api, echo_server_port)
        secret = _make_ticket(api, alice, alice_target, expiry=expiry)

    resp, session = _open_ticket_link(url, secret)
    assert resp.status_code // 100 in (2, 3)
    assert _info_username(url, session) == alice.username

    # Check within 0.3 s of the expiry, so the 5 s expiry sweep has rarely
    # run yet and the per-request re-check is what ends the session.
    time.sleep(max(0, (expiry - datetime.now(timezone.utc)).total_seconds()) + 0.3)
    _anonymous_after(url, session)


def test_ticket_session_is_anonymous_after_its_user_is_restricted_to_other_addresses(
    shared_wg, echo_server_port
):
    """The user's allowed IP ranges are judged on each request of a ticket
    session, as they were when the session started."""
    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        alice, alice_target = _create_test_user(api, echo_server_port)
        secret = _make_ticket(api, alice, alice_target)

        resp, session = _open_ticket_link(url, secret)
        assert resp.status_code // 100 in (2, 3)
        assert _info_username(url, session) == alice.username

        # The update replaces every field it carries (absent fields are
        # cleared), so send back what the user has now with only the ranges
        # changed.
        current = api.get_user(alice.id)
        current = getattr(current, "inner", current)
        # Still signed in, from loopback, with no ranges set.
        assert _info_username(url, session) == alice.username
        # A range the test client (loopback) is not in.
        api.update_user(
            alice.id,
            sdk.UserDataRequest(
                username=current.username,
                description=current.description,
                credential_policy=current.credential_policy,
                rate_limit_bytes_per_second=current.rate_limit_bytes_per_second,
                allowed_ip_ranges=["192.0.2.0/24"],
            ),
        )

    _anonymous_after(url, session)


def _still_signed_in(url, session, username):
    assert _info_username(url, session) == username
    assert session.get(f"{url}/some/path", allow_redirects=False).status_code != 401


def _refused_ticket_link(url, secret):
    resp, fresh = _open_ticket_link(url, secret)
    assert resp.status_code // 100 != 2, "the ticket link opened"
    info = fresh.get(f"{url}/@warpgate/api/info")
    info.raise_for_status()
    assert info.json().get("username") in (None, ""), info.json()


def test_ticket_session_survives_its_user_being_locked(
    processes: ProcessManager, echo_server_port
):
    """An automatic lockout refuses new sign-ins and ticket use but does not
    end a session that is already signed in."""
    wg = _lp_wg(processes, ip_max=100, user_max=3)
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        alice, alice_target = _create_test_user(api, echo_server_port)
        secret = _make_ticket(api, alice, alice_target)

    resp, session = _open_ticket_link(url, secret)
    assert resp.status_code // 100 in (2, 3)
    _still_signed_in(url, session, alice.username)

    for _ in range(3):
        _post_login(url, alice.username, "wrong")
    time.sleep(0.2)

    # The live session carries on ...
    for _ in range(3):
        _still_signed_in(url, session, alice.username)
    # ... while a new sign-in and a new use of the ticket are refused.
    resp, fresh = _post_login(url, alice.username, "correct_password")
    assert resp.status_code // 100 != 2
    _refused_ticket_link(url, secret)


def test_ticket_session_survives_its_address_being_blocked(
    processes: ProcessManager, echo_server_port
):
    """An address block refuses new sign-ins and ticket use from that address
    but does not end a session that is already signed in."""
    wg = _lp_wg(processes, ip_max=3, user_max=100)
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        alice, alice_target = _create_test_user(api, echo_server_port)
        secret = _make_ticket(api, alice, alice_target)

    resp, session = _open_ticket_link(url, secret)
    assert resp.status_code // 100 in (2, 3)
    _still_signed_in(url, session, alice.username)

    # Loopback is not exempt by default, so three failed logins from here
    # block this address.
    for _ in range(3):
        _post_login(url, alice.username, "wrong")
    time.sleep(0.2)

    for _ in range(3):
        _still_signed_in(url, session, alice.username)
    resp, _ = _post_login(url, alice.username, "correct_password")
    assert resp.json().get("state") == "IpBlocked", resp.text
    _refused_ticket_link(url, secret)
