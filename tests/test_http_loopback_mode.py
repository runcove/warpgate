"""Loopback mode (`http.plain_http_on_loopback`).

Warpgate serves plain HTTP on 127.0.0.1. A state-changing request or
websocket upgrade, to Warpgate itself or to a proxied target, that carries
the session cookie must come from Warpgate's own origin: an `Origin` equal to
`http://127.0.0.1:<port>`, or without one `Sec-Fetch-Site: same-origin` or
`none`. Requests without the session cookie (admin tokens) are not checked. HTTP targets may be
reached through a Unix socket in a private directory.

Connections are also checked to come from the OS account Warpgate runs as;
these tests run as that account, so every connection here passes that check.
"""

import http.server
import json
import os
import shutil
import socketserver
import tempfile
import threading
from uuid import uuid4

import pytest
import requests
from websocket import WebSocketBadStatusException, create_connection

from .conftest import ProcessManager
from .test_http_common import *  # noqa
from .util import alloc_port, wait_port

ADMIN_TOKEN = {"X-Warpgate-Token": "token-value"}


@pytest.fixture(scope="module")
def loopback_wg(processes: ProcessManager):
    port = alloc_port()
    wg = processes.start_wg(
        http_port=port,
        config_patch={
            "http": {
                "listen": f"127.0.0.1:{port}",
                "plain_http_on_loopback": True,
            }
        },
    )
    wait_port(port, for_process=wg.process, recv=False)
    yield wg


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class _UnixHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(
            {"path": self.path, "host": self.headers.get("Host")}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def address_string(self):
        return "unix"

    def log_message(self, *args):
        pass


@pytest.fixture
def unix_app():
    """A tiny HTTP app on a Unix socket in a fresh 0700 directory."""
    directory = tempfile.mkdtemp(prefix="wg-uds-")
    os.chmod(directory, 0o700)
    path = os.path.join(directory, "app.sock")
    server = _UnixHTTPServer(path, _UnixHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield directory, path
    finally:
        server.shutdown()
        server.server_close()
        shutil.rmtree(directory, ignore_errors=True)


class _Setup:
    """A user allowed to reach the targets this setup creates."""

    def __init__(self, port):
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.origin = self.url
        self.other_origin = f"http://127.0.0.1:{port + 1}"
        self.role = self.admin("POST", "/roles", {"name": f"role-{uuid4()}"}).json()
        self.user = self.admin(
            "POST", "/users", {"username": f"user-{uuid4()}"}
        ).json()
        self.admin(
            "POST",
            f"/users/{self.user['id']}/credentials/passwords",
            {"password": "123"},
        )
        self.admin("POST", f"/users/{self.user['id']}/roles/{self.role['id']}")

    def admin(self, method, path, body=None, origin=True, expect_ok=True):
        headers = dict(ADMIN_TOKEN)
        if origin:
            headers["Origin"] = self.origin
        response = requests.request(
            method,
            f"{self.url}/@warpgate/admin/api{path}",
            json=body,
            headers=headers,
        )
        if expect_ok:
            assert response.status_code // 100 == 2, (
                f"{method} {path}: {response.status_code} {response.text}"
            )
        return response

    def http_target_body(self, options):
        return {
            "name": f"target-{uuid4()}",
            "require_approval": False,
            "ticket_requests_disabled": False,
            "ticket_require_approval": False,
            "options": {
                "kind": "Http",
                "headers": {},
                "tls": {"mode": "Disabled", "verify": False},
                **options,
            },
        }

    def create_target(self, options):
        target = self.admin("POST", "/targets", self.http_target_body(options)).json()
        self.admin("POST", f"/targets/{target['id']}/roles/{self.role['id']}")
        return target

    def login(self):
        session = requests.Session()
        response = session.post(
            f"{self.url}/@warpgate/api/auth/login",
            json={"username": self.user["username"], "password": "123"},
            headers={"Origin": self.origin, "Sec-Fetch-Site": "same-origin"},
        )
        assert response.status_code // 100 == 2, response.text
        return session


@pytest.fixture
def setup(loopback_wg):
    return _Setup(loopback_wg.http_port)


def _cookie_header(session):
    return "; ".join(f"{c.name}={c.value}" for c in session.cookies)


def _browser_headers(sender, origin, other_origin, mode="cors"):
    if sender == "own":
        return {
            "Origin": origin,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": mode,
            "Sec-Fetch-Dest": "empty",
        }
    if sender == "other-port":
        return {
            "Origin": other_origin,
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": mode,
            "Sec-Fetch-Dest": "empty",
        }
    if sender == "same-site-without-origin":
        return {
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": mode,
            "Sec-Fetch-Dest": "empty",
        }
    return {}


class TestHTTPLoopbackMode:
    def test_admin_api_with_a_session_cookie_needs_its_own_origin(self, setup):
        body = {"name": f"role-{uuid4()}"}
        response = setup.admin("POST", "/roles", body, expect_ok=False)
        assert response.status_code // 100 == 2, response.status_code

        # A token client: no cookie, no browser headers.
        response = setup.admin(
            "POST", "/roles", {"name": f"role-{uuid4()}"}, origin=False, expect_ok=False
        )
        assert response.status_code // 100 == 2, response.status_code

        session = setup.login()
        cookie = {"Cookie": _cookie_header(session)}
        for headers in [
            {"Origin": setup.other_origin},
            {"Sec-Fetch-Site": "same-site"},
            {},
        ]:
            response = requests.post(
                f"{setup.url}/@warpgate/admin/api/roles",
                json={"name": f"role-{uuid4()}"},
                headers={**ADMIN_TOKEN, **cookie, **headers},
            )
            assert response.status_code == 403, (headers, response.status_code)

        # Reading is not checked.
        response = requests.get(
            f"{setup.url}/@warpgate/admin/api/roles",
            headers={**ADMIN_TOKEN, "Origin": setup.other_origin},
        )
        assert response.status_code == 200

    @pytest.mark.parametrize(
        "sender,allowed",
        [
            ("own", True),
            ("other-port", False),
            ("same-site-without-origin", False),
            ("no-browser-headers", False),
        ],
    )
    def test_proxied_requests_need_its_own_origin(
        self, setup, echo_server_port, sender, allowed
    ):
        target = setup.create_target({"url": f"http://localhost:{echo_server_port}"})
        session = setup.login()
        # Selecting the target is a read, never checked.
        response = session.get(f"{setup.url}/?warpgate-target={target['name']}")
        assert response.status_code == 200, response.status_code

        headers = _browser_headers(sender, setup.origin, setup.other_origin)
        htmx = {
            "HX-Request": "true",
            "HX-Current-URL": f"{setup.url}/",
        }
        form = {"Content-Type": "application/x-www-form-urlencoded"}
        requests_to_send = [
            ("POST", "/vms/new", {**htmx, "HX-Target": "modal-container", **form}, "name=somevm"),
            ("POST", "/vms/somevm/pause", htmx, None),
            ("POST", "/vms/somevm/start", {}, None),
            ("DELETE", "/vms/somevm", {**htmx, "HX-Target": "modal-container", **form}, "name=somevm"),
        ]
        for method, path, extra, body in requests_to_send:
            response = session.request(
                method, f"{setup.url}{path}", headers={**headers, **extra}, data=body
            )
            if allowed:
                # Whatever the target answers, it was not refused by Warpgate.
                assert response.status_code != 403, (method, path)
            else:
                assert response.status_code == 403, (method, path, response.status_code)

        ws_url = f"ws://127.0.0.1:{setup.port}/socket"
        ws_headers = [
            f"{name}: {value}"
            for name, value in _browser_headers(
                sender, setup.origin, setup.other_origin, mode="websocket"
            ).items()
            if name != "Origin"
        ]
        ws_origin = {
            "own": setup.origin,
            "other-port": setup.other_origin,
        }.get(sender)
        connect = lambda: create_connection(  # noqa: E731
            ws_url,
            cookie=_cookie_header(session),
            header=ws_headers,
            origin=ws_origin,
            suppress_origin=ws_origin is None,
        )
        if allowed:
            ws = connect()
            ws.send("test")
            assert ws.recv() == "test"
            ws.close()
        else:
            with pytest.raises(WebSocketBadStatusException) as refused:
                connect()
            assert refused.value.status_code == 403

    def test_unix_socket_target(self, setup, unix_app):
        directory, path = unix_app
        target = setup.create_target(
            {"url": "http://app.local", "unix_socket": path}
        )
        session = setup.login()
        response = session.get(
            f"{setup.url}/hello?warpgate-target={target['name']}"
        )
        assert response.status_code == 200, response.text
        assert response.json() == {"path": "/hello", "host": "app.local"}

        # A directory open to others is refused at the next request.
        os.chmod(directory, 0o755)
        try:
            response = session.get(f"{setup.url}/hello")
            assert response.status_code == 502, response.status_code
        finally:
            os.chmod(directory, 0o700)

    def test_unix_socket_must_be_absolute(self, setup):
        response = setup.admin(
            "POST",
            "/targets",
            setup.http_target_body(
                {"url": "http://app.local", "unix_socket": "relative/app.sock"}
            ),
            expect_ok=False,
        )
        assert response.status_code == 400, response.status_code
