"""End-to-end evidence that a request's query values stay out of the log.

The unit tests in `warpgate-common-http/src/logging.rs` and
`warpgate-protocol-http/src/proxy.rs` pin the logged forms directly. This one
goes through a real warpgate process: a WebSocket upgrade and a request to a
target that is down, each carrying a distinctive value in its query, and then
reads the process log. Each half also asserts that the line it is about was
written, so a test that logged nothing cannot pass.
"""

import ssl
import time
from pathlib import Path
from uuid import uuid4

import requests
from websocket import create_connection

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_http_common import *  # noqa
from .test_http_error_disclosure import _start_wg_with_log
from .util import alloc_port

WS_SENTINEL = "ws-sentinel-5f0c2a"
HTTP_SENTINEL = "http-sentinel-b81e47"


def _http_target(api, role, name, url):
    target = api.create_target(
        sdk.TargetDataRequest(
            name=name,
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    headers={},
                    url=url,
                    tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return target


def _wait_for_log(log_path: Path, needles, deadline: float = 5.0) -> str:
    end = time.time() + deadline
    text = ""
    while time.time() < end:
        text = log_path.read_text(errors="replace")
        if all(needle in text for needle in needles):
            break
        time.sleep(0.2)
    return text


class TestHTTPQueryLog:
    def test_query_values_never_reach_the_log(
        self,
        echo_server_port,
        processes: ProcessManager,
        tmp_path: Path,
    ):
        wg, log_path = _start_wg_with_log(processes, tmp_path, {})
        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            echo = _http_target(
                api, role, f"echo-{uuid4()}", f"http://localhost:{echo_server_port}"
            )
            # Nothing listens here: the request fails at the gateway.
            dead = _http_target(
                api, role, f"dead-{uuid4()}", f"http://localhost:{alloc_port()}"
            )

        session = requests.Session()
        session.verify = False
        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        cookie = "; ".join(f"{k}={v}" for k, v in session.cookies.get_dict().items())

        ws = create_connection(
            f"wss://localhost:{wg.http_port}/socket"
            f"?warpgate-target={echo.name}&access_token={WS_SENTINEL}",
            cookie=cookie,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
        ws.send("test")
        assert ws.recv() == "test"
        ws.close()

        response = session.get(
            f"{url}/x?warpgate-target={dead.name}&access_token={HTTP_SENTINEL}"
        )
        assert response.status_code == 502, response.text

        log = _wait_for_log(log_path, ["- WebSocket", "Request failed"])
        # The lines this is about were written, with the key and not the value.
        assert "- WebSocket" in log
        assert "Request failed" in log
        assert "access_token=redacted" in log
        assert WS_SENTINEL not in log
        assert HTTP_SENTINEL not in log
