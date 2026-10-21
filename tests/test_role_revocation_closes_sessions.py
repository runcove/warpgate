"""Taking a role away cuts the live sessions it was the user's only way to.

A user's live SSH session to a target ends as soon as an admin removes the
user's access to it - the role from the user, the role from the target, or
the role itself - and their session to a target they can still reach stays
up. A live HTTP websocket to the lost target ends too, while the browser
session and its websocket to the other target stay.
"""

import ssl
import time
from uuid import uuid4

import requests
from websocket import (
    WebSocketConnectionClosedException,
    WebSocketTimeoutException,
    create_connection,
)

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_http_common import *  # noqa
from .test_ssh_proto import common_args
from .util import read_until, wait_port, target_host


def _target(api, ssh_port, role_id):
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"ssh-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetSSHOptions(
                    kind="Ssh",
                    allow_insecure_algos=False,
                    host=target_host(ssh_port),
                    port=ssh_port,
                    username="root",
                    auth=sdk.SSHTargetAuth(
                        sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                    ),
                )
            ),
        )
    )
    api.add_target_role(target.id, role_id)
    return target


class Test:
    def _setup(self, processes: ProcessManager, pubkey):
        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        ssh_port = processes.start_ssh_server(trusted_keys=[pubkey.read_text()])
        wait_port(ssh_port)
        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            revoked = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            kept = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, revoked.id)
            api.add_user_role(user.id, kept.id)
            lost_target = _target(api, ssh_port, revoked.id)
            kept_target = _target(api, ssh_port, kept.id)
        return wg, url, user, revoked, lost_target, kept_target

    def _open(self, processes, wg, user, target, timeout):
        """An SSH session that stays open far longer than the test."""
        marker = f"revocation-{uuid4().hex}"
        client = processes.start_ssh_client(
            f"{user.username}:{target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-tt",
            *common_args,
            f"echo {marker}; sleep 3600",
            password="123",
        )
        output = read_until(client.stdout, marker.encode(), time.monotonic() + timeout)
        assert marker.encode() in output, "marker never appeared in session output"
        return client

    def _assert_cut_and_kept(self, lost, kept):
        assert lost.wait(timeout=30) is not None, "the revoked session stayed up"
        time.sleep(2)
        assert kept.poll() is None, "the session to a still-granted target ended"
        kept.kill()

    def test_removing_a_role_from_the_user(
        self, processes: ProcessManager, timeout, wg_c_ed25519_pubkey
    ):
        wg, url, user, revoked, lost_target, kept_target = self._setup(
            processes, wg_c_ed25519_pubkey
        )
        lost = self._open(processes, wg, user, lost_target, timeout)
        kept = self._open(processes, wg, user, kept_target, timeout)

        with admin_client(url) as api:
            api.delete_user_role(user.id, revoked.id)

        self._assert_cut_and_kept(lost, kept)

    def test_removing_a_role_from_the_target(
        self, processes: ProcessManager, timeout, wg_c_ed25519_pubkey
    ):
        wg, url, user, revoked, lost_target, kept_target = self._setup(
            processes, wg_c_ed25519_pubkey
        )
        lost = self._open(processes, wg, user, lost_target, timeout)
        kept = self._open(processes, wg, user, kept_target, timeout)

        with admin_client(url) as api:
            api.delete_target_role(lost_target.id, revoked.id)

        self._assert_cut_and_kept(lost, kept)

    def test_deleting_the_role(
        self, processes: ProcessManager, timeout, wg_c_ed25519_pubkey
    ):
        wg, url, user, revoked, lost_target, kept_target = self._setup(
            processes, wg_c_ed25519_pubkey
        )
        lost = self._open(processes, wg, user, lost_target, timeout)
        kept = self._open(processes, wg, user, kept_target, timeout)

        with admin_client(url) as api:
            api.delete_role(revoked.id)

        self._assert_cut_and_kept(lost, kept)


def _echo_target(api, echo_server_port, role_id):
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
                    tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                )
            ),
        )
    )
    api.add_target_role(target.id, role_id)
    return target


def _closed_within(ws, seconds):
    ws.settimeout(0.25)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if ws.recv() == "":
                return True
        except WebSocketConnectionClosedException:
            return True
        except WebSocketTimeoutException:
            continue
    return False


class TestHttp:
    def test_removing_a_role_ends_the_websocket_to_the_lost_target(
        self, echo_server_port, shared_wg: WarpgateProcess
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            revoked = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            kept = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, revoked.id)
            api.add_user_role(user.id, kept.id)
            lost_target = _echo_target(api, echo_server_port, revoked.id)
            kept_target = _echo_target(api, echo_server_port, kept.id)

        session = requests.Session()
        session.verify = False
        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code // 100 == 2

        cookie = "; ".join(f"{k}={v}" for k, v in session.cookies.get_dict().items())

        def connect(target):
            ws = create_connection(
                f"wss://localhost:{shared_wg.http_port}/socket"
                f"?warpgate-target={target.name}",
                cookie=cookie,
                sslopt={"cert_reqs": ssl.CERT_NONE},
            )
            ws.send("test")
            assert ws.recv() == "test"
            return ws

        lost = connect(lost_target)
        kept_ws = connect(kept_target)

        with admin_client(url) as api:
            api.delete_user_role(user.id, revoked.id)

        assert _closed_within(lost, 10), "the websocket to the lost target stayed open"
        lost.close()

        kept_ws.settimeout(5)
        kept_ws.send("still")
        assert kept_ws.recv() == "still"
        kept_ws.close()

        # The browser session itself is still logged in.
        info = session.get(f"{url}/@warpgate/api/info").json()
        assert info["username"] == user.username
