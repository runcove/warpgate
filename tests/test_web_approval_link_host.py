"""The browser approval link is built on the control-plane host.

On the layout where the global `external_host` is a bound site, Warpgate's own
`/@warpgate` routes are only served on the control-plane host
(`http.external_host`), so the link an SSH client is shown must point there.
"""

import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_http_common import echo_server_port  # noqa: F401
from .test_http_host_binding import _echo_target
from .test_http_user_auth_oidc import _resolve_hosts_to_localhost
from .util import target_host, wait_port

MAIN_HOST = "warpgate.approval-link.test"
ADMIN_HOST = f"admin.{MAIN_HOST}"


def test_the_ssh_approval_link_points_at_the_control_plane_host(
    processes: ProcessManager,
    wg_c_ed25519_pubkey: Path,
    echo_server_port,
    timeout,
):
    wg = processes.start_wg(
        config_patch={
            "external_host": MAIN_HOST,
            "http": {"external_host": ADMIN_HOST},
        }
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(wg.ssh_port, for_process=wg.process)

    ssh_port = processes.start_ssh_server(
        trusted_keys=[wg_c_ed25519_pubkey.read_text()]
    )
    wait_port(ssh_port)

    port = wg.http_port
    main_host = f"{MAIN_HOST}:{port}"
    admin_url = f"https://{ADMIN_HOST}:{port}"
    # `localhost` is bound to nothing, so setup goes through it.
    setup_url = f"https://localhost:{port}"

    with admin_client(setup_url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        api.add_user_role(user.id, role.id)
        api.update_user(
            user.id,
            sdk.UserDataRequest(
                username=user.username,
                credential_policy=sdk.UserRequireCredentialsPolicy(
                    ssh=[sdk.CredentialKind.WEBUSERAPPROVAL],
                ),
            ),
        )
        # The global host serves this target: the whole-site layout.
        _echo_target(api, echo_server_port, role, "bound", main_host)
        ssh_target = api.create_target(
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
        api.add_target_role(ssh_target.id, role.id)

    with _resolve_hosts_to_localhost(MAIN_HOST, ADMIN_HOST):
        session = requests.Session()
        session.verify = False
        response = session.post(
            f"{admin_url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code == 201, response.text

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "ls",
            "/bin/sh",
            stderr=subprocess.PIPE,
        )

        # The list endpoint, not the stream: it has no race with the request
        # being created before the subscription.
        auth_id = None
        for _ in range(100):
            pending = session.get(
                f"{admin_url}/@warpgate/api/auth/web-auth-requests"
            ).json()
            ssh_pending = [p for p in pending if p["protocol"] == "SSH"]
            if ssh_pending:
                auth_id = ssh_pending[0]["id"]
                break
            time.sleep(0.1)
        assert auth_id is not None, "no pending SSH approval request"

        # The approval API answers on the host the link names.
        response = session.get(f"{admin_url}/@warpgate/api/auth/state/{auth_id}")
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "WebUserApprovalNeeded"
        response = session.post(
            f"{admin_url}/@warpgate/api/auth/state/{auth_id}/approve",
            json={"scope": "Once"},
        )
        assert response.status_code == 200, response.text

        ssh_client.stdin.write(b"\r\n")
        stdout, stderr = ssh_client.communicate(timeout=timeout)

    assert stdout == b"/bin/sh\n"
    assert ssh_client.returncode == 0

    (link,) = re.findall(rb"https?://\S+/@warpgate#/login/\S+", stderr)
    link = urlsplit(link.decode())
    assert link.scheme == "https"
    assert link.netloc == f"{ADMIN_HOST}:{port}"
    assert link.fragment == f"/login/{auth_id}"
