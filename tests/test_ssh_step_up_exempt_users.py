import base64
import hashlib
import re
import subprocess
import time
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .util import target_host, wait_port

ALLOWED_LOG = "allowed by step-up exemption"
STEP_UP_REQUIRED_LOG = "SSH step-up required"
SESSION_FIELD = re.compile(r"\bsession=([0-9A-Fa-f-]{32,36})\b")
REMOTE_IP_FIELD = re.compile(r"\bremote_ip=([^\s,}]+)")


def _fingerprint(pubkey_path: str) -> str:
    """The OpenSSH SHA256 fingerprint of a `.pub` file, as `ssh-keygen -lf`
    prints it and as `step_up_interval.exempt_users[].keys` lists it."""
    blob = base64.b64decode(Path(pubkey_path).read_text().split()[1])
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def _start(processes: ProcessManager, username: str, keys, log_path: Path):
    config_patch = {
        "ssh": {
            "web_auth_auto_continue": True,
            "web_auth_wait_timeout": "25s",
        },
        "step_up_interval": {
            "ssh": "12h",
            "exempt_users": [{"user": username, "keys": keys}],
        },
    }
    log_file = open(log_path, "w")
    wg = processes.start_wg(
        config_patch=config_patch,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(wg.ssh_port, for_process=wg.process)
    return wg


def _setup_service_user(api, ssh_port, username, pubkeys):
    """A user with public keys only (no password, no SSO credential, as an
    `exempt_users` entry requires) and an SSH target it may use. The policy
    asks for the key alone, so any `WebUserApproval` in a login comes from the
    step-up check and not from the user's credential policy."""
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=username))
    for label, pubkey_text in pubkeys:
        api.create_public_key_credential(
            user.id,
            sdk.NewPublicKeyCredential(label=label, openssh_public_key=pubkey_text),
        )
    api.add_user_role(user.id, role.id)
    api.update_user(
        user.id,
        sdk.UserDataRequest(
            username=username,
            credential_policy=sdk.UserRequireCredentialsPolicy(
                ssh=[sdk.CredentialKind.PUBLICKEY]
            ),
        ),
    )
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
    return ssh_target


def _client(processes, wg, username, ssh_target, identity, *command):
    return processes.start_ssh_client(
        f"{username}:{ssh_target.name}@localhost",
        "-p",
        str(wg.ssh_port),
        "-o",
        f"IdentityFile={identity}",
        *command,
        stderr=subprocess.PIPE,
    )


def _lines_for(log_path: Path, username: str, message: str):
    return [
        line
        for line in log_path.read_text().splitlines()
        if username in line and message in line
    ]


def _field(line: str, pattern: "re.Pattern[str]", name: str) -> str:
    # The tracing span prefix on every line (`SSH{session=<uuid>}:`) prints a
    # session field too, so look only at what follows the event's message:
    # tracing prints the event's own fields after it.
    _, found, event_fields = line.rpartition(ALLOWED_LOG)
    assert found, f"not the exemption line: {line}"
    match = pattern.search(event_fields)
    assert match, f"the exemption line has no {name} field: {line}"
    return match.group(1)


def _is_loopback(address: str) -> bool:
    ip = ip_address(address)
    return (getattr(ip, "ipv4_mapped", None) or ip).is_loopback


def _setup_two_key_user(processes: ProcessManager, wg_c_ed25519_pubkey: Path):
    """One service user with two keys, only the ed25519 one listed in
    `exempt_users`. Returns (wg, username, ssh_target, log_path)."""
    username = f"svc-{uuid4()}"
    log_path = processes.ctx.tmpdir / f"wg-log-{uuid4()}.log"
    wg = _start(
        processes, username, [_fingerprint("ssh-keys/id_ed25519.pub")], log_path
    )

    ssh_port = processes.start_ssh_server(
        trusted_keys=[wg_c_ed25519_pubkey.read_text()]
    )
    wait_port(ssh_port)

    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        ssh_target = _setup_service_user(
            api,
            ssh_port,
            username,
            [
                ("listed", open("ssh-keys/id_ed25519.pub").read().strip()),
                ("not listed", open("ssh-keys/id_rsa.pub").read().strip()),
            ],
        )
    return wg, username, ssh_target, log_path


class TestStepUpExemptUsers:
    @pytest.mark.asyncio
    async def test_listed_key_skips_web_approval(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
    ):
        """The listed key reaches the target with no `WebUserApproval`."""
        wg, username, ssh_target, log_path = _setup_two_key_user(
            processes, wg_c_ed25519_pubkey
        )

        # The listed key: straight through, nothing to approve.
        listed = _client(
            processes,
            wg,
            username,
            ssh_target,
            "ssh-keys/id_ed25519",
            "echo",
            "listed-ok",
        )
        out, _ = listed.communicate(timeout=60)
        assert listed.returncode == 0
        assert b"listed-ok" in out
        allowed = _lines_for(log_path, username, ALLOWED_LOG)
        assert len(allowed) == 1, "no exemption log line, or more than one"
        # The line says which session it admitted and from where.
        UUID(_field(allowed[0], SESSION_FIELD, "session"))
        assert _is_loopback(
            _field(allowed[0], REMOTE_IP_FIELD, "remote_ip")
        ), "the exemption line does not show the client's address"
        assert not _lines_for(
            log_path, username, STEP_UP_REQUIRED_LOG
        ), "the listed key was asked for step-up"

    @pytest.mark.asyncio
    async def test_unlisted_key_still_needs_web_approval(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
    ):
        """The other key of the same user still gets the step-up check."""
        wg, username, ssh_target, log_path = _setup_two_key_user(
            processes, wg_c_ed25519_pubkey
        )

        # The other key of the same user: the login stops at the step-up check
        # and waits for a browser approval that never comes.
        unlisted = _client(
            processes,
            wg,
            username,
            ssh_target,
            "ssh-keys/id_rsa",
            "echo",
            "unlisted-ok",
        )
        try:
            deadline = time.monotonic() + 30
            while not _lines_for(log_path, username, STEP_UP_REQUIRED_LOG):
                assert (
                    time.monotonic() < deadline
                ), "the unlisted key was not asked for step-up"
                assert unlisted.poll() is None, "the unlisted key got a session"
                time.sleep(0.2)
            assert unlisted.poll() is None
        finally:
            unlisted.kill()
        out, _ = unlisted.communicate(timeout=10)
        assert b"unlisted-ok" not in out
        assert len(_lines_for(log_path, username, ALLOWED_LOG)) == 0
