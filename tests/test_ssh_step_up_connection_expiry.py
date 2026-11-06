import asyncio
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import aiohttp
import pytest

from .api_client import admin_client
from .conftest import ProcessManager
from .test_ssh_user_auth_in_browser import _setup_pubkey_user
from .util import wait_port

WINDOW = "10s"
CLOSED_LOG = "step-up window has passed"


def _start(processes: ProcessManager, step_up_interval, log_path: Path):
    config_patch = {
        "ssh": {
            "web_auth_auto_continue": True,
            "web_auth_wait_timeout": "25s",
        },
    }
    if step_up_interval:
        config_patch["step_up_interval"] = {"ssh": step_up_interval}
    log_file = open(log_path, "w")
    wg = processes.start_wg(
        config_patch=config_patch,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(wg.ssh_port, for_process=wg.process)
    return wg


def _client(processes, wg, user, ssh_target, *command):
    return processes.start_ssh_client(
        f"{user.username}:{ssh_target.name}@localhost",
        "-p",
        str(wg.ssh_port),
        "-o",
        "IdentityFile=ssh-keys/id_ed25519",
        *command,
        stderr=subprocess.PIPE,
    )


class TestStepUpConnectionExpiry:
    @pytest.mark.asyncio
    async def test_open_connection_closes_when_the_step_up_window_passes(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
    ):
        log_path = processes.ctx.tmpdir / f"wg-log-{uuid4()}.log"
        wg = _start(processes, WINDOW, log_path)

        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        pubkey_text = open("ssh-keys/id_ed25519.pub").read().strip()
        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = _setup_pubkey_user(api, ssh_port, pubkey_text, False)

        session = aiohttp.ClientSession()
        try:
            await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                headers={"Host": f"localhost:{wg.http_port}"},
                ssl=False,
            )
            # The key has never done SSO, so the login asks for it; approving
            # stamps `last_sso_at` and opens a connection that runs far longer
            # than the window.
            started = time.monotonic()
            ssh_client = _client(
                processes, wg, user, ssh_target, "sleep", "120"
            )

            auth_id = None
            for _ in range(200):
                pending = await (
                    await session.get(
                        f"{url}/@warpgate/api/auth/web-auth-requests", ssl=False
                    )
                ).json()
                ssh_pending = [p for p in pending if p["protocol"] == "SSH"]
                if ssh_pending:
                    auth_id = ssh_pending[0]["id"]
                    break
                await asyncio.sleep(0.1)
            assert auth_id is not None, "the login never asked for SSO"

            r = await session.post(
                f"{url}/@warpgate/api/auth/state/{auth_id}/approve",
                json={"scope": "Once"},
                ssl=False,
            )
            assert r.status == 200
        finally:
            await session.close()

        # `sleep 120` would run for two minutes; the window is 10s.
        try:
            ssh_client.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            ssh_client.kill()
            raise AssertionError(
                "the connection stayed open past its step-up window"
            )
        elapsed = time.monotonic() - started

        assert ssh_client.returncode != 0
        # `started` is taken before the approval that stamps the key, so a
        # close before the 10s window is up is a regression.
        assert elapsed >= 10, f"closed after {elapsed:.1f}s, inside the window"
        assert elapsed < 60
        assert CLOSED_LOG in log_path.read_text()

    @pytest.mark.asyncio
    async def test_connection_stays_open_without_step_up(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
    ):
        log_path = processes.ctx.tmpdir / f"wg-log-{uuid4()}.log"
        wg = _start(processes, None, log_path)

        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        pubkey_text = open("ssh-keys/id_ed25519.pub").read().strip()
        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = _setup_pubkey_user(api, ssh_port, pubkey_text, False)

        started = time.monotonic()
        ssh_client = _client(processes, wg, user, ssh_target, "sleep", "15")
        ssh_client.communicate(timeout=60)
        elapsed = time.monotonic() - started

        assert ssh_client.returncode == 0
        assert elapsed >= 15
        assert CLOSED_LOG not in log_path.read_text()
