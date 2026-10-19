"""Taking a role away cuts the live sessions it was the user's only way to.

A user's live SSH session to a target ends as soon as an admin removes the
user's access to it - the role from the user, the role from the target, or
the role itself - and their session to a target they can still reach stays
up.
"""

import time
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_ssh_proto import common_args
from .util import read_until, wait_port


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
                    host="localhost",
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
