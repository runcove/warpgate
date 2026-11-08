"""The ticket row lock, under real concurrency.

Warpgate's own database can be PostgreSQL or MySQL, where two transactions
really overlap; the in-process tests of the same race run on in-memory SQLite,
whose one connection serialises them. These tests hold the lock on a ticket row
from outside, in a transaction of their own, and watch what Warpgate does
while they hold it:

* registering a session under a ticket (`TargetSession::open_or_lookup`) must
  wait for the row, then be refused if the ticket was deleted meanwhile;
* deleting a ticket (`Services::delete_ticket_closing_sessions`) or a target
  (`resources::targets::delete`) must wait for the row, and then collect the
  sessions that were registered while it waited, so that they get closed.

Without the lock the open would not wait (a plain read does not block) and the
deletes would collect their sessions before the registration commits, so each
of these fails if the lock is removed.
"""

import os
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_http_common import echo_server_port  # noqa
from .util import own_database_url, read_until, wait_mysql_port, wait_port

# How long a request that must be waiting for the lock is given to prove it is
# not (an unlocked request finishes in milliseconds).
HOLD_SECONDS = 3
SQL_TIMEOUT = 20


class SqlSession:
    """One connection to the database, driven through the psql / mysql client
    on a pipe so that a transaction stays open between calls."""

    def __init__(self, kind: str, url: str):
        self.kind = kind
        parsed = urlparse(url)
        name = parsed.path.lstrip("/")
        env = dict(os.environ)
        if kind == "postgres":
            env["PGPASSWORD"] = parsed.password
            cmd = [
                "psql", "-h", parsed.hostname, "-p", str(parsed.port),
                "-U", parsed.username, "-d", name,
                "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
            ]
        else:
            env["MYSQL_PWD"] = parsed.password
            # MariaDB's "mysql" name is deprecated and warns on stderr.
            client = shutil.which("mariadb") or "mysql"
            cmd = [
                client, f"--user={parsed.username}", f"--host={parsed.hostname}",
                f"--port={parsed.port}", "--batch", "--skip-column-names",
                "--unbuffered", name,
            ]
        # Results are parsed from stdout only; stderr is kept for messages.
        self.stderr = tempfile.TemporaryFile()
        self.process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, env=env,
        )

    def errors(self) -> str:
        self.stderr.seek(0)
        return self.stderr.read().decode(errors="replace")

    def uuid(self, value) -> str:
        """A UUID as an SQL literal: PostgreSQL has a uuid type, sea-orm
        stores it as BINARY(16) on MySQL."""
        if self.kind == "postgres":
            return f"'{value}'"
        return f"UNHEX(REPLACE('{value}', '-', ''))"

    def run(self, sql: str) -> str:
        """Runs statements and returns their output, once the client has
        answered a marker query sent after them."""
        marker = f"done-{uuid4().hex}"
        self.process.stdin.write(f"{sql}\nSELECT '{marker}';\n".encode())
        self.process.stdin.flush()
        out = read_until(
            self.process.stdout, marker.encode(), time.monotonic() + SQL_TIMEOUT
        ).decode()
        assert marker in out, (
            f"the SQL client did not finish {sql!r}: {out!r} {self.errors()!r}"
        )
        assert "ERROR" not in out and "ERROR" not in self.errors(), (
            f"{sql!r} failed: {out!r} {self.errors()!r}"
        )
        return out

    def scalar(self, sql: str) -> int:
        return int(self.run(sql).split()[0])

    def close(self):
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.stderr.close()


@pytest.fixture(scope="module", params=["postgres", "mysql"])
def db_wg(request, processes: ProcessManager):
    kind = request.param
    if kind == "postgres":
        port = processes.start_postgres_server()
    else:
        port = processes.start_mysql_server()
        wait_mysql_port(port)
    url = own_database_url(kind, port)
    wg = processes.start_wg(database_url=url)
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield kind, url, wg


@pytest.fixture
def sql(db_wg):
    kind, url, _ = db_wg
    opened = []

    def connect():
        session = SqlSession(kind, url)
        opened.append(session)
        return session

    yield connect
    for session in opened:
        session.close()


class Seeded:
    def __init__(self, user, target, ticket, secret):
        self.user = user
        self.target = target
        self.ticket = ticket
        self.secret = secret


def seed(url, echo_server_port) -> Seeded:
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.add_user_role(user.id, role.id)
        target = api.create_target(sdk.TargetDataRequest(
            name=f"echo-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(sdk.TargetOptionsTargetHTTPOptions(
                kind="Http",
                headers={},
                url=f"http://localhost:{echo_server_port}",
                tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
            )),
        ))
        api.add_target_role(target.id, role.id)
        # No use limit: spending a use updates the ticket row, which would
        # make the request wait for reasons other than the lock under test.
        created = api.create_ticket(sdk.CreateTicketRequest(
            target_name=target.name,
            username=user.username,
        ))
    return Seeded(user, target, created.ticket, created.secret)


def lock_ticket(db: SqlSession, ticket_id) -> None:
    db.run(
        "BEGIN;\n"
        f"SELECT 1 FROM tickets WHERE id = {db.uuid(ticket_id)} FOR UPDATE;"
    )


def register_session_under_ticket(db: SqlSession, seeded: Seeded):
    """Inserts, inside the open transaction, what a protocol registers once a
    ticket has admitted a connection. Returns the user session's id."""
    session_id = uuid4()
    db.run(
        "INSERT INTO user_sessions (id, username, user_id, remote_address, started, "
        "ended, protocol, node_id, auth_state_node_id) VALUES "
        f"({db.uuid(session_id)}, 'alice', NULL, '127.0.0.1:22', CURRENT_TIMESTAMP, "
        "NULL, 'HTTP', NULL, NULL);\n"
        "INSERT INTO target_sessions (id, user_session_id, target_snapshot, target_id, "
        "started, ended, ticket_id, node_id) VALUES "
        f"({db.uuid(uuid4())}, {db.uuid(session_id)}, '{{\"name\":\"web\"}}', "
        f"{db.uuid(seeded.target.id)}, CURRENT_TIMESTAMP, NULL, "
        f"{db.uuid(seeded.ticket.id)}, NULL);"
    )
    return session_id


def test_opening_under_a_ticket_waits_for_its_row_and_is_refused_if_it_is_deleted(
    db_wg, sql, echo_server_port
):
    _, _, wg = db_wg
    url = f"https://localhost:{wg.http_port}"
    seeded = seed(url, echo_server_port)
    holder = sql()
    reader = sql()

    lock_ticket(holder, seeded.ticket.id)
    try:
        def open_session():
            return requests.get(
                f"{url}/some/path?warpgate-target={seeded.target.name}",
                headers={"Authorization": f"Warpgate {seeded.secret}"},
                verify=False,
                allow_redirects=False,
                timeout=60,
            )

        with ThreadPoolExecutor(max_workers=1) as pool:
            opening = pool.submit(open_session)
            time.sleep(HOLD_SECONDS)
            # Fails without the lock: a plain read of the ticket does not wait.
            assert not opening.done(), (
                "the open did not wait for the ticket row "
                f"(answered {opening.result().status_code})"
            )

            holder.run(f"DELETE FROM tickets WHERE id = {holder.uuid(seeded.ticket.id)};\nCOMMIT;")
            response = opening.result(timeout=60)
    finally:
        holder.run("ROLLBACK;")

    assert response.status_code // 100 != 2, response.status_code
    assert reader.scalar(
        "SELECT COUNT(*) FROM target_sessions "
        f"WHERE target_id = {reader.uuid(seeded.target.id)};"
    ) == 0


@pytest.mark.parametrize("what", ["ticket", "target", "user"])
def test_deleting_waits_for_the_ticket_row_and_closes_the_session_registered_meanwhile(
    db_wg, sql, echo_server_port, what
):
    _, _, wg = db_wg
    url = f"https://localhost:{wg.http_port}"
    seeded = seed(url, echo_server_port)
    holder = sql()
    reader = sql()

    def delete():
        with admin_client(url) as api:
            if what == "ticket":
                api.delete_ticket(seeded.ticket.id)
            elif what == "user":
                api.delete_user(seeded.user.id)
            else:
                api.delete_target(seeded.target.id)

    lock_ticket(holder, seeded.ticket.id)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            deleting = pool.submit(delete)
            time.sleep(HOLD_SECONDS)
            assert not deleting.done(), "the delete did not wait for the ticket row"

            # A protocol registers a session under the ticket while the
            # delete waits, and commits.
            session_id = register_session_under_ticket(holder, seeded)
            holder.run("COMMIT;")

            deleting.result(timeout=60)
    finally:
        holder.run("ROLLBACK;")

    # Fails without the lock: the delete would have collected the sessions
    # before this one existed and never closed it.
    assert reader.scalar(
        "SELECT COUNT(*) FROM user_sessions "
        f"WHERE id = {reader.uuid(session_id)} AND ended IS NOT NULL;"
    ) == 1
