import logging
import os
import requests
import select
import socket
import sqlite3
import subprocess
import threading
import time
import uuid

import yaml


# Each xdist worker (gw0, gw1, ...) hands out ports from its own range, so
# workers never race each other for the same port. A serial run is worker 0.
# ponytail: 3000 ports per worker keeps 20 workers under 61234; widen the
# stride if a worker ever runs out.
_worker = int(os.getenv("PYTEST_XDIST_WORKER", "gw0").removeprefix("gw"))
last_port = 1234 + _worker * 3000

# Process listening on each allocated port, so that wait_port fails as soon as
# that process exits instead of waiting out its timeout.
port_owners: dict = {}


def _prestarted_targets():
    """CI's pre-started targets (WARPGATE_E2E_TARGETS=prestarted): {kind: (host, port)}.

    The runcove warpgate-integration job starts an sshd, a MySQL and a Postgres before the
    tests' sandbox, which has no docker, and names them in WARPGATE_E2E_<KIND>_HOST and
    _PORT. In that mode every one must be set: there is no fallback to localhost. Unset,
    nothing changes."""
    mode = os.getenv("WARPGATE_E2E_TARGETS", "")
    if mode == "":
        return {}
    if mode != "prestarted":
        raise RuntimeError(f"WARPGATE_E2E_TARGETS is {mode!r}; the only mode is 'prestarted'")
    out = {}
    for kind in ("ssh", "mysql", "postgres"):
        host = os.getenv(f"WARPGATE_E2E_{kind.upper()}_HOST", "")
        port = os.getenv(f"WARPGATE_E2E_{kind.upper()}_PORT", "")
        if not host or not port.isdigit() or not 0 < int(port) < 65536:
            raise RuntimeError(
                f"WARPGATE_E2E_TARGETS=prestarted, but WARPGATE_E2E_{kind.upper()}_HOST and _PORT "
                f"are {host!r} and {port!r}, not a host and a port; there is no fallback to localhost"
            )
        out[kind] = (host, int(port))
    if len({p for _, p in out.values()}) != len(out):
        raise RuntimeError("WARPGATE_E2E_TARGETS=prestarted, but two targets share a port")
    return out


prestarted_targets = _prestarted_targets()
# The pre-started targets' hosts by port. alloc_port never hands these ports out,
# so a port here is always a pre-started target's, never one of ours.
target_hosts = {port: host for host, port in prestarted_targets.values()}


def target_host(port, default="localhost"):
    """The host a test reaches a target on: the pre-started target's for its
    port, otherwise `default`, the address the test always used."""
    return target_hosts.get(port, default)

def own_database_url(kind, port):
    """The URL of a database for a Warpgate of its own (`database_url`), on the
    Postgres (kind "postgres") or MySQL (kind "mysql") server at `port`.

    Started by the test itself, the server is that Warpgate's alone and the URL
    names its `db` on localhost, as it always did. A pre-started server is shared
    and is reached on its own host, so each call makes an empty database there
    with the same clients the tests use, and Warpgate gets that one."""
    user = {"postgres": "user", "mysql": "root"}[kind]
    scheme = {"postgres": "postgres", "mysql": "mysql"}[kind]
    if port not in target_hosts:
        return f"{scheme}://{user}:123@localhost:{port}/db"
    host = target_hosts[port]
    name = f"wg_{uuid.uuid4().hex}"
    if kind == "postgres":
        cmd = ["psql", "-h", host, "-p", str(port), "-U", user, "-d", "db", "-v", "ON_ERROR_STOP=1", "-c", f"CREATE DATABASE {name}"]
        env = {**os.environ, "PGPASSWORD": "123"}
    else:
        cmd = ["mysql", f"--user={user}", "--password=123", f"--host={host}", f"--port={port}", f"--execute=CREATE DATABASE {name}"]
        env = os.environ
    subprocess.run(cmd, check=True, env=env, stdout=subprocess.DEVNULL)
    return f"{scheme}://{user}:123@{host}:{port}/{name}"


mysql_client_ssl_opt = "--ssl"
mysql_client_opts = []
if "GITHUB_ACTION" in os.environ:
    # Github uses MySQL instead of MariaDB
    mysql_client_ssl_opt = "--ssl-mode=REQUIRED"
    mysql_client_opts = ["--enable-cleartext-plugin"]


def read_until(stream, needle: bytes, deadline: float) -> bytes:
    """Read from `stream` (a pipe) until `needle` appears or `deadline` passes."""
    buf = b""
    while time.monotonic() < deadline and needle not in buf:
        ready, _, _ = select.select([stream], [], [], 1)
        if ready:
            buf += os.read(stream.fileno(), 4096)
    return buf


def _port_is_free(port):
    # Warpgate listens on [::] and Docker publishes on 0.0.0.0, so the port
    # must be bindable on both families.
    for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        with socket.socket(family, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
            except OSError:
                return False
    return True


def alloc_port():
    # ponytail: free now is not free at bind time; the monotonic counter
    # keeps this process from racing itself, nothing guards other processes.
    global last_port
    last_port += 1
    while last_port in target_hosts or not _port_is_free(last_port):
        last_port += 1
    return last_port


def _wait_timeout(fn, msg, timeout=60):
    # A thread that died from an exception is not alive either; capture the
    # exception so the failure is re-raised instead of read as success.
    failure = []

    def run():
        try:
            fn()
        except BaseException as e:  # noqa: BLE001 - re-raised below
            failure.append(e)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        # Callable so the caller can describe what the wait kept seeing.
        raise Exception(msg() if callable(msg) else msg)
    if failure:
        raise failure[0]


def wait_port(port, recv=True, timeout=60, for_process: subprocess.Popen = None, connect_timeout=5, read_timeout=5):
    logging.debug(f"Waiting for port {port}")
    for_process = for_process or port_owners.get(port)
    # What the last attempt saw, so that a timeout names a symptom.
    last_seen = ["no attempt completed"]

    def wait():
        while True:
            try:
                s = socket.create_connection((target_host(port), port), timeout=connect_timeout)
                try:
                    if recv:
                        s.settimeout(read_timeout)
                        answered = bool(s.recv(100))
                    else:
                        answered = True
                finally:
                    s.close()
                if answered:
                    logging.debug(f"Port {port} is up")
                    return
                # Accepted and closed the connection unanswered. A listener
                # that is up but not serving yet is the thing this loop waits
                # for, so record it and keep waiting -- Warpgate's own SSH
                # port does this for the first moments after it binds.
                last_seen[0] = "it accepts connections and closes them unanswered"
            except socket.error as e:
                last_seen[0] = f"connecting to it raised {e!r}"

            if for_process:
                try:
                    for_process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    continue
                raise Exception(
                    f"Process exited with code {for_process.returncode} "
                    f"while waiting for port {port}"
                )
            else:
                time.sleep(0.1)

    _wait_timeout(wait, lambda: f"Port {port} is not up: {last_seen[0]}", timeout=timeout)


def wait_mysql_port(port):
    logging.debug(f"Waiting for MySQL port {port}")

    def wait():
        while True:
            try:
                subprocess.check_call(
                    f'mysql --user=root --password=123 --host={target_host(port, "127.0.0.1")} --port={port} --execute="show schemas;"',
                    shell=True,
                )
                logging.debug(f"Port {port} is up")
                break
            except subprocess.CalledProcessError:
                time.sleep(1)
                continue

    _wait_timeout(wait, f"Port {port} is not up")


def open_wg_sqlite_db(config_path):
    """A read connection to a node's sqlite database. A sqlite: URL names a
    directory (relative to the config dir) that holds db.sqlite3."""
    config = yaml.safe_load(config_path.open())
    db_url = config["database_url"]
    assert db_url.startswith("sqlite:")
    db_file = config_path.parent / db_url.removeprefix("sqlite:") / "db.sqlite3"
    # busy timeout: the nodes write to the same file concurrently
    return sqlite3.connect(db_file, timeout=5)


def create_ticket(url, username, target_name):
    session = requests.Session()
    session.verify = False
    response = session.post(
        f"{url}/@warpgate/api/auth/login",
        json={
            "username": "admin",
            "password": "123",
        },
    )
    assert response.status_code // 100 == 2
    response = session.post(
        f"{url}/@warpgate/admin/api/tickets",
        json={
            "username": username,
            "target_name": target_name,
        },
    )
    assert response.status_code == 201
    return response.json()["secret"]
