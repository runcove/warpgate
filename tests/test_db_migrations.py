import requests

from .conftest import ProcessManager, WarpgateProcess
from .util import own_database_url, wait_port, wait_mysql_port


def _check_info_endpoint(wg: WarpgateProcess, timeout: int) -> None:
    wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)
    session = requests.Session()
    session.verify = False
    response = session.get(f"https://localhost:{wg.http_port}/@warpgate/api/info")
    assert response.status_code == 200


class TestPostgresMigrations:
    def test_postgres_migrations(self, processes: ProcessManager, timeout):
        db_port = processes.start_postgres_server()
        wg = processes.start_wg(
            database_url=own_database_url("postgres", db_port),
        )
        _check_info_endpoint(wg, timeout)


class TestMariaDBMigrations:
    def test_mariadb_migrations(self, processes: ProcessManager, timeout):
        db_port = processes.start_mariadb_server()
        wait_mysql_port(db_port)
        wg = processes.start_wg(
            database_url=own_database_url("mysql", db_port),
        )
        _check_info_endpoint(wg, timeout)


class TestMysqlMigrations:
    def test_mysql_migrations(self, processes: ProcessManager, timeout):
        db_port = processes.start_mysql_server()
        wait_mysql_port(db_port)
        wg = processes.start_wg(
            database_url=own_database_url("mysql", db_port),
        )
        _check_info_endpoint(wg, timeout)
