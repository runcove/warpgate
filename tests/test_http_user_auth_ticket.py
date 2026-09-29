import requests
from uuid import uuid4

from .api_client import admin_client, sdk
from .approval_util import create_password_user, create_postgres_target
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


class TestHTTPUserAuthTicket:
    def test_auth_password_success(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            echo_target = api.create_target(sdk.TargetDataRequest(
                name=f"echo-{uuid4()}",
                require_approval=False,
                ticket_requests_disabled=False,
                ticket_require_approval=False,
                options=sdk.TargetOptions(sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    headers={},
                    url=f"http://localhost:{echo_server_port}",
                    tls=sdk.Tls(
                        mode=sdk.TlsMode.DISABLED,
                        verify=False,
                    ),
                )),
            ))
            api.add_target_role(echo_target.id, role.id)

            other_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"other-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            headers={},
                            url="http://badhost",
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.DISABLED,
                                verify=False,
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(other_target.id, role.id)
            secret = api.create_ticket(sdk.CreateTicketRequest(
                target_name=echo_target.name,
                username=user.username,
            )).secret

        # ---

        session = requests.Session()
        session.verify = False

        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
        )
        assert response.status_code // 100 != 2

        # Ticket as a header
        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
            headers={
                "Authorization": f"Warpgate {secret}",
            },
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

        # Bad ticket
        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
            headers={
                "Authorization": f"Warpgate bad{secret}",
            },
        )
        assert response.status_code // 100 != 2

        # Ticket as a GET param
        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}/some/path?warpgate-ticket={secret}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

        # Ensure no access to other targets
        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}/some/path?warpgate-ticket={secret}&warpgate-target=admin",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2

        assert response.json()["path"] == "/some/path"
        response = session.get(
            f"{url}/some/path?warpgate-ticket={secret}&warpgate-target={other_target.name}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

    def test_query_ticket_page_load_moves_to_the_clean_address(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            echo_target = api.create_target(sdk.TargetDataRequest(
                name=f"echo-{uuid4()}",
                require_approval=False,
                ticket_requests_disabled=False,
                ticket_require_approval=False,
                options=sdk.TargetOptions(sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    headers={},
                    url=f"http://localhost:{echo_server_port}",
                    tls=sdk.Tls(
                        mode=sdk.TlsMode.DISABLED,
                        verify=False,
                    ),
                )),
            ))
            api.add_target_role(echo_target.id, role.id)
            ticket = api.create_ticket(sdk.CreateTicketRequest(
                target_name=echo_target.name,
                username=user.username,
                number_of_uses=3,
            ))

        def uses_left():
            with admin_client(url) as api:
                return next(
                    t.uses_left for t in api.get_tickets() if t.id == ticket.ticket.id
                )

        page_load = {
            "Accept": "text/html",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        }

        # A browser's page load spends the ticket and is sent to the clean
        # address, with the session cookie set on the redirect itself.
        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}/some/path?a=1&warpgate-ticket={ticket.secret}",
            headers=page_load,
            allow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["Location"] == "/some/path?a=1"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert "warpgate-http-session" in response.cookies
        assert uses_left() == 2

        # The clean address is served on the session alone, spending nothing.
        response = session.get(
            f"{url}{response.headers['Location']}",
            headers=page_load,
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"
        assert response.json()["args"] == {"a": "1"}
        assert "Referrer-Policy" not in response.headers
        assert uses_left() == 2

        # A client that does not say it is loading a page is served in place.
        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}/some/path?warpgate-ticket={ticket.secret}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert uses_left() == 1

        # A path a browser would read as another host is never redirected to.
        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}//example.invalid/?warpgate-ticket={ticket.secret}",
            headers=page_load,
            allow_redirects=False,
        )
        assert response.status_code != 303
        assert not response.headers.get("Location", "").startswith("//")
        assert response.headers["Referrer-Policy"] == "no-referrer"
        # Positive control: the ticket did authenticate this request, so the
        # page load really reached the redirect decision.
        assert uses_left() == 0

    def test_non_http_ticket_opens_no_session(self, shared_wg: WarpgateProcess):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role = create_password_user(api)
            target = create_postgres_target(api, role, 1, require_approval=False)
            ticket = api.create_ticket(sdk.CreateTicketRequest(
                target_name=target.name, username=user.username, number_of_uses=1,
            ))

            session = requests.Session()
            session.verify = False
            response = session.get(
                f"{url}/some/path?warpgate-ticket={ticket.secret}",
                allow_redirects=False,
            )
            assert response.status_code // 100 != 2
            info = session.get(f"{url}/@warpgate/api/info").json()
            assert info["username"] is None
            assert not info["authorized_via_ticket"]
            uses_left = next(
                t.uses_left for t in api.get_tickets() if t.id == ticket.ticket.id
            )
            assert uses_left == 1
