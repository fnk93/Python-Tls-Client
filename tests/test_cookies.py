from __future__ import annotations

import tls_client

from tls_client.exceptions import ClientNotFoundError


def test_cookies():
    client_identifier = "chrome_107"
    session = tls_client.Session(
        client_identifier=client_identifier,
        random_tls_extension_order=True,
    )
    print(session.get("https://httpbin.org/cookies/set/testcookie/12345"))
    print(session.get("https://httpbin.org/cookies").json())
    print(session.cookies.get_dict())
    print(session.get_cookies(url="https://httpbin.org"))
    session.clear_cookies()
    print(session.cookies.get_dict())
    try:
        print(session.get_cookies(url="https://httpbin.org"))
    except ClientNotFoundError:
        print("Client has been reset.")
    print(session.get("https://httpbin.org/cookies").json())


if __name__ == "__main__":
    test_cookies()
