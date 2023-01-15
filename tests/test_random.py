from __future__ import annotations

import tls_client


def test_proxy_on_get():
    client_identifier = "chrome_107"
    session = tls_client.Session(
        client_identifier=client_identifier,
        random_tls_extension_order=True,
        debug=True,
    )
    # resp = session.get('https://api.ipify.org/?format=json', headers={123: 123}, timeout_seconds=0)
    _ = session.get("http://www.amazon.de", allow_redirects=True)
    print(session.cookies.get_dict())
    print(session.get_cookies(url="https://www.amazon.de"))
    _ = session.get("https://www.amazon.de", allow_redirects=True)
    print(session.cookies.get_dict())
    print(session.get_cookies(url="https://www.amazon.de"))
    _ = session.get("https://www.amazon.de", allow_redirects=True)
    print(session.cookies.get_dict())
    print(session.get_cookies(url="https://www.amazon.de"))
    session.close()


if __name__ == "__main__":
    test_proxy_on_get()
