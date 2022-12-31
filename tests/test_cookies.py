import tls_client


def test_cookies():
    client_identifier = "chrome_107"
    session = tls_client.Session(
        client_identifier=client_identifier,
        random_tls_extension_order=True,
    )
    print(session.get('https://httpbin.org/cookies/set/testcookie/12345', without_cookiejar=True))
    print(session.get('https://httpbin.org/cookies', without_cookiejar=True).json())
    print(session.cookies.get_dict())
    print(session.cookies.clear())
    print(session.cookies.get_dict())
    print(session.get('https://httpbin.org/cookies', without_cookiejar=True).json())


if __name__ == '__main__':
    test_cookies()
