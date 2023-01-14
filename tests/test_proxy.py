import tls_client


def test_proxy_on_get():
    client_identifier = "chrome_107"
    session = tls_client.Session(
        client_identifier=client_identifier,
        random_tls_extension_order=True,
        debug=True,
    )
    resp = session.get('https://----api.ipify.org/?format=json', proxy="http://49.241:137")
    print(resp.json())
    session.close()


if __name__ == '__main__':
    test_proxy_on_get()
