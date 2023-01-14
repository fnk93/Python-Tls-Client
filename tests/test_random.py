from json import JSONDecodeError
import tls_client


def test_proxy_on_get():
    client_identifier = "chrome_107"
    session = tls_client.Session(
        client_identifier=client_identifier,
        random_tls_extension_order=True,
        debug=True,
    )
    # resp = session.get('https://api.ipify.org/?format=json', headers={123: 123}, timeout_seconds=0)
    resp = session.get('http://abc.defgh.ijkl.mmmn', headers={123: 123}, timeout_milliseconds=10, allow_redirects=True)
    try:
        print(resp.json())
    except JSONDecodeError:
        print(resp.text)
    session.close()


if __name__ == '__main__':
    test_proxy_on_get()
