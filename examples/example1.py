import tls_client

session = tls_client.Session(
    client_identifier="chrome_105"
)

session.get(
    "https://github.com/psf/requests"
)
