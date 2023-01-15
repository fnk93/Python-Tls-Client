from __future__ import annotations

import json

from typing import Any

from tls_client.cookies import RequestsCookieJar
from tls_client.cookies import cookiejar_from_dict
from tls_client.exceptions import ResponseEmptyError
from tls_client.structures import CaseInsensitiveDict


class Response:
    """object, which contains the response to an HTTP request."""

    def __init__(self) -> None:
        # Reference of URL the response is coming from (especially useful with redirects)
        self.url = None

        # Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        # String of responded HTTP Body.
        self.text = None

        # Case-insensitive Dictionary of Response Headers.
        self.headers = CaseInsensitiveDict()

        # A CookieJar of Cookies the server sent back.
        self.cookies = cookiejar_from_dict({})

    def __enter__(self) -> Response:
        return self

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"

    def json(self, **kwargs: Any) -> Any:
        """parse response body to json (dict/list)"""
        if self.text is None:
            raise ResponseEmptyError()
        return json.loads(self.text, **kwargs)


def build_response(res: dict[str, Any], res_cookies: RequestsCookieJar) -> Response:
    """Build a Response object."""
    response = Response()
    # Add target / url
    response.url = res["target"]
    # Add status code
    response.status_code = res["status"]
    # Add headers
    response_headers = {}
    if res["headers"] is not None:
        for header_key, header_value in res["headers"].items():
            if len(header_value) == 1:
                response_headers[header_key] = header_value[0]
            else:
                response_headers[header_key] = header_value
    response.headers = CaseInsensitiveDict(response_headers)
    # Add cookies
    response.cookies = res_cookies
    # Add response body
    response.text = res["body"]
    return response
