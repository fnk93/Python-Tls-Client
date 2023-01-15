"""This module contains exceptions used."""
from __future__ import annotations

from typing import Any


class RequestError(IOError):
    """There was an ambiguous exception that occurred while handling your request."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize RequestError with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        super().__init__(*args, **kwargs)


class GetCookieError(IOError):
    """There was an ambiguous exception that occurred while handling get cookies."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize GetCookieError with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        super().__init__(*args, **kwargs)


class CloseError(IOError):
    """There was an ambiguous exception that occurred while handling session close."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize CloseError with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        super().__init__(*args, **kwargs)


class ResponseEmptyError(RequestError):
    """Response is empty."""


class TlsClientError(RequestError, GetCookieError, CloseError):
    """General error with the TLS client."""


class ClientCreateError(TlsClientError):
    """Unable to create new TLS client."""


class SessionCloseError(CloseError):
    """Session close failed."""


class CookieReadError(GetCookieError):
    """Cookie read failed."""


class ClientNotFoundError(TlsClientError):
    """Cookie read failed."""


class InvalidJSONError(RequestError):
    """A JSON error occurred."""


class JSONDecodeError(InvalidJSONError):
    """Couldn't decode the text into json."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Init an instance.

        Construct the JSONDecodeError instance first with all
        args. Then use it's args to construct the IOError so that
        the json specific args aren't used as IOError specific args
        and the error message from JSONDecodeError is preserved.
        """
        InvalidJSONError.__init__(self, *self.args, **kwargs)


class HTTPError(RequestError):
    """An HTTP error occurred."""


class MalformedResponseError(RequestError):
    """Response is malformed."""


class ConnectionError(RequestError):
    """A Connection error occurred."""


class ProxyError(ConnectionError):
    """A proxy error occurred."""


class SSLError(ConnectionError):
    """An SSL error occurred."""


class Timeout(RequestError):
    """The request timed out.

    Catching this error will catch both
    :exc:`~requests.exceptions.ConnectTimeout` and
    :exc:`~requests.exceptions.ReadTimeout` errors.
    """


class ConnectTimeout(ConnectionError, Timeout):
    """The request timed out while trying to connect to the remote server.

    Requests that produced this error are safe to retry.
    """


class ReadTimeout(Timeout):
    """The server did not send any data in the allotted amount of time."""


class URLRequired(RequestError):
    """A valid URL is required to make a request."""


class TooManyRedirects(RequestError):
    """Too many redirects."""


class MissingSchema(RequestError, ValueError):
    """The URL scheme (e.g. http or https) is missing."""


class InvalidSchema(RequestError, ValueError):
    """The URL scheme provided is either invalid or unsupported."""


class InvalidURL(RequestError, ValueError):
    """The URL provided was somehow invalid."""


class InvalidHeader(RequestError, ValueError):
    """The header value provided was somehow invalid."""


class InvalidProxyURL(InvalidURL):
    """The proxy URL provided is invalid."""


class ChunkedEncodingError(RequestError):
    """The server declared chunked encoding but sent an invalid chunk."""


class ContentDecodingError(RequestError):
    """Failed to decode response content."""


class StreamConsumedError(RequestError, TypeError):
    """The content for this response was already consumed."""


class RetryError(RequestError):
    """Custom retries logic failed."""


class UnrewindableBodyError(RequestError):
    """Requests encountered an error when trying to rewind a body."""
