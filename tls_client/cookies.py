from __future__ import annotations

import copy
import threading

from collections.abc import Generator
from collections.abc import ItemsView
from collections.abc import KeysView
from collections.abc import MutableMapping
from collections.abc import ValuesView
from http.client import HTTPMessage
from http.client import HTTPResponse
from http.cookiejar import Cookie
from http.cookiejar import CookieJar
from http.cookiejar import CookiePolicy
from http.cookiejar import DefaultCookiePolicy
from typing import Any
from typing import Optional
from typing import TypeVar
from typing import Union
from urllib.parse import urlparse
from urllib.parse import urlunparse
from urllib.request import Request

from tls_client.structures import CaseInsensitiveDict


_T = TypeVar("_T")


class MockRequest(Request):
    """
    Mimic a urllib2.Request to get the correct cookie string for the request.
    """

    def __init__(self, request_url: str, request_headers: CaseInsensitiveDict) -> None:
        self.request_url = request_url
        self.request_headers = request_headers
        self._new_headers: dict[str, str] = {}
        self.type = urlparse(self.request_url).scheme

    def get_type(self) -> str:
        return self.type

    def get_host(self) -> str:
        return urlparse(self.request_url).netloc

    def get_origin_req_host(self) -> str:
        return self.get_host()

    def get_full_url(self) -> str:
        # Only return the response's URL if the user hadn't set the Host
        # header
        if not self.request_headers.get("Host"):
            return self.request_url
        # If they did set it, retrieve it and reconstruct the expected domain
        host = self.request_headers["Host"]
        parsed = urlparse(self.request_url)
        # Reconstruct the URL as we expect it
        return urlunparse(
            [
                parsed.scheme,
                host,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ]
        )

    def is_unverifiable(self) -> bool:
        return True

    def has_header(self, name: str) -> bool:
        return name in self.request_headers or name in self._new_headers

    def get_header(self, header_name: str, default: _T) -> str | _T:
        return self.request_headers.get(
            header_name, self._new_headers.get(header_name, default)
        )

    def add_unredirected_header(self, name: str, value: str) -> None:
        self._new_headers[name] = value

    def get_new_headers(self) -> dict[str, str]:
        return self._new_headers

    @property
    def unverifiable(self) -> bool:
        return self.is_unverifiable()

    @property
    def origin_req_host(self) -> str:
        return self.get_origin_req_host()

    @property
    def host(self) -> str:
        return self.get_host()


class MockResponse(HTTPResponse):
    """
    Wraps a httplib.HTTPMessage to mimic a urllib.addinfourl.
    The objective is to retrieve the response cookies correctly.
    """

    def __init__(self, headers: HTTPMessage) -> None:
        self._headers = headers

    def info(self) -> HTTPMessage:
        return self._headers


class CookieConflictError(RuntimeError):
    """There are two cookies that meet the criteria specified in the cookie jar.
    Use .get and .set and include domain and path args in order to be more specific.
    """


class RequestsCookieJar(CookieJar, MutableMapping[str, Any]):
    """Origin: requests library (https://github.com/psf/requests)
    Compatibility class; is a cookielib.CookieJar, but exposes a dict
    interface.

    This is the CookieJar we create by default for requests and sessions that
    don't specify one, since some clients may expect response.cookies and
    session.cookies to support dict operations.

    Requests does not use the dict interface internally; it's just for
    compatibility with external client code. All requests code should work
    out of the box with externally provided instances of ``CookieJar``, e.g.
    ``LWPCookieJar`` and ``FileCookieJar``.

    Unlike a regular CookieJar, this class is pickleable.

    .. warning:: dictionary operations that are normally O(1) may be O(n).
    """

    def __init__(self, policy: CookiePolicy | None = None) -> None:
        super().__init__(policy)

    def get(
        self,
        name: str,
        default: Optional[Any] = None,
        domain: Optional[str] = None,
        path: Optional[str] = None,
    ) -> str | Any | None:
        """Dict-like get() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.

        .. warning:: operation is O(n), not O(1).
        """
        try:
            return self._find_no_duplicates(name, domain, path)
        except KeyError:
            return default

    def set(self, name: str, value: str | None = None, **kwargs: Any) -> Cookie | None:
        """Dict-like set() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.
        """
        # support client code that unsets cookies by assignment of a None value:
        if value is None:
            remove_cookie_by_name(
                self, name, domain=kwargs.get("domain"), path=kwargs.get("path")
            )
            return None

        c = create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c

    def iterkeys(self) -> Generator[str, None, None]:
        """Dict-like iterkeys() that returns an iterator of names of cookies
        from the jar.

        .. seealso:: itervalues() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.name

    def keys(self) -> KeysView[str]:
        """Dict-like keys() that returns a list of names of cookies from the
        jar.

        .. seealso:: values() and items().
        """
        return KeysView(self)
        # return list(self.iterkeys())

    def itervalues(self) -> Generator[str | None, None, None]:
        """Dict-like itervalues() that returns an iterator of values of cookies
        from the jar.

        .. seealso:: iterkeys() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.value

    def values(self) -> ValuesView[Any]:
        """Dict-like values() that returns a list of values of cookies from the
        jar.

        .. seealso:: keys() and items().
        """
        return ValuesView(self)
        # return list(self.itervalues())

    def iteritems(self) -> Generator[tuple[str, str | None], None, None]:
        """Dict-like iteritems() that returns an iterator of name-value tuples
        from the jar.

        .. seealso:: iterkeys() and itervalues().
        """
        for cookie in iter(self):
            yield cookie.name, cookie.value

    def items(self) -> ItemsView[str, Any]:
        """Dict-like items() that returns a list of name-value tuples from the
        jar. Allows client-code to call ``dict(RequestsCookieJar)`` and get a
        vanilla python dict of key value pairs.

        .. seealso:: keys() and values().
        """
        return ItemsView(self)
        # return list(self.iteritems())

    def list_domains(self) -> list[str]:
        """Utility method to list all the domains in the jar."""
        domains = []
        for cookie in iter(self):
            if cookie.domain not in domains:
                domains.append(cookie.domain)
        return domains

    def list_paths(self) -> list[str]:
        """Utility method to list all the paths in the jar."""
        paths = []
        for cookie in iter(self):
            if cookie.path not in paths:
                paths.append(cookie.path)
        return paths

    def multiple_domains(self) -> bool:
        """Returns True if there are multiple domains in the jar.
        Returns False otherwise.

        :rtype: bool
        """
        domains = []
        for cookie in iter(self):
            if cookie.domain is not None and cookie.domain in domains:
                return True
            domains.append(cookie.domain)
        return False  # there is only one domain in jar

    def get_dict(
        self, domain: Optional[str] = None, path: Optional[str] = None
    ) -> dict[str, str | None]:
        """Takes as an argument an optional domain and path and returns a plain
        old Python dict of name-value pairs of cookies that meet the
        requirements.

        :rtype: dict
        """
        dictionary = {}
        for cookie in iter(self):
            if (domain is None or cookie.domain == domain) and (
                path is None or cookie.path == path
            ):
                dictionary[cookie.name] = cookie.value
        return dictionary

    def __contains__(self, name: object) -> bool:
        try:
            return super().__contains__(name)
        except CookieConflictError:
            return True

    def __getitem__(self, name: str) -> str:
        """Dict-like __getitem__() for compatibility with client code. Throws
        exception if there are more than one cookie with name. In that case,
        use the more explicit get() method instead.

        .. warning:: operation is O(n), not O(1).
        """
        return self._find_no_duplicates(name)

    def __setitem__(self, name: str, value: str | None = None) -> None:
        """Dict-like __setitem__ for compatibility with client code. Throws
        exception if there is already a cookie of that name in the jar. In that
        case, use the more explicit set() method instead.
        """
        self.set(name, value)

    def __delitem__(self, name: str) -> None:
        """Deletes a cookie given a name. Wraps ``cookielib.CookieJar``'s
        ``remove_cookie_by_name()``.
        """
        remove_cookie_by_name(self, name)

    def set_cookie(self, cookie: Cookie, *args: Any, **kwargs: Any) -> None:
        if (
            cookie.value is not None
            and hasattr(cookie.value, "startswith")
            and cookie.value.startswith('"')
            and cookie.value.endswith('"')
        ):
            cookie.value = cookie.value.replace('\\"', "")
        return super().set_cookie(cookie, *args, **kwargs)

    def update(self, other: CookieJar | MutableMapping[Any, Any]) -> None:  # type: ignore[override]
        """Updates this jar with cookies from another CookieJar or dict-like"""
        if isinstance(other, CookieJar):
            for cookie in other:
                self.set_cookie(copy.copy(cookie))
        else:
            super().update(other)

    def _find(
        self, name: str, domain: Optional[str] = None, path: Optional[str] = None
    ) -> str | None:
        """Requests uses this method internally to get cookie values.

        If there are conflicting cookies, _find arbitrarily chooses one.
        See _find_no_duplicates if you want an exception thrown if there are
        conflicting cookies.

        :param name: a string containing name of cookie
        :param domain: (optional) string containing domain of cookie
        :param path: (optional) string containing path of cookie
        :return: cookie.value
        """
        for cookie in iter(self):
            if (
                cookie.name == name
                and (domain is None or cookie.domain == domain)
                and (path is None or cookie.path == path)
            ):
                return cookie.value

        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def _find_no_duplicates(
        self, name: str, domain: Optional[str] = None, path: Optional[str] = None
    ) -> str:
        """Both ``__get_item__`` and ``get`` call this function: it's never
        used elsewhere in Requests.

        :param name: a string containing name of cookie
        :param domain: (optional) string containing domain of cookie
        :param path: (optional) string containing path of cookie
        :raises KeyError: if cookie is not found
        :raises CookieConflictError: if there are multiple cookies
            that match name and optionally domain and path
        :return: cookie.value
        """
        to_return = None
        for cookie in iter(self):
            if (
                cookie.name == name
                and (domain is None or cookie.domain == domain)
                and (path is None or cookie.path == path)
            ):
                if to_return is not None:
                    # if there are multiple cookies that meet passed in criteria
                    raise CookieConflictError(
                        f"There are multiple cookies with name, {name!r}"
                    )
                # we will eventually return this as long as no cookie conflict
                to_return = cookie.value

        if to_return:
            return to_return
        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def __getstate__(self) -> dict[str, Any]:
        """Unlike a normal CookieJar, this class is pickleable."""
        state = self.__dict__.copy()
        # remove the unpickleable RLock object
        state.pop("_cookies_lock")
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        """Unlike a normal CookieJar, this class is pickleable."""
        self.__dict__.update(state)
        if "_cookies_lock" not in self.__dict__:
            self._cookies_lock = threading.RLock()

    def copy(self) -> RequestsCookieJar:
        """Return a copy of this RequestsCookieJar."""
        new_cj = RequestsCookieJar()
        new_cj.set_policy(self.get_policy())
        new_cj.update(self)
        return new_cj

    def get_policy(self) -> CookiePolicy:
        """Return the CookiePolicy instance used."""
        try:
            return self._policy  # type: ignore[attr-defined] # pyright: ignore
        except AttributeError:
            return DefaultCookiePolicy()


def remove_cookie_by_name(
    cookiejar: RequestsCookieJar,
    name: str,
    domain: str | None = None,
    path: str | None = None,
) -> None:
    """Removes a cookie by name, by default over all domains and paths."""
    clearables = []
    for cookie in cookiejar:
        if cookie.name != name:
            continue
        if domain is not None and domain != cookie.domain:
            continue
        if path is not None and path != cookie.path:
            continue
        clearables.append((cookie.domain, cookie.path, cookie.name))

    for domain, path, name in clearables:
        cookiejar.clear(domain, path, name)


def create_cookie(
    name: str,
    value: str,
    **kwargs: Optional[int] | Optional[str] | bool | dict[str, str | None] | None,
) -> Cookie:
    """Make a cookie from underspecified parameters."""
    result: dict[
        str, Optional[int] | Optional[str] | bool | dict[str, Optional[str]]
    ] = {
        "version": 0,
        "name": name,
        "value": value,
        "port": None,
        "domain": "",
        "path": "/",
        "secure": False,
        "expires": None,
        "discard": True,
        "comment": None,
        "comment_url": None,
        "rest": {"HttpOnly": None},
        "rfc2109": False,
    }

    badargs = set(kwargs) - set(result)
    if badargs:
        raise TypeError(
            f"create_cookie() got unexpected keyword arguments: {list(badargs)}"
        )

    version = kwargs.get("version", 0)
    if not isinstance(version, int):
        raise TypeError(f"create_cookies() got wrong 'version' type: {type(version)}")
    name_new = kwargs.get("name", name)
    if not isinstance(name_new, str):
        raise TypeError(f"create_cookies() got wrong 'name_new' type: {type(name_new)}")
    name = name_new
    value_new = kwargs.get("value", value)
    if not isinstance(value_new, str):
        raise TypeError(
            f"create_cookies() got wrong 'value_new' type: {type(value_new)}"
        )
    value = value_new
    port = kwargs.get("port")
    if not isinstance(port, str) and port is not None:
        raise TypeError(f"create_cookies() got wrong 'port' type: {type(port)}")
    port_specified = port is not None and port != ""
    domain = kwargs.get("domain", "")
    if not isinstance(domain, str):
        raise TypeError(f"create_cookies() got wrong 'domain' type: {type(domain)}")
    domain_specified = domain != ""
    domain_initial_dot = domain.startswith(".")
    path = kwargs.get("path", "/")
    if not isinstance(path, str):
        raise TypeError(f"create_cookies() got wrong 'path' type: {type(path)}")
    path_specified = path != ""
    secure = kwargs.get("secure", False)
    if not isinstance(secure, bool):
        raise TypeError(f"create_cookies() got wrong 'secure' type: {type(secure)}")
    expires = kwargs.get("expires", None)
    if not isinstance(expires, int) and expires is not None:
        raise TypeError(f"create_cookies() got wrong 'expires' type: {type(expires)}")
    discard = kwargs.get("discard", True)
    if not isinstance(discard, bool):
        raise TypeError(f"create_cookies() got wrong 'discard' type: {type(discard)}")
    comment = kwargs.get("comment", None)
    if not isinstance(comment, str) and comment is not None:
        raise TypeError(f"create_cookies() got wrong 'comment' type: {type(comment)}")
    comment_url = kwargs.get("comment_url", None)
    if not isinstance(comment_url, str) and comment_url is not None:
        raise TypeError(
            f"create_cookies() got wrong 'comment_url' type: {type(comment_url)}"
        )
    rest = kwargs.get(
        "rest",
        {
            "HttpOnly": None,
        },
    )
    if not isinstance(rest, dict):
        raise TypeError(f"create_cookies() got wrong 'rest' type: {type(rest)}")
    rfc2109 = kwargs.get("rfc2109", False)
    if not isinstance(rfc2109, bool):
        raise TypeError(f"create_cookies() got wrong 'rfc2109' type: {type(rfc2109)}")

    return Cookie(
        version=version,
        name=name,
        value=value,
        port=port,
        port_specified=port_specified,
        domain=domain,
        domain_specified=domain_specified,
        domain_initial_dot=domain_initial_dot,
        path=path,
        path_specified=path_specified,
        secure=secure,
        expires=expires,
        discard=discard,
        comment=comment,
        comment_url=comment_url,
        rest=rest,  # type: ignore[arg-type] # pyright: ignore
        rfc2109=rfc2109,
    )


def cookiejar_from_dict(cookie_dict: dict[str, str]) -> RequestsCookieJar:
    """transform a dict to CookieJar"""
    cookie_jar = RequestsCookieJar()
    if cookie_dict is not None:
        for name, value in cookie_dict.items():
            cookie_jar.set_cookie(create_cookie(name=name, value=value))
    return cookie_jar


def merge_cookies(
    cookiejar: RequestsCookieJar, cookies: Union[dict[str, str], RequestsCookieJar]
) -> RequestsCookieJar:
    """Merge cookies in session and cookies provided in request"""
    if isinstance(cookies, dict):
        cookies = cookiejar_from_dict(cookies)

    for cookie in cookies:
        cookiejar.set_cookie(cookie)

    return cookiejar


def get_cookie_header(
    request_url: str,
    request_headers: CaseInsensitiveDict,
    cookie_jar: RequestsCookieJar,
) -> str:
    r = MockRequest(request_url, request_headers)
    cookie_jar.add_cookie_header(r)
    return r.get_new_headers().get("Cookie", "")


def extract_cookies_to_jar(
    request_url: str,
    request_headers: CaseInsensitiveDict,
    cookie_jar: RequestsCookieJar,
    response_headers: dict[str, Any],
) -> RequestsCookieJar:
    response_cookie_jar = cookiejar_from_dict({})

    req = MockRequest(request_url, request_headers)
    # mimic HTTPMessage
    http_message = HTTPMessage()
    http_message._headers = []  # type: ignore[attr-defined] # pyright: ignore
    for header_name, header_values in response_headers.items():
        for header_value in header_values:
            http_message._headers.append((header_name, header_value))  # type: ignore[attr-defined] # pyright: ignore
    res = MockResponse(http_message)
    response_cookie_jar.extract_cookies(res, req)

    merge_cookies(cookie_jar, response_cookie_jar)
    return response_cookie_jar
