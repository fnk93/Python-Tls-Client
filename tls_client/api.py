"""Allow requests without session."""
from __future__ import annotations

import base64
import ctypes

from json import dumps
from json import loads
from typing import Any
from typing import Optional
from typing import Union
from urllib import parse as url_parse

from tls_client.cffi import free_memory
from tls_client.cffi import request
from tls_client.cookies import cookiejar_from_dict
from tls_client.cookies import extract_cookies_to_jar
from tls_client.cookies import get_cookie_header
from tls_client.exceptions import ClientCreateError
from tls_client.exceptions import InvalidProxyURL
from tls_client.exceptions import InvalidSchema
from tls_client.exceptions import InvalidURL
from tls_client.exceptions import MalformedResponseError
from tls_client.exceptions import ReadTimeout
from tls_client.exceptions import RequestError
from tls_client.exceptions import TlsClientError
from tls_client.exceptions import URLRequired
from tls_client.response import Response
from tls_client.response import build_response
from tls_client.structures import CaseInsensitiveDict


def execute_request(
    # self,
    method: str,
    url: str,
    client_identifier: Optional[str] = None,
    ja3_string: Optional[str] = None,
    h2_settings: Optional[dict[str, int]] = None,
    h2_settings_order: Optional[list[str]] = None,
    supported_signature_algorithms: Optional[list[str]] = None,
    supported_versions: Optional[list[str]] = None,
    key_share_curves: Optional[list[str]] = None,
    cert_compression_algo: Optional[str] = None,
    pseudo_header_order: Optional[list[str]] = None,
    connection_flow: Optional[int] = None,
    priority_frames: Optional[list[dict[Any, Any]]] = None,
    # header_order: Optional[list[str]] = None,
    header_priority: Optional[dict[str, Any]] = None,
    random_tls_extension_order: Optional[bool] = False,
    params: Optional[dict[str, str]] = None,
    data: Optional[Union[str, dict[Any, Any], bytes, bytearray]] = None,
    headers: Optional[dict[str, str]] = None,
    header_order: Optional[list[str]] = None,
    cookies: Optional[dict[str, str]] = None,
    json: Optional[dict[Any, Any]] = None,
    allow_redirects: Optional[bool] = False,
    insecure_skip_verify: Optional[bool] = False,
    timeout_seconds: Optional[int] = 30,
    timeout_milliseconds: Optional[float] = None,
    proxy: Optional[Union[dict[str, str], str]] = None,
    without_cookiejar: Optional[bool] = False,
    is_byte_request: bool = False,
    is_byte_response: bool = False,
    debug: Optional[bool] = None,
    force_http1: bool = False,
) -> Response:
    """Execute a request via shared TLS library.

    Args:
        method: HTTP method.
        url: Request URL.
        params: Dictionary of params. Defaults to None.
        data: Data to send. Defaults to None.
        headers: Headers to use. Defaults to None.
        header_order: Header order to use. Defaults to None.
        cookies: Cookie dict. Defaults to None.
        json: JSON dictionary. Defaults to None.
        allow_redirects: Whether to allow and follow redirects. Defaults to False.
        insecure_skip_verify: Whether to activate insecure skip verify. Defaults to False.
        timeout_seconds: Request timeout in seconds. Defaults to 30.
        timeout_milliseconds: Request timeout in milliseconds. Defaults to None.
        proxy: Dictionary of proxies or proxy URL as string. Defaults to None.
        without_cookiejar: Whether to not use a cookiejar. Defaults to False.
        is_byte_request: Whether request is bytes. Defaults to False.
        is_byte_response: Whether response should be in bytes. Defaults to False.

    Raises:
        TLSClientExeption: Error in shared library.

    Returns:
        Response object.
    """
    if debug is None:
        debug = False
    # --- URL ------------------------------------------------------------------------------------------------------
    # Prepare URL - add params to url
    if params is not None:
        url = f"{url}?{url_parse.urlencode(params, doseq=True)}"

    # --- Request Body ---------------------------------------------------------------------------------------------
    # Prepare request body - build request body
    # Data has priority. JSON is only used if data is None.
    request_body: Union[str, bytes, bytearray, None]
    if data is None and json is not None:
        if isinstance(json, (dict, list)):
            json_body = dumps(json)
        # else:
        #     json_body = json
        request_body = json_body
        content_type = "application/json"
    elif data is not None and not (isinstance(data, (str, bytes, bytearray))):
        request_body = url_parse.urlencode(data, doseq=True)
        content_type = "application/x-www-form-urlencoded"
    else:
        request_body = data
        content_type = None

    # --- Headers --------------------------------------------------------------------------------------------------
    # merge headers of session and of the request
    # req_headers = self.headers.copy()
    req_headers = CaseInsensitiveDict({})
    if headers is not None:
        for header_key, header_value in headers.items():
            # check if all header keys and values are strings
            if type(header_key) is str and type(header_value) is str:
                req_headers[header_key] = headers.get(header_key, header_value)
    # set content type if it isn't set
    if content_type is not None and "content-type" not in req_headers:
        req_headers["Content-Type"] = content_type

    # --- Header Order
    # if header_order is None:
    #     header_order = self.header_order

    # --- Cookies --------------------------------------------------------------------------------------------------
    cookies = cookies or {}
    # Merge with session cookies
    req_cookies = cookiejar_from_dict(cookies)
    # req_cookies = merge_cookies(self.cookies, cookies)
    cookie_header = get_cookie_header(
        request_url=url, request_headers=req_headers, cookie_jar=req_cookies
    )
    if cookie_header is not None:
        req_headers["Cookie"] = cookie_header

    # --- Proxy ----------------------------------------------------------------------------------------------------
    # proxy = proxy

    if type(proxy) is dict and "http" in proxy:
        req_proxy = proxy["http"]
    elif type(proxy) is str:
        req_proxy = proxy
    else:
        req_proxy = ""

    # --- Request --------------------------------------------------------------------------------------------------
    if isinstance(request_body, (bytes, bytearray)):
        is_byte_request = True
        request_body = base64.b64encode(request_body)
    if timeout_milliseconds is not None:
        timeout_seconds = None
    request_payload: dict[str, Any] = {
        # "sessionId": self._session_id,
        "followRedirects": allow_redirects,
        "forceHttp1": force_http1,
        "isByteResponse": is_byte_response,  # TODO: check
        "withDebug": debug,
        "isByteRequest": is_byte_request,
        "withoutCookieJar": without_cookiejar,
        "withDefaultCookieJar": False,
        "insecureSkipVerify": insecure_skip_verify,
        "timeoutSeconds": timeout_seconds,
        "timeoutMilliseconds": timeout_milliseconds,
        "proxyUrl": req_proxy,
        "headers": dict(req_headers),
        "headerOrder": header_order,
        "requestUrl": url,
        "requestMethod": method,
        "requestBody": request_body,
        "requestCookies": [],  # Empty because it's handled in python
    }
    if client_identifier is None:
        request_payload["customTlsClient"] = {
            "ja3String": ja3_string,
            "supportedSignatureAlgorithms": supported_signature_algorithms,
            "supportedVersions": supported_versions,
            "keyShareCurves": key_share_curves,
            "certCompressionAlgo": cert_compression_algo,
            "h2Settings": h2_settings,
            "h2SettingsOrder": h2_settings_order,
            "pseudoHeaderOrder": pseudo_header_order,
            "connectionFlow": connection_flow,
            "priorityFrames": priority_frames,
            "headerPriority": header_priority,
        }
    else:
        request_payload["tlsClientIdentifier"] = client_identifier
        request_payload["withRandomTLSExtensionOrder"] = random_tls_extension_order

    # this is a pointer to the response
    response = request(dumps(request_payload).encode("utf-8"))
    # dereference the pointer to a byte array
    response_bytes = ctypes.string_at(response)
    # convert our byte array to a string (tls client returns json)
    response_string = response_bytes.decode("utf-8")
    # convert response string to json
    response_object = loads(response_string)
    # print(response_object)
    free_memory(response_object["id"].encode("utf-8"))

    # --- Response -------------------------------------------------------------------------------------------------
    # Error handling
    if response_object.get("status") == 0:
        # error sources:
        # requestInput := tls_client_cffi_src.RequestInput{}
        # marshallError := json.Unmarshal([]byte(requestParamsJson), &requestInput)

        # if marshallError != nil {
        #     clientErr := tls_client_cffi_src.NewTLSClientError(marshallError)
        #     return handleErrorResponse("", false, clientErr)
        # }

        # tlsClient, sessionId, withSession, err := tls_client_cffi_src.CreateClient(requestInput)

        # if err != nil {
        #     return handleErrorResponse(sessionId, withSession, err)
        # }

        # req, err := tls_client_cffi_src.BuildRequest(requestInput)

        # if err != nil {
        #     clientErr := tls_client_cffi_src.NewTLSClientError(err)
        #     return handleErrorResponse(sessionId, withSession, clientErr)
        # }
        # resp, reqErr := tlsClient.Do(req)

        # if reqErr != nil {
        #     clientErr := tls_client_cffi_src.NewTLSClientError(fmt.Errorf("failed to do request: %w", reqErr))
        #     return handleErrorResponse(sessionId, withSession, clientErr)
        # }

        # targetCookies := tlsClient.GetCookies(resp.Request.URL)

        # response, err := tls_client_cffi_src.BuildResponse(sessionId, withSession, resp, targetCookies, requestInput.IsByteResponse)
        # if err != nil {
        #     return handleErrorResponse(sessionId, withSession, err)
        # }

        # jsonResponse, marshallError := json.Marshal(response)

        # if marshallError != nil {
        #     clientErr := tls_client_cffi_src.NewTLSClientError(marshallError)
        #     return handleErrorResponse(sessionId, withSession, clientErr)
        # }

        raise build_request_error(
            response_object["body"], request_payload=request_payload
        )
    # Set response cookies
    response_cookie_jar = extract_cookies_to_jar(
        request_url=url,
        request_headers=req_headers,
        cookie_jar=req_cookies,
        response_headers=response_object["headers"],
    )
    # build response class
    return build_response(response_object, response_cookie_jar)


def build_request_error(
    # self,
    error_body: str,
    request_payload: dict[str, Any],
) -> RequestError:
    """Construct an exception for a request."""
    if "Client.Timeout exceeded while awaiting headers" in error_body:
        return ReadTimeout(error_body)
    elif "unsupported protocol scheme" in error_body:
        return InvalidSchema(error_body)
    elif "specify scheme explicitly" in error_body:
        return InvalidProxyURL(error_body)
    elif "no such host" in error_body:
        return InvalidURL(error_body)
    elif (
        "cannot build client with both defined timeout in seconds and timeout in"
        " milliseconds."
        in error_body
    ):
        return ClientCreateError(error_body)
    elif (
        "make sure to specify full url like https://username:password@hostname.com:443/"
        in error_body
    ):
        return InvalidProxyURL(error_body)
    elif "no request url or request method provided" in error_body:
        return URLRequired(error_body)
    elif "malformed HTTP response" in error_body:
        return MalformedResponseError(error_body)
    return TlsClientError(error_body)


def get(url: str, **kwargs: Any) -> Response:
    """Send a GET request.

    Args:
        url: Request URL.
        **kwargs: Arbitrary keyword arguments.

    Raises:
        RequestError: Error in shared library.

    Returns:
        A response object.
    """
    return execute_request(method="GET", url=url, **kwargs)


def options(url: str, **kwargs: Any) -> Response:
    """Send a OPTIONS request.

    Args:
        url: Request URL.
        **kwargs: Arbitrary keyword arguments.

    Raises:
        RequestError: Error in shared library.

    Returns:
        A response object.
    """
    return execute_request(method="OPTIONS", url=url, **kwargs)


def head(url: str, **kwargs: Any) -> Response:
    """Send a HEAD request.

    Args:
        url: Request URL.
        **kwargs: Arbitrary keyword arguments.

    Raises:
        RequestError: Error in shared library.

    Returns:
        A response object.
    """
    return execute_request(method="HEAD", url=url, **kwargs)


def post(
    url: str,
    data: Optional[Union[str, dict[Any, Any], bytes, bytearray]] = None,
    json: Optional[dict[Any, Any]] = None,
    **kwargs: Any,
) -> Response:
    """Send a POST request.

    Args:
        url: Request URL.
        data: Data to send. Defaults to None.
        json: JSON dictionary. Defaults to None.
        **kwargs: Arbitrary keyword arguments.

    Raises:
        RequestError: Error in shared library.

    Returns:
        A response object.
    """
    return execute_request(method="POST", url=url, data=data, json=json, **kwargs)


def put(
    url: str,
    data: Optional[Union[str, dict[Any, Any], bytes, bytearray]] = None,
    json: Optional[dict[Any, Any]] = None,
    **kwargs: Any,
) -> Response:
    """Send a PUT request.

    Args:
        url: Request URL.
        data: Data to send. Defaults to None.
        json: JSON dictionary. Defaults to None.
        **kwargs: Arbitrary keyword arguments.

    Raises:
        RequestError: Error in shared library.

    Returns:
        A response object.
    """
    return execute_request(method="PUT", url=url, data=data, json=json, **kwargs)


def patch(
    url: str,
    data: Optional[Union[str, dict[Any, Any], bytes, bytearray]] = None,
    json: Optional[dict[Any, Any]] = None,
    **kwargs: Any,
) -> Response:
    """Send a PATCH request.

    Args:
        url: Request URL.
        data: Data to send. Defaults to None.
        json: JSON dictionary. Defaults to None.
        **kwargs: Arbitrary keyword arguments.

    Raises:
        RequestError: Error in shared library.

    Returns:
        A response object.
    """
    return execute_request(method="PATCH", url=url, data=data, json=json, **kwargs)


def delete(url: str, **kwargs: Any) -> Response:
    """Send a DELETE request.

    Args:
        url: Request URL.
        **kwargs: Arbitrary keyword arguments.

    Raises:
        RequestError: Error in shared library.

    Returns:
        A response object.
    """
    return execute_request(method="DELETE", url=url, **kwargs)
