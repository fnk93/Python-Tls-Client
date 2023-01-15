from __future__ import annotations

import base64
import ctypes
import urllib.parse
import uuid

from json import dumps
from json import loads
from typing import Any
from typing import Optional
from typing import Union

from tls_client.__version__ import __version__
from tls_client.cffi import close_session
from tls_client.cffi import free_memory
from tls_client.cffi import get_cookies_from_session
from tls_client.cffi import request
from tls_client.cookies import cookiejar_from_dict
from tls_client.cookies import extract_cookies_to_jar
from tls_client.cookies import get_cookie_header
from tls_client.cookies import merge_cookies
from tls_client.exceptions import ClientCreateError
from tls_client.exceptions import ClientNotFoundError
from tls_client.exceptions import CookieReadError
from tls_client.exceptions import InvalidProxyURL
from tls_client.exceptions import InvalidSchema
from tls_client.exceptions import InvalidURL
from tls_client.exceptions import ReadTimeout
from tls_client.exceptions import SessionCloseError
from tls_client.exceptions import TlsClientError
from tls_client.exceptions import URLRequired
from tls_client.response import Response
from tls_client.response import build_response
from tls_client.structures import CaseInsensitiveDict


RequestError = Union[
    TlsClientError,
    ReadTimeout,
    InvalidSchema,
    InvalidProxyURL,
    InvalidURL,
    ClientCreateError,
    URLRequired,
]
GetCookieError = Union[CookieReadError, TlsClientError]
CloseError = Union[SessionCloseError, TlsClientError]


class Session:
    def __init__(
        self,
        client_identifier: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
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
        header_order: Optional[list[str]] = None,
        header_priority: Optional[dict[str, Any]] = None,
        random_tls_extension_order: Optional[bool] = False,
        force_http1: Optional[bool] = False,
        debug: bool = False,
    ) -> None:
        self._session_id = str(uuid.uuid4())
        self._debug = debug
        # --- Standard Settings ----------------------------------------------------------------------------------------

        # Case-insensitive dictionary of headers, send on each request
        self.headers = CaseInsensitiveDict(
            {
                "User-Agent": f"tls-client/{__version__}",
                # "Accept-Encoding": "gzip, deflate, br",
                "Accept": "*/*",
                "Connection": "keep-alive",
            }
        )
        if headers is not None:
            for key, value in headers.items():
                self.headers[key] = value
        # Example:
        # {
        #     "http": "http://user:pass@ip:port",
        #     "https": "http://user:pass@ip:port"
        # }
        self.proxies: dict[str, str] = {}

        # Dictionary of querystring data to attach to each request. The dictionary values may be lists for representing
        # multivalued query parameters.
        self.params: dict[Any, Any] = {}

        # CookieJar containing all currently outstanding cookies set on this session
        self.cookies = cookiejar_from_dict({})

        # --- Advanced Settings ----------------------------------------------------------------------------------------

        # Examples:
        # Chrome --> chrome_103, chrome_104, chrome_105, chrome_106
        # Firefox --> firefox_102, firefox_104
        # Opera --> opera_89, opera_90
        # Safari --> safari_15_3, safari_15_6_1, safari_16_0
        # iOS --> safari_ios_15_5, safari_ios_15_6, safari_ios_16_0
        # iPadOS --> safari_ios_15_6
        self.client_identifier = client_identifier

        # Set JA3 --> TLSVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats
        # Example:
        # 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0
        self.ja3_string = ja3_string

        # HTTP2 Header Frame Settings
        # Possible Settings:
        # HEADER_TABLE_SIZE
        # SETTINGS_ENABLE_PUSH
        # MAX_CONCURRENT_STREAMS
        # INITIAL_WINDOW_SIZE
        # MAX_FRAME_SIZE
        # MAX_HEADER_LIST_SIZE
        #
        # Example:
        # {
        #     "HEADER_TABLE_SIZE": 65536,
        #     "MAX_CONCURRENT_STREAMS": 1000,
        #     "INITIAL_WINDOW_SIZE": 6291456,
        #     "MAX_HEADER_LIST_SIZE": 262144
        # }
        self.h2_settings = h2_settings

        # HTTP2 Header Frame Settings Order
        # Example:
        # [
        #     "HEADER_TABLE_SIZE",
        #     "MAX_CONCURRENT_STREAMS",
        #     "INITIAL_WINDOW_SIZE",
        #     "MAX_HEADER_LIST_SIZE"
        # ]
        self.h2_settings_order = h2_settings_order

        # Supported Signature Algorithms
        # Possible Settings:
        # PKCS1WithSHA256
        # PKCS1WithSHA384
        # PKCS1WithSHA512
        # PSSWithSHA256
        # PSSWithSHA384
        # PSSWithSHA512
        # ECDSAWithP256AndSHA256
        # ECDSAWithP384AndSHA384
        # ECDSAWithP521AndSHA512
        # PKCS1WithSHA1
        # ECDSAWithSHA1
        #
        # Example:
        # [
        #     "ECDSAWithP256AndSHA256",
        #     "PSSWithSHA256",
        #     "PKCS1WithSHA256",
        #     "ECDSAWithP384AndSHA384",
        #     "PSSWithSHA384",
        #     "PKCS1WithSHA384",
        #     "PSSWithSHA512",
        #     "PKCS1WithSHA512",
        # ]
        self.supported_signature_algorithms = supported_signature_algorithms

        # Supported Versions
        # Possible Settings:
        # GREASE
        # 1.3
        # 1.2
        # 1.1
        # 1.0
        #
        # Example:
        # [
        #     "GREASE",
        #     "1.3",
        #     "1.2"
        # ]
        self.supported_versions = supported_versions

        # Key Share Curves
        # Possible Settings:
        # GREASE
        # P256
        # P384
        # P521
        # X25519
        #
        # Example:
        # [
        #     "GREASE",
        #     "X25519"
        # ]
        self.key_share_curves = key_share_curves

        # Cert Compression Algorithm
        # Examples: "zlib", "brotli", "zstd"
        self.cert_compression_algo = cert_compression_algo

        # Pseudo Header Order (:authority, :method, :path, :scheme)
        # Example:
        # [
        #     ":method",
        #     ":authority",
        #     ":scheme",
        #     ":path"
        # ]
        self.pseudo_header_order = pseudo_header_order

        # Connection Flow / Window Size Increment
        # Example:
        # 15663105
        self.connection_flow = connection_flow

        # Example:
        # [
        #   {
        #     "streamID": 3,
        #     "priorityParam": {
        #       "weight": 201,
        #       "streamDep": 0,
        #       "exclusive": false
        #     }
        #   },
        #   {
        #     "streamID": 5,
        #     "priorityParam": {
        #       "weight": 101,
        #       "streamDep": false,
        #       "exclusive": 0
        #     }
        #   }
        # ]
        self.priority_frames = priority_frames

        # Order of your headers
        # Example:
        # [
        #   "key1",
        #   "key2"
        # ]
        self.header_order = header_order

        # Header Priority
        # Example:
        # {
        #   "streamDep": 1,
        #   "exclusive": true,
        #   "weight": 1
        # }
        self.header_priority = header_priority

        # randomize tls extension order
        self.random_tls_extension_order = random_tls_extension_order

        # force HTTP1
        self.force_http1 = force_http1

        # true - to be able to provide a base64 encoded request body which is an array of bytes
        # self.is_byte_request = is_byte_request

    def execute_request(
        self,
        method: str,
        url: str,
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
            debug = self._debug
        # --- URL ------------------------------------------------------------------------------------------------------
        # Prepare URL - add params to url
        if params is not None:
            url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"

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
            request_body = urllib.parse.urlencode(data, doseq=True)
            content_type = "application/x-www-form-urlencoded"
        else:
            request_body = data
            content_type = None

        # --- Headers --------------------------------------------------------------------------------------------------
        # merge headers of session and of the request
        req_headers = self.headers.copy()
        if headers is not None:
            for header_key, header_value in headers.items():
                # check if all header keys and values are strings
                if type(header_key) is str and type(header_value) is str:
                    req_headers[header_key] = headers.get(header_key, header_value)
        # set content type if it isn't set
        if content_type is not None and "content-type" not in req_headers:
            req_headers["Content-Type"] = content_type

        # --- Header Order
        if header_order is None:
            header_order = self.header_order

        # --- Cookies --------------------------------------------------------------------------------------------------
        cookies = cookies or {}
        # Merge with session cookies
        req_cookies = merge_cookies(self.cookies, cookies)
        cookie_header = get_cookie_header(
            request_url=url, request_headers=req_headers, cookie_jar=req_cookies
        )
        if cookie_header is not None:
            req_headers["Cookie"] = cookie_header

        # --- Proxy ----------------------------------------------------------------------------------------------------
        proxy = proxy or self.proxies

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
            "sessionId": self._session_id,
            "followRedirects": allow_redirects,
            "forceHttp1": self.force_http1,
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
        if self.client_identifier is None:
            request_payload["customTlsClient"] = {
                "ja3String": self.ja3_string,
                "supportedSignatureAlgorithms": self.supported_signature_algorithms,
                "supportedVersions": self.supported_versions,
                "keyShareCurves": self.key_share_curves,
                "certCompressionAlgo": self.cert_compression_algo,
                "h2Settings": self.h2_settings,
                "h2SettingsOrder": self.h2_settings_order,
                "pseudoHeaderOrder": self.pseudo_header_order,
                "connectionFlow": self.connection_flow,
                "priorityFrames": self.priority_frames,
                "headerPriority": self.header_priority,
            }
        else:
            request_payload["tlsClientIdentifier"] = self.client_identifier
            request_payload[
                "withRandomTLSExtensionOrder"
            ] = self.random_tls_extension_order

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

            raise self.build_request_error(
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

    def get(self, url: str, **kwargs: Any) -> Response:
        """Send a GET request.

        Args:
            url: Request URL.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            TLSClientExeption: Error in shared library.

        Returns:
            A response object.
        """
        return self.execute_request(method="GET", url=url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        """Send a OPTIONS request.

        Args:
            url: Request URL.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            TLSClientExeption: Error in shared library.

        Returns:
            A response object.
        """
        return self.execute_request(method="OPTIONS", url=url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        """Send a HEAD request.

        Args:
            url: Request URL.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            TLSClientExeption: Error in shared library.

        Returns:
            A response object.
        """
        return self.execute_request(method="HEAD", url=url, **kwargs)

    def post(
        self,
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
            TLSClientExeption: Error in shared library.

        Returns:
            A response object.
        """
        return self.execute_request(
            method="POST", url=url, data=data, json=json, **kwargs
        )

    def put(
        self,
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
            TLSClientExeption: Error in shared library.

        Returns:
            A response object.
        """
        return self.execute_request(
            method="PUT", url=url, data=data, json=json, **kwargs
        )

    def patch(
        self,
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
            TLSClientExeption: Error in shared library.

        Returns:
            A response object.
        """
        return self.execute_request(
            method="PATCH", url=url, data=data, json=json, **kwargs
        )

    def delete(self, url: str, **kwargs: Any) -> Response:
        """Send a DELETE request.

        Args:
            url: Request URL.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            TLSClientExeption: Error in shared library.

        Returns:
            A response object.
        """
        return self.execute_request(method="DELETE", url=url, **kwargs)

    def get_cookies(
        self,
        url: str,
    ) -> Any:
        get_cookies_payload = {
            "sessionId": self._session_id,
            "url": url,
        }

        # this is a pointer to the response
        get_cookies_response = get_cookies_from_session(
            dumps(get_cookies_payload).encode("utf-8")
        )
        # dereference the pointer to a byte array
        get_cookies_response_bytes = ctypes.string_at(get_cookies_response)
        # convert our byte array to a string (tls client returns json)
        get_cookies_response_string = get_cookies_response_bytes.decode("utf-8")
        # convert response string to json
        get_cookies_response_object = loads(get_cookies_response_string)
        free_memory(get_cookies_response_object["id"].encode("utf-8"))
        if get_cookies_response_object.get("status") == 0:
            raise self.build_get_cookie_error(get_cookies_response_object["body"])
            # error sources:
            # marshallError := json.Unmarshal([]byte(getCookiesParamsJson), &cookiesInput)

            # if marshallError != nil {
            #     clientErr := tls_client_cffi_src.NewTLSClientError(marshallError)
            #     return handleErrorResponse("", false, clientErr)
            # }

            # tlsClient, err := tls_client_cffi_src.GetClient(cookiesInput.SessionId)

            # if err != nil {
            #     clientErr := tls_client_cffi_src.NewTLSClientError(err)
            #     return handleErrorResponse(cookiesInput.SessionId, true, clientErr)
            # }

            # u, parsErr := url.Parse(cookiesInput.Url)
            # if parsErr != nil {
            #     clientErr := tls_client_cffi_src.NewTLSClientError(parsErr)
            #     return handleErrorResponse(cookiesInput.SessionId, true, clientErr)
            # }

            # cookies := tlsClient.GetCookies(u)

            # out := tls_client_cffi_src.CookiesFromSessionOutput{
            #     Id:      uuid.New().String(),
            #     Cookies: cookies,
            # }

            # jsonResponse, marshallError := json.Marshal(out)

            # if marshallError != nil {
            #     clientErr := tls_client_cffi_src.NewTLSClientError(marshallError)
            #     return handleErrorResponse(cookiesInput.SessionId, true, clientErr)
            # }
        return get_cookies_response_object

    def reset(
        self,
    ) -> None:
        """Reset the session."""
        self.cookies.clear()
        self.close()
        self._session_id = str(uuid.uuid4())

    def set_session(
        self,
        client_identifier: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
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
        header_order: Optional[list[str]] = None,
        header_priority: Optional[dict[str, Any]] = None,
        random_tls_extension_order: Optional[bool] = False,
        force_http1: Optional[bool] = False,
        debug: bool = False,
    ) -> None:
        self.reset()
        self._debug = debug
        # --- Standard Settings ----------------------------------------------------------------------------------------

        # Case-insensitive dictionary of headers, send on each request
        self.headers = CaseInsensitiveDict(
            {
                "User-Agent": f"tls-client/{__version__}",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "*/*",
                "Connection": "keep-alive",
            }
        )
        if headers is not None:
            for key, value in headers.items():
                self.headers[key] = value
        # Example:
        # {
        #     "http": "http://user:pass@ip:port",
        #     "https": "http://user:pass@ip:port"
        # }
        self.proxies = {}

        # Dictionary of querystring data to attach to each request. The dictionary values may be lists for representing
        # multivalued query parameters.
        self.params = {}

        # CookieJar containing all currently outstanding cookies set on this session
        # self.cookies = cookiejar_from_dict({})

        # --- Advanced Settings ----------------------------------------------------------------------------------------

        # Examples:
        # Chrome --> chrome_103, chrome_104, chrome_105, chrome_106
        # Firefox --> firefox_102, firefox_104
        # Opera --> opera_89, opera_90
        # Safari --> safari_15_3, safari_15_6_1, safari_16_0
        # iOS --> safari_ios_15_5, safari_ios_15_6, safari_ios_16_0
        # iPadOS --> safari_ios_15_6
        self.client_identifier = client_identifier

        # Set JA3 --> TLSVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats
        # Example:
        # 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0
        self.ja3_string = ja3_string

        # HTTP2 Header Frame Settings
        # Possible Settings:
        # HEADER_TABLE_SIZE
        # SETTINGS_ENABLE_PUSH
        # MAX_CONCURRENT_STREAMS
        # INITIAL_WINDOW_SIZE
        # MAX_FRAME_SIZE
        # MAX_HEADER_LIST_SIZE
        #
        # Example:
        # {
        #     "HEADER_TABLE_SIZE": 65536,
        #     "MAX_CONCURRENT_STREAMS": 1000,
        #     "INITIAL_WINDOW_SIZE": 6291456,
        #     "MAX_HEADER_LIST_SIZE": 262144
        # }
        self.h2_settings = h2_settings

        # HTTP2 Header Frame Settings Order
        # Example:
        # [
        #     "HEADER_TABLE_SIZE",
        #     "MAX_CONCURRENT_STREAMS",
        #     "INITIAL_WINDOW_SIZE",
        #     "MAX_HEADER_LIST_SIZE"
        # ]
        self.h2_settings_order = h2_settings_order

        # Supported Signature Algorithms
        # Possible Settings:
        # PKCS1WithSHA256
        # PKCS1WithSHA384
        # PKCS1WithSHA512
        # PSSWithSHA256
        # PSSWithSHA384
        # PSSWithSHA512
        # ECDSAWithP256AndSHA256
        # ECDSAWithP384AndSHA384
        # ECDSAWithP521AndSHA512
        # PKCS1WithSHA1
        # ECDSAWithSHA1
        #
        # Example:
        # [
        #     "ECDSAWithP256AndSHA256",
        #     "PSSWithSHA256",
        #     "PKCS1WithSHA256",
        #     "ECDSAWithP384AndSHA384",
        #     "PSSWithSHA384",
        #     "PKCS1WithSHA384",
        #     "PSSWithSHA512",
        #     "PKCS1WithSHA512",
        # ]
        self.supported_signature_algorithms = supported_signature_algorithms

        # Supported Versions
        # Possible Settings:
        # GREASE
        # 1.3
        # 1.2
        # 1.1
        # 1.0
        #
        # Example:
        # [
        #     "GREASE",
        #     "1.3",
        #     "1.2"
        # ]
        self.supported_versions = supported_versions

        # Key Share Curves
        # Possible Settings:
        # GREASE
        # P256
        # P384
        # P521
        # X25519
        #
        # Example:
        # [
        #     "GREASE",
        #     "X25519"
        # ]
        self.key_share_curves = key_share_curves

        # Cert Compression Algorithm
        # Examples: "zlib", "brotli", "zstd"
        self.cert_compression_algo = cert_compression_algo

        # Pseudo Header Order (:authority, :method, :path, :scheme)
        # Example:
        # [
        #     ":method",
        #     ":authority",
        #     ":scheme",
        #     ":path"
        # ]
        self.pseudo_header_order = pseudo_header_order

        # Connection Flow / Window Size Increment
        # Example:
        # 15663105
        self.connection_flow = connection_flow

        # Example:
        # [
        #   {
        #     "streamID": 3,
        #     "priorityParam": {
        #       "weight": 201,
        #       "streamDep": 0,
        #       "exclusive": false
        #     }
        #   },
        #   {
        #     "streamID": 5,
        #     "priorityParam": {
        #       "weight": 101,
        #       "streamDep": false,
        #       "exclusive": 0
        #     }
        #   }
        # ]
        self.priority_frames = priority_frames

        # Order of your headers
        # Example:
        # [
        #   "key1",
        #   "key2"
        # ]
        self.header_order = header_order

        # Header Priority
        # Example:
        # {
        #   "streamDep": 1,
        #   "exclusive": true,
        #   "weight": 1
        # }
        self.header_priority = header_priority

        # randomize tls extension order
        self.random_tls_extension_order = random_tls_extension_order

        # force HTTP1
        self.force_http1 = force_http1

    def set_debug(
        self,
        debug: bool,
    ) -> None:
        self._debug = debug

    def clear_cookies(
        self,
    ) -> None:
        """Clear cookies."""
        self.cookies.clear()
        self.close()
        self._session_id = str(uuid.uuid4())

    def build_request_error(
        self,
        error_body: str,
        request_payload: dict[str, Any],
    ) -> RequestError:
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
            "make sure to specify full url like"
            " https://username:password@hostname.com:443/"
            in error_body
        ):
            return InvalidProxyURL(error_body)
        elif "no request url or request method provided" in error_body:
            return URLRequired(error_body)
        return TlsClientError(error_body)

    def build_get_cookie_error(
        self,
        error_body: str,
    ) -> GetCookieError:
        if "no client found for" in error_body:
            return ClientNotFoundError(error_body)
        return CookieReadError(error_body)

    def build_close_error(
        self,
        error_body: str,
    ) -> CloseError:
        ...
        return SessionCloseError(error_body)

    def close(
        self,
    ) -> Any:
        """Close session."""
        close_session_payload = {"sessionId": self._session_id}

        # this is a pointer to the response
        close_response = close_session(dumps(close_session_payload).encode("utf-8"))
        # dereference the pointer to a byte array
        close_response_bytes = ctypes.string_at(close_response)
        # convert our byte array to a string (tls client returns json)
        close_response_string = close_response_bytes.decode("utf-8")
        # convert response string to json
        close_response_object = loads(close_response_string)
        free_memory(close_response_object["id"].encode("utf-8"))
        if close_response_object.get("status") == 0:
            raise self.build_close_error(error_body=close_response_object["body"])
            # error sources:
            # destroySessionInput := tls_client_cffi_src.DestroySessionInput{}
            # marshallError := json.Unmarshal([]byte(destroySessionParamsJson), &destroySessionInput)

            # if marshallError != nil {
            #     clientErr := tls_client_cffi_src.NewTLSClientError(marshallError)
            #     return handleErrorResponse("", false, clientErr)
            # }

            # tls_client_cffi_src.RemoveSession(destroySessionInput.SessionId)

            # out := tls_client_cffi_src.DestroyOutput{
            #     Id:      uuid.New().String(),
            #     Success: true,
            # }

            # jsonResponse, marshallError := json.Marshal(out)

            # if marshallError != nil {
            #     clientErr := tls_client_cffi_src.NewTLSClientError(marshallError)
            #     return handleErrorResponse(destroySessionInput.SessionId, true, clientErr)
            # }
        return close_response_object
