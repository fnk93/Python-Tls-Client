"""Contains logic for loading the correct library."""
from __future__ import annotations

import ctypes

from pathlib import Path
from platform import machine
from sys import platform

from tls_client.constants import SHARED_LIB_VERSION


if platform == "darwin":
    platform_name = "darwin"
    file_type = "dylib"
    file_arch = "arm64" if machine() == "arm64" else "amd64"
elif platform in ("win32", "cygwin"):
    platform_name = "windows"
    file_type = "dll"
    file_arch = "64" if ctypes.sizeof(ctypes.c_void_p) == 8 else "32"
else:
    # TODO: check this
    platform_name = "linux"
    file_type = "so"
    if machine() == "aarch64":
        file_arch = "arm64"
    elif "x86" in machine():
        file_arch = "alpine-amd64"
    else:
        file_arch = "ubuntu-amd64"

# root_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = Path(__file__).parent.parent
file_name = f"tls-client-{platform_name}-{file_arch}-{SHARED_LIB_VERSION}.{file_type}"
file_loc = root_dir / "shared_lib" / "cffi_dist" / "dist" / file_name
file_loc_str = str(file_loc.absolute())
library = ctypes.cdll.LoadLibrary(file_loc_str)

# extract the exposed request function from the shared package
request = library.request
request.argtypes = [ctypes.c_char_p]
request.restype = ctypes.c_char_p

get_cookies_from_session = library.getCookiesFromSession
get_cookies_from_session.argtypes = [ctypes.c_char_p]
get_cookies_from_session.restype = ctypes.c_char_p

add_cookies_to_session = library.addCookiesToSession
add_cookies_to_session.argtypes = [ctypes.c_char_p]
add_cookies_to_session.restype = ctypes.c_char_p

free_memory = library.freeMemory
free_memory.argtypes = [ctypes.c_char_p]

close_session = library.destroySession
close_session.argtypes = [ctypes.c_char_p]
close_session.restype = ctypes.c_char_p

close_all = library.destroyAll
close_all.restype = ctypes.c_char_p
