import ctypes
import json
import asyncio
import logging
import os, psutil
from pathlib import Path


# create logger with 'spam_application'
logger = logging.getLogger('MemTest-NoSession')
logger.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(ch)

logger.info("Setup logger.")

# load the tls-client shared package for your OS you are currently running your python script (i'm running on mac)
root_dir = Path(__file__).parent.parent
file_name = 'tls-client-darwin-arm64-1.2.0.dylib'
file_loc = root_dir / 'shared_lib' / 'cffi_dist' / 'dist' / file_name
file_loc_str = str(file_loc.absolute())
library = ctypes.cdll.LoadLibrary(file_loc_str)

# extract the exposed request function from the shared package
request = library.request
request.argtypes = [ctypes.c_char_p]
request.restype = ctypes.c_char_p

getCookiesFromSession = library.getCookiesFromSession
getCookiesFromSession.argtypes = [ctypes.c_char_p]
getCookiesFromSession.restype = ctypes.c_char_p

addCookiesToSession = library.addCookiesToSession
addCookiesToSession.argtypes = [ctypes.c_char_p]
addCookiesToSession.restype = ctypes.c_char_p

freeMemory = library.freeMemory
freeMemory.argtypes = [ctypes.c_char_p]

destroySession = library.destroySession
destroySession.argtypes = [ctypes.c_char_p]
destroySession.restype = ctypes.c_char_p

destroyAll = library.destroyAll
destroyAll.restype = ctypes.c_char_p


async def main():
    i = 0
    while True:
        i = i + 1
        requestPayload = {
            "tlsClientIdentifier": "chrome_107",
            "followRedirects": False,
            "insecureSkipVerify": False,
            "withoutCookieJar": False,
            "withDefaultCookieJar": False,
            "isByteRequest": False,
            "forceHttp1": False,
            "withDebug": False,
            "withRandomTLSExtensionOrder": False,
            "session": i,
            "timeoutSeconds": 30,
            "timeoutMilliseconds": 0,
            "proxyUrl": "",
            "headers": {
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
                "accept-encoding": "gzip, deflate, br",
                "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"
            },
            "headerOrder": [
                "accept",
                "user-agent",
                "accept-encoding",
                "accept-language"
            ],
            "requestUrl": "https://microsoft.com",
            "requestMethod": "GET",
            "requestBody": "",
            "requestCookies": []
        }
        request(json.dumps(requestPayload).encode('utf-8'))
        process = psutil.Process(os.getpid())
        logger.info(f"{process.memory_info().rss / 1024 / 1024} MB used.")
        await asyncio.sleep(5)
        continue

if __name__ ==  '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
