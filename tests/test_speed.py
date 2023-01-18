from __future__ import annotations

import asyncio
import logging
import time

from typing import Any

import tls_client

from tls_client.api import get


# create logger with 'spam_application'
logger = logging.getLogger("MemTest-WithSession")
logger.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handlers
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(ch)

logger.info("Setup logger.")


async def do_session_get(
    url: str, client_identifier: str, headers: dict[Any, Any], header_order: list[str]
) -> int | None:
    session = tls_client.Session(
        client_identifier=client_identifier,
        random_tls_extension_order=True,
    )
    try:
        resp = session.get(url=url, headers=headers, header_order=header_order)
    except Exception:
        status_code = None
    else:
        status_code = resp.status_code
    session.close()

    return status_code


async def do_no_session_get(
    url: str, client_identifier: str, headers: dict[Any, Any], header_order: list[str]
) -> int | None:
    try:
        resp = get(
            url=url,
            headers=headers,
            header_order=header_order,
            client_identifier=client_identifier,
            random_tls_extension_order=True,
        )
    except Exception:
        status_code = None
    else:
        status_code = resp.status_code
    return status_code


async def create_and_run_sessions(requests: int = 0):
    start = time.time()
    tasks = []
    client_identifier = "chrome_107"
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "user-agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML,"
            " like Gecko) Chrome/105.0.0.0 Safari/537.36"
        ),
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    header_order = ["accept", "user-agent", "accept-encoding", "accept-language"]
    url = "https://microsoft.com"
    for _ in range(requests):
        tasks.append(
            asyncio.create_task(
                do_session_get(
                    url=url,
                    client_identifier=client_identifier,
                    headers=headers,
                    header_order=header_order,
                )
            )
        )
    results = await asyncio.gather(*tasks, return_exceptions=True)
    end = time.time()
    logger.info(f"Requesting {requests} via sessions took: {end - start}s.")
    logger.info(
        "# of 200-responses:"
        f" {len([res for res in results if res is not None])}/{requests}"
    )


async def run_raw_requests(requests: int = 0):
    start = time.time()
    tasks = []
    client_identifier = "chrome_107"
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "user-agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML,"
            " like Gecko) Chrome/105.0.0.0 Safari/537.36"
        ),
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    header_order = ["accept", "user-agent", "accept-encoding", "accept-language"]
    url = "https://microsoft.com"
    for _ in range(requests):
        tasks.append(
            asyncio.create_task(
                do_no_session_get(
                    url=url,
                    client_identifier=client_identifier,
                    headers=headers,
                    header_order=header_order,
                )
            )
        )
    results = await asyncio.gather(*tasks, return_exceptions=True)
    end = time.time()
    logger.info(f"Requesting {requests} via sessions took: {end - start}s.")
    logger.info(
        "# of 200-responses:"
        f" {len([res for res in results if res is not None])}/{requests}"
    )


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    logger.info("TESTING SESSIONS")
    loop.run_until_complete(create_and_run_sessions(requests=50))
    logger.info("TESTING RAW REQUESTS")
    loop.run_until_complete(run_raw_requests(requests=50))
