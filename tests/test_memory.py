from __future__ import annotations

import asyncio
import logging
import os

from time import time

import psutil

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


async def create_and_run_sessions(ticks: int = 0):
    i = 0
    start = time()
    while True and ticks > 0:
        i = i + 1
        client_identifier = "chrome_107"
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
            ),
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
        }
        header_order = ["accept", "user-agent", "accept-encoding", "accept-language"]
        url = "https://microsoft.com"
        session = tls_client.Session(
            client_identifier=client_identifier,
            random_tls_extension_order=True,
        )
        session.get(url=url, headers=headers, header_order=header_order)
        # request(json.dumps(requestPayload).encode('utf-8'))
        process = psutil.Process(os.getpid())
        logger.info(f"{process.memory_info().rss / 1024 / 1024} MB used.")
        io_stats = process.io_counters()
        read_ops_per_sec = io_stats.read_count / (time() - start)
        read_kb_per_sec = io_stats.read_bytes / 1024 / (time() - start)
        write_ops_per_sec = io_stats.write_count / (time() - start)
        write_kb_per_sec = io_stats.write_bytes / 1024 / (time() - start)
        logger.info(
            f"Read Ops {read_ops_per_sec} Ops/s | Write Ops {write_ops_per_sec} Ops/s |"
            f" Read {read_kb_per_sec} kb/s | Write {write_kb_per_sec} kb/s"
        )
        logger.info(session.close())
        await asyncio.sleep(5)
        ticks -= 1


async def run_raw_requests(ticks: int = 0):
    i = 0
    start = time()
    while True and ticks > 0:
        i = i + 1
        client_identifier = "chrome_107"
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
            ),
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
        }
        header_order = ["accept", "user-agent", "accept-encoding", "accept-language"]
        url = "https://microsoft.com"
        # session = tls_client.Session(
        #     client_identifier=client_identifier,
        #     random_tls_extension_order=True,
        # )
        get(
            url=url,
            headers=headers,
            header_order=header_order,
            client_identifier=client_identifier,
            random_tls_extension_order=True,
        )
        # request(json.dumps(requestPayload).encode('utf-8'))
        process = psutil.Process(os.getpid())
        logger.info(f"{process.memory_info().rss / 1024 / 1024} MB used.")
        io_stats = process.io_counters()
        read_ops_per_sec = io_stats.read_count / (time() - start)
        read_kb_per_sec = io_stats.read_bytes / 1024 / (time() - start)
        write_ops_per_sec = io_stats.write_count / (time() - start)
        write_kb_per_sec = io_stats.write_bytes / 1024 / (time() - start)
        logger.info(
            f"Read Ops {read_ops_per_sec} Ops/s | Write Ops {write_ops_per_sec} Ops/s |"
            f" Read {read_kb_per_sec} kb/s | Write {write_kb_per_sec} kb/s"
        )
        # logger.info(session.close())
        await asyncio.sleep(5)
        ticks -= 1


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    logger.info("TESTING SESSIONS")
    loop.run_until_complete(create_and_run_sessions(ticks=50))
    logger.info("TESTING RAW REQUESTS")
    loop.run_until_complete(run_raw_requests(ticks=50))
