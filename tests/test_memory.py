import asyncio
import logging
import os

import psutil
import tls_client


# create logger with 'spam_application'
logger = logging.getLogger('MemTest-WithSession')
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


async def main():
    i = 0
    while True:
        i = i + 1
        client_identifier = "chrome_107"
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"
        }
        header_order = [
            "accept",
            "user-agent",
            "accept-encoding",
            "accept-language"
        ]
        url = "https://microsoft.com"
        session = tls_client.Session(
            client_identifier=client_identifier,
            random_tls_extension_order=True,
        )
        session.get(url=url, headers=headers, header_order=header_order)
        # request(json.dumps(requestPayload).encode('utf-8'))
        process = psutil.Process(os.getpid())
        logger.info(f"{process.memory_info().rss / 1024 / 1024} MB used.")
        logger.info(session.close())
        await asyncio.sleep(5)
        continue

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())