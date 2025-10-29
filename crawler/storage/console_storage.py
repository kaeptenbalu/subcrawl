# © Copyright 2021 HP Development Company, L.P.
import json
import pprint
from re import subn

from utils import SubCrawlColors
from .default_storage import DefaultStorage


class ConsoleStorage(DefaultStorage):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def load_scraped_domains(self):
        return []

    def store_result(self, result_data):
        total_urls = 0

        print(SubCrawlColors.PURPLE + "\n" + "*" * 25 +
              " CONSOLE STORAGE - SUMMARY " + "*" * 26 + "\n" +
              SubCrawlColors.RESET)

        for domain in result_data:
            results = dict()

            total_urls += len(result_data[domain])

            for url_content in result_data[domain]:
                for module in url_content["modules"]:
                    if url_content["modules"][module]:
                        if len(url_content["modules"][module]) > 0:
                            results.setdefault(module, []).append(url_content["modules"][module])

            if len(results) > 0:
                print(SubCrawlColors.CYAN + "<=====   " + str(domain) +
                      "  =====>" + SubCrawlColors.RESET)

                for payload_module in results:
                    for result in results[payload_module]:
                        # JARM hat spezielle Struktur
                        if payload_module == "JARMProcessing":
                            fingerprint = result.get("fingerprint", "NO_FINGERPRINT")
                            port = result.get("port", "NO_PORT")
                            print(f"\t[{payload_module}] {fingerprint} (port: {port}){SubCrawlColors.RESET}")
                        else:
                            matches = result.get("matches", "NO_MATCHES")
                            url = result.get("url", "NO_URL")
                            sha256 = result.get("hash", "NO_HASH")
                            print(f"\t[{payload_module}] {matches} ( {url} ){SubCrawlColors.RESET}")
                            print(f"\t\t[SHA256] {sha256}")
                print("")

        return True
