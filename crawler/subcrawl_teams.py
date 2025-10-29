import argparse
import base64
import datetime
import hashlib
import inspect
import io
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from io import BytesIO
from multiprocessing import cpu_count
from urllib.parse import urljoin, urlparse, urlunparse

import magic
import requests
import yaml
from bs4 import BeautifulSoup
from mergedeep import Strategy, merge
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from processing import *
from storage import *
from utils import (SubCrawlBanner, SubCrawlColors, SubCrawlHelpers,
                   SubCrawlLogger, SubCrawlLoggerLevels)

try:
    from kafka import KafkaConsumer
    consumer = KafkaConsumer(
        'urls',
        bootstrap_servers=['kafka:9092'],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='urls-crawler',
        auto_commit_interval_ms=1000,
        consumer_timeout_ms=2000,
        value_deserializer=lambda x: json.loads(x.decode('utf-8')))
except Exception:
    consumer = None

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

process_pool = None
logger = None
global_cfg = None
process_cfg = None
process_processing_modules = None
init_pages = []
crawl_pages = set() # Geändert zu einem Set für effizientere Duplikatsprüfung
storage_modules = []
processing_modules = []

def initialize():
    global logger, global_cfg, process_pool

    with open("config.yml", "r") as ymlfile:
        global_cfg = yaml.safe_load(ymlfile)

    if not global_cfg:
        print('[!] Error loading configuration file, engine could not start')
        sys.exit(0)

    logger = SubCrawlLogger("subcrawl.log", "SubCrawl",
                            SubCrawlLoggerLevels[SubCrawlHelpers.get_config(
                                global_cfg, 'crawler',
                                'log_level').upper()].value).get_logger()
    logger.debug("[ENGINE] SubCrawl engine initialized.")

def main(argv):
    banner = SubCrawlBanner(SubCrawlHelpers.get_config(
        global_cfg, "crawler", "logos_path"),
        SubCrawlHelpers.get_config(global_cfg, "crawler", "tag_line"))
    banner.print_banner()

    options = setup_args(argv)
    start_time = datetime.datetime.now()
    logger.debug("[ENGINE] Main function started.")

    # region process storage/payload modules

    str_storage_modules = []
    if options.storage_modules:
        for storage_module in options.storage_modules.split(","):
            str_storage_modules.append(storage_module)
    else:
        for storage_module in SubCrawlHelpers.get_config(global_cfg, "crawler", "storage_modules"):
            str_storage_modules.append(storage_module)

    for storage_module in str_storage_modules:
        try:
            dynamic_class = str2Class(storage_module.strip())
            storage_modules.append(dynamic_class(global_cfg, logger))
            logger.info("[ENGINE] Loaded storage module: " + storage_module)
        except Exception as e:
            logger.error("[ENGINE] Error loading storage module: " + storage_module + ": " + str(e))

    str_processing_modules = []
    if options.processing_modules:
        for processing_module in options.processing_modules.split(","):
            str_processing_modules.append(processing_module)
    else:
        for processing_module in SubCrawlHelpers.get_config(global_cfg, "crawler", "processing_modules"):
            str_processing_modules.append(str(processing_module))

    for processing_module in str_processing_modules:
        try:
            dynamic_class = str2Class(processing_module.strip())
            processing_modules.append(dynamic_class(global_cfg, logger))
            logger.info("[ENGINE] Loaded processing module: " + processing_module)
        except Exception as e:
            logger.error("[ENGINE] Error loading processing module: " + processing_module + ": " + str(e))

    # endregion

    cpus = max(1, cpu_count() - 1)
    process_pool = ProcessPoolExecutor(cpus)
    logger.debug(f"[ENGINE] Process pool initialized with {cpus} CPUs.")

    # scrape_urls_with_teams_id speichert (URL, teams_id) Tupel
    scrape_urls_with_teams_id = []
    scraped_domains = set()
    for s_module in storage_modules:
        scraped_domains.update(s_module.load_scraped_domains())

    logger.info("[ENGINE] Parsing input sources...")

    # region gather input URLs
    if options.kafka and consumer:
        logger.info("[ENGINE] Using Kafka queue for URL processing...")
        for message in consumer:
            url = message.value
            # Kafka input hat keine teams_id, daher Standard auf None
            teams_id = None
            if SubCrawlHelpers.is_valid_url(url):
                norm_url = normalize_url(url)
                scrape_urls_with_teams_id.append((norm_url, teams_id))
    else:
        logger.info("[ENGINE] Using file input for URL processing...")
        try:
            with open(options.file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    parts = line.split('°', 1) # Splitte bei '°', maximal 1 Split
                    url = parts[0].strip()
                    teams_id = parts[1].strip() if len(parts) > 1 else None # teams_id extrahieren, falls vorhanden

                    if SubCrawlHelpers.is_valid_url(url):
                        norm_url = normalize_url(url)
                        scrape_urls_with_teams_id.append((norm_url, teams_id))
        except Exception as e:
            logger.error("[ENGINE] Error reading input file for URL processing: " + str(e))
            sys.exit(-1)

    # Verwende ein Set, um eindeutige (URL, teams_id) Paare zu gewährleisten
    unique_scrape_urls_with_teams_id = set(scrape_urls_with_teams_id)
    logger.info("[ENGINE] Found " + str(len(unique_scrape_urls_with_teams_id)) + " unique URLs to scrape")
    logger.debug(f"[ENGINE] Unique URLs to scrape: {unique_scrape_urls_with_teams_id}")
    # endregion

    # region generate new URLs

    # domain_urls bildet netloc auf eine Liste von (url, teams_id) Tupeln ab
    domain_urls = dict()
    distinct_urls_for_processing = [] # Speichert (url, teams_id) Tupel für scrape_manager
    
    for start_url, teams_id in unique_scrape_urls_with_teams_id:
        parsed = urlparse(start_url)
        base = parsed.scheme + "://" + parsed.netloc
        paths = parsed.path[:-1].split('/') if parsed.path else []
        tmp_url = base

        if not SubCrawlHelpers.get_config(global_cfg, "crawler", "scan_simple_domains") and (not paths or (len(paths) == 1 and paths[0] == "")):
            continue

        # Baue alle Zwischenpfade, aber mit Query/Fragment nur für die letzte Stufe (das Original)
        # Jede generierte URL trägt die ursprüngliche teams_id
        for i, path in enumerate(paths):
            if path == '':
                continue
            tmp_url = urljoin(tmp_url, path) + "/"
            # Speichere (url, teams_id) Tupel
            if (tmp_url, teams_id) not in distinct_urls_for_processing:
                distinct_urls_for_processing.append((tmp_url, teams_id))
                domain_urls.setdefault(parsed.netloc, []).append((tmp_url, teams_id))
        
        # Füge das Original (mit Query/Fragment) hinzu
        if (start_url, teams_id) not in distinct_urls_for_processing:
            distinct_urls_for_processing.append((start_url, teams_id))
            domain_urls.setdefault(parsed.netloc, []).append((start_url, teams_id))
    logger.debug(f"[ENGINE] Generated {len(distinct_urls_for_processing)} distinct URLs for processing across {len(domain_urls)} hosts.")
    # endregion

    logger.info("[ENGINE] Done parsing URLs, ready to begin scraping " + str(len(domain_urls)) + " hosts and " + str(len(distinct_urls_for_processing)) + " URLs... starting in " + str(SubCrawlHelpers.get_config(global_cfg, "crawler", "delay_execution_time")) + " seconds!")
    time.sleep(int(SubCrawlHelpers.get_config(global_cfg, "crawler", "delay_execution_time")))

    # region crawl

    list_of_domains_for_processing = []
    for domain_netloc, url_teams_id_list in domain_urls.items():
        # url_teams_id_list ist eine Liste von (url, teams_id) Tupeln
        list_of_domains_for_processing.append((url_teams_id_list, global_cfg, processing_modules))
    logger.debug(f"[ENGINE] Prepared {len(list_of_domains_for_processing)} domain batches for multiprocessing.")

    final_crawl_pages = set()
    original_scrape_data = dict()

    for batch_urls_for_processing in chunks(list_of_domains_for_processing, SubCrawlHelpers.get_config(global_cfg, "crawler", "batch_size")):
        logger.debug(f"[ENGINE] Processing a batch of {len(batch_urls_for_processing)} domains.")
        result_dicts = process_pool.map(scrape_manager, batch_urls_for_processing)

        for result in result_dicts:
            # scrape_data in result ist ein JSON-String, muss geladen werden
            if "scrape_data" in result and result["scrape_data"]:
                merge(original_scrape_data, json.loads(result["scrape_data"]), strategy=Strategy.ADDITIVE)
            
            # crawl_pages sind immer noch ein Set von URLs
            if "crawl_pages" in result and result["crawl_pages"]:
                final_crawl_pages.update(result["crawl_pages"])
    
    scrape_data = original_scrape_data
    logger.debug(f"[ENGINE] Final scrape_data to be passed to storage modules: {scrape_data}")

    for s_module in storage_modules:
        s_module.store_result(scrape_data)
    logger.debug("[ENGINE] All storage modules processed.")

    elapsed = datetime.datetime.now() - start_time
    logger.info("Execution time (D:H:M:S): %02d:%02d:%02d:%02d" % (elapsed.days, elapsed.seconds // 3600, elapsed.seconds // 60 % 60, elapsed.seconds % 60))
    logger.debug("[ENGINE] Main function finished.")

    # endregion

def scrape_manager(data):
    # data ist (url_teams_id_list, cfg, processing_modules)
    url_teams_id_list, cfg, processing_modules = data
    global process_cfg
    global init_pages
    global process_processing_modules
    global crawl_pages # Zugriff auf das globale Set

    process_cfg = cfg
    # init_pages sollte eine Liste von URLs nur für interne Verfolgung sein
    init_pages = [url for url, _ in url_teams_id_list]
    process_processing_modules = processing_modules
    # crawl_pages muss für jeden Prozess neu initialisiert werden, da es global ist
    # und Änderungen in einem Prozess nicht die anderen beeinflussen sollen,
    # außer durch explizite Rückgabe.
    crawl_pages = set() # Wichtig: Set für jeden Prozess neu initialisieren

    logger.debug("[ENGINE] Starting down path... " + url_teams_id_list[0][0]) # Logge die erste URL

    result_dicts = []
    original_scrape_data_in_manager = dict()
    collected_crawl_pages_in_manager = set()

    for url, teams_id in url_teams_id_list: # Iteriere über (url, teams_id) Tupel
        s_data = []
        scrape_result = scrape(url, s_data, teams_id) # teams_id an scrape übergeben
        logger.debug(f"[ENGINE] scrape_manager received from scrape for {url}: {scrape_result.get('scrape_data')}") # Loggt nur den scrape_data Teil
        
        if "scrape_data" in scrape_result and scrape_result["scrape_data"]:
            merge(original_scrape_data_in_manager, scrape_result["scrape_data"], strategy=Strategy.ADDITIVE)
        
        if "crawl_pages" in scrape_result and scrape_result["crawl_pages"]:
            collected_crawl_pages_in_manager.update(scrape_result["crawl_pages"])

    logger.debug(f"[ENGINE] scrape_manager final merged data (before JSON dump): {original_scrape_data_in_manager}")
    # Rückgabe als JSON-String für Multiprocessing
    return {"crawl_pages": list(collected_crawl_pages_in_manager), "scrape_data": json.dumps(original_scrape_data_in_manager)}

def scrape(start_url, s_data, teams_id=None): # teams_id Parameter hinzugefügt
    global crawl_pages # Zugriff auf das globale Set
    scrape_domain_data = dict() # Umbenannt, um Konflikte zu vermeiden
    try:
        request_start = datetime.datetime.now()
        logger.debug("[ENGINE] Scanning URL: " + start_url)
        resp = requests.get(start_url, timeout=SubCrawlHelpers.get_config(
            process_cfg, "crawler", "http_request_timeout"),
            headers=SubCrawlHelpers.get_config(process_cfg, "crawler", "headers"),
            verify=False,
            allow_redirects=SubCrawlHelpers.get_config(process_cfg, "crawler", "follow_redirects"))

        if resp.status_code == 200:
            response_size_ok = True
            size = 0
            maxsize = SubCrawlHelpers.get_config(process_cfg, "crawler", "http_max_size")
            ctt = BytesIO()

            for chunk in resp.iter_content(2048):
                size += len(chunk)
                ctt.write(chunk)
                current_time = datetime.datetime.now()
                if size > maxsize or \
                        (current_time - request_start).total_seconds() > \
                        SubCrawlHelpers.get_config(process_cfg, "crawler", "http_download_timeout"):
                    resp.close()
                    response_size_ok = False
                    logger.debug(f"[ENGINE] Response too large ({size} > {maxsize}) or download timeout ({current_time - request_start} > {SubCrawlHelpers.get_config(process_cfg, 'crawler', 'http_download_timeout')}s) for {start_url}.")
                    break

            if response_size_ok:
                logger.debug(f"[ENGINE] Response size OK for {start_url}. Proceeding with content processing.")
                content = ctt.getvalue()
                signature = ""
                title = None
                bs = None
                content_magic = "NONE"
                try:
                    bs = BeautifulSoup(str(content), "html.parser")
                    title = bs.find('title')
                except Exception:
                    bs = None
                content_magic = magic.from_buffer(content).lower()

                title_text = None
                if title is not None:
                    title_text = title.get_text()
                else:
                    # versuche Fallback auf title-Tag mit select_one (robuster)
                    try:
                        t2 = bs.select_one('title') if bs else None
                        if t2:
                            title_text = t2.string
                    except Exception:
                        title_text = None

                try:
                    text = base64.b64encode(content).decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.error("[ENGINE] " + str(e))
                    text = ""

                module_results = {}

                # Verzeichnis-Liste erkennen (Index of) und recursiv crawlen, aber immer scrape_entry erzeugen!
                is_opendir = False
                if title_text and "index of" in title_text.lower() and bs is not None:
                    is_opendir = True
                    logger.debug(f"[ENGINE] Open directory detected for {start_url}. Discovering links.")
                    # Links rekursiv sammeln
                    for link in bs.find_all('a'):
                        if link.has_attr('href'):
                            href = link.attrs['href']
                            if href is not None and not href.startswith("?"):
                                next_page = urljoin(start_url, href)
                                if next_page not in crawl_pages and next_page not in init_pages \
                                        and not next_page.lower().endswith(tuple(SubCrawlHelpers.get_config(process_cfg, "crawler", "ext_exclude"))):
                                    logger.debug("[ENGINE] Discovered: " + next_page)
                                    crawl_pages.add(next_page) # Zu Set hinzufügen
                                    # Bei rekursivem Crawling dieselbe teams_id weitergeben
                                    scrape(next_page, s_data, teams_id)

                # scrape_entry wird IMMER erstellt
                scrape_entry = {
                    'scraped_on': datetime.datetime.now().isoformat(),
                    'sha256': SubCrawlHelpers.get_sha256(content),
                    'url': start_url,
                    'content_type': content_magic,
                    'signature': signature,
                    'data': {
                        'text': text,
                        'title': title_text,
                        'resp': {
                            'headers': dict(resp.headers) if resp else '',
                            'status_code': resp.status_code if resp else '',
                        },
                    },
                    "modules": {},
                    "teams_id": teams_id # teams_id hier hinzufügen
                }
                logger.debug(f"[ENGINE] Scrape entry created for {start_url}. SHA256: {scrape_entry['sha256']}")

                # Processing-Module aufrufen
                for p_module in process_processing_modules:
                    mod_res = p_module.process(start_url, content)
                    if mod_res:
                        module_results[type(p_module).__name__] = mod_res
                        logger.debug(f"[ENGINE] Processing module {type(p_module).__name__} returned results for {start_url}.")
                scrape_entry["modules"] = module_results

                s_data.append(scrape_entry)
                parsed = urlparse(start_url)
                # scrape_domain_data ist {netloc: [scrape_entry, ...]}
                # Diese Merge-Strategie kombiniert Listen für dasselbe netloc
                scrape_domain_data.setdefault(parsed.netloc, []).extend(s_data)
            else:
                logger.debug(f"[ENGINE] Response size NOT OK for {start_url}. Content processing skipped.")
        else:
            logger.debug(f"[ENGINE] HTTP Status Code {resp.status_code} for {start_url}. Content processing skipped.")

    except Exception as e:
        logger.debug(f"[ENGINE] Error scraping {start_url}: {e}")

    logger.debug(f"[ENGINE] scrape for {start_url} returning scrape_data: {scrape_domain_data}")
    # Rückgabe von scrape_domain_data (ein Dict {netloc: [scrape_entry, ...]})
    # und crawl_pages (ein Set von URLs)
    return {"crawl_pages": list(crawl_pages), "scrape_data": scrape_domain_data}

def normalize_url(unparsed_url):
    """
    Gibt für Datei-URLs den Verzeichnis-Pfad (mit abschließendem Slash) zurück,
    sonst die URL wie eingegeben (inkl. Query und Fragment).
    """
    try:
        parsed = urlparse(unparsed_url)
        path = parsed.path
        file_endings = ('.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.zip', '.rar')
        if any(path.lower().endswith(ext) for ext in file_endings):
            # Verzeichnis bis zum letzten Slash, Query/Fragment werden entfernt
            if "/" in path:
                dir_path = path[:path.rfind('/') + 1]  # inkl. abschließendem Slash
            else:
                dir_path = '/'
            logger.debug(f"[URL_PARSER] Normalized file URL '{unparsed_url}' to directory path '{dir_path}'.")
            return urlunparse((parsed.scheme, parsed.netloc, dir_path, '', '', ''))
        else:
            # Sonst: URL wie eingegeben (inkl. Query und Fragment)
            logger.debug(f"[URL_PARSER] URL '{unparsed_url}' is not a file, returning as is.")
            return unparsed_url
    except Exception as e:
        logger.error("[URL_PARSER] Error with URL " + unparsed_url + " " + str(e))
        return None

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def unique_content(content):
    unique_dict = dict()
    for key in content:
        unique_dict[key] = set(content[key])
    return unique_dict

def str2Class(str):
    return getattr(sys.modules[__name__], str)

def print_classes():
    clsmembers_storage = inspect.getmembers(sys.modules["storage"], inspect.isclass)
    clsmembers_processing = inspect.getmembers(sys.modules["processing"], inspect.isclass)

    print("\n  Available processing modules: ")
    for mod in clsmembers_processing:
        print("  - " + mod[0])

    print("\n  Available storage modules: ")
    for mod in clsmembers_storage:
        print("  - " + mod[0])

def setup_args(argv):
    parser = argparse.ArgumentParser(description="")

    parser.add_argument('-f', '--file', action="store", dest="file_path", help="Path of input URL file")
    parser.add_argument('-k', '--kafka', action="store_true", dest="kafka", help="Use Kafka Queue as input")
    parser.add_argument('-p', '--processing', action="store", dest="processing_modules", help="Processing modules to be executed comma separated.")
    parser.add_argument('-s', '--storage', action="store", dest="storage_modules", help="Storage modules to be executed comma separated.")

    if len(argv) == 0:
        parser.print_help()
        print_classes()
        sys.exit(0)

    return parser.parse_args()

initialize()

if __name__ == '__main__':
    main(sys.argv[1:])
