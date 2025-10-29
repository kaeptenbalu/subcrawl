import csv
import io
import logging
from io import StringIO
from urllib.parse import urlparse
import requests
from pymisp import ExpandedPyMISP, MISPAttribute, MISPEvent, MISPObject
from utils import SubCrawlColors, SubCrawlHelpers
from .default_storage import DefaultStorage

class MISPStorage(DefaultStorage):

    cfg = None
    logger = None

    def __init__(self, config, logger):
        logging.getLogger("pymisp").setLevel(logging.CRITICAL)
        self.cfg = config
        self.logger = logger

    def load_scraped_domains(self):
        misp = ExpandedPyMISP(
            SubCrawlHelpers.get_config(self.cfg, "misp", "misp_url"),
            SubCrawlHelpers.get_config(self.cfg, "misp", "misp_api_key"),
            False
        )
        domains = set()
        domain_event_id = SubCrawlHelpers.get_config(self.cfg, "misp", "domain_event")
        if domain_event_id and int(domain_event_id) != 0:
            domain_event = misp.get_event(domain_event_id, pythonify=True)
            for att in domain_event.attributes:
                if att.type == "domain":
                    domains.add(att.value)
        else:
            self.logger.warning('[MISP] No domain MISP event configured')
        return domains

    def store_result(self, result_data):
        misp = ExpandedPyMISP(
            SubCrawlHelpers.get_config(self.cfg, "misp", "misp_url"),
            SubCrawlHelpers.get_config(self.cfg, "misp", "misp_api_key"),
            False
        )
        domain_event_id = SubCrawlHelpers.get_config(self.cfg, "misp", "domain_event")
        domain_event = None
        if domain_event_id and int(domain_event_id) != 0:
            domain_event = misp.get_event(domain_event_id, pythonify=True)

        # --------- urlhaus Import ---------
        url_info = {}
        try:
            r = requests.get(SubCrawlHelpers.get_config(self.cfg, "crawler", "urlhaus_api"), allow_redirects=True, timeout=10)
            csv_data = io.StringIO(r.content.decode("utf-8"))
            for _ in range(8):
                next(csv_data)
            csv_reader = csv.DictReader(csv_data)
            for row in csv_reader:
                domain = urlparse(row["url"]).netloc
                if domain not in url_info:
                    url_info[domain] = set()
                url_info[domain].update(row["tags"].lower().split(","))
        except Exception:
            pass

        # --------- Event Handling ---------
        misp_event_cache = {}  # cache already fetched/created events

        for domain, url_contents in result_data.items():
            urlhaus_tags = url_info.get(domain, set())
            if not url_contents:
                continue

            # --- check for finding and set tags ---
            finding = False
            opendir_found = False
            yara_tags = set()
            clamav_tags = set()
            all_tags = set(urlhaus_tags)  # urlhaus tags

            for url_content in url_contents:
                title = url_content.get("data", {}).get("title", "")
                content_type = url_content.get("content_type", "")
                modules = url_content.get("modules", {})

                # Opendir Detection
                if ("html" in str(content_type).lower()) and title and "index of" in str(title).lower():
                    opendir_found = True
                    finding = True
                    all_tags.add("opendir")
                    break  # reicht, ein Opendir reicht

                # Module Findings
                for module, modval in modules.items():
                    if not modval:
                        continue
                    if module == "YARAProcessing" and isinstance(modval, dict):
                        matches = modval.get("matches", "")
                        match_list = [m for m in matches if m and m != "NO_MATCHES"] if isinstance(matches, list) else ([str(matches)] if matches and matches != "NO_MATCHES" else [])
                        if match_list:
                            finding = True
                            yara_tags.update(match_list)
                            for match_val in match_list:
                                all_tags.add(f"yara:{match_val}")
                            all_tags.add("finding")
                    elif module == "ClamAVProcessing" and isinstance(modval, dict):
                        matches = modval.get("matches", "")
                        match_list = [m for m in matches if m and m != "NO_MATCHES"] if isinstance(matches, list) else ([str(matches)] if matches and matches != "NO_MATCHES" else [])
                        if match_list:
                            finding = True
                            clamav_tags.add("clamav")
                            all_tags.add("clamav")
                            all_tags.add("finding")
                    elif module == "PayloadProcessing" and isinstance(modval, dict):
                        matches = modval.get("matches", "")
                        info = modval.get("info", "")
                        match_list = [m for m in matches if m and m != "NO_MATCHES"] if isinstance(matches, list) else ([str(matches)] if matches and matches != "NO_MATCHES" else [])
                        if match_list or info:
                            finding = True
                            all_tags.add("PayloadProcessing")
                            all_tags.add("finding")

            # Also urlhaus-Finding is finding
            if urlhaus_tags:
                finding = True
                all_tags.add("finding")

            # when Finding create Event
            if not finding:
                continue

            # search Event or create event  ---
            if domain in misp_event_cache:
                event = misp_event_cache[domain]
                self.log_existing_event(event.id)
            else:
                search = misp.search_index(eventinfo=domain, pythonify=True)
                if search:
                    event = search[0]
                    self.log_existing_event(event.id)
                else:
                    event = MISPEvent()
                    event.distribution = 1
                    event.threat_level_id = 4
                    event.analysis = 1
                    event.info = domain
                    for tag in all_tags:
                        if tag:
                            event.add_tag(tag)
                    event.add_tag("tlp:green")
                    event = misp.add_event(event, pythonify=True)
                misp_event_cache[domain] = event

            changed = False
            server_created = False
            scripttech_created = False
            jarm_added = False

            # --- add Domain as Attribute ---
            attribute = MISPAttribute()
            attribute.type = "domain"
            attribute.value = domain
            misp.add_attribute(event, attribute)
            changed = True
            if domain_event:
                dom_attribute = MISPAttribute()
                dom_attribute.type = "domain"
                dom_attribute.value = domain
                misp.add_attribute(domain_event, dom_attribute)

            # --- first  Opendir then break ---
            for url_content in url_contents:
                url = url_content.get("url", "")
                sha256 = url_content.get("sha256", "")
                title = url_content.get("data", {}).get("title", "")
                content_type = url_content.get("content_type", "")
                headers = url_content.get("data", {}).get("resp", {}).get("headers", {})
                status_code = url_content.get("data", {}).get("resp", {}).get("status_code", "")
                modules = url_content.get("modules", {})

                obj = MISPObject(name='opendir-url', strict=True, misp_objects_path_custom='./misp-objects')
                obj.add_attribute('url', value=str(url))
                obj.add_attribute('sha256', value=str(sha256))
                obj.add_attribute('title', value=str(title))
                obj.add_attribute('status-code', value=status_code)
                for header_key, header_val in headers.items():
                    obj.add_attribute('header', comment=header_key, value=header_val)

                # Server/Scripting-Technology nur 1x pro Event
                if not server_created and "Server" in headers:
                    attribute = MISPAttribute()
                    attribute.type = "other"
                    attribute.comment = "Webserver"
                    attribute.value = headers["Server"]
                    misp.add_attribute(event, attribute)
                    server_created = True
                    changed = True
                if not scripttech_created and "X-Powered-By" in headers:
                    attribute = MISPAttribute()
                    attribute.type = "other"
                    attribute.comment = "Scripting Technology"
                    attribute.value = headers["X-Powered-By"]
                    misp.add_attribute(event, attribute)
                    scripttech_created = True
                    changed = True

                # --------- Opendir Detection: Nur einmal, dann break! ---------
                if ("html" in str(content_type).lower()) and title and "index of" in str(title).lower():
                    opendir_found = True
                    if self.logger.isEnabledFor(logging.DEBUG):
                        self.logger.debug(f"[DEBUG] Detected opendir for URL {url} (domain: {domain})")
                    misp.add_object(event, obj)
                    changed = True
                    break  # <<<<<<<< Abbruch nach erstem Fund!

                misp.add_object(event, obj)
                changed = True

                # --- Nur bis zum ersten Opendir: Die weiteren Module-Checks werden dann nicht mehr gemacht ---
                for module, modval in modules.items():
                    if not modval:
                        continue

                    if module == "TLSHProcessing" and isinstance(modval, dict):
                        matches = modval.get("matches", "")
                        match_val = str(matches)
                        attr = MISPAttribute()
                        attr.type = "other"
                        attr.value = f"tlsh:{match_val}:{sha256}"
                        attr.comment = f"TLSH: {match_val} für {url}"
                        misp.add_attribute(event, attr)
                        changed = True

                    elif module == "YARAProcessing" and isinstance(modval, dict):
                        matches = modval.get("matches", "")
                        match_list = [m for m in matches if m and m != "NO_MATCHES"] if isinstance(matches, list) else ([str(matches)] if matches and matches != "NO_MATCHES" else [])
                        for match_val in match_list:
                            attr = MISPAttribute()
                            attr.type = "other"
                            attr.value = f"yara:{match_val}:{sha256}"
                            attr.comment = f"{match_val} für {url}"
                            misp.add_attribute(event, attr)
                            changed = True

                    elif module == "ClamAVProcessing" and isinstance(modval, dict):
                        matches = modval.get("matches", "")
                        match_list = [m for m in matches if m and m != "NO_MATCHES"] if isinstance(matches, list) else ([str(matches)] if matches and matches != "NO_MATCHES" else [])
                        for match_val in match_list:
                            attr = MISPAttribute()
                            attr.type = "other"
                            attr.value = f"clamav:{match_val}:{sha256}"
                            attr.comment = f"{match_val} für {url}"
                            misp.add_attribute(event, attr)
                            changed = True

                    elif module == "PayloadProcessing" and isinstance(modval, dict):
                        matches = modval.get("matches", "")
                        info = modval.get("info", "")
                        match_list = [m for m in matches if m and m != "NO_MATCHES"] if isinstance(matches, list) else ([str(matches)] if matches and matches != "NO_MATCHES" else [])
                        if match_list or info:
                            for match_val in match_list or [None]:
                                attr = MISPAttribute()
                                attr.type = "other"
                                attr.value = f"payloadprocessing:{match_val if match_val else 'generic'}:{sha256}"
                                detail = f"{match_val}" if match_val else ""
                                if info:
                                    detail = f"{detail}, info: {info}" if detail else f"info: {info}"
                                attr.comment = f"{detail} für {url}" if detail else f"für {url}"
                                misp.add_attribute(event, attr)
                                changed = True
                                try:
                                    misp.tag(event.uuid, "PayloadProcessing")
                                except Exception:
                                    pass

                    elif module == "SDhashProcessing" and isinstance(modval, dict):
                        match_val = str(modval.get("sdhash", ""))
                        attr = MISPAttribute()
                        attr.type = "other"
                        attr.value = f"sdhash:{match_val}:{sha256}"
                        attr.comment = f"SDhash: {match_val} für {url}"
                        misp.add_attribute(event, attr)
                        changed = True

                # Zusatzobjekte
                try:
                    for module, modval in modules.items():
                        if not modval:
                            continue
                        if module == "JARMProcessing" and not jarm_added:
                            jarm_obj = MISPObject(name='jarm', strict=True)
                            jarm_obj.add_attribute("jarm", value=str(modval.get("fingerprint", "")))
                            misp.add_object(event, jarm_obj)
                            jarm_added = True
                            changed = True
                        elif module == "SDhashProcessing":
                            obj.add_attribute('sdhash', value=str(modval.get("sdhash", "")))
                        elif module == "TLSHProcessing":
                            obj.add_attribute('tlsh', value=str(modval.get("tlsh", "")))
                        elif module == "YARAProcessing":
                            for rule in modval.get("rules", []):
                                obj.add_attribute('yara', value=str(rule))
                except Exception as e:
                    self.logger.error('[MISP] ' + str(e))

            # --------- Tagging ---------
            for tag in all_tags:
                if tag:
                    try:
                        misp.tag(event.id, tag)
                    except Exception:
                        pass

            # only puflish by change!
            if changed:
                misp.publish(event)
                self.logger.info("[MISP] Event created: " + domain)

        if domain_event:
            misp.publish(domain_event)

    def log_existing_event(self, event_id):
        with open("events.txt", "a") as f:
            f.write(f"{event_id}\n")
