import csv
import io
import logging
from io import StringIO
from urllib.parse import urlparse
import requests
import json  # Neu hinzugefügt für die Teams Webhook-Payload
from pymisp import ExpandedPyMISP, MISPAttribute, MISPEvent, MISPObject
from utils import SubCrawlColors, SubCrawlHelpers
from .default_storage import DefaultStorage

class MISPStorageEmail(DefaultStorage):

    cfg = None
    logger = None

    # Dein Teams Webhook URL
    # ACHTUNG: Diese URL ist sensibel und sollte nicht öffentlich geteilt werden.
    # Idealerweise sollte diese URL aus der Konfiguration (self.cfg) geladen werden,
    # aber für dieses Beispiel ist sie hier direkt eingefügt.
    TEAMS_WEBHOOK_URL = "https://dmdrogerie.webhook.office.com/webhookb2/86445914-63b2-4b83-82c4-e9ed545acffe@655bc315-ddc8-46fd-8e94-a3e104272732/IncomingWebhook/1d640e93a2614cbcafd76b0c115302e2/e4e88a36-e889-4306-8d08-3c70bde96678/V2jqnp-EQO2yBPYfCa3HKPPJzllEYBGg2mf4M4tDmdWLQ1"

    def __init__(self, config, logger):
        logging.getLogger("pymisp").setLevel(logging.CRITICAL)
        self.cfg = config
        self.logger = logger

    def _send_teams_message(self, message_text):
        """
        Sendet eine einfache Textnachricht an den konfigurierten Teams Webhook.
        """
        headers = {
            "Content-Type": "application/json"
        }

        payload = {
            "text": message_text
        }

        try:
            response = requests.post(self.TEAMS_WEBHOOK_URL, headers=headers, data=json.dumps(payload))
            if response.status_code == 200:
                self.logger.debug("Teams Nachricht erfolgreich gesendet.")
            else:
                self.logger.error(f"Fehler beim Senden der Teams Nachricht. Statuscode: {response.status_code}, Antwort: {response.text}")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ein Fehler beim Senden der Teams Nachricht ist aufgetreten: {e}")

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
            self.logger.error("[URLhaus] Fehler beim Importieren der URLhaus-Daten.")
            pass

        # --------- Event Handling ---------
        misp_event_cache = {}  # cache already fetched/created events

        for domain, url_contents in result_data.items():
            urlhaus_tags = url_info.get(domain, set())
            if not url_contents:
                continue

            # --- Prüfen ob ein Finding vorliegt und Tags sammeln ---
            finding = False
            opendir_found = False
            yara_tags = set()
            clamav_tags = set()
            payload_tags = set() # Neu: Für PayloadProcessing-Matches
            all_tags = set(urlhaus_tags)  # urlhaus tags immer mitnehmen

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
                            payload_tags.update(match_list) # Payload-Matches für die Nachricht sammeln
                            all_tags.add("PayloadProcessing")
                            all_tags.add("finding")

            # Auch urlhaus-Finding zählt als finding
            if urlhaus_tags:
                finding = True
                all_tags.add("finding")

            # Nur wenn ein Finding vorliegt, Event anlegen!
            if not finding:
                continue

            # --- Event suchen oder anlegen ---
            event_action = "created"  # Standard für Teams-Nachricht
            if domain in misp_event_cache:
                event = misp_event_cache[domain]
                self.log_existing_event(event.id)
                event_action = "updated"
            else:
                search = misp.search_index(eventinfo=domain, pythonify=True)
                if search:
                    event = search[0]
                    self.log_existing_event(event.id)
                    event_action = "updated"
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

            # --- Einmal Domain als Attribute ---
            # Prüfen, ob das Domain-Attribut bereits existiert, um Duplikate zu vermeiden
            domain_attr_exists = any(attr.type == "domain" and attr.value == domain for attr in event.attributes) if event.attributes else False
            if not domain_attr_exists:
                attribute = MISPAttribute()
                attribute.type = "domain"
                attribute.value = domain
                misp.add_attribute(event, attribute)
                changed = True
            if domain_event:
                # Prüfen, ob das Domain-Attribut bereits im domain_event existiert
                domain_event_attr_exists = any(attr.type == "domain" and attr.value == domain for attr in domain_event.attributes) if domain_event.attributes else False
                if not domain_event_attr_exists:
                    dom_attribute = MISPAttribute()
                    dom_attribute.type = "domain"
                    dom_attribute.value = domain
                    misp.add_attribute(domain_event, dom_attribute)

            # --- Nur bis zum ersten Opendir prüfen, dann break ---
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
                        match_val = str(modval.get("tlsh", "")) # Korrigiert: 'tlsh' statt 'matches'
                        if match_val:
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
                                except Exception as e:
                                    self.logger.warning(f"Could not tag event {event.uuid} with PayloadProcessing: {e}")

                    elif module == "SDhashProcessing" and isinstance(modval, dict):
                        match_val = str(modval.get("sdhash", "")) # Korrigiert: 'sdhash' statt 'matches'
                        if match_val:
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
                            jarm_fingerprint = str(modval.get("fingerprint", "")) # Korrigiert: 'fingerprint'
                            if jarm_fingerprint:
                                jarm_obj = MISPObject(name='jarm', strict=True)
                                jarm_obj.add_attribute("jarm", value=jarm_fingerprint)
                                misp.add_object(event, jarm_obj)
                                jarm_added = True
                                changed = True
                        elif module == "SDhashProcessing":
                            sdhash_val = str(modval.get("sdhash", ""))
                            if sdhash_val:
                                obj.add_attribute('sdhash', value=sdhash_val)
                        elif module == "TLSHProcessing":
                            tlsh_val = str(modval.get("tlsh", ""))
                            if tlsh_val:
                                obj.add_attribute('tlsh', value=tlsh_val)
                        elif module == "YARAProcessing":
                            for rule in modval.get("rules", []):
                                if rule:
                                    obj.add_attribute('yara', value=str(rule))
                except Exception as e:
                    self.logger.error(f'[MISP] Fehler beim Hinzufügen von Zusatzobjekten: {e}')

            # --------- Tagging ---------
            for tag in all_tags:
                if tag:
                    try:
                        misp.tag(event.id, tag)
                    except Exception as e:
                        self.logger.warning(f"Could not tag event {event.id} with '{tag}': {e}")

            # Nur wenn was geändert wurde publishen!
            if changed:
                misp.publish(event)
                self.logger.info(f"[MISP] Event {event_action}: {domain} (ID: {event.id})")

                # --- Teams Nachricht senden ---
                teams_message_parts = [
                    f"**MISP Event {event_action.capitalize()}**",
                    f"**Domain:** `{domain}`",
                    f"**Event ID:** `{event.id}`"
                ]

                findings_summary = []
                if opendir_found:
                    findings_summary.append("Open Directory")
                if yara_tags:
                    findings_summary.append(f"YARA Matches: {', '.join(yara_tags)}")
                if clamav_tags:
                    findings_summary.append("ClamAV Detections")
                if payload_tags:
                    findings_summary.append(f"Payload Processing: {', '.join(payload_tags)}")
                if urlhaus_tags:
                    findings_summary.append(f"URLhaus Tags: {', '.join(urlhaus_tags)}")

                if findings_summary:
                    teams_message_parts.append(f"**Findings:**\n- " + "\n- ".join(findings_summary))
                else:
                    teams_message_parts.append("**Findings:** _Keine spezifischen Findings gemeldet (aber Event wurde erstellt/aktualisiert)_")

                if all_tags:
                    teams_message_parts.append(f"**Alle Tags:** `{', '.join(sorted(list(all_tags)))}`")

                # Optional: Link zum MISP Event, falls MISP URL konfiguriert ist
                misp_base_url = SubCrawlHelpers.get_config(self.cfg, "misp", "misp_url")
                if misp_base_url:
                    # Sicherstellen, dass die Basis-URL keinen abschließenden Schrägstrich hat
                    misp_base_url = misp_base_url.rstrip('/')
                    teams_message_parts.append(f"**MISP Link:** [Zum Event]({misp_base_url}/events/view/{event.id})")

                teams_message = "\n\n".join(teams_message_parts)
                self._send_teams_message(teams_message)

        if domain_event:
            misp.publish(domain_event)
            self.logger.info(f"[MISP] Domain Event updated: {domain_event.id}")

    def log_existing_event(self, event_id):
        with open("events.txt", "a") as f:
            f.write(f"{event_id}\n")
