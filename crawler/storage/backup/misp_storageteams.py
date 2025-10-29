# storage/misp_storageteams.py
import logging
import requests
import json
from urllib.parse import urlparse
import csv
import io

from pymisp import ExpandedPyMISP
from utils import SubCrawlColors, SubCrawlHelpers
from .default_storage import DefaultStorage

class MISPStorageTeams(DefaultStorage):

    cfg = None
    logger = None
    TEAMS_WEBHOOK_URL = None

    def __init__(self, config, logger):
        logging.getLogger("pymisp").setLevel(logging.CRITICAL)
        self.cfg = config
        self.logger = logger
        self.TEAMS_WEBHOOK_URL = SubCrawlHelpers.get_config(self.cfg, "teams", "webhook_url")
        if not self.TEAMS_WEBHOOK_URL:
            self.logger.error("[TeamsStorage] Teams Webhook URL not configured. Teams notifications will not be sent.")
        self.logger.debug("[TeamsStorage] MISPStorageTeams initialized.")

    def _send_teams_message(self, message_text):
        """
        Sendet eine einfache Textnachricht an den konfigurierten Teams Webhook.
        """
        if not self.TEAMS_WEBHOOK_URL:
            self.logger.debug("[TeamsStorage] _send_teams_message called, but TEAMS_WEBHOOK_URL is not set.")
            return

        headers = {"Content-Type": "application/json"}
        payload = {"text": message_text}

        try:
            self.logger.debug(f"[TeamsStorage] Attempting to send Teams message. Payload: {json.dumps(payload)}")
            response = requests.post(self.TEAMS_WEBHOOK_URL, headers=headers, data=json.dumps(payload), timeout=15)
            if response.status_code == 200:
                self.logger.debug("Teams Nachricht erfolgreich gesendet.")
            else:
                self.logger.error(f"Fehler beim Senden der Teams Nachricht. Statuscode: {response.status_code}, Antwort: {response.text}")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ein Fehler beim Senden der Teams Nachricht ist aufgetreten: {e}")

    def load_scraped_domains(self):
        """
        Dieses Modul lädt keine Domains, da es nur benachrichtigt.
        """
        self.logger.debug("[TeamsStorage] load_scraped_domains called. Returning empty set.")
        return set()

    def store_result(self, result_data):
        """
        Verarbeitet die gescrapten Daten, sucht nach Findings und sendet Teams-Nachrichten
        sowie erstellt/aktualisiert MISP-Events.
        """
        self.logger.debug("[TeamsStorage] store_result called.")
        misp = ExpandedPyMISP(
            SubCrawlHelpers.get_config(self.cfg, "misp", "misp_url"),
            SubCrawlHelpers.get_config(self.cfg, "misp", "misp_api_key"),
            False
        )
        self.logger.debug(f"[TeamsStorage] MISP connection initialized for URL: {SubCrawlHelpers.get_config(self.cfg, 'misp', 'misp_url')}")

        # --- URLhaus Import ---
        url_info = {}
        try:
            urlhaus_api_url = SubCrawlHelpers.get_config(self.cfg, "crawler", "urlhaus_api")
            self.logger.debug(f"[TeamsStorage] Attempting to fetch URLhaus data from: {urlhaus_api_url}")
            r = requests.get(urlhaus_api_url, allow_redirects=True, timeout=20)
            r.raise_for_status()
            csv_data = io.StringIO(r.content.decode("utf-8", errors="ignore"))
            for _ in range(8):  # Skip header lines
                next(csv_data, None)
            csv_reader = csv.DictReader(csv_data)
            for row in csv_reader:
                try:
                    domain = urlparse(row.get("url", "")).netloc
                    if not domain:
                        continue
                    if domain not in url_info:
                        url_info[domain] = set()
                    tags_raw = row.get("tags", "")
                    if tags_raw:
                        url_info[domain].update(t.strip().lower() for t in tags_raw.split(",") if t.strip())
                except Exception:
                    continue
            self.logger.debug(f"[TeamsStorage] Successfully loaded {len(url_info)} domains from URLhaus.")
        except Exception as e:
            self.logger.error(f"[TeamsStorage] Fehler beim Importieren der URLhaus-Daten für Teams-Benachrichtigung: {e}")

        # --- Verarbeitung pro Domain ---
        for domain, url_contents in result_data.items():
            self.logger.debug(f"[TeamsStorage] Start processing for domain: {domain}")
            if not url_contents:
                self.logger.debug(f"[TeamsStorage] No URL contents for domain: {domain}. Skipping.")
                continue

            # Teams-ID (wir nehmen die vom ersten Eintrag)
            associated_teams_id = (url_contents[0] or {}).get('teams_id')
            self.logger.debug(f"[TeamsStorage] Retrieved associated_teams_id for {domain}: '{associated_teams_id}'")

            # URLhaus-Tags für diese Domain
            urlhaus_tags = url_info.get(domain, set())

            finding = False
            opendir_found = False
            yara_tags = set()
            clamav_tags = set()
            payload_tags = set()
            all_tags = set(urlhaus_tags)  # Start with URLhaus tags

            # Inhalte prüfen
            for url_content in url_contents:
                current_url = url_content.get("url", "N/A")
                self.logger.debug(f"[TeamsStorage] Analyzing URL content for: {current_url}")
                title = url_content.get("data", {}).get("title", "")
                content_type = url_content.get("content_type", "")
                modules = url_content.get("modules", {}) or {}

                # Opendir
                if ("html" in str(content_type).lower()) and title and "index of" in str(title).lower():
                    opendir_found = True
                    finding = True
                    all_tags.add("opendir")
                    self.logger.debug(f"[TeamsStorage] Open Directory found for {current_url}.")

                # Module
                for module, modval in modules.items():
                    if not modval or not isinstance(modval, dict):
                        self.logger.debug(f"[TeamsStorage] Module {module} has no value for {current_url}.")
                        continue

                    if module == "YARAProcessing":
                        matches = modval.get("matches", [])
                        match_list = [m for m in (matches if isinstance(matches, list) else [matches]) if m and m != "NO_MATCHES"]
                        if match_list:
                            finding = True
                            yara_tags.update(map(str, match_list))
                            for match_val in match_list:
                                all_tags.add(f"yara:{match_val}")
                            all_tags.add("finding")
                            self.logger.debug(f"[TeamsStorage] YARA matches found for {current_url}: {match_list}")

                    elif module == "ClamAVProcessing":
                        matches = modval.get("matches", [])
                        match_list = [m for m in (matches if isinstance(matches, list) else [matches]) if m and m != "NO_MATCHES"]
                        if match_list:
                            finding = True
                            clamav_tags.add("clamav")
                            all_tags.add("clamav")
                            all_tags.add("finding")
                            self.logger.debug(f"[TeamsStorage] ClamAV detection for {current_url}: {match_list}")

                    elif module == "PayloadProcessing":
                        matches = modval.get("matches", [])
                        info = modval.get("info", "")
                        match_list = [m for m in (matches if isinstance(matches, list) else [matches]) if m and m != "NO_MATCHES"]
                        if match_list or info:
                            finding = True
                            payload_tags.update(map(str, match_list))
                            all_tags.add("PayloadProcessing")
                            all_tags.add("finding")
                            self.logger.debug(f"[TeamsStorage] PayloadProcessing matches/info for {current_url}: Matches={match_list}, Info={info}")

            # URLhaus-Tags zählen ebenfalls als Finding
            if urlhaus_tags:
                finding = True
                all_tags.add("finding")
                self.logger.debug(f"[TeamsStorage] URLhaus tags found for {domain}: {urlhaus_tags}")

            self.logger.debug(f"[TeamsStorage] Final 'finding' status for {domain}: {finding}")

            # Keine Findings -> ggf. Teams-Nachricht "keine Findings", aber KEIN MISP-Event
            if not finding:
                if associated_teams_id:
                    self.logger.debug(f"[TeamsStorage] No findings, but associated_teams_id is present. Sending 'no findings' message for {domain}.")
                    teams_message = (
                        f"**SubCrawl Scan Ergebnis**\n\n"
                        f"**Domain:** `{domain}`\n\n"
                        f"**Associated Teams ID:** `{associated_teams_id}`\n\n"
                        f"Keine spezifischen Findings für diese URL gefunden. "
                        f"Seien Sie trotzdem vorsichtig."
                    )
                    self._send_teams_message(teams_message)
                    self.logger.warning(f"[TeamsStorage] Keine Findings für {domain} gefunden.")
                else:
                    self.logger.debug(f"[TeamsStorage] No findings and no associated_teams_id. Skipping Teams message for {domain}.")
                continue  # nächste Domain

            # Ab hier: Findings vorhanden -> MISP Event suchen/erstellen
            event = None
            event_action = "updated"  # default

            try:
                search = misp.search_index(eventinfo=domain, pythonify=True)
            except Exception as e:
                search = None
                self.logger.error(f"[TeamsStorage] MISP search_index failed for '{domain}': {e}")

            if search:
                event = search[0]
                try:
                    event = misp.get_event(event.id, pythonify=True)
                except Exception as e:
                    self.logger.error(f"[TeamsStorage] get_event failed for '{domain}': {e}")
                    event = None
                self.logger.debug(f"[TeamsStorage] Bestehendes MISP Event für Domain '{domain}' gefunden: {getattr(event, 'id', 'UNKNOWN')}")
            else:
                # Neues Event
                self.logger.info(f"[TeamsStorage] Kein MISP Event für Domain '{domain}' gefunden. Erstelle ein neues.")
                try:
                    new_event_data = {
                        "info": f"SubCrawl Findings for {domain}",
                        "threat_level_id": 4,   # 4: Undefined
                        "analysis": 0,          # 0: Initial
                        "distribution": 0       # 0: Your organization only
                        # orgc_id wird vom API-Key/Server gesetzt, daher hier weggelassen
                    }
                    event = misp.add_event(new_event_data, pythonify=True)
                    if event:
                        event_action = "created"
                        self.logger.info(f"[TeamsStorage] Neues MISP Event erstellt: {event.id} für Domain '{domain}'.")
                        # Domain als Attribut
                        try:
                            misp.add_attribute(event, {'type': 'domain', 'value': domain, 'category': 'Network activity'})
                        except Exception as e:
                            self.logger.error(f"[TeamsStorage] add_attribute domain failed: {e}")
                        # Tags hinzufügen
                        for tag_name in all_tags:
                            if tag_name:
                                try:
                                    misp.add_tag(event, tag_name)
                                except Exception as e:
                                    self.logger.error(f"[TeamsStorage] add_tag('{tag_name}') failed: {e}")
                    else:
                        self.logger.error(f"[TeamsStorage] Fehler beim Erstellen eines neuen MISP Events für Domain '{domain}': Event-Objekt ist None.")
                        event_action = "finding (MISP Event Erstellung fehlgeschlagen)"
                except Exception as e:
                    self.logger.error(f"[TeamsStorage] Ausnahme beim Erstellen eines neuen MISP Events für Domain '{domain}': {e}")
                    event = None
                    event_action = "finding (MISP Event Erstellung fehlgeschlagen)"

            # Teams-Nachricht zusammenbauen
            teams_message_parts = [
                f"**MISP Event {event_action.capitalize()}**",
                f"**Domain:** `{domain}`",
            ]
            if event:
                teams_message_parts.append(f"**Event ID:** `{event.id}`")
            else:
                teams_message_parts.append(f"**Status:** {event_action}")

            if associated_teams_id:
                teams_message_parts.append(f"**Associated Teams ID:** `{associated_teams_id}`")

            findings_summary = []
            if opendir_found:
                findings_summary.append("Open Directory")
            if yara_tags:
                findings_summary.append(f"YARA Matches: {', '.join(sorted(yara_tags))}")
            if clamav_tags:
                findings_summary.append("ClamAV Detections")
            if payload_tags:
                findings_summary.append(f"Payload Processing: {', '.join(sorted(payload_tags))}")
            if urlhaus_tags:
                findings_summary.append(f"URLhaus Tags: {', '.join(sorted(urlhaus_tags))}")

            if findings_summary:
                teams_message_parts.append(f"**Findings:**\n- " + "\n- ".join(findings_summary))
            else:
                teams_message_parts.append("**Findings:** _Details werden im MISP Event hinzugefügt._")

            # Aktuelle MISP-Tags (nur wenn Event vorhanden)
            if event:
                try:
                    current_misp_tags = {tag.name for tag in (event.tags or [])}
                except Exception:
                    current_misp_tags = set()
                if current_misp_tags:
                    teams_message_parts.append(f"**Alle Tags:** `{', '.join(sorted(list(current_misp_tags)))}`")

            misp_base_url = SubCrawlHelpers.get_config(self.cfg, "misp", "misp_url")
            if event and misp_base_url:
                misp_base_url = misp_base_url.rstrip('/')
                teams_message_parts.append(f"**MISP Link:** [Zum Event]({misp_base_url}/events/view/{event.id})")

            teams_message = "\n\n".join(teams_message_parts)
            self._send_teams_message(teams_message)
            self.logger.debug(f"[TeamsStorage] Finished processing for domain: {domain}. Teams message sent (if applicable).")

    def log_existing_event(self, event_id):
        """
        Diese Funktion wird von diesem Modul nicht verwendet, da es keine Events loggt,
        sondern nur benachrichtigt und erstellt.
        """
        self.logger.debug(f"[TeamsStorage] log_existing_event called for event ID: {event_id}, but not implemented in this module.")
        pass
