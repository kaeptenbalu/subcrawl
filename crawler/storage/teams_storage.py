import csv
import io
import logging
from typing import Dict, Set, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from utils import SubCrawlColors, SubCrawlHelpers
from .default_storage import DefaultStorage

# Konstanten
URLHAUS_CSV_HEADER_LINES = 8
REQUEST_TIMEOUT = 15
URLHAUS_TIMEOUT = 20

@dataclass
class Finding:
    """Repräsentiert ein Finding mit allen relevanten Informationen"""
    domain: str
    teams_id: Optional[str]
    yara_tags: Set[str]
    clamav_tags: Set[str]
    payload_tags: Set[str]
    urlhaus_tags: Set[str]
    opendir_found: bool
    all_tags: Set[str]

class TeamsStorage(DefaultStorage):
    """
    Storage-Klasse, die nur Teams-Benachrichtigungen versendet.
    Es werden keine MISP-Events erstellt oder geändert.
    """

    def __init__(self, config: Dict, logger: logging.Logger):
        self.cfg = config
        self.logger = logger
        self.teams_webhook_url = self._init_teams_webhook()
        self.logger.debug("[TeamsStorage] MISPStorageTeams initialized (Teams-only mode).")

    def _init_teams_webhook(self) -> Optional[str]:
        """Initialisiert Teams Webhook URL"""
        webhook_url = SubCrawlHelpers.get_config(self.cfg, "teams", "webhook_url")
        if not webhook_url:
            self.logger.warning("[TeamsStorage] No teams webhook configured")
        return webhook_url

    def _fetch_urlhaus_data(self) -> Dict[str, Set[str]]:
        """Lädt und verarbeitet URLhaus Daten"""
        url_info: Dict[str, Set[str]] = {}
        try:
            urlhaus_api = SubCrawlHelpers.get_config(self.cfg, "crawler", "urlhaus_api")
            if not urlhaus_api:
                return url_info
            r = requests.get(urlhaus_api, allow_redirects=True, timeout=URLHAUS_TIMEOUT)
            r.raise_for_status()
            csv_data = io.StringIO(r.content.decode("utf-8", errors="ignore"))
            for _ in range(URLHAUS_CSV_HEADER_LINES):
                next(csv_data, None)
            reader = csv.DictReader(csv_data)
            for row in reader:
                domain = urlparse(row.get("url", "")).netloc
                if not domain:
                    continue
                if domain not in url_info:
                    url_info[domain] = set()
                tags_raw = row.get("tags", "")
                if tags_raw:
                    url_info[domain].update([t.strip().lower() for t in tags_raw.split(",") if t.strip()])
            self.logger.debug(f"[TeamsStorage] Loaded {len(url_info)} domains from URLhaus.")
        except Exception as e:
            self.logger.debug(f"[TeamsStorage] URLhaus fetch failed: {e}")
        return url_info

    def _analyze_url_content(self, url_content: Dict) -> Dict[str, Any]:
        """Analysiert einzelne URL-Inhalte auf Findings"""
        result = {
            "opendir_found": False,
            "yara_tags": set(),
            "clamav_tags": set(),
            "payload_tags": set()
        }

        title = url_content.get("data", {}).get("title", "")
        content_type = url_content.get("content_type", "")
        modules = url_content.get("modules", {}) or {}

        # Open Directory Check
        if ("html" in str(content_type).lower()) and title and "index of" in str(title).lower():
            result["opendir_found"] = True

        # Module Analyse
        for module, modval in modules.items():
            if not modval or not isinstance(modval, dict):
                continue

            if module == "YARAProcessing":
                matches = modval.get("matches", [])
                if isinstance(matches, list):
                    result["yara_tags"].update([m for m in matches if m and m != "NO_MATCHES"])
                else:
                    if matches and matches != "NO_MATCHES":
                        result["yara_tags"].add(str(matches))

            elif module == "ClamAVProcessing":
                matches = modval.get("matches", [])
                if isinstance(matches, list) and any(m and m != "NO_MATCHES" for m in matches):
                    result["clamav_tags"].add("clamav")
                else:
                    if matches and matches != "NO_MATCHES":
                        result["clamav_tags"].add("clamav")

            elif module == "PayloadProcessing":
                matches = modval.get("matches", [])
                info = modval.get("info", "")
                if (isinstance(matches, list) and any(matches)) or info:
                    if isinstance(matches, list):
                        result["payload_tags"].update([m for m in matches if m and m != "NO_MATCHES"])
                    else:
                        if matches and matches != "NO_MATCHES":
                            result["payload_tags"].add(str(matches))

        return result

    def _create_teams_message(self, finding: Finding) -> str:
        """Erstellt formatierte Teams-Nachricht (nur Ergebnis, keine MISP-Links)."""
        parts = [f"**SubCrawl Scan Ergebnis**", f"**Domain:** `{finding.domain}`"]
        if finding.teams_id:
            parts.append(f"**Associated Teams ID:** `{finding.teams_id}`")
        summary = []
        if finding.opendir_found:
            summary.append("Open Directory")
        if finding.yara_tags:
            summary.append("YARA: " + ", ".join(sorted(finding.yara_tags)))
        if finding.clamav_tags:
            summary.append("ClamAV")
        if finding.payload_tags:
            summary.append("Payload: " + ", ".join(sorted(finding.payload_tags)))
        if finding.urlhaus_tags:
            summary.append("URLhaus: " + ", ".join(sorted(finding.urlhaus_tags)))
        if finding.all_tags:
            # include other aggregated tags (if any)
            extra = sorted(t for t in finding.all_tags if not t.startswith(("yara:", "payloadprocessing:", "clamav", "opendir", "urlhaus:")))
            if extra:
                summary.append("Tags: " + ", ".join(extra))
        if summary:
            parts.append("**Findings:**\n- " + "\n- ".join(summary))
        else:
            parts.append("Keine spezifischen Findings gefunden.")
        return "\n\n".join(parts)

    def _send_teams_message(self, message_text: str) -> None:
        """Sendet Nachricht an Teams Webhook (simple JSON payload)."""
        if not self.teams_webhook_url:
            self.logger.debug("[TeamsStorage] No Teams webhook configured, skipping send.")
            return
        headers = {"Content-Type": "application/json"}
        payload = {"text": message_text}
        try:
            r = requests.post(self.teams_webhook_url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                self.logger.error(f"[TeamsStorage] Teams webhook returned {r.status_code}")
        except Exception as e:
            self.logger.error(f"[TeamsStorage] Failed to send teams message: {e}")

    def load_scraped_domains(self) -> Set[str]:
        """In Teams-only mode gibt es keine MISP-Domainliste; leer zurückgeben."""
        self.logger.debug("[TeamsStorage] load_scraped_domains called (Teams-only mode) -> returning empty set")
        return set()

    def store_result(self, result_data: Dict[str, List[Dict]]) -> None:
        """
        Verarbeitet Ergebnisse und sendet nur Teams-Benachrichtigungen.
        Es werden keine MISP-Events, Attribute oder Tags erstellt.
        """
        url_info = self._fetch_urlhaus_data()

        for domain, url_contents in result_data.items():
            if not url_contents:
                continue

            # aggregate findings similar to previous behavior
            opendir_found = False
            yara_tags = set()
            clamav_tags = set()
            payload_tags = set()
            all_tags = set(url_info.get(domain, set()))

            for url_content in url_contents:
                analysis = self._analyze_url_content(url_content)
                if analysis.get("opendir_found"):
                    opendir_found = True
                    all_tags.add("opendir")
                    # don't break here – still collect teams_id from other entries
                yara_tags.update(analysis.get("yara_tags", set()))
                clamav_tags.update(analysis.get("clamav_tags", set()))
                payload_tags.update(analysis.get("payload_tags", set()))
                if analysis.get("yara_tags"):
                    all_tags.update({f"yara:{t}" for t in analysis.get("yara_tags", set())})
                    all_tags.add("finding")
                if analysis.get("clamav_tags"):
                    all_tags.add("clamav")
                    all_tags.add("finding")
                if analysis.get("payload_tags"):
                    all_tags.add("PayloadProcessing")
                    all_tags.add("finding")

            if url_info.get(domain):
                all_tags.add("finding")

            # determine teams_id (best-effort)
            teams_id = None
            for entry in url_contents:
                if not teams_id:
                    teams_id = entry.get("teams_id") or entry.get("teams") or entry.get("teamsId") or entry.get("data", {}).get("teams_id")

            finding = Finding(
                domain=domain,
                teams_id=teams_id,
                yara_tags=yara_tags,
                clamav_tags=clamav_tags,
                payload_tags=payload_tags,
                urlhaus_tags=url_info.get(domain, set()),
                opendir_found=opendir_found,
                all_tags=all_tags
            )

            # If no findings but teams_id exists, still send an informational message
            if not finding.all_tags and finding.teams_id:
                msg = (
                    f"**SubCrawl Scan Ergebnis**\n\n"
                    f"**Domain:** `{domain}`\n\n"
                    f"**Associated Teams ID:** `{finding.teams_id}`\n\n"
                    f"Keine spezifischen Findings gefunden."
                )
                self._send_teams_message(msg)
                continue

            # Only send Teams message (no MISP operations)
            try:
                msg = self._create_teams_message(finding)
                self._send_teams_message(msg)
                self.logger.info(f"[TeamsStorage] Teams message sent for {domain}")
            except Exception as e:
                self.logger.error(f"[TeamsStorage] Failed to create/send Teams message for {domain}: {e}")

    def _get_event_id(self, event: Any) -> Optional[str]:
        """Retained for compatibility but not used in Teams-only mode."""
        return None

    def _add_attribute_if_missing(self, event_id: str, attr: Dict[str, Any]) -> None:
        """No-op in Teams-only mode."""
        return

    def _handle_finding(self, finding: Finding) -> None:
        """Backward-compatible hook: send Teams message only."""
        try:
            msg = self._create_teams_message(finding)
            self._send_teams_message(msg)
        except Exception:
            pass

    def log_existing_event(self, event_id: str) -> None:
        """No MISP events in Teams-only mode; keep method for compatibility (no-op)."""
        return