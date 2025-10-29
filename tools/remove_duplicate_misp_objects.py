#!/usr/bin/env python3
import warnings
import urllib3
import argparse
from pymisp import ExpandedPyMISP

warnings.filterwarnings("ignore", category=FutureWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MISP_URL = "https://localhost"
MISP_API_KEY = "JTVAZtGwIwuRwL2RQAvl1VL3lkpdpK0CWHgc7ivK"

def get_url_from_object(obj):
    for attr in obj.attributes:
        if attr.type == "url":
            return attr.value
    return None

def main(event_id):
    misp = ExpandedPyMISP(MISP_URL, MISP_API_KEY, ssl=False)
    event = misp.get_event(event_id, pythonify=True)
    if not event:
        print(f"Event mit ID {event_id} nicht gefunden.")
        return

    print(f"Vorher: {len(event.objects)} Objekte im Event.")

    seen_urls = set()
    to_delete = []

    for obj in event.objects:
        url = get_url_from_object(obj)
        if url is None:
            continue
        if url in seen_urls:
            print(f"Duplikat-Objekt mit URL {url} wird entfernt.")
            to_delete.append(obj)
        else:
            seen_urls.add(url)

    # Objekte wirklich löschen!
    for obj in to_delete:
        misp.delete_object(obj.id)

    # Neu laden, um die aktuelle Anzahl zu sehen
    event = misp.get_event(event_id, pythonify=True)
    print(f"Nachher: {len(event.objects)} eindeutige Objekte im Event.")
    if to_delete:
        print("Event wurde mit entfernten URL-Duplikaten aktualisiert.")
    else:
        print("Keine Duplikate gefunden.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Entfernt Objekte mit doppelten URL-Attributen aus einem MISP Event.")
    parser.add_argument('--event', type=int, required=True, help='Event ID')
    args = parser.parse_args()
    main(args.event)
