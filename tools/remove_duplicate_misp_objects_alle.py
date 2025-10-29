#!/usr/bin/env python3
import warnings
import urllib3
from pymisp import ExpandedPyMISP
import time
import logging

# Logging einrichten
logging.basicConfig(filename='script.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
warnings.filterwarnings("ignore", category=FutureWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MISP_URL = "https://localhost"
MISP_API_KEY = "JTVAZtGwIwuRwL2RQAvl1VL3lkpdpK0CWHgc7ivK"
ORG = "DM"  # Der Org-Slug deiner Organisation
BATCH_SIZE = 5  # Weiter reduzierte Anzahl der Events pro Abruf
MAX_EVENTS = 50  # Maximale Anzahl der Events, die verarbeitet werden

def get_url_from_object(obj):
    for attr in obj.attributes:
        if attr.type == "url":
            return attr.value
    return None

def process_event(misp, event):
    event_id = event.id
    logging.info(f"Verarbeite Event {event_id}: '{event.info}'")
    orig_count = len(event.objects)
    seen_urls = set()
    to_delete = []

    for obj in event.objects:
        url = get_url_from_object(obj)
        if url is None:
            continue
        if url in seen_urls:
            logging.info(f"  Duplikat-Objekt mit URL {url} wird entfernt.")
            to_delete.append(obj)
        else:
            seen_urls.add(url)

    for obj in to_delete:
        misp.delete_object(obj.id)

    updated_event = misp.get_event(event_id, pythonify=True)
    logging.info(f"  Vorher: {orig_count} | Nachher: {len(updated_event.objects)} eindeutige Objekte\n")

def main():
    misp = ExpandedPyMISP(MISP_URL, MISP_API_KEY, ssl=False)

    logging.info(f"Suche nach Events der Organisation: {ORG}")
    
    total_events = misp.search("events", pythonify=True, org=ORG, limit=0)
    total_count = total_events['response']['total']
    logging.info(f"Gesamtanzahl der Events: {total_count}\n")
    
    offset = 0
    processed_count = 0

    while offset < total_count and processed_count < MAX_EVENTS:
        try:
            logging.info(f"Abrufen von Events mit Offset {offset}...")
            events = misp.search("events", pythonify=True, org=ORG, limit=BATCH_SIZE, offset=offset)

            if not events:
                logging.info("Keine weiteren Events gefunden.")
                break
            
            logging.info(f"{len(events)} Events von Organisation '{ORG}' gefunden.\n")
            
            for event in events:
                process_event(misp, event)
                processed_count += 1  # Zähler für verarbeitete Events
                if processed_count >= MAX_EVENTS:
                    logging.info("Maximale Anzahl von verarbeiteten Events erreicht.")
                    break

            offset += BATCH_SIZE  
            time.sleep(2)  # Wartezeit erhöhen
        except Exception as e:
            logging.error(f"Fehler bei der Verarbeitung: {e}")
            break

if __name__ == "__main__":
    main()
