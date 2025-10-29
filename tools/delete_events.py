from pymisp import ExpandedPyMISP
import logging

# Konfiguration
MISP_URL = 'https://misp.local'
MISP_KEY = '3bq6Y0xoXpMSFGaOAH39uzwry0Vj6uJdMYwdf7Ln'
MISP_VERIFYCERT = False  # ggf. True setzen, wenn Zertifikat gültig

def main():
    logging.basicConfig(level=logging.INFO)
    misp = ExpandedPyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    events = misp.search(controller='events', pythonify=True)

    for event in events:
        tag_names = set(tag.name for tag in event.tags)
        if 'tlp:green' in tag_names:
            if len(tag_names) == 1:
                print(f"Lösche Event {event.id} ({event.info}) mit nur Tag tlp:green")
                try:
                    misp.delete_event(event)
                except Exception as e:
                    print(f"Fehler beim Löschen von Event {event.id}: {e}")
            else:
                print(f"Event {event.id} hat tlp:green, aber auch andere Tags: {tag_names}")
        else:
            print(f"Event {event.id} hat kein tlp:green, wird nicht gelöscht.")

if __name__ == "__main__":
    main()
