import json

# JSON-Datei einlesen mit utf-8-sig
with open("urls.json", "r", encoding="utf-8-sig") as file:
    data = json.load(file)

# Liste für die RemoteUrls
remote_urls = []

# RemoteUrl extrahieren
for item in data:
    remote_url = item["RemoteUrl"]
    remote_urls.append(remote_url)

# In eine Textdatei schreiben
with open("urls.txt", "w") as file:
    for url in remote_urls:
        file.write(url + "\n")

print("Remote URLs wurden in 'urls.txt' geschrieben.")
