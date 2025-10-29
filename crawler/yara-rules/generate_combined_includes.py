import os

# Die zu durchsuchenden YARA-Regel-Ordner (relativ zum Skript)
folders = [
    "pwc",
    "manuel",
    "lw-yara",
    "PhishingKit-Yara-Rules",
    "packers",
    "subcrawl"
]

# Zielordner für die kombinierten .yar-Dateien
target_dir = "alle"

# Zielordner anlegen, falls nicht vorhanden
os.makedirs(target_dir, exist_ok=True)

for folder in folders:
    includes = []

    # Rekursiv alle .yar/.yara Dateien suchen
    for dirpath, dirnames, filenames in os.walk(folder):
        for fname in filenames:
            if fname.endswith((".yar", ".yara")):
                rel_path = os.path.relpath(os.path.join(dirpath, fname), ".")
                rel_path = rel_path.replace("\\", "/")
                includes.append(f'include "./{rel_path}"')

    # Duplikate entfernen und sortieren
    includes = sorted(set(includes))

    # Schreibe die Kombi-Datei in den Zielordner "alle/"
    out_file = os.path.join(target_dir, f"{folder}.yar")
    with open(out_file, "w", encoding="utf-8") as f:
        for inc in includes:
            f.write(inc + "\n")

    print(f"Alle Includes für {folder} in {out_file} geschrieben.")
