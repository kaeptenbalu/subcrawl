#!/bin/bash

# Überprüfen, ob die Datei urls.urls existiert
if [ ! -f "urls.txt" ]; then
    echo "Die Datei 'urls.txt' existiert nicht."
    exit 1
fi

# Teilen der Datei in Teile mit 100 Zeilen
split -l 100 urls.txt && mv xaa urls.txt

# Warten
sleep 5

# Definiere den Namen der Ausgabedatei
output_file="files_starting_with_x.txt"

# Leere die Ausgabedatei, falls sie bereits existiert
> "$output_file"

# Aktuellen Pfad speichern
current_path=$(pwd)

# Suche nach Dateien, die mit 'x' anfangen und schreibe den vollen Pfad in die Ausgabedatei
for file in x*; do
    if [ -e "$file" ]; then  # Überprüfen, ob die Datei existiert
        echo "$current_path/$file" >> "$output_file"
    fi
done

echo "Dateien, die mit 'x' anfangen, wurden in '$output_file' geschrieben."
