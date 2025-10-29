rule Phishing_DE_Hermes_Track_and_Trace_v3 {
    meta:
        description = "Detects a Hermes phishing page. This final version focuses on the most stable artifacts: the backend form action and internal form structure."
        author = "manuel.boll@dm.de"
        date = "2025-10-09"
        reference = "User submission, iteratively refined"
        hash = "d9c3b8a3493e82b7948332d56a237f34c2c776b1580d388e63a160759086384a" // SHA256 of the original phishing HTML

    strings:
        // Primärer, hochgradig zuverlässiger Indikator für die Backend-Logik
        $form_action = "action=\"Config/track.php\"" ascii wide

        // Sekundäre, stabile Indikatoren
        $regex_js = /src="js\/[a-f0-9]{32}\.js"/ ascii wide
        $submit_button = "button type=\"submit\" name=\"submit\"" ascii wide
        $local_asset_path = "src=\"assets/images/" ascii wide

        // Kontext-String
        $title = "<title>Hermes Sendungsverfolgung</title>" ascii wide

    condition:
        // Überprüfung auf HTML-Signatur und eine vernünftige Dateigröße
        (uint16(0) == 0x3c68 or uint16(0) == 0x3c21) and filesize < 200KB

        // Kernanforderung: Muss den korrekten Titel und die eindeutige Formular-Aktion haben
        and $title
        and $form_action

        // Unterstützende Anforderung: Muss mindestens einen der anderen stabilen Indikatoren aufweisen
        and 1 of ($regex_js, $submit_button, $local_asset_path)
}
