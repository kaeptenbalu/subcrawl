rule tfbank_phishing_html_de
{
    meta:
        description = "Erkennt TF Bank Phishing-Webseite im deutschen Sprachraum (Fake Login / Captcha-Template)"
        author = "manuel@boll.net"
        last_modified = "2025-07-11"
        reference = "https://tfbnkdeat0926130700.page.link/tobR/"

    strings:
        $title = "<title>Meine TF Bank</title>"
        $form = /<form[^>]+action=["']process\.php["']/ nocase
        $recaptcha = "data-sitekey=\"6LcftYErAAAAAJFgFzlBJNW-oB9uxybw98Q6dgFL\""
        $captcha_text1 = "Bitte bestätigen Sie, dass Sie kein automatisierter Zugriff sind."
        $captcha_text2 = "Ich bin kein Roboter"
        $submit = "class=\"login-btn\">Weiter</button>"
        $credit_card_failed = "class=\"credit-card-failed\" id=\"captcha-error-box\""
        $visitors_js = "url: 'visitors.php',"
        $logo_path = "assets/images/logo.png"
        $favicon = "assets/images/icon.png"
        $bg = "background: url(assets/images/bg.webp)"

    condition:
        /* Mindestens mehrere charakteristische Strings/Texte/Tokens gemeinsam */
        (
            4 of ($title, $form, $recaptcha, $captcha_text1, $captcha_text2, $submit, $credit_card_failed, $visitors_js)
            and all of ($logo_path, $favicon, $bg)
        ) or
        (
            $title and $recaptcha and $form and $visitors_js
        )
}
