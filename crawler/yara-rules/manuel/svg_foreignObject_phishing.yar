rule svg_foreignObject_phishing
{
    meta:
        description = "Erkennt Phishing-Webseiten, die HTML per atob(Base64) in ein SVG-foreignObject injizieren und dynamisch einen Download-Link setzen"
        author = "manuel@boll.net"
        last_modified = "2025-07-14"
        reference = "JS/SVG-HTML-Inject & Download Button Manipulation"

    strings:
        $create_foreignObject = "document.createElementNS('http://www.w3.org/2000/svg', 'foreignObject')"
        $atob_html = "div.innerHTML = atob("
        $append_svg = ".appendChild(foreignObject);"
        $downloadSet = "function downloadSet()"
        $set_href = "element.setAttribute('href',"
        $interval_loading = "setInterval(function() {"
        $loading_width = "document.getElementById(\"loading\").style.width = i + \"%\";"
        $show_loaded = "document.getElementById(\"loaded\").style.display = \"block\";"
        $hide_wait = "document.getElementById(\"wait\").style.display = \"none\";"

    condition:
        all of ($create_foreignObject, $atob_html, $append_svg) and
        1 of ($downloadSet, $set_href) and
        2 of ($interval_loading, $loading_width, $show_loaded, $hide_wait)
}
