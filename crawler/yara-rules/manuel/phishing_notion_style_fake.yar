rule fake_notion_landing_variant
{
  meta:
    description = "Detects suspicious Notion-style phishing landing pages"
    author = "manuel@boll.net"
    date = "2025-07-10"
    reference = "Notion HTML clone phishing"

  strings:
    $domain       = "notion.site" nocase
    $webstart     = "__webStartTime=performance.now()" nocase
    $shimmer      = "startup-shimmer" nocase
    $noscript     = "<noscript><meta http-equiv=\"" nocase
    $robots       = "<meta name=\"robots\" content=\"noindex\"" nocase
    $canonical    = "<link rel=\"canonical\" href=" nocase
    $short_title  = "<title>.</title>"
    $unsupported  = "unsupported-browser.html" nocase
    $twitter_card = "<meta name=\"twitter:card\" content=\"summary_large_image\">" nocase
    $apple_touch  = "<link rel=\"apple-touch-icon\"" nocase

  condition:
    7 of ($domain, $webstart, $shimmer, $noscript, $robots, $canonical, $short_title, $unsupported, $twitter_card, $apple_touch)
}
