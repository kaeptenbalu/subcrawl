rule JS_Fakepush_Obfuscation_Giderator_v1
{
  meta:
    description = "Erkennt die in der gelieferten Payload verwendete JS-Obfuskierung (fakepush/giderator, ROT13-Tokens + J.Ia/J.Ho Tabellenmuster)"
    author      = "GPT-5 Thinking"
    date        = "2025-08-22"
    reference   = "Obfuskationsartefakte: snxrchfu*, NqrkVapyhqr/AdexInclude, oybpxNqfgreen, Tvqengbe, cersrgpurq, J.Ia( ), J.Ho( )"

  strings:
    /* ROT13-bezogene Tokenfamilien */
    $s1  = /snxrchfu[a-zA-Z0-9_]{0,24}/ nocase
    $s2  = "snxrchfuNqrkVapyhqr" nocase         // "fakepushAdexInclude"
    $s3  = "NqrkVapyhqr" nocase                 // "AdexInclude"
    $s4  = "oybpxNqfgreen" nocase               // "blockAdsterra"
    $s5  = "Tvqengbe" nocase                    // "Giderator"
    $s6  = "cersrgpurq" nocase                  // "prefetched"

    /* Kennzeichnende Obfuskations-Hilfsfunktionen / Token-Map-Zugriffe */
    $m1  = "J.Ia(" ascii
    $m2  = "J.Ho(" ascii
    $m3  = /J\.[A-Za-z]{1,2}[),\[]/ ascii       // z. B. J.AW, J.cO, ...

    /* Weitere Artefakte */
    $x2  = "snxrchfuNqrk" nocase
    $x3  = "snxrchfuGvzrbhg" nocase             // "...Timeout"
    $x4  = "oybpxNqfgreen" nocase

  condition:
    filesize < 5MB and
    (
      ($m1 and $m2) or
      ( #m3 >= 50 )
    )
    and
    (
      ( #s1 + #s2 + #s3 + #s4 + #s5 + #s6 + #x2 + #x3 + #x4 ) >= 3
    )
}
