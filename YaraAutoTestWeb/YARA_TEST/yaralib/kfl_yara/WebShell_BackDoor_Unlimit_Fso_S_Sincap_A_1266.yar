rule WebShell_BackDoor_Unlimit_Fso_S_Sincap_A_1266 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file sincap.php"
    family = "Fso"
    hacker = "None"
    hash = "dc5c2c2392b84a1529abd92e98e9aa5b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Sincap.A"
    threattype = "BackDoor"
  strings:
    $s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">"
    $s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin="
  condition:
    all of them
}