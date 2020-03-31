rule WebShell_BackDoor_Unlimit_Mithril_V1_45_Mithril_A_1318 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Mithril.exe"
    family = "Mithril"
    hacker = "None"
    hash = "f1484f882dc381dde6eaa0b80ef64a07"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Mithril.V1.45.Mithril.A"
    threattype = "BackDoor"
  strings:
    $s2 = "cress.exe"
    $s7 = "\\Debug\\Mithril."
  condition:
    all of them
}