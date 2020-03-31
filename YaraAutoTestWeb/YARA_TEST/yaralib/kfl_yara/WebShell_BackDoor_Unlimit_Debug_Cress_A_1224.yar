rule WebShell_BackDoor_Unlimit_Debug_Cress_A_1224 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file cress.exe"
    family = "Debug"
    hacker = "None"
    hash = "36a416186fe010574c9be68002a7286a"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Debug.Cress.A"
    threattype = "BackDoor"
  strings:
    $s0 = "\\Mithril "
    $s4 = "Mithril.exe"
  condition:
    all of them
}