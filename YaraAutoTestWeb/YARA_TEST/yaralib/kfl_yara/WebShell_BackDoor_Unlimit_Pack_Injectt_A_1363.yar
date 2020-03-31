rule WebShell_BackDoor_Unlimit_Pack_Injectt_A_1363 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file InjectT.exe"
    family = "Pack"
    hacker = "None"
    hash = "983b74ccd57f6195a0584cdfb27d55e8"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Pack.Injectt.A"
    threattype = "BackDoor"
  strings:
    $s3 = "ail To Open Registry"
    $s4 = "32fDssignim"
    $s5 = "vide Internet S"
    $s6 = "d]Software\\M"
    $s7 = "TInject.Dll"
  condition:
    all of them
}