rule WebShell_BackDoor_Unlimit_Dbgntboot_A_1222 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file dbgntboot.dll"
    family = "Dbgntboot"
    hacker = "None"
    hash = "4d87543d4d7f73c1529c9f8066b475ab"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Dbgntboot.A"
    threattype = "BackDoor"
  strings:
    $s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
    $s3 = "sth junk the M$ Wind0wZ retur"
  condition:
    all of them
}