rule WebShell_BackDoor_Unlimit_Httpdoor_A_1279 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file httpdoor.exe"
    family = "Httpdoor"
    hacker = "None"
    hash = "6097ea963455a09474471a9864593dc3"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Httpdoor.A"
    threattype = "BackDoor"
  strings:
    $s4 = "''''''''''''''''''DaJKHPam"
    $s5 = "o,WideCharR]!n]"
    $s6 = "HAutoComplete"
    $s7 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:sch"
  condition:
    all of them
}