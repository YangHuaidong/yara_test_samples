rule WebShell_BackDoor_Unlimit_Binder2_Binder2_A_1197 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file binder2.exe"
    family = "Binder2"
    hacker = "None"
    hash = "d594e90ad23ae0bc0b65b59189c12f11"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Binder2.Binder2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "IsCharAlphaNumericA"
    $s2 = "WideCharToM"
    $s4 = "g 5pur+virtu!"
    $s5 = "\\syslog.en"
    $s6 = "heap7'7oqk?not="
    $s8 = "- Kablto in"
  condition:
    all of them
}