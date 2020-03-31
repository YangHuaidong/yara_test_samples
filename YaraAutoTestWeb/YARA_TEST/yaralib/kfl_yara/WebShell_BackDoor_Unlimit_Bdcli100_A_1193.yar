rule WebShell_BackDoor_Unlimit_Bdcli100_A_1193 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file bdcli100.exe"
    family = "Bdcli100"
    hacker = "None"
    hash = "b12163ac53789fb4f62e4f17a8c2e028"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Bdcli100.A"
    threattype = "BackDoor"
  strings:
    $s5 = "unable to connect to "
    $s8 = "backdoor is corrupted on "
  condition:
    all of them
}