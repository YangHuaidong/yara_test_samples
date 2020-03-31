rule WebShell_BackDoor_Unlimit_Setupbdoor_A_1420 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file SetupBDoor.exe"
    family = "Setupbdoor"
    hacker = "None"
    hash = "41f89e20398368e742eda4a3b45716b6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Setupbdoor.A"
    threattype = "BackDoor"
  strings:
    $s1 = "\\BDoor\\SetupBDoor"
  condition:
    all of them
}