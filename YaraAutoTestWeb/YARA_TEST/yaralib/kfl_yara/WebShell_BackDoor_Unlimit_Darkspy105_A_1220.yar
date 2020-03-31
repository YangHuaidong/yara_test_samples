rule WebShell_BackDoor_Unlimit_Darkspy105_A_1220 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file DarkSpy105.exe"
    family = "Darkspy105"
    hacker = "None"
    hash = "f0b85e7bec90dba829a3ede1ab7d8722"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Darkspy105.A"
    threattype = "BackDoor"
  strings:
    $s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"
  condition:
    all of them
}