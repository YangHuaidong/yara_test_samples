rule WebShell_BackDoor_Unlimit_U_Uay_A_1451 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file uay.exe"
    family = "U"
    hacker = "None"
    hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.U.Uay.A"
    threattype = "BackDoor"
  strings:
    $s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
    $s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"
  condition:
    1 of them
}