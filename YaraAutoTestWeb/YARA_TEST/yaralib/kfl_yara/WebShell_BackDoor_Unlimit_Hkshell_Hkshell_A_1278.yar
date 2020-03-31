rule WebShell_BackDoor_Unlimit_Hkshell_Hkshell_A_1278 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file hkshell.exe"
    family = "Hkshell"
    hacker = "None"
    hash = "168cab58cee59dc4706b3be988312580"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hkshell.Hkshell.A"
    threattype = "BackDoor"
  strings:
    $s1 = "PrSessKERNELU"
    $s2 = "Cur3ntV7sion"
    $s3 = "Explorer8"
  condition:
    all of them
}