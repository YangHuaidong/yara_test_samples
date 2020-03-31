rule WebShell_BackDoor_Unlimit_Hkshell_Hkrmv_A_1277 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file hkrmv.exe"
    family = "Hkshell"
    hacker = "None"
    hash = "bd3a0b7a6b5536f8d96f50956560e9bf"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hkshell.Hkrmv.A"
    threattype = "BackDoor"
  strings:
    $s5 = "/THUMBPOSITION7"
    $s6 = "\\EvilBlade\\"
  condition:
    all of them
}