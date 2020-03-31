rule WebShell_BackDoor_Unlimit_Debug_Bdoor_A_1223 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file BDoor.dll"
    family = "Debug"
    hacker = "None"
    hash = "e4e8e31dd44beb9320922c5f49739955"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Debug.Bdoor.A"
    threattype = "BackDoor"
  strings:
    $s1 = "\\BDoor\\"
    $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
  condition:
    all of them
}