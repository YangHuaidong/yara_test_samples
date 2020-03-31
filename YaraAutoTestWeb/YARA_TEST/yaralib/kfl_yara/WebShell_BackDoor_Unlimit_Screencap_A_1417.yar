rule WebShell_BackDoor_Unlimit_Screencap_A_1417 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file screencap.exe"
    family = "Screencap"
    hacker = "None"
    hash = "51139091dea7a9418a50f2712ea72aa6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Screencap.A"
    threattype = "BackDoor"
  strings:
    $s0 = "GetDIBColorTable"
    $s1 = "Screen.bmp"
    $s2 = "CreateDCA"
  condition:
    all of them
}