rule WebShell_BackDoor_Unlimit_Bin_Server_A_1195 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Server.exe"
    family = "Bin"
    hacker = "None"
    hash = "1d5aa9cbf1429bb5b8bf600335916dcd"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Bin.Server.A"
    threattype = "BackDoor"
  strings:
    $s0 = "configserver"
    $s1 = "GetLogicalDrives"
    $s2 = "WinExec"
    $s4 = "fxftest"
    $s5 = "upfileok"
    $s7 = "upfileer"
  condition:
    all of them
}