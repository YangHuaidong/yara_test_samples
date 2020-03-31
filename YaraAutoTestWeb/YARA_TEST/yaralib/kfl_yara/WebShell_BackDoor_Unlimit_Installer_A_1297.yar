rule WebShell_BackDoor_Unlimit_Installer_A_1297 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file installer.cmd"
    family = "Installer"
    hacker = "None"
    hash = "a507919ae701cf7e42fa441d3ad95f8f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Installer.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Restore Old Vanquish"
    $s4 = "ReInstall Vanquish"
  condition:
    all of them
}