rule WebShell_BackDoor_Unlimit_Byshell063_Ntboot_2_A_1201 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ntboot.dll"
    family = "Byshell063"
    hacker = "None"
    hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Byshell063.Ntboot.2.A"
    threattype = "BackDoor"
  strings:
    $s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"
  condition:
    all of them
}