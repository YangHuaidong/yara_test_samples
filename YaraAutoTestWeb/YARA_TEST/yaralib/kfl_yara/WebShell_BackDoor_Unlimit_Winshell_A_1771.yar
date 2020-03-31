rule WebShell_BackDoor_Unlimit_Winshell_A_1771 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file winshell.exe"
    family = "Winshell"
    hacker = "None"
    hash = "3144410a37dd4c29d004a814a294ea26"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Winshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
    $s1 = "WinShell Service"
    $s2 = "__GLOBAL_HEAP_SELECTED"
    $s3 = "__MSVCRT_HEAP_SELECT"
    $s4 = "Provide Windows CmdShell Service"
    $s5 = "URLDownloadToFileA"
    $s6 = "RegisterServiceProcess"
    $s7 = "GetModuleBaseNameA"
    $s8 = "WinShell v5.0 (C)2002 janker.org"
  condition:
    all of them
}