rule WebShell_BackDoor_Unlimit_Regshell_A_1403 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file regshell.exe"
    family = "Regshell"
    hacker = "None"
    hash = "db2fdc821ca6091bab3ebd0d8bc46ded"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Regshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Changes the base hive to HKEY_CURRENT_USER."
    $s4 = "Displays a list of values and sub-keys in a registry Hive."
    $s5 = "Enter a menu selection number (1 - 3) or 99 to Exit: "
  condition:
    all of them
}