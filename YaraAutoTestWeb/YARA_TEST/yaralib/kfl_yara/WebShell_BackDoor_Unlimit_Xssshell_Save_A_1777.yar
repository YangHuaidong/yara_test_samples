rule WebShell_BackDoor_Unlimit_Xssshell_Save_A_1777 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file save.asp"
    family = "Xssshell"
    hacker = "None"
    hash = "865da1b3974e940936fe38e8e1964980"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Xssshell.Save.A"
    threattype = "BackDoor"
  strings:
    $s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
    $s5 = "VictimID = fm_NStr(Victims(i))"
  condition:
    all of them
}