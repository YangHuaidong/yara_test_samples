rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Radhat_A_1758 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file radhat.asp"
    family = "Webshell"
    hacker = "None"
    hash = "72cb5ef226834ed791144abaa0acdfd4"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Radhat.A"
    threattype = "BackDoor"
  strings:
    $s1 = "sod=Array(\"D\",\"7\",\"S"
  condition:
    all of them
}