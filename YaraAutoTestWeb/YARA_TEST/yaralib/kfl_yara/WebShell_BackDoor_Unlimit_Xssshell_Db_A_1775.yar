rule WebShell_BackDoor_Unlimit_Xssshell_Db_A_1775 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file db.asp"
    family = "Xssshell"
    hacker = "None"
    hash = "cb62e2ec40addd4b9930a9e270f5b318"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Xssshell.Db.A"
    threattype = "BackDoor"
  strings:
    $s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"
  condition:
    all of them
}