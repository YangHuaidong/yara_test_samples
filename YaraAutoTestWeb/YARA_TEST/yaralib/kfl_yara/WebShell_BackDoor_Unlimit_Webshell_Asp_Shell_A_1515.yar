rule WebShell_BackDoor_Unlimit_Webshell_Asp_Shell_A_1515 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file shell.asp"
    family = "Webshell"
    hacker = "None"
    hash = "e63f5a96570e1faf4c7b8ca6df750237"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Shell.A"
    threattype = "BackDoor"
  strings:
    $s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
    $s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
  condition:
    all of them
}