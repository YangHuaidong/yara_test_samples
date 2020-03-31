rule WebShell_BackDoor_Unlimit_Webshell_Asp_404_A_1502 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 404.asp"
    family = "Webshell"
    hacker = "None"
    hash = "d9fa1e8513dbf59fa5d130f389032a2d"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.404.A"
    threattype = "BackDoor"
  strings:
    $s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"
  condition:
    all of them
}