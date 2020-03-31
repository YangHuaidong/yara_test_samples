rule WebShell_BackDoor_Unlimit_Webshell_Asp_01_A_1499 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 01.asp"
    family = "Webshell"
    hacker = "None"
    hash = "61a687b0bea0ef97224c7bd2df118b87"
    judge = "unknown"
    reference = "None"
    score = 50
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.01.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%eval request(\"pass\")%>" fullword
  condition:
    all of them
}