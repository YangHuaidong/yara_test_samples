rule WebShell_BackDoor_Unlimit_Webshell_Asp_1_A_1500 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 1.asp"
    family = "Webshell"
    hacker = "None"
    hash = "8991148adf5de3b8322ec5d78cb01bdb"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.1.A"
    threattype = "BackDoor"
  strings:
    $s4 = "!22222222222222222222222222222222222222222222222222" fullword
    $s8 = "<%eval request(\"pass\")%>" fullword
  condition:
    all of them
}