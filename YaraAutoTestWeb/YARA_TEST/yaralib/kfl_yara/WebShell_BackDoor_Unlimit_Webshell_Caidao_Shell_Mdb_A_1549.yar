rule WebShell_BackDoor_Unlimit_Webshell_Caidao_Shell_Mdb_A_1549 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file mdb.asp"
    family = "Webshell"
    hacker = "None"
    hash = "fbf3847acef4844f3a0d04230f6b9ff9"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Caidao.Shell.Mdb.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<% execute request(\"ice\")%>a " fullword
  condition:
    all of them
}