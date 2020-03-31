rule WebShell_BackDoor_Unlimit_Webshell_Spjspshell_A_1733 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file spjspshell.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "d39d51154aaad4ba89947c459a729971"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Spjspshell.A"
    threattype = "BackDoor"
  strings:
    $s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:"
  condition:
    all of them
}