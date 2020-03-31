rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Guige_A_1610 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file guige.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "2c9f2dafa06332957127e2c713aacdd2"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Guige.A"
    threattype = "BackDoor"
  strings:
    $s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null"
  condition:
    all of them
}