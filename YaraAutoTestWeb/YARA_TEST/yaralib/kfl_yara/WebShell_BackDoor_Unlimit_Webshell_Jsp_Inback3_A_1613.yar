rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Inback3_A_1613 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file inback3.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "ea5612492780a26b8aa7e5cedd9b8f4e"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Inback3.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
  condition:
    all of them
}