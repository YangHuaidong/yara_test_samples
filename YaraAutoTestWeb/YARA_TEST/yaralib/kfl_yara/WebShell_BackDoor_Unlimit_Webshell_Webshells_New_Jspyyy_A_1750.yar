rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Jspyyy_A_1750 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file jspyyy.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Jspyyy.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"
  condition:
    all of them
}