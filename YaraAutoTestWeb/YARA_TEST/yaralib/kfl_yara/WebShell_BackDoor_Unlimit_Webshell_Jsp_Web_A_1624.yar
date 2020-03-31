rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Web_A_1624 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file web.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "4bc11e28f5dccd0c45a37f2b541b2e98"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Web.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."
  condition:
    all of them
}