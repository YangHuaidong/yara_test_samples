rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Zx_A_1625 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file zx.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "67627c264db1e54a4720bd6a64721674"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Zx.A"
    threattype = "BackDoor"
  strings:
    $s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"
  condition:
    all of them
}