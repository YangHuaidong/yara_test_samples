rule WebShell_BackDoor_Unlimit_Webshell_Jsp_K8Cmd_A_1615 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file k8cmd.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "b39544415e692a567455ff033a97a682"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.K8Cmd.A"
    threattype = "BackDoor"
  strings:
    $s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
  condition:
    all of them
}