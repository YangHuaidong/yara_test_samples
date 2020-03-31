rule WebShell_BackDoor_Unlimit_Webshell_Customize_A_1560 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file customize.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "d55578eccad090f30f5d735b8ec530b1"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Customize.A"
    threattype = "BackDoor"
  strings:
    $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
  condition:
    all of them
}