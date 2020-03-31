rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Utils_A_1623 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file utils.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "9827ba2e8329075358b8e8a53e20d545"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Utils.A"
    threattype = "BackDoor"
  strings:
    $s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
    $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
  condition:
    all of them
}