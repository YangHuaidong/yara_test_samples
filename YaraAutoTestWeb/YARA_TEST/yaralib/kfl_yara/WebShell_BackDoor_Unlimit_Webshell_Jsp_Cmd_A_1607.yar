rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Cmd_A_1607 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmd.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "5391c4a8af1ede757ba9d28865e75853"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Cmd.A"
    threattype = "BackDoor"
  strings:
    $s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
  condition:
    all of them
}