rule WebShell_BackDoor_Unlimit_Webshell_Jsp_List1_A_1618 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file list1.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "8d9e5afa77303c9c01ff34ea4e7f6ca6"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.List1.A"
    threattype = "BackDoor"
  strings:
    $s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive"
    $s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\""
  condition:
    all of them
}