rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Tree_A_1621 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file tree.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "bcdf7bbf7bbfa1ffa4f9a21957dbcdfa"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Tree.A"
    threattype = "BackDoor"
  strings:
    $s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki"
    $s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ"
  condition:
    all of them
}