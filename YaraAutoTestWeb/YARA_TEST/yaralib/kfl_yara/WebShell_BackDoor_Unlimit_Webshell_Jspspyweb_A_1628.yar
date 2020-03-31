rule WebShell_BackDoor_Unlimit_Webshell_Jspspyweb_A_1628 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Jspspyweb.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "4e9be07e95fff820a9299f3fb4ace059"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jspspyweb.A"
    threattype = "BackDoor"
  strings:
    $s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7"
    $s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control"
  condition:
    all of them
}