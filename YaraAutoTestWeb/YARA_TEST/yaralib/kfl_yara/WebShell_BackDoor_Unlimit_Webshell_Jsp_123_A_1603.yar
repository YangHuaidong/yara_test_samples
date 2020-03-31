rule WebShell_BackDoor_Unlimit_Webshell_Jsp_123_A_1603 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 123.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "c691f53e849676cac68a38d692467641"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.123.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7"
    $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
    $s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword
  condition:
    all of them
}