rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Asd_A_1606 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file asd.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "a042c2ca64176410236fcc97484ec599"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Asd.A"
    threattype = "BackDoor"
  strings:
    $s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
    $s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"
  condition:
    all of them
}