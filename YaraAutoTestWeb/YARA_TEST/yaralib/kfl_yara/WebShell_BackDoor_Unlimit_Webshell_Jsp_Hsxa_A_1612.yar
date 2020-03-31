rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Hsxa_A_1612 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file hsxa.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "d0e05f9c9b8e0b3fa11f57d9ab800380"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Hsxa.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
  condition:
    all of them
}