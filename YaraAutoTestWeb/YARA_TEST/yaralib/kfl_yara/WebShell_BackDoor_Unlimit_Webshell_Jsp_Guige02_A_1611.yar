rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Guige02_A_1611 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file guige02.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "a3b8b2280c56eaab777d633535baf21d"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Guige02.A"
    threattype = "BackDoor"
  strings:
    $s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
    $s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"
  condition:
    all of them
}