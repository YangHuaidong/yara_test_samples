rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Jjjsp3_A_1748 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file JJjsp3.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "949ffee1e07a1269df7c69b9722d293e"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Jjjsp3.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"
  condition:
    all of them
}