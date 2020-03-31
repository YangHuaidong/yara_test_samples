rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Cmdjsp_A_1609 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmdjsp.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "b815611cc39f17f05a73444d699341d4"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Cmdjsp.A"
    threattype = "BackDoor"
  strings:
    $s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
  condition:
    all of them
}