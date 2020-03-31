rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Jshell_A_1614 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file jshell.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "124b22f38aaaf064cef14711b2602c06"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Jshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "kXpeW[\"" fullword
    $s4 = "[7b:g0W@W<" fullword
    $s5 = "b:gHr,g<" fullword
    $s8 = "RhV0W@W<" fullword
    $s9 = "S_MR(u7b" fullword
  condition:
    all of them
}