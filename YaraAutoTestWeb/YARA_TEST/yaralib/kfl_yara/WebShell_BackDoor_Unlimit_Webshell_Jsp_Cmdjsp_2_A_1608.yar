rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Cmdjsp_2_A_1608 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmdjsp.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "1b5ae3649f03784e2a5073fa4d160c8b"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Cmdjsp.2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
    $s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
  condition:
    all of them
}