rule WebShell_BackDoor_Unlimit_Jsp_Reverse_Jsp_A_1305 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file jsp-reverse.jsp.txt"
    family = "Jsp"
    hacker = "None"
    hash = "8b0e6779f25a17f0ffb3df14122ba594"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Jsp.Reverse.Jsp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "// backdoor.jsp"
    $s1 = "JSP Backdoor Reverse Shell"
    $s2 = "http://michaeldaw.org"
  condition:
    2 of them
}