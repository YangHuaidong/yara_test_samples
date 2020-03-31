rule WebShell_BackDoor_Unlimit_Elmaliseker_Asp_A_1238 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file elmaliseker.asp.txt"
    family = "Elmaliseker"
    hacker = "None"
    hash = "b32d1730d23a660fd6aa8e60c3dc549f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Elmaliseker.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\""
    $s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">"
    $s2 = "dim zombie_array,special_array"
    $s3 = "http://vnhacker.org"
  condition:
    1 of them
}