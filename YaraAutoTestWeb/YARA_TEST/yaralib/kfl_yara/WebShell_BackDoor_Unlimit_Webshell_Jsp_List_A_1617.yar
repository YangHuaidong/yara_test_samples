rule WebShell_BackDoor_Unlimit_Webshell_Jsp_List_A_1617 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file list.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "1ea290ff4259dcaeb680cec992738eda"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.List.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
    $s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn"
    $s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword
  condition:
    all of them
}