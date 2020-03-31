rule WebShell_BackDoor_Unlimit_Fso_S_Remexp_A_1263 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file RemExp.asp"
    family = "Fso"
    hacker = "None"
    hash = "b69670ecdbb40012c73686cd22696eeb"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Remexp.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
    $s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
    $s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"
  condition:
    all of them
}