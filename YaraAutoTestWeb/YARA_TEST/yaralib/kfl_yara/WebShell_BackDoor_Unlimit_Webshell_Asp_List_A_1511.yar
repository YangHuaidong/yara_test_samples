rule WebShell_BackDoor_Unlimit_Webshell_Asp_List_A_1511 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file list.asp"
    family = "Webshell"
    hacker = "None"
    hash = "1cfa493a165eb4b43e6d4cc0f2eab575"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.List.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
    $s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
  condition:
    all of them
}