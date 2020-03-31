rule WebShell_BackDoor_Unlimit_Fso_S_Remexp_2_A_1262 {
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
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Remexp.2.A"
    threattype = "BackDoor"
  strings:
    $s2 = " Then Response.Write \""
    $s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"
  condition:
    all of them
}