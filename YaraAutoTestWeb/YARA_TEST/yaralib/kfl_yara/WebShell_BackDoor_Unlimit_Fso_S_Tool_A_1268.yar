rule WebShell_BackDoor_Unlimit_Fso_S_Tool_A_1268 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file tool.asp"
    family = "Fso"
    hacker = "None"
    hash = "3a1e1e889fdd974a130a6a767b42655b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Tool.A"
    threattype = "BackDoor"
  strings:
    $s7 = "\"\"%windir%\\\\calc.exe\"\")"
  condition:
    all of them
}