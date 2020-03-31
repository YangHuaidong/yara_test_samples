rule WebShell_BackDoor_Unlimit_Fso_S_Ntdaddy_A_1256 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ntdaddy.asp"
    family = "Fso"
    hacker = "None"
    hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Ntdaddy.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"
  condition:
    all of them
}