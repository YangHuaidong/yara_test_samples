rule WebShell_BackDoor_Unlimit_Fso_S_Cmd_A_1252 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file cmd.asp"
    family = "Fso"
    hacker = "None"
    hash = "cbe8e365d41dd3cd8e462ca434cf385f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Cmd.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
    $s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
  condition:
    all of them
}