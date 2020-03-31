rule WebShell_BackDoor_Unlimit_Webshell_Asp_Cmdasp_A_1507 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmdasp.asp"
    family = "Webshell"
    hacker = "None"
    hash = "57b51418a799d2d016be546f399c2e9b"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Cmdasp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
    $s7 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
  condition:
    all of them
}