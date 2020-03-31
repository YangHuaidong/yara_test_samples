rule WebShell_BackDoor_Unlimit_Webshell_Asp_Cmd_A_1506 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmd.asp"
    family = "Webshell"
    hacker = "None"
    hash = "97af88b478422067f23b001dd06d56a9"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Cmd.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
  condition:
    all of them
}