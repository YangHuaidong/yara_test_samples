rule WebShell_BackDoor_Unlimit_Webshell_Cmdasp_Asp_Php_A_1556 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file CmdAsp.asp.php.txt"
    family = "Webshell"
    hacker = "None"
    hash = "cb18e1ac11e37e236e244b96c2af2d313feda696"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Cmdasp.Asp.Php.A"
    threattype = "BackDoor"
  strings:
    $s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
    $s4 = "' Author: Maceo <maceo @ dogmile.com>" fullword
    $s5 = "' -- Use a poor man's pipe ... a temp file -- '" fullword
    $s6 = "' --------------------o0o--------------------" fullword
    $s8 = "' File: CmdAsp.asp" fullword
    $s11 = "<-- CmdAsp.asp -->" fullword
    $s14 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
    $s16 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
    $s19 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
  condition:
    4 of them
}