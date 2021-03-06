rule WebShell_BackDoor_Unlimit_Asp_Shell_A_1182 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file shell.asp"
    family = "Asp"
    hacker = "None"
    hash = "8bf1ff6f8edd45e3102be5f8a1fe030752f45613"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Asp.Shell.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "%ComSpec% /c dir" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "Server.ScriptTimeout = 180" fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "cmd = Request.Form(\"cmd\")" fullword ascii /* PEStudio Blacklist: strings */
    $s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
    $s7 = "Dim wshell, intReturn, strPResult" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 15KB and 4 of them
}