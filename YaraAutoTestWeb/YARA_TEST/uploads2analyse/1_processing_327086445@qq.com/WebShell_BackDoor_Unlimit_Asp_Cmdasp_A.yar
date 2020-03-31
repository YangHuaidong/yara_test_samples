rule WebShell_BackDoor_Unlimit_Asp_Cmdasp_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file CmdAsp.asp"
    family = "Asp"
    hacker = "None"
    hash = "79d4f3425f7a89befb0ef3bafe5e332f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Asp.Cmdasp.A"
    threattype = "BackDoor"
  strings:
    $s2 = "' -- Read the output from our command and remove the temp file -- '"
    $s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
    $s9 = "' -- create the COM objects that we will be using -- '"
  condition:
    all of them
}