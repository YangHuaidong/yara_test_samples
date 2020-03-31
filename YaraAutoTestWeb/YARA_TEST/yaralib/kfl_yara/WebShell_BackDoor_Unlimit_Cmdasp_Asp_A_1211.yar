rule WebShell_BackDoor_Unlimit_Cmdasp_Asp_A_1211 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file CmdAsp.asp.txt"
    family = "Cmdasp"
    hacker = "None"
    hash = "64f24f09ec6efaa904e2492dffc518b9"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Cmdasp.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "CmdAsp.asp"
    $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
    $s2 = "-- Use a poor man's pipe ... a temp file --"
    $s3 = "maceo @ dogmile.com"
  condition:
    2 of them
}