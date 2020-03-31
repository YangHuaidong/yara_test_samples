rule WebShell_BackDoor_Unlimit_Fmlibraryv3_A_1246 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file fmlibraryv3.asp"
    family = "Fmlibraryv3"
    hacker = "None"
    hash = "c34c248fed6d5a20d8203924a2088acc"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fmlibraryv3.A"
    threattype = "BackDoor"
  strings:
    $s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"
  condition:
    all of them
}