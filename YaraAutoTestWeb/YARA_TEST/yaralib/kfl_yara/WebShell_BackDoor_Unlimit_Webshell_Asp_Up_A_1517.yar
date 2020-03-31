rule WebShell_BackDoor_Unlimit_Webshell_Asp_Up_A_1517 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file up.asp"
    family = "Webshell"
    hacker = "None"
    hash = "f775e721cfe85019fe41c34f47c0d67c"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Up.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio"
    $s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword
  condition:
    1 of them
}