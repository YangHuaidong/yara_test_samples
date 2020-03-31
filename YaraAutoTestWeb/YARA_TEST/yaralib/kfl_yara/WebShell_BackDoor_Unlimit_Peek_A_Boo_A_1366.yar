rule WebShell_BackDoor_Unlimit_Peek_A_Boo_A_1366 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file peek-a-boo.exe"
    family = "Peek"
    hacker = "None"
    hash = "aca339f60d41fdcba83773be5d646776"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Peek.A.Boo.A"
    threattype = "BackDoor"
  strings:
    $s0 = "__vbaHresultCheckObj"
    $s1 = "\\VB\\VB5.OLB"
    $s2 = "capGetDriverDescriptionA"
    $s3 = "__vbaExceptHandler"
    $s4 = "EVENT_SINK_Release"
    $s8 = "__vbaErrorOverflow"
  condition:
    all of them
}