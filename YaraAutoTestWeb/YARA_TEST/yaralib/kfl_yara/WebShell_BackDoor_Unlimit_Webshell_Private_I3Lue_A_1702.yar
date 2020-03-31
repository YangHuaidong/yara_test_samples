rule WebShell_BackDoor_Unlimit_Webshell_Private_I3Lue_A_1702 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Private-i3lue.php"
    family = "Webshell"
    hacker = "None"
    hash = "13f5c7a035ecce5f9f380967cf9d4e92"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Private.I3Lue.A"
    threattype = "BackDoor"
  strings:
    $s8 = "case 15: $image .= \"\\21\\0\\"
  condition:
    all of them
}