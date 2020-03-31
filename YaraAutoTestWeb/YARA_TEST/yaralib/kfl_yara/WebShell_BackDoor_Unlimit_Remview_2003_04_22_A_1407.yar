rule WebShell_BackDoor_Unlimit_Remview_2003_04_22_A_1407 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file remview_2003_04_22.php"
    family = "Remview"
    hacker = "None"
    hash = "17d3e4e39fbca857344a7650f7ea55e3"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Remview.2003.04.22.A"
    threattype = "BackDoor"
  strings:
    $s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""
  condition:
    all of them
}