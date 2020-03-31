rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Php6_A_1756 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file php6.php"
    family = "Webshell"
    hacker = "None"
    hash = "ea75280224a735f1e445d244acdfeb7b"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Php6.A"
    threattype = "BackDoor"
  strings:
    $s1 = "array_map(\"asx73ert\",(ar"
    $s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
    $s4 = "shell.php?qid=zxexp  " fullword
  condition:
    1 of them
}