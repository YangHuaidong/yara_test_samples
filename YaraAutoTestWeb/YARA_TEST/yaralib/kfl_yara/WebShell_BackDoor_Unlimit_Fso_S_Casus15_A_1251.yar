rule WebShell_BackDoor_Unlimit_Fso_S_Casus15_A_1251 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file casus15.php"
    family = "Fso"
    hacker = "None"
    hash = "8d155b4239d922367af5d0a1b89533a3"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Casus15.A"
    threattype = "BackDoor"
  strings:
    $s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))"
  condition:
    all of them
}