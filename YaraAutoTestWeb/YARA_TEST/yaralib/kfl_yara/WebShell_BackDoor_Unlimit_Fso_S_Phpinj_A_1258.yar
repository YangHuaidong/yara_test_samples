rule WebShell_BackDoor_Unlimit_Fso_S_Phpinj_A_1258 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file phpinj.php"
    family = "Fso"
    hacker = "None"
    hash = "dd39d17e9baca0363cc1c3664e608929"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Phpinj.A"
    threattype = "BackDoor"
  strings:
    $s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';"
  condition:
    all of them
}