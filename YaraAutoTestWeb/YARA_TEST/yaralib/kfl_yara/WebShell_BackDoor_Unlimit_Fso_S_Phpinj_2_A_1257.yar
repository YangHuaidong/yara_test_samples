rule WebShell_BackDoor_Unlimit_Fso_S_Phpinj_2_A_1257 {
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
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Phpinj.2.A"
    threattype = "BackDoor"
  strings:
    $s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO"
  condition:
    all of them
}