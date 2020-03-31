rule WebShell_BackDoor_Unlimit_Fso_S_Phvayv_A_1260 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file phvayv.php"
    family = "Fso"
    hacker = "None"
    hash = "205ecda66c443083403efb1e5c7f7878"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Phvayv.A"
    threattype = "BackDoor"
  strings:
    $s2 = "wrap=\"OFF\">XXXX</textarea></font><font face"
  condition:
    all of them
}