rule WebShell_BackDoor_Unlimit_Fso_S_Phvayv_2_A_1259 {
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
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Phvayv.2.A"
    threattype = "BackDoor"
  strings:
    $s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font"
  condition:
    all of them
}