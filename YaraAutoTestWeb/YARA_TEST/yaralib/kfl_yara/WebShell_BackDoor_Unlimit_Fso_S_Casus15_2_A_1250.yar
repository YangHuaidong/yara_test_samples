rule WebShell_BackDoor_Unlimit_Fso_S_Casus15_2_A_1250 {
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
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Casus15.2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "copy ( $dosya_gonder"
  condition:
    all of them
}