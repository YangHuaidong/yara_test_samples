rule WebShell_BackDoor_Unlimit_Webshell_Casus_1_5_A_1550 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file CasuS 1.5.php"
    family = "Webshell"
    hacker = "None"
    hash = "7eee8882ad9b940407acc0146db018c302696341"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Casus.1.5.A"
    threattype = "BackDoor"
  strings:
    $s2 = "<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO"
    $s8 = "$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");" fullword
    $s18 = "if (file_exists(\"F:\\\\\")){" fullword
  condition:
    1 of them
}