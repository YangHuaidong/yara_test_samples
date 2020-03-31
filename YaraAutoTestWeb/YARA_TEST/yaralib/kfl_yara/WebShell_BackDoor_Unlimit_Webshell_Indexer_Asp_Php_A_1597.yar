rule WebShell_BackDoor_Unlimit_Webshell_Indexer_Asp_Php_A_1597 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
    family = "Webshell"
    hacker = "None"
    hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Indexer.Asp.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword
    $s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword
    $s2 = "<form action=\"?Gonder\" method=\"post\">" fullword
    $s4 = "<form action=\"?oku\" method=\"post\">" fullword
    $s7 = "var message=\"SaNaLTeRoR - " fullword
    $s8 = "nDexEr - Reader\"" fullword
  condition:
    3 of them
}