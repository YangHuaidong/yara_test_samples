rule WebShell_BackDoor_Unlimit_Webshell_Php_B37_A_1654 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file b37.php"
    family = "Webshell"
    hacker = "None"
    hash = "0421445303cfd0ec6bc20b3846e30ff0"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.B37.A"
    threattype = "BackDoor"
  strings:
    $s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc"
  condition:
    all of them
}