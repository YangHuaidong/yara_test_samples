rule WebShell_BackDoor_Unlimit_Webshell_Php_Fbi_A_1661 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file fbi.php"
    family = "Webshell"
    hacker = "None"
    hash = "1fb32f8e58c8deb168c06297a04a21f1"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Fbi.A"
    threattype = "BackDoor"
  strings:
    $s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo"
  condition:
    all of them
}