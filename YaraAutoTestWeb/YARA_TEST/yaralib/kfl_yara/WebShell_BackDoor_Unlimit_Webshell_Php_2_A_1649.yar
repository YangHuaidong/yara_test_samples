rule WebShell_BackDoor_Unlimit_Webshell_Php_2_A_1649 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 2.php"
    family = "Webshell"
    hacker = "None"
    hash = "267c37c3a285a84f541066fc5b3c1747"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
  condition:
    all of them
}