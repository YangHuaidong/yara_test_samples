rule WebShell_BackDoor_Unlimit_Stnc_Php_Php_A_1442 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file STNC.php.php.txt"
    family = "Stnc"
    hacker = "None"
    hash = "2e56cfd5b5014cbbf1c1e3f082531815"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Stnc.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "drmist.ru" fullword
    $s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80"
    $s2 = "STNC WebShell"
    $s3 = "http://www.security-teams.net/index.php?showtopic="
  condition:
    1 of them
}