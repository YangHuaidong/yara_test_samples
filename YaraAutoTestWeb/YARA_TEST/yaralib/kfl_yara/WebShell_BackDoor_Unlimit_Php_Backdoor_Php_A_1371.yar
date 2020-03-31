rule WebShell_BackDoor_Unlimit_Php_Backdoor_Php_A_1371 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file php-backdoor.php.txt"
    family = "Php"
    hacker = "None"
    hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Backdoor.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "http://michaeldaw.org   2006"
    $s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
    $s3 = "coded by z0mbie"
  condition:
    1 of them
}