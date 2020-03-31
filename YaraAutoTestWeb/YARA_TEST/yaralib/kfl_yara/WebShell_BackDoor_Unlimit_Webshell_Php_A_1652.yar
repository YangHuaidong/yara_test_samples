rule WebShell_BackDoor_Unlimit_Webshell_Php_A_1652 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file webshell.php.txt"
    family = "Webshell"
    hacker = "None"
    hash = "e425241b928e992bde43dd65180a4894"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.A"
    threattype = "BackDoor"
  strings:
    $s2 = "<die(\"Couldn't Read directory, Blocked!!!\");"
    $s3 = "PHP Web Shell"
  condition:
    all of them
}