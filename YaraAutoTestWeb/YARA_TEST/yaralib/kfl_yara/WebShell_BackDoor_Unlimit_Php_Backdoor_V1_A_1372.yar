rule WebShell_BackDoor_Unlimit_Php_Backdoor_V1_A_1372 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file PHP Backdoor v1.php"
    family = "Php"
    hacker = "None"
    hash = "0506ba90759d11d78befd21cabf41f3d"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Backdoor.V1.A"
    threattype = "BackDoor"
  strings:
    $s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
    $s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"
  condition:
    all of them
}