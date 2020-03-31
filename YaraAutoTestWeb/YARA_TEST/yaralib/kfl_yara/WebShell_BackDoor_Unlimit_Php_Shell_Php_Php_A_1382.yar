rule WebShell_BackDoor_Unlimit_Php_Shell_Php_Php_A_1382 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file PHP Shell.php.php.txt"
    family = "Php"
    hacker = "None"
    hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Shell.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
    $s1 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
  condition:
    all of them
}