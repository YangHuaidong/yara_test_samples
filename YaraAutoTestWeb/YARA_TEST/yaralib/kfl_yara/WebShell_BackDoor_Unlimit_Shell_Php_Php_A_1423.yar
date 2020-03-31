rule WebShell_BackDoor_Unlimit_Shell_Php_Php_A_1423 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file shell.php.php.txt"
    family = "Shell"
    hacker = "None"
    hash = "1a95f0163b6dea771da1694de13a3d8d"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Shell.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
    $s2 = "$tmpfile = tempnam('/tmp', 'phpshell');"
    $s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword
  condition:
    1 of them
}