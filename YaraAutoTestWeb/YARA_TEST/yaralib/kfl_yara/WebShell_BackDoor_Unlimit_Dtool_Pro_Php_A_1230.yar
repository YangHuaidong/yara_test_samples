rule WebShell_BackDoor_Unlimit_Dtool_Pro_Php_A_1230 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file DTool Pro.php.txt"
    family = "Dtool"
    hacker = "None"
    hash = "366ad973a3f327dfbfb915b0faaea5a6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Dtool.Pro.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "r3v3ng4ns\\nDigite"
    $s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi"
    $s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n"
  condition:
    1 of them
}