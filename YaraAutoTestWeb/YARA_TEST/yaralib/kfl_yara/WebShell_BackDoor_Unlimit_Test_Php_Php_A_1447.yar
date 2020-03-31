rule WebShell_BackDoor_Unlimit_Test_Php_Php_A_1447 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Test.php.php.txt"
    family = "Test"
    hacker = "None"
    hash = "77e331abd03b6915c6c6c7fe999fcb50"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Test.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
    $s2 = "fwrite ($fp, \"$yazi\");" fullword
    $s3 = "$entry_line=\"HACKed by EntriKa\";" fullword
  condition:
    1 of them
}