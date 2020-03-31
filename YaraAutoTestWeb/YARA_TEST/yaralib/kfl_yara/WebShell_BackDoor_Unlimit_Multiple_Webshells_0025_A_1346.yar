rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0025_A_1346 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
    hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
    hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0025.A"
    threattype = "BackDoor"
    was = "_c99shell_v1_0_php_php_c99php_SsEs_php_php"
  strings:
    $s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}" fullword
  condition:
    1 of them
}