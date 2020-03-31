rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0029_A_1350 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
    hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
    hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
    hash3 = "d089e7168373a0634e1ac18c0ee00085"
    hash4 = "38fd7e45f9c11a37463c3ded1c76af4c"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0029.A"
    threattype = "BackDoor"
    was = "_c99shell_v1_0_php_php_c99php_1_c2007_php_php_c100_php"
  strings:
    $s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); " fullword
  condition:
    all of them
}