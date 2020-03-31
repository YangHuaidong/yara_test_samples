rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0015_A_1336 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "9c5bb5e3a46ec28039e8986324e42792"
    hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
    hash2 = "09609851caa129e40b0d56e90dfc476c"
    hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0015.A"
    threattype = "BackDoor"
    was = "_wacking_php_php_1_SpecialShell_99_php_php_c100_php"
  strings:
    $s0 = "if(eregi(\"./shbd $por\",$scan))"
    $s1 = "$_POST['backconnectip']"
    $s2 = "$_POST['backcconnmsg']"
  condition:
    1 of them
}