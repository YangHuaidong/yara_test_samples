rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0011_A_1332 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
    hash1 = "3ca5886cd54d495dc95793579611f59a"
    hash2 = "9c5bb5e3a46ec28039e8986324e42792"
    hash3 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
    hash4 = "09609851caa129e40b0d56e90dfc476c"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0011.A"
    threattype = "BackDoor"
    was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php"
  strings:
    $s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA"
    $s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec"
  condition:
    1 of them
}