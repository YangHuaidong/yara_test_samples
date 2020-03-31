rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0001_A_1322 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files 1.txt, c2007.php.php.txt, c100.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "44542e5c3e9790815c49d5f9beffbbf2"
    hash1 = "d089e7168373a0634e1ac18c0ee00085"
    hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0001.A"
    threattype = "BackDoor"
    was = "_1_c2007_php_php_c100_php"
  strings:
    $s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\""
    $s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
  condition:
    1 of them
}