rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0019_A_1340 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
    hash1 = "3ca5886cd54d495dc95793579611f59a"
    hash2 = "9c5bb5e3a46ec28039e8986324e42792"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0019.A"
    threattype = "BackDoor"
    was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php"
  strings:
    $s0 = "<b>Dumped! Dump has been writed to "
    $s1 = "if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st"
    $s2 = "<input type=submit name=actarcbuff value=\\\"Pack buffer to archive"
  condition:
    1 of them
}