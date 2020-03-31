rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0008_A_1329 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt, ctt_sh.php.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
    hash1 = "3ca5886cd54d495dc95793579611f59a"
    hash2 = "9c5bb5e3a46ec28039e8986324e42792"
    hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
    hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
    hash5 = "09609851caa129e40b0d56e90dfc476c"
    hash6 = "671cad517edd254352fe7e0c7c981c39"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0008.A"
    threattype = "BackDoor"
    was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php_ctt_sh_php_php"
  strings:
    $s0 = "  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\""
    $s1 = "  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile"
    $s2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr"
    $s3 = "  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m"
  condition:
    all of them
}