rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0022_A_1343 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, SpecialShell_99.php.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
    hash1 = "3ca5886cd54d495dc95793579611f59a"
    hash2 = "9c5bb5e3a46ec28039e8986324e42792"
    hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
    hash4 = "09609851caa129e40b0d56e90dfc476c"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0022.A"
    threattype = "BackDoor"
    was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_SpecialShell_99_php_php"
  strings:
    $s0 = "c99ftpbrutecheck"
    $s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);" fullword
    $s2 = "$fqb_lenght = $nixpwdperpage;" fullword
    $s3 = "$sock = @ftp_connect($host,$port,$timeout);" fullword
  condition:
    2 of them
}