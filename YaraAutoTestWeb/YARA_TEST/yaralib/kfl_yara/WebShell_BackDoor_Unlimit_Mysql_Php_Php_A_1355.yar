rule WebShell_BackDoor_Unlimit_Mysql_Php_Php_A_1355 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file mysql.php.php.txt"
    family = "Mysql"
    hacker = "None"
    hash = "12bbdf6ef403720442a47a3cc730d034"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Mysql.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "action=mysqlread&mass=loadmass\">load all defaults"
    $s2 = "if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru"
    $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = "
  condition:
    1 of them
}