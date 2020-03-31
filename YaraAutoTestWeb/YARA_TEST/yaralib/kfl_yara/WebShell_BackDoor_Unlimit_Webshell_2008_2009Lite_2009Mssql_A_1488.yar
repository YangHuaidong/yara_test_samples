rule WebShell_BackDoor_Unlimit_Webshell_2008_2009Lite_2009Mssql_A_1488 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
    hash1 = "3f4d454d27ecc0013e783ed921eeecde"
    hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.2008.2009Lite.2009Mssql.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');"
    $s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all"
  condition:
    all of them
}