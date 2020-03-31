rule WebShell_BackDoor_Unlimit_Zacosmall_Php_A_1778 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file zacosmall.php.txt"
    family = "Zacosmall"
    hacker = "None"
    hash = "5295ee8dc2f5fd416be442548d68f7a6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Zacosmall.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "rand(1,99999);$sj98"
    $s1 = "$dump_file.='`'.$rows2[0].'`"
    $s3 = "filename=\\\"dump_{$db_dump}_${table_d"
  condition:
    2 of them
}