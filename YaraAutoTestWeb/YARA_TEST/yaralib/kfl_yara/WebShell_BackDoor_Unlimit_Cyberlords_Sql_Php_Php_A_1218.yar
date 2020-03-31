rule WebShell_BackDoor_Unlimit_Cyberlords_Sql_Php_Php_A_1218 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file cyberlords_sql.php.php.txt"
    family = "Cyberlords"
    hacker = "None"
    hash = "03b06b4183cb9947ccda2c3d636406d4"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Cyberlords.Sql.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Coded by n0 [nZer0]"
    $s1 = " www.cyberlords.net"
    $s2 = "U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE"
    $s3 = "return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);"
  condition:
    1 of them
}