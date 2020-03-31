rule WebShell_BackDoor_Unlimit_Webshell_Php_Sql_A_1674 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file sql.php"
    family = "Webshell"
    hacker = "None"
    hash = "2cf20a207695bbc2311a998d1d795c35"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Sql.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_"
    $s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
  condition:
    all of them
}