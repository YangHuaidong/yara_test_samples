rule WebShell_BackDoor_Unlimit_Webshell_Mysql_Tool_A_1639 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file mysql_tool.php"
    family = "Webshell"
    hacker = "None"
    hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Mysql.Tool.A"
    threattype = "BackDoor"
  strings:
    $s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
    $s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
  condition:
    2 of them
}