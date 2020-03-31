rule WebShell_BackDoor_Unlimit_Webshell_Php_G00Nv13_A_1662 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file g00nv13.php"
    family = "Webshell"
    hacker = "None"
    hash = "35ad2533192fe8a1a76c3276140db820"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.G00Nv13.A"
    threattype = "BackDoor"
  strings:
    $s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
    $s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"
  condition:
    all of them
}