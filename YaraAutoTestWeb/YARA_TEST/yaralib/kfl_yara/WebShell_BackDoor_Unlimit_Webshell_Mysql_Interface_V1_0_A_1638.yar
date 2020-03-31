rule WebShell_BackDoor_Unlimit_Webshell_Mysql_Interface_V1_0_A_1638 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Mysql interface v1.0.php"
    family = "Webshell"
    hacker = "None"
    hash = "a12fc0a3d31e2f89727b9678148cd487"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Mysql.Interface.V1.0.A"
    threattype = "BackDoor"
  strings:
    $s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"
  condition:
    all of them
}