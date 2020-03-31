rule WebShell_BackDoor_Unlimit_Webshell_Mysqlwebsh_A_1641 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file mysqlwebsh.php"
    family = "Webshell"
    hacker = "None"
    hash = "babfa76d11943a22484b3837f105fada"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Mysqlwebsh.A"
    threattype = "BackDoor"
  strings:
    $s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#"
  condition:
    all of them
}