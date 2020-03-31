rule WebShell_BackDoor_Unlimit_Webshell_Php_S_U_A_1671 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file s-u.php"
    family = "Webshell"
    hacker = "None"
    hash = "efc7ba1a4023bcf40f5e912f1dd85b5a"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.S.U.A"
    threattype = "BackDoor"
  strings:
    $s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea"
  condition:
    all of them
}