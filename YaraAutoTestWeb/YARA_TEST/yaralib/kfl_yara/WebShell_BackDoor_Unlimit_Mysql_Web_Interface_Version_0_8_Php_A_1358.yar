rule WebShell_BackDoor_Unlimit_Mysql_Web_Interface_Version_0_8_Php_A_1358 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file MySQL Web Interface Version 0.8.php.txt"
    family = "Mysql"
    hacker = "None"
    hash = "36d4f34d0a22080f47bb1cb94107c60f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Mysql.Web.Interface.Version.0.8.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "SooMin Kim"
    $s1 = "http://popeye.snu.ac.kr/~smkim/mysql"
    $s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename"
    $s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi"
  condition:
    2 of them
}