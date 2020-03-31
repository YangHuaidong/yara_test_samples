rule WebShell_BackDoor_Unlimit_Webshell_Mysql_Web_Interface_Version_0_8_A_1640 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file MySQL Web Interface Version 0.8.php"
    family = "Webshell"
    hacker = "None"
    hash = "36d4f34d0a22080f47bb1cb94107c60f"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Mysql.Web.Interface.Version.0.8.A"
    threattype = "BackDoor"
  strings:
    $s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>"
  condition:
    all of them
}