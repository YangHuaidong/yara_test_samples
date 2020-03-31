rule WebShell_BackDoor_Unlimit_Chinese_Spam_Echoer_A_1208 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/07/18"
    description = "Catches chinese PHP spam files (printers)"
    family = "Chinese"
    hacker = "None"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Chinese.Spam.Echoer.A"
    threattype = "BackDoor"
  strings:
    $a = "set_time_limit(0)"
    $b = "date_default_timezone_set('PRC');"
    $c = "$Content_mb;"
    $d = "/index.php?host="
  condition:
    all of them
}