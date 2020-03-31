rule WebShell_BackDoor_Unlimit_Webshell_Cpg_143_Incl_Xpl_A_1558 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cpg_143_incl_xpl.php"
    family = "Webshell"
    hacker = "None"
    hash = "5937b131b67d8e0afdbd589251a5e176"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Cpg.143.Incl.Xpl.A"
    threattype = "BackDoor"
  strings:
    $s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA"
    $s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time"
  condition:
    1 of them
}