rule WebShell_BackDoor_Unlimit_Webshell_Macker_S_Private_Phpshell_A_1633 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Macker's Private PHPShell.php"
    family = "Webshell"
    hacker = "None"
    hash = "e24cbf0e294da9ac2117dc660d890bb9"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Macker.S.Private.Phpshell.A"
    threattype = "BackDoor"
  strings:
    $s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n"
    $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
    $s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
  condition:
    all of them
}