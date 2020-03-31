rule WebShell_BackDoor_Unlimit_Webshell_H4Ntu_Shell_Powered_By_Tsoi__A_1592 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file h4ntu shell [powered by tsoi].php"
    family = "Webshell"
    hacker = "None"
    hash = "06ed0b2398f8096f1bebf092d0526137"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.H4Ntu.Shell.Powered.By.Tsoi..A"
    threattype = "BackDoor"
  strings:
    $s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
    $s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
    $s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
    $s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($"
  condition:
    all of them
}