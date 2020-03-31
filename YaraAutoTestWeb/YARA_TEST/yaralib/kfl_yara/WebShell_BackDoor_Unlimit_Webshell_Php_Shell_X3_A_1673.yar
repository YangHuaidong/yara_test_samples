rule WebShell_BackDoor_Unlimit_Webshell_Php_Shell_X3_A_1673 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file PHP Shell.php"
    family = "Webshell"
    hacker = "None"
    hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Shell.X3.A"
    threattype = "BackDoor"
  strings:
    $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
    $s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
    $s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("
  condition:
    2 of them
}