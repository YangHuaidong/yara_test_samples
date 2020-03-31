rule WebShell_BackDoor_Unlimit_Webshell_Caidao_Shell_Ice_2_A_1547 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ice.php"
    family = "Webshell"
    hacker = "None"
    hash = "1d6335247f58e0a5b03e17977888f5f2"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Caidao.Shell.Ice.2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php ${${eval($_POST[ice])}};?>" fullword
  condition:
    all of them
}