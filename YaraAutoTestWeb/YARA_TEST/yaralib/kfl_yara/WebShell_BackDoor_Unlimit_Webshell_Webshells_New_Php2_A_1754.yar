rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Php2_A_1754 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file php2.php"
    family = "Webshell"
    hacker = "None"
    hash = "fbf2e76e6f897f6f42b896c855069276"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Php2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="
  condition:
    all of them
}