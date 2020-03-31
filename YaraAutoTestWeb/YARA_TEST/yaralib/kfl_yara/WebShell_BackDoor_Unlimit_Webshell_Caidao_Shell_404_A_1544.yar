rule WebShell_BackDoor_Unlimit_Webshell_Caidao_Shell_404_A_1544 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 404.php"
    family = "Webshell"
    hacker = "None"
    hash = "ee94952dc53d9a29bdf4ece54c7a7aa7"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Caidao.Shell.404.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St"
  condition:
    all of them
}