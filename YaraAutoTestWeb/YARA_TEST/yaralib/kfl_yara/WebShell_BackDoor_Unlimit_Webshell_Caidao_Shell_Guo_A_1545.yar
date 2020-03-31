rule WebShell_BackDoor_Unlimit_Webshell_Caidao_Shell_Guo_A_1545 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file guo.php"
    family = "Webshell"
    hacker = "None"
    hash = "9e69a8f499c660ee0b4796af14dc08f0"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Caidao.Shell.Guo.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php ($www= $_POST['ice'])!"
    $s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww"
  condition:
    1 of them
}