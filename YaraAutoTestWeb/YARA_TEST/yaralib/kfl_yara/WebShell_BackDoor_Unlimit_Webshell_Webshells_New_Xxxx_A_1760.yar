rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Xxxx_A_1760 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file xxxx.php"
    family = "Webshell"
    hacker = "None"
    hash = "5bcba70b2137375225d8eedcde2c0ebb"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Xxxx.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php eval($_POST[1]);?>  " fullword
  condition:
    all of them
}