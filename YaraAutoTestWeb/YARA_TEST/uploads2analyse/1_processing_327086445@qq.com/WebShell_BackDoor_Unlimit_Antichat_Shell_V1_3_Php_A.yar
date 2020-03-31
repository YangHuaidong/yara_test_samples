rule WebShell_BackDoor_Unlimit_Antichat_Shell_V1_3_Php_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Antichat Shell v1.3.php.txt"
    family = "Antichat"
    hacker = "None"
    hash = "40d0abceba125868be7f3f990f031521"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Antichat.Shell.V1.3.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Antichat"
    $s1 = "Can't open file, permission denide"
    $s2 = "$ra44"
  condition:
    2 of them
}