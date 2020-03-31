rule WebShell_BackDoor_Unlimit_Php_Backdoor_Connect_Pl_Php_A_1370 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file PHP Backdoor Connect.pl.php.txt"
    family = "Php"
    hacker = "None"
    hash = "57fcd9560dac244aeaf95fd606621900"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Backdoor.Connect.Pl.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "LorD of IRAN HACKERS SABOTAGE"
    $s1 = "LorD-C0d3r-NT"
    $s2 = "echo --==Userinfo==-- ;"
  condition:
    1 of them
}