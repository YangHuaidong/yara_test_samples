rule WebShell_BackDoor_Unlimit_Dive_Shell_1_0___Emperor_Hacking_Team_Php_A_1227 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Dive Shell 1.0 - Emperor Hacking Team.php.txt"
    family = "Dive"
    hacker = "None"
    hash = "1b5102bdc41a7bc439eea8f0010310a5"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Dive.Shell.1.0...Emperor.Hacking.Team.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Emperor Hacking TEAM"
    $s1 = "Simshell" fullword
    $s2 = "ereg('^[[:blank:]]*cd[[:blank:]]"
    $s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST"
  condition:
    2 of them
}