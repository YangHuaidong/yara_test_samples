rule WebShell_BackDoor_Unlimit_Webshell_Dive_Shell_1_0_Emperor_Hacking_Team_Xxx_A_1565 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files Dive Shell 1.0 - Emperor Hacking Team.php, phpshell.php, SimShell 1.0 - Simorgh Security MGZ.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "1b5102bdc41a7bc439eea8f0010310a5"
    hash1 = "f8a6d5306fb37414c5c772315a27832f"
    hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Dive.Shell.1.0.Emperor.Hacking.Team.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals"
    $s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
  condition:
    all of them
}