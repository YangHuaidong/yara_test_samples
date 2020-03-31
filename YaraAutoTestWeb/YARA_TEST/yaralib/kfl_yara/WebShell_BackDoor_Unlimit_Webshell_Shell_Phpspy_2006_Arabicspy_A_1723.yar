rule WebShell_BackDoor_Unlimit_Webshell_Shell_Phpspy_2006_Arabicspy_A_1723 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "791708057d8b429d91357d38edf43cc0"
    hash1 = "40a1f840111996ff7200d18968e42cfe"
    hash2 = "e0202adff532b28ef1ba206cf95962f2"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Shell.Phpspy.2006.Arabicspy.A"
    threattype = "BackDoor"
  strings:
    $s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype"
    $s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P"
  condition:
    all of them
}