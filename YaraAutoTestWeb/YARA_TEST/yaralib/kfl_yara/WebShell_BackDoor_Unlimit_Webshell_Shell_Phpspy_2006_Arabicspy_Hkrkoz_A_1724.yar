rule WebShell_BackDoor_Unlimit_Webshell_Shell_Phpspy_2006_Arabicspy_Hkrkoz_A_1724 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "791708057d8b429d91357d38edf43cc0"
    hash1 = "40a1f840111996ff7200d18968e42cfe"
    hash2 = "e0202adff532b28ef1ba206cf95962f2"
    hash3 = "802f5cae46d394b297482fd0c27cb2fc"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Shell.Phpspy.2006.Arabicspy.Hkrkoz.A"
    threattype = "BackDoor"
  strings:
    $s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
  condition:
    all of them
}