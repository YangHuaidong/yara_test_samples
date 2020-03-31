rule WebShell_BackDoor_Unlimit_Webshell_Shell_Phpspy_2005_Full_Phpspy_2005_Lite_Phpspy_2006_Arabicspy_Phpspy_Hkrkoz_A_1722 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files shell.php, phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, arabicspy.php, PHPSPY.php, hkrkoz.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "791708057d8b429d91357d38edf43cc0"
    hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
    hash2 = "42f211cec8032eb0881e87ebdb3d7224"
    hash3 = "40a1f840111996ff7200d18968e42cfe"
    hash4 = "e0202adff532b28ef1ba206cf95962f2"
    hash5 = "0712e3dc262b4e1f98ed25760b206836"
    hash6 = "802f5cae46d394b297482fd0c27cb2fc"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Shell.Phpspy.2005.Full.Phpspy.2005.Lite.Phpspy.2006.Arabicspy.Phpspy.Hkrkoz.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
    $s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d"
  condition:
    all of them
}