rule WebShell_BackDoor_Unlimit_Webshell_Phpspy_2005_Full_Phpspy_2005_Lite_Phpspy_2006_Phpspy_A_1698 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
    hash1 = "42f211cec8032eb0881e87ebdb3d7224"
    hash2 = "40a1f840111996ff7200d18968e42cfe"
    hash3 = "0712e3dc262b4e1f98ed25760b206836"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpspy.2005.Full.Phpspy.2005.Lite.Phpspy.2006.Phpspy.A"
    threattype = "BackDoor"
  strings:
    $s4 = "http://www.4ngel.net" fullword
    $s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
    $s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
    $s9 = "Codz by Angel" fullword
  condition:
    2 of them
}