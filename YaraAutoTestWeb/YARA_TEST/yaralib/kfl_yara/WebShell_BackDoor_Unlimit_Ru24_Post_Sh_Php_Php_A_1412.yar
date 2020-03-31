rule WebShell_BackDoor_Unlimit_Ru24_Post_Sh_Php_Php_A_1412 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file ru24_post_sh.php.php.txt"
    family = "Ru24"
    hacker = "None"
    hash = "5b334d494564393f419af745dc1eeec7"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Ru24.Post.Sh.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
    $s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
    $s4 = "Writed by DreAmeRz" fullword
  condition:
    1 of them
}