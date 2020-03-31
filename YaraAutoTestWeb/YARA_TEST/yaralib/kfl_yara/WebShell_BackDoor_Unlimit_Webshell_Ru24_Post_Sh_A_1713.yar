rule WebShell_BackDoor_Unlimit_Webshell_Ru24_Post_Sh_A_1713 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file ru24_post_sh.php"
    family = "Webshell"
    hacker = "None"
    hash = "d2c18766a1cd4dda928c12ff7b519578ccec0769"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Ru24.Post.Sh.A"
    threattype = "BackDoor"
  strings:
    $s1 = "http://www.ru24-team.net" fullword
    $s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
    $s6 = "Ru24PostWebShell"
    $s7 = "Writed by DreAmeRz" fullword
    $s9 = "$function=passthru; // system, exec, cmd" fullword
  condition:
    1 of them
}