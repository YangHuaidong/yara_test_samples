rule WebShell_BackDoor_Unlimit_Webshell_Phpshell_2_1_Config_A_1695 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file config.php"
    family = "Webshell"
    hacker = "None"
    hash = "bd83144a649c5cc21ac41b505a36a8f3"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpshell.2.1.Config.A"
    threattype = "BackDoor"
  strings:
    $s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword
  condition:
    all of them
}