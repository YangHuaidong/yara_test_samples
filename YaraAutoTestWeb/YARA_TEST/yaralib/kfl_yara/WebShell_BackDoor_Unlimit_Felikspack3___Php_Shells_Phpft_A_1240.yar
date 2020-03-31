rule WebShell_BackDoor_Unlimit_Felikspack3___Php_Shells_Phpft_A_1240 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file phpft.php"
    family = "Felikspack3"
    hacker = "None"
    hash = "60ef80175fcc6a879ca57c54226646b1"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Felikspack3...Php.Shells.Phpft.A"
    threattype = "BackDoor"
  strings:
    $s6 = "PHP Files Thief"
    $s11 = "http://www.4ngel.net"
  condition:
    all of them
}