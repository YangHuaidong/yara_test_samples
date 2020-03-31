rule WebShell_BackDoor_Unlimit_Felikspack3___Php_Shells_Usr_A_1243 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file usr.php"
    family = "Felikspack3"
    hacker = "None"
    hash = "ade3357520325af50c9098dc8a21a024"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Felikspack3...Php.Shells.Usr.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"
  condition:
    all of them
}