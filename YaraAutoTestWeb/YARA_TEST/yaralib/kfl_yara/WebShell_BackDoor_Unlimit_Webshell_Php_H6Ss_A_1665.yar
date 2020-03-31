rule WebShell_BackDoor_Unlimit_Webshell_Php_H6Ss_A_1665 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file h6ss.php"
    family = "Webshell"
    hacker = "None"
    hash = "272dde9a4a7265d6c139287560328cd5"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.H6Ss.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php eval(gzuncompress(base64_decode(\""
  condition:
    all of them
}