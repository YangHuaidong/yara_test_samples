rule WebShell_BackDoor_Unlimit_Webshell_Php_Ghost_A_1664 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ghost.php"
    family = "Webshell"
    hacker = "None"
    hash = "38dc8383da0859dca82cf0c943dbf16d"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Ghost.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'"
    $s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***"
    $s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword
  condition:
    all of them
}