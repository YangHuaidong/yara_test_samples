rule WebShell_BackDoor_Unlimit_Php_Cloaked_Webshell_Superfetchexec_A_1373 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
    family = "Php"
    hacker = "None"
    judge = "unknown"
    reference = "http://goo.gl/xFvioC"
    score = 50
    threatname = "WebShell[BackDoor]/Unlimit.Php.Cloaked.Webshell.Superfetchexec.A"
    threattype = "BackDoor"
  strings:
    $s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"
  condition:
    $s0
}