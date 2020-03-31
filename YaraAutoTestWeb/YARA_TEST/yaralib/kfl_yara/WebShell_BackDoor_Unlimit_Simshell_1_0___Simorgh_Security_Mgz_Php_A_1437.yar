rule WebShell_BackDoor_Unlimit_Simshell_1_0___Simorgh_Security_Mgz_Php_A_1437 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
    family = "Simshell"
    hacker = "None"
    hash = "37cb1db26b1b0161a4bf678a6b4565bd"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Simshell.1.0...Simorgh.Security.Mgz.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Simorgh Security Magazine "
    $s1 = "Simshell.css"
    $s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], "
    $s3 = "www.simorgh-ev.com"
  condition:
    2 of them
}