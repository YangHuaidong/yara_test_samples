rule WebShell_BackDoor_Unlimit_Webshell_Php_Dodo_Zip_A_1660 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file zip.php"
    family = "Webshell"
    hacker = "None"
    hash = "b7800364374077ce8864796240162ad5"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Dodo.Zip.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x"
    $s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
  condition:
    all of them
}