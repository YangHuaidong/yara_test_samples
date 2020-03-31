rule WebShell_BackDoor_Unlimit_Webshell_B374K_Php_A_1524 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file b374k.php.php"
    family = "Webshell"
    hacker = "None"
    hash = "04c99efd187cf29dc4e5603c51be44170987bce2"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.B374K.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
    $s6 = "// password (default is: b374k)"
    $s8 = "//******************************************************************************"
    $s9 = "// b374k 2.2" fullword
    $s10 = "eval(\"?>\".gzinflate(base64_decode("
  condition:
    3 of them
}