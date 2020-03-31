rule WebShell_BackDoor_Unlimit_Webshell_Php_Include_W_Shell_A_1666 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file php-include-w-shell.php"
    family = "Webshell"
    hacker = "None"
    hash = "1a7f4868691410830ad954360950e37c582b0292"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Include.W.Shell.A"
    threattype = "BackDoor"
  strings:
    $s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
    $s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
    $s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword
  condition:
    1 of them
}