rule WebShell_BackDoor_Unlimit_Php_Include_W_Shell_Php_A_1376 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file php-include-w-shell.php.txt"
    family = "Php"
    hacker = "None"
    hash = "4e913f159e33867be729631a7ca46850"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Include.W.Shell.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd"
    $s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB"
  condition:
    1 of them
}