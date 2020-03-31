rule WebShell_BackDoor_Unlimit_Webshell_B374K_Mini_Shell_Php_Php_A_1523 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
    family = "Webshell"
    hacker = "None"
    hash = "afb88635fbdd9ebe86b650cc220d3012a8c35143"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.B374K.Mini.Shell.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "@error_reporting(0);" fullword
    $s2 = "@eval(gzinflate(base64_decode($code)));" fullword
    $s3 = "@set_time_limit(0); " fullword
  condition:
    all of them
}