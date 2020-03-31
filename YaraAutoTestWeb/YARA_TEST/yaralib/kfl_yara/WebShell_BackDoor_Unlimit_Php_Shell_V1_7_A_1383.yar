rule WebShell_BackDoor_Unlimit_Php_Shell_V1_7_A_1383 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
    family = "Php"
    hacker = "None"
    hash = "b5978501c7112584532b4ca6fb77cba5"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Shell.V1.7.A"
    threattype = "BackDoor"
  strings:
    $s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]"
  condition:
    all of them
}