rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Readme_A_1688 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file README.md"
    family = "Webshell"
    hacker = "None"
    hash = "ef2c567b4782c994db48de0168deb29c812f7204"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Readme.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
    $s1 = "php-webshells" fullword
  condition:
    all of them
}