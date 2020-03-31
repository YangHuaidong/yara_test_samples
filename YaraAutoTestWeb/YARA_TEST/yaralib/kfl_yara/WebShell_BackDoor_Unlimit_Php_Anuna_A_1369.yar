rule WebShell_BackDoor_Unlimit_Php_Anuna_A_1369 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/07/18"
    description = "Catches a PHP Trojan"
    family = "Php"
    hacker = "None"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Anuna.A"
    threattype = "BackDoor"
  strings:
    $a = /<\?php \$[a-z]+ = '/
    $b = /\$[a-z]+=explode\(chr\(\([0-9]+[-+][0-9]+\)\)/
    $c = /\$[a-z]+=\([0-9]+[-+][0-9]+\)/
    $d = /if \(!function_exists\('[a-z]+'\)\)/
  condition:
    all of them
}