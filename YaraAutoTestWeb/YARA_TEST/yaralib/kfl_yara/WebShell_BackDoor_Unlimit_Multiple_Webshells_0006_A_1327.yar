rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0006_A_1327 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, ctt_sh.php.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
    hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
    hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
    hash3 = "671cad517edd254352fe7e0c7c981c39"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0006.A"
    threattype = "BackDoor"
    was = "_c99shell_v1_0_php_php_c99php_SsEs_php_php_ctt_sh_php_php"
  strings:
    $s0 = "\"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze\""
    $s2 = "\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\""
    $s4 = "\"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo\""
  condition:
    2 of them
}