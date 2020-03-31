rule WebShell_BackDoor_Unlimit_R57Shell_Php_Php_A_1399 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file r57shell.php.php.txt"
    family = "R57Shell"
    hacker = "None"
    hash = "d28445de424594a5f14d0fe2a7c4e94f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.R57Shell.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "r57shell" fullword
    $s1 = " else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx "
    $s2 = "RusH security team"
    $s3 = "'ru_text12' => 'back-connect"
  condition:
    1 of them
}