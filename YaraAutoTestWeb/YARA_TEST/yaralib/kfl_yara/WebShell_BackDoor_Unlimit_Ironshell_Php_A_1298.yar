rule WebShell_BackDoor_Unlimit_Ironshell_Php_A_1298 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file ironshell.php.txt"
    family = "Ironshell"
    hacker = "None"
    hash = "8bfa2eeb8a3ff6afc619258e39fded56"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Ironshell.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "www.ironwarez.info"
    $s1 = "$cookiename = \"wieeeee\";"
    $s2 = "~ Shell I"
    $s3 = "www.rootshell-team.info"
    $s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);"
  condition:
    1 of them
}