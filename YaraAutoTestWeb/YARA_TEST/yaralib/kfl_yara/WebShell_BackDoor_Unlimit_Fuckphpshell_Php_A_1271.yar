rule WebShell_BackDoor_Unlimit_Fuckphpshell_Php_A_1271 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file fuckphpshell.php.txt"
    family = "Fuckphpshell"
    hacker = "None"
    hash = "554e50c1265bb0934fcc8247ec3b9052"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fuckphpshell.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$succ = \"Warning! "
    $s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!"
    $s2 = "\\*=-- MEMBERS AREA --=*/"
    $s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o"
  condition:
    2 of them
}