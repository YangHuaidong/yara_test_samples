rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0018_A_1339 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files webadmin.php.php.txt, iMHaPFtp.php.php.txt, Private-i3lue.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "b268e6fa3bf3fe496cffb4ea574ec4c7"
    hash1 = "12911b73bc6a5d313b494102abcf5c57"
    hash2 = "13f5c7a035ecce5f9f380967cf9d4e92"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0018.A"
    threattype = "BackDoor"
    was = "_webadmin_php_php_iMHaPFtp_php_php_Private_i3lue_php"
  strings:
    $s0 = "return $type . $owner . $group . $other;" fullword
    $s1 = "$owner  = ($mode & 00400) ? 'r' : '-';" fullword
  condition:
    all of them
}