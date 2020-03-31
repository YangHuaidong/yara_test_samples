rule WebShell_BackDoor_Unlimit_Csh_Php_Php_A_1217 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file csh.php.php.txt"
    family = "Csh"
    hacker = "None"
    hash = "194a9d3f3eac8bc56d9a7c55c016af96"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Csh.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = ".::[c0derz]::. web-shell"
    $s1 = "http://c0derz.org.ua"
    $s2 = "vint21h@c0derz.org.ua"
    $s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root"
  condition:
    1 of them
}