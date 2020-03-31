rule WebShell_BackDoor_Unlimit_W3D_Php_Php_A_1458 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file w3d.php.php.txt"
    family = "W3D"
    hacker = "None"
    hash = "987f66b29bfb209a0b4f097f84f57c3b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.W3D.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "W3D Shell"
    $s1 = "By: Warpboy"
    $s2 = "No Query Executed"
  condition:
    2 of them
}