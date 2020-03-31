rule WebShell_BackDoor_Unlimit_Sincap_Php_Php_A_1438 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Sincap.php.php.txt"
    family = "Sincap"
    hacker = "None"
    hash = "b68b90ff6012a103e57d141ed38a7ee9"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Sincap.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');"
    $s2 = "$tampon4=$tampon3-1"
    $s3 = "@aventgrup.net"
  condition:
    2 of them
}