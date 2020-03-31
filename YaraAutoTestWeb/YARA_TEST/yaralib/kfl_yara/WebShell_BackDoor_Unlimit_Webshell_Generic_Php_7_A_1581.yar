rule WebShell_BackDoor_Unlimit_Webshell_Generic_Php_7_A_1581 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files Mysql interface v1.0.php, MySQL Web Interface Version 0.8.php, Mysql_interface_v1.0.php, MySQL_Web_Interface_Version_0.8.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "de98f890790756f226f597489844eb3e53a867a9"
    hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
    hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
    hash3 = "715f17e286416724e90113feab914c707a26d456"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Generic.Php.7.A"
    threattype = "BackDoor"
  strings:
    $s0 = "header(\"Content-disposition: filename=$filename.sql\");" fullword
    $s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword
    $s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword
    $s4 = "if( $action == \"dumpTable\" )" fullword
  condition:
    2 of them
}