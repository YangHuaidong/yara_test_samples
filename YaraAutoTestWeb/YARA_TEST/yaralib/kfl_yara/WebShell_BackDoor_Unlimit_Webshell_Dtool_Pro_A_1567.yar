rule WebShell_BackDoor_Unlimit_Webshell_Dtool_Pro_A_1567 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file DTool Pro.php"
    family = "Webshell"
    hacker = "None"
    hash = "e2ee1c7ba7b05994f65710b7bbf935954f2c3353"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Dtool.Pro.A"
    threattype = "BackDoor"
  strings:
    $s1 = "function PHPget(){inclVar(); if(confirm(\"O PHPget agora oferece uma lista pront"
    $s2 = "<font size=3>by r3v3ng4ns - revengans@gmail.com </font>" fullword
    $s3 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDig"
    $s11 = "//Turns the 'ls' command more usefull, showing it as it looks in the shell" fullword
    $s13 = "if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";" fullword
    $s14 = "//To keep the changes in the url, when using the 'GET' way to send php variables" fullword
    $s16 = "function PHPf(){inclVar();var o=prompt(\"[ PHPfilEditor ] by r3v3ng4ns\\nDigite "
    $s18 = "if(empty($fu)) $fu = @$_GET['fu'];" fullword
  condition:
    3 of them
}