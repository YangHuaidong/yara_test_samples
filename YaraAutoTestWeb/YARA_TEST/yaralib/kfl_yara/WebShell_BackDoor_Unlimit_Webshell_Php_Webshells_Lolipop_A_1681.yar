rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Lolipop_A_1681 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file lolipop.php"
    family = "Webshell"
    hacker = "None"
    hash = "86f23baabb90c93465e6851e40104ded5a5164cb"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Lolipop.A"
    threattype = "BackDoor"
  strings:
    $s3 = "$commander = $_POST['commander']; " fullword
    $s9 = "$sourcego = $_POST['sourcego']; " fullword
    $s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
  condition:
    all of them
}