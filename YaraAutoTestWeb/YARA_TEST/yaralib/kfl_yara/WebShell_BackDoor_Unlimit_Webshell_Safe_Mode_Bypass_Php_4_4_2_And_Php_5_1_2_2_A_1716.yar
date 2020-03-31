rule WebShell_BackDoor_Unlimit_Webshell_Safe_Mode_Bypass_Php_4_4_2_And_Php_5_1_2_2_A_1716 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
    family = "Webshell"
    hacker = "None"
    hash = "8fdd4e0e87c044177e9e1c97084eb5b18e2f1c25"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Safe.Mode.Bypass.Php.4.4.2.And.Php.5.1.2.2.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
    $s3 = "xb5@hotmail.com</FONT></CENTER></B>\");" fullword
    $s4 = "$v = @ini_get(\"open_basedir\");" fullword
    $s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
  condition:
    2 of them
}