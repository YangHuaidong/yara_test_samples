rule WebShell_BackDoor_Unlimit_Webshell_Generic_Php_5_A_1579 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files ex0shell.php, megabor.php, GRP WebShell 2.0 release build 2018 (C)2006,Great.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "64461ad8d8f23ea078201a31d747157f701a4e00"
    hash1 = "3df1afbcfa718da6fc8af27554834ff6d1a86562"
    hash2 = "ad86ef7f24f75081318146edc788e5466722a629"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Generic.Php.5.A"
    threattype = "BackDoor"
  strings:
    $s0 = "(($perms & 0x0400) ? 'S' : '-'));" fullword
    $s10 = "} elseif (($perms & 0x8000) == 0x8000) {" fullword
    $s11 = "if (($perms & 0xC000) == 0xC000) {" fullword
    $s12 = "$info .= (($perms & 0x0008) ?" fullword
    $s16 = "// Block special" fullword
    $s18 = "$info = 's';" fullword
  condition:
    all of them
}