rule WebShell_BackDoor_Unlimit_Webshell_Generic_Php_3_A_1577 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files Antichat Shell v1.3.php, Antichat Shell. Modified by Go0o$E.php, Antichat Shell.php, fatal.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "d829e87b3ce34460088c7775a60bded64e530cd4"
    hash1 = "d710c95d9f18ec7c76d9349a28dd59c3605c02be"
    hash2 = "f044d44e559af22a1a7f9db72de1206f392b8976"
    hash3 = "41780a3e8c0dc3cbcaa7b4d3c066ae09fb74a289"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Generic.Php.3.A"
    threattype = "BackDoor"
  strings:
    $s0 = "header('Content-Length:'.filesize($file).'');" fullword
    $s4 = "<textarea name=\\\"command\\\" rows=\\\"5\\\" cols=\\\"150\\\">\".@$_POST['comma"
    $s7 = "if(filetype($dir . $file)==\"file\")$files[]=$file;" fullword
    $s14 = "elseif (($perms & 0x6000) == 0x6000) {$info = 'b';} " fullword
    $s20 = "$info .= (($perms & 0x0004) ? 'r' : '-');" fullword
  condition:
    all of them
}