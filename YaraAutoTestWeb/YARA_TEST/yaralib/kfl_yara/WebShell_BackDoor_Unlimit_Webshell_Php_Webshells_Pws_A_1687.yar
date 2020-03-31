rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Pws_A_1687 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file pws.php"
    family = "Webshell"
    hacker = "None"
    hash = "7a405f1c179a84ff8ac09a42177a2bcd8a1a481b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Pws.A"
    threattype = "BackDoor"
  strings:
    $s6 = "if ($_POST['cmd']){" fullword
    $s7 = "$cmd = $_POST['cmd'];" fullword
    $s10 = "echo \"FILE UPLOADED TO $dez\";" fullword
    $s11 = "if (file_exists($uploaded)) {" fullword
    $s12 = "copy($uploaded, $dez);" fullword
    $s17 = "passthru($cmd);" fullword
  condition:
    4 of them
}