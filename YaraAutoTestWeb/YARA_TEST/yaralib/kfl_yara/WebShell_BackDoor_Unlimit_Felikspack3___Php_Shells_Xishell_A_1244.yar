rule WebShell_BackDoor_Unlimit_Felikspack3___Php_Shells_Xishell_A_1244 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file xIShell.php"
    family = "Felikspack3"
    hacker = "None"
    hash = "997c8437c0621b4b753a546a53a88674"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Felikspack3...Php.Shells.Xishell.A"
    threattype = "BackDoor"
  strings:
    $s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"
  condition:
    all of them
}