rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Cw_A_1679 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file cw.php"
    family = "Webshell"
    hacker = "None"
    hash = "e65e0670ef6edf0a3581be6fe5ddeeffd22014bf"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Cw.A"
    threattype = "BackDoor"
  strings:
    $s1 = "// Dump Database [pacucci.com]" fullword
    $s2 = "$dump = \"-- Database: \".$_POST['db'] .\" \\n\";" fullword
    $s7 = "$aids = passthru(\"perl cbs.pl \".$_POST['connhost'].\" \".$_POST['connport']);" fullword
    $s8 = "<b>IP:</b> <u>\" . $_SERVER['REMOTE_ADDR'] .\"</u> - Server IP:</b> <a href='htt"
    $s14 = "$dump .= \"-- Cyber-Warrior.Org\\n\";" fullword
    $s20 = "if(isset($_POST['doedit']) && $_POST['editfile'] != $dir)" fullword
  condition:
    3 of them
}