rule WebShell_BackDoor_Unlimit_Webshell__Ajax_Php_Command_Shell_Ajax_Php_Command_Shell_Soldierofallah_A_1462 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files Ajax_PHP Command Shell.php, Ajax_PHP_Command_Shell.php, soldierofallah.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "fa11deaee821ca3de7ad1caafa2a585ee1bc8d82"
    hash1 = "c0a4ba3e834fb63e0a220a43caaf55c654f97429"
    hash2 = "16fa789b20409c1f2ffec74484a30d0491904064"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell..Ajax.Php.Command.Shell.Ajax.Php.Command.Shell.Soldierofallah.A"
    threattype = "BackDoor"
  strings:
    $s1 = "'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\"," fullword
    $s2 = "'Running processes' => \"runcommand('ps -aux','GET')\"," fullword
    $s3 = "$dt = $_POST['filecontent'];" fullword
    $s4 = "'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\"," fullword
    $s6 = "print \"Sorry, none of the command functions works.\";" fullword
    $s11 = "document.cmdform.command.value='';" fullword
    $s12 = "elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST"
  condition:
    3 of them
}