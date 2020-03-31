rule WebShell_BackDoor_Unlimit_Webshell_Php_Cmd_A_1658 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmd.php"
    family = "Webshell"
    hacker = "None"
    hash = "c38ae5ba61fd84f6bbbab98d89d8a346"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Cmd.A"
    threattype = "BackDoor"
  strings:
    $s0 = "if($_GET['cmd']) {" fullword
    $s1 = "// cmd.php = Command Execution" fullword
    $s7 = "  system($_GET['cmd']);" fullword
  condition:
    all of them
}