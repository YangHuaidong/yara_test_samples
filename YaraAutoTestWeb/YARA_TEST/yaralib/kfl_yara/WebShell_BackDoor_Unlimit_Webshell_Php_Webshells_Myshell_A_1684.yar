rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Myshell_A_1684 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file myshell.php"
    family = "Webshell"
    hacker = "None"
    hash = "5bd52749872d1083e7be076a5e65ffcde210e524"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Myshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu"
    $s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
    $s15 = "<title>$MyShellVersion - Access Denied</title>" fullword
    $s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT"
  condition:
    1 of them
}