rule WebShell_BackDoor_Unlimit_Dxshell_Php_Php_A_1232 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file DxShell.php.php.txt"
    family = "Dxshell"
    hacker = "None"
    hash = "33a2b31810178f4c2e71fbdeb4899244"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Dxshell.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
    $s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><"
  condition:
    1 of them
}