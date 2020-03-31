rule WebShell_BackDoor_Unlimit_Webshell_Dx_Dx_A_1568 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Dx.php"
    family = "Webshell"
    hacker = "None"
    hash = "9cfe372d49fe8bf2fac8e1c534153d9b"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Dx.Dx.A"
    threattype = "BackDoor"
  strings:
    $s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
    $s9 = "class=linelisting><nobr>POST (php eval)</td><"
  condition:
    1 of them
}