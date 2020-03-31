rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Lostdc_A_1682 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file lostDC.php"
    family = "Webshell"
    hacker = "None"
    hash = "d54fe07ea53a8929620c50e3a3f8fb69fdeb1cde"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Lostdc.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$info .= '[~]Server: ' .$_SERVER['HTTP_HOST'] .'<br />';" fullword
    $s4 = "header ( \"Content-Description: Download manager\" );" fullword
    $s5 = "print \"<center>[ Generation time: \".round(getTime()-startTime,4).\" second"
    $s9 = "if (mkdir($_POST['dir'], 0777) == false) {" fullword
    $s12 = "$ret = shellexec($command);" fullword
  condition:
    2 of them
}