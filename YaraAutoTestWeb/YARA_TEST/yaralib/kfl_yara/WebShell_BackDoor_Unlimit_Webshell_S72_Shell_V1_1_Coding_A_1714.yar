rule WebShell_BackDoor_Unlimit_Webshell_S72_Shell_V1_1_Coding_A_1714 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file s72 Shell v1.1 Coding.php"
    family = "Webshell"
    hacker = "None"
    hash = "c2e8346a5515c81797af36e7e4a3828e"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.S72.Shell.V1.1.Coding.A"
    threattype = "BackDoor"
  strings:
    $s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "
  condition:
    all of them
}