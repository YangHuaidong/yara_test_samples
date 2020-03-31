rule WebShell_BackDoor_Unlimit_Webshell_Cgitelnet_A_1552 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file cgitelnet.php"
    family = "Webshell"
    hacker = "None"
    hash = "72e5f0e4cd438e47b6454de297267770a36cbeb3"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Cgitelnet.A"
    threattype = "BackDoor"
  strings:
    $s9 = "# Author Homepage: http://www.rohitab.com/" fullword
    $s10 = "elsif($Action eq \"command\") # user wants to run a command" fullword
    $s18 = "# in a command line on Windows NT." fullword
    $s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword
  condition:
    2 of them
}