rule WebShell_BackDoor_Unlimit_Webshell_Networkfilemanagerphp_A_1643 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file NetworkFileManagerPHP.php"
    family = "Webshell"
    hacker = "None"
    hash = "acdbba993a5a4186fd864c5e4ea0ba4f"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Networkfilemanagerphp.A"
    threattype = "BackDoor"
  strings:
    $s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
  condition:
    all of them
}