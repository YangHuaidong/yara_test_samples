rule WebShell_BackDoor_Unlimit_Webshell_Zacosmall_A_1766 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file zacosmall.php"
    family = "Webshell"
    hacker = "None"
    hash = "5295ee8dc2f5fd416be442548d68f7a6"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Zacosmall.A"
    threattype = "BackDoor"
  strings:
    $s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"
  condition:
    all of them
}