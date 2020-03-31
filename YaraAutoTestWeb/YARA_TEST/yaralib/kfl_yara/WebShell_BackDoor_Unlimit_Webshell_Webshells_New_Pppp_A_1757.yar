rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Pppp_A_1757 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file pppp.php"
    family = "Webshell"
    hacker = "None"
    hash = "cf01cb6e09ee594545693c5d327bdd50"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Pppp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Mail: chinese@hackermail.com" fullword
    $s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo "
    $s6 = "Site: http://blog.weili.me" fullword
  condition:
    1 of them
}