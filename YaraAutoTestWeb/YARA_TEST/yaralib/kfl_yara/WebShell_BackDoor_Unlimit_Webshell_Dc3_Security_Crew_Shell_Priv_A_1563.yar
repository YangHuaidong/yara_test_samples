rule WebShell_BackDoor_Unlimit_Webshell_Dc3_Security_Crew_Shell_Priv_A_1563 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
    family = "Webshell"
    hacker = "None"
    hash = "1b2a4a7174ca170b4e3a8cdf4814c92695134c8a"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Dc3.Security.Crew.Shell.Priv.A"
    threattype = "BackDoor"
  strings:
    $s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
    $s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));" fullword
    $s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));" fullword
    $s15 = "search_file($_POST['search'],urldecode($_POST['dir']));" fullword
    $s16 = "echo base64_decode($images[$_GET['pic']]);" fullword
    $s20 = "if (isset($_GET['rename_all'])) {" fullword
  condition:
    3 of them
}