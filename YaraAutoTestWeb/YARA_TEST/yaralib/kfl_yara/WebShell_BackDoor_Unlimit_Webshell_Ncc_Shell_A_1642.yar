rule WebShell_BackDoor_Unlimit_Webshell_Ncc_Shell_A_1642 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file NCC-Shell.php"
    family = "Webshell"
    hacker = "None"
    hash = "64d4495875a809b2730bd93bec2e33902ea80a53"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Ncc.Shell.A"
    threattype = "BackDoor"
  strings:
    $s0 = " if (isset($_FILES['probe']) and ! $_FILES['probe']['error']) {" fullword
    $s1 = "<b>--Coded by Silver" fullword
    $s2 = "<title>Upload - Shell/Datei</title>" fullword
    $s8 = "<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b><"
    $s14 = "~|_Team .:National Cracker Crew:._|~<br>" fullword
    $s18 = "printf(\"Sie ist %u Bytes gro" fullword
  condition:
    3 of them
}