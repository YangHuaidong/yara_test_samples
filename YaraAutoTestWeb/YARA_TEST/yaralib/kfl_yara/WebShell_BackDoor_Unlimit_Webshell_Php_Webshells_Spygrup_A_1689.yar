rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Spygrup_A_1689 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file spygrup.php"
    family = "Webshell"
    hacker = "None"
    hash = "12f9105332f5dc5d6360a26706cd79afa07fe004"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Spygrup.A"
    threattype = "BackDoor"
  strings:
    $s2 = "kingdefacer@msn.com</FONT></CENTER></B>\");" fullword
    $s6 = "if($_POST['root']) $root = $_POST['root'];" fullword
    $s12 = "\".htmlspecialchars($file).\" Bu Dosya zaten Goruntuleniyor<kingdefacer@msn.com>" fullword
    $s18 = "By KingDefacer From Spygrup.org>" fullword
  condition:
    3 of them
}