rule WebShell_BackDoor_Unlimit_Moroccan_Spamers_Ma_Edition_By_Ghost_Php_A_1319 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
    family = "Moroccan"
    hacker = "None"
    hash = "d1b7b311a7ffffebf51437d7cd97dc65"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Moroccan.Spamers.Ma.Edition.By.Ghost.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = ";$sd98=\"john.barker446@gmail.com\""
    $s1 = "print \"Sending mail to $to....... \";"
    $s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei"
  condition:
    1 of them
}