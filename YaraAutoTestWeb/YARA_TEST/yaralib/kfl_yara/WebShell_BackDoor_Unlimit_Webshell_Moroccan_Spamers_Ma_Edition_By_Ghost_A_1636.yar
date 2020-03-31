rule WebShell_BackDoor_Unlimit_Webshell_Moroccan_Spamers_Ma_Edition_By_Ghost_A_1636 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Moroccan Spamers Ma-EditioN By GhOsT.php"
    family = "Webshell"
    hacker = "None"
    hash = "31e5473920a2cc445d246bc5820037d8fe383201"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Moroccan.Spamers.Ma.Edition.By.Ghost.A"
    threattype = "BackDoor"
  strings:
    $s4 = "$content = chunk_split(base64_encode($content)); " fullword
    $s12 = "print \"Sending mail to $to....... \"; " fullword
    $s16 = "if (!$from && !$subject && !$message && !$emaillist){ " fullword
  condition:
    all of them
}