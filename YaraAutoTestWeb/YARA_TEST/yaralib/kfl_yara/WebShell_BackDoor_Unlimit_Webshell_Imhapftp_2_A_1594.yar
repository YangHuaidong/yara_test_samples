rule WebShell_BackDoor_Unlimit_Webshell_Imhapftp_2_A_1594 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file iMHaPFtp.php"
    family = "Webshell"
    hacker = "None"
    hash = "12911b73bc6a5d313b494102abcf5c57"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Imhapftp.2.A"
    threattype = "BackDoor"
  strings:
    $s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
    $s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"
  condition:
    1 of them
}