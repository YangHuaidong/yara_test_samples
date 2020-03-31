rule WebShell_BackDoor_Unlimit_Webshell_Safe0Ver_A_1718 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file safe0ver.php"
    family = "Webshell"
    hacker = "None"
    hash = "366639526d92bd38ff7218b8539ac0f154190eb8"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Safe0Ver.A"
    threattype = "BackDoor"
  strings:
    $s3 = "$scriptident = \"$scriptTitle By Evilc0der.com\";" fullword
    $s4 = "while (file_exists(\"$lastdir/newfile$i.txt\"))" fullword
    $s5 = "else { /* <!-- Then it must be a File... --> */" fullword
    $s7 = "$contents .= htmlentities( $line ) ;" fullword
    $s8 = "<br><p><br>Safe Mode ByPAss<p><form method=\"POST\">" fullword
    $s14 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
    $s20 = "/* <!-- End of Actions --> */" fullword
  condition:
    3 of them
}