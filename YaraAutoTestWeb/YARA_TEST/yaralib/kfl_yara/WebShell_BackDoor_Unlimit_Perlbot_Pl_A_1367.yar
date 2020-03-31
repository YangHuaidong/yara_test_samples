rule WebShell_BackDoor_Unlimit_Perlbot_Pl_A_1367 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file perlbot.pl.txt"
    family = "Perlbot"
    hacker = "None"
    hash = "7e4deb9884ffffa5d82c22f8dc533a45"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Perlbot.Pl.A"
    threattype = "BackDoor"
  strings:
    $s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")"
    $s1 = "#Acesso a Shel - 1 ON 0 OFF"
  condition:
    1 of them
}