rule WebShell_BackDoor_Unlimit_Connectback2_Pl_A_1215 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file connectback2.pl.txt"
    family = "Connectback2"
    hacker = "None"
    hash = "473b7d226ea6ebaacc24504bd740822e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Connectback2.Pl.A"
    threattype = "BackDoor"
  strings:
    $s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   "
    $s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel"
    $s2 = "ConnectBack Backdoor"
  condition:
    1 of them
}