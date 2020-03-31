rule WebShell_BackDoor_Unlimit_Asmodeus_V0_1_Pl_A_1178 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Asmodeus v0.1.pl.txt"
    family = "Asmodeus"
    hacker = "None"
    hash = "0978b672db0657103c79505df69cb4bb"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Asmodeus.V0.1.Pl.A"
    threattype = "BackDoor"
  strings:
    $s0 = "[url=http://www.governmentsecurity.org"
    $s1 = "perl asmodeus.pl client 6666 127.0.0.1"
    $s2 = "print \"Asmodeus Perl Remote Shell"
    $s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword
  condition:
    2 of them
}