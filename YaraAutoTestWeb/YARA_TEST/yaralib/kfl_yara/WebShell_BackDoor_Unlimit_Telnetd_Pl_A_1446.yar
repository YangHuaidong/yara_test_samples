rule WebShell_BackDoor_Unlimit_Telnetd_Pl_A_1446 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file telnetd.pl.txt"
    family = "Telnetd"
    hacker = "None"
    hash = "5f61136afd17eb025109304bd8d6d414"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Telnetd.Pl.A"
    threattype = "BackDoor"
  strings:
    $s0 = "0ldW0lf" fullword
    $s1 = "However you are lucky :P"
    $s2 = "I'm FuCKeD"
    $s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#"
    $s4 = "atrix@irc.brasnet.org"
  condition:
    1 of them
}