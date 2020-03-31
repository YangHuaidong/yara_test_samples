rule WebShell_BackDoor_Unlimit_Telnet_Pl_A_1445 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file telnet.pl.txt"
    family = "Telnet"
    hacker = "None"
    hash = "dd9dba14383064e219e29396e242c1ec"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Telnet.Pl.A"
    threattype = "BackDoor"
  strings:
    $s0 = "W A R N I N G: Private Server"
    $s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   "
  condition:
    all of them
}