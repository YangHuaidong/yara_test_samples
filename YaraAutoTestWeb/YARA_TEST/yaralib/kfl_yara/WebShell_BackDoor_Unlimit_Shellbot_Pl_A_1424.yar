rule WebShell_BackDoor_Unlimit_Shellbot_Pl_A_1424 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file shellbot.pl.txt"
    family = "Shellbot"
    hacker = "None"
    hash = "b2a883bc3c03a35cfd020dd2ace4bab8"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Shellbot.Pl.A"
    threattype = "BackDoor"
  strings:
    $s0 = "ShellBOT"
    $s1 = "PacktsGr0up"
    $s2 = "CoRpOrAtIoN"
    $s3 = "# Servidor de irc que vai ser usado "
    $s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"
  condition:
    2 of them
}