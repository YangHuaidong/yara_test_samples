rule WebShell_BackDoor_Unlimit_Pwreveal_A_1394 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file pwreveal.exe"
    family = "Pwreveal"
    hacker = "None"
    hash = "b4e8447826a45b76ca45ba151a97ad50"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Pwreveal.A"
    threattype = "BackDoor"
  strings:
    $s0 = "*<Blank - no es"
    $s3 = "JDiamondCS "
    $s8 = "sword set> [Leith=0 bytes]"
    $s9 = "ION\\System\\Floating-"
  condition:
    all of them
}