rule WebShell_BackDoor_Unlimit_Nstview_Nstview_A_1361 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file nstview.php"
    family = "Nstview"
    hacker = "None"
    hash = "3871888a0c1ac4270104918231029a56"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Nstview.Nstview.A"
    threattype = "BackDoor"
  strings:
    $s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");"
  condition:
    all of them
}