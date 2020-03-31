rule WebShell_BackDoor_Unlimit_Shelltools_G0T_Root_Fport_A_1426 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Fport.exe"
    family = "Shelltools"
    hacker = "None"
    hash = "dbb75488aa2fa22ba6950aead1ef30d5"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Shelltools.G0T.Root.Fport.A"
    threattype = "BackDoor"
  strings:
    $s4 = "Copyright 2000 by Foundstone, Inc."
    $s5 = "You must have administrator privileges to run fport - exiting..."
  condition:
    all of them
}