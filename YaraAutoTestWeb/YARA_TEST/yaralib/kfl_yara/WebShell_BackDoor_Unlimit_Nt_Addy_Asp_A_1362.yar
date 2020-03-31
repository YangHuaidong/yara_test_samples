rule WebShell_BackDoor_Unlimit_Nt_Addy_Asp_A_1362 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file NT Addy.asp.txt"
    family = "Nt"
    hacker = "None"
    hash = "2e0d1bae844c9a8e6e351297d77a1fec"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Nt.Addy.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
    $s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
    $s4 = "RAW D.O.S. COMMAND INTERFACE"
  condition:
    1 of them
}