rule WebShell_BackDoor_Unlimit_Shelltools_G0T_Root_Resolve_A_1428 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file resolve.exe"
    family = "Shelltools"
    hacker = "None"
    hash = "69bf9aa296238610a0e05f99b5540297"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Shelltools.G0T.Root.Resolve.A"
    threattype = "BackDoor"
  strings:
    $s0 = "3^n6B(Ed3"
    $s1 = "^uldn'Vt(x"
    $s2 = "\\= uPKfp"
    $s3 = "'r.axV<ad"
    $s4 = "p,modoi$=sr("
    $s5 = "DiamondC8S t"
    $s6 = "`lQ9fX<ZvJW"
  condition:
    all of them
}