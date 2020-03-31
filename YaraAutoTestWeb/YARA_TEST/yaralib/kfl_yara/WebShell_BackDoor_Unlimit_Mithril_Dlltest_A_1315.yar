rule WebShell_BackDoor_Unlimit_Mithril_Dlltest_A_1315 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file dllTest.dll"
    family = "Mithril"
    hacker = "None"
    hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Mithril.Dlltest.A"
    threattype = "BackDoor"
  strings:
    $s0 = "please enter the password:"
    $s3 = "\\dllTest.pdb"
  condition:
    all of them
}