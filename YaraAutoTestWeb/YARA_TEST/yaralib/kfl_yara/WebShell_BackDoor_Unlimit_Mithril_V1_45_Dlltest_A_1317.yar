rule WebShell_BackDoor_Unlimit_Mithril_V1_45_Dlltest_A_1317 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file dllTest.dll"
    family = "Mithril"
    hacker = "None"
    hash = "1b9e518aaa62b15079ff6edb412b21e9"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Mithril.V1.45.Dlltest.A"
    threattype = "BackDoor"
  strings:
    $s3 = "syspath"
    $s4 = "\\Mithril"
    $s5 = "--list the services in the computer"
  condition:
    all of them
}