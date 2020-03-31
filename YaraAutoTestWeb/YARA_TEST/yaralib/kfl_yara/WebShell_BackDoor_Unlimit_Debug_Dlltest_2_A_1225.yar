rule WebShell_BackDoor_Unlimit_Debug_Dlltest_2_A_1225 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file dllTest.dll"
    family = "Debug"
    hacker = "None"
    hash = "1b9e518aaa62b15079ff6edb412b21e9"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Debug.Dlltest.2.A"
    threattype = "BackDoor"
  strings:
    $s4 = "\\Debug\\dllTest.pdb"
    $s5 = "--list the services in the computer"
  condition:
    all of them
}