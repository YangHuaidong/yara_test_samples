rule WebShell_BackDoor_Unlimit_Vanquish_2_A_1456 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file vanquish.exe"
    family = "Vanquish"
    hacker = "None"
    hash = "2dcb9055785a2ee01567f52b5a62b071"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Vanquish.2.A"
    threattype = "BackDoor"
  strings:
    $s2 = "Vanquish - DLL injection failed:"
  condition:
    all of them
}