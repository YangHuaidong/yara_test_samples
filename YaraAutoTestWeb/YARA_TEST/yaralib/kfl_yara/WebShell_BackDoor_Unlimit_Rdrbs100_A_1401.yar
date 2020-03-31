rule WebShell_BackDoor_Unlimit_Rdrbs100_A_1401 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file rdrbs100.exe"
    family = "Rdrbs100"
    hacker = "None"
    hash = "7c752bcd6da796d80a6830c61a632bff"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Rdrbs100.A"
    threattype = "BackDoor"
  strings:
    $s3 = "Server address must be IP in A.B.C.D format."
    $s4 = " mapped ports in the list. Currently "
  condition:
    all of them
}