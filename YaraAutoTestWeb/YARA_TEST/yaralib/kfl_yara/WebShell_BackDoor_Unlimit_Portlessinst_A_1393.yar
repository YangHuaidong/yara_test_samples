rule WebShell_BackDoor_Unlimit_Portlessinst_A_1393 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file portlessinst.exe"
    family = "Portlessinst"
    hacker = "None"
    hash = "74213856fc61475443a91cd84e2a6c2f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Portlessinst.A"
    threattype = "BackDoor"
  strings:
    $s2 = "Fail To Open Registry"
    $s3 = "f<-WLEggDr\""
    $s6 = "oMemoryCreateP"
  condition:
    all of them
}