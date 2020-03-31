rule WebShell_BackDoor_Unlimit_Webshell_Toolaspshell_A_1736 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file toolaspshell.php"
    family = "Webshell"
    hacker = "None"
    hash = "11d236b0d1c2da30828ffd2f393dd4c6a1022e3f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Toolaspshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef"
    $s12 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
    $s20 = "destino3 = folderItem.path & \"\\index.asp\"" fullword
  condition:
    2 of them
}