rule WebShell_BackDoor_Unlimit_Zxshell2_0_Rar_Folder_Nc_A_1780 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file nc.exe"
    family = "Zxshell2"
    hacker = "None"
    hash = "2cd1bf15ae84c5f6917ddb128827ae8b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Zxshell2.0.Rar.Folder.Nc.A"
    threattype = "BackDoor"
  strings:
    $s0 = "WSOCK32.dll"
    $s1 = "?bSUNKNOWNV"
    $s7 = "p@gram Jm6h)"
    $s8 = "ser32.dllCONFP@"
  condition:
    all of them
}