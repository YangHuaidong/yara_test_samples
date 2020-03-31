rule WebShell_BackDoor_Unlimit_Zxshell2_0_Rar_Folder_Zxshell_A_1782 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ZXshell.exe"
    family = "Zxshell2"
    hacker = "None"
    hash = "246ce44502d2f6002d720d350e26c288"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Zxshell2.0.Rar.Folder.Zxshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "WPreviewPagesn"
    $s1 = "DA!OLUTELY N"
  condition:
    all of them
}