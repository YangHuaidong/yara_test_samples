rule WebShell_BackDoor_Unlimit_Zxshell2_0_Rar_Folder_Zxrecv_A_1781 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file zxrecv.exe"
    family = "Zxshell2"
    hacker = "None"
    hash = "5d3d12a39f41d51341ef4cb7ce69d30f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Zxshell2.0.Rar.Folder.Zxrecv.A"
    threattype = "BackDoor"
  strings:
    $s0 = "RyFlushBuff"
    $s1 = "teToWideChar^FiYP"
    $s2 = "mdesc+8F D"
    $s3 = "\\von76std"
    $s4 = "5pur+virtul"
    $s5 = "- Kablto io"
    $s6 = "ac#f{lowi8a"
  condition:
    all of them
}