rule WebShell_BackDoor_Unlimit_Down_Rar_Folder_Down_A_1229 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file down.asp"
    family = "Down"
    hacker = "None"
    hash = "db47d7a12b3584a2e340567178886e71"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Down.Rar.Folder.Down.A"
    threattype = "BackDoor"
  strings:
    $s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"
  condition:
    all of them
}