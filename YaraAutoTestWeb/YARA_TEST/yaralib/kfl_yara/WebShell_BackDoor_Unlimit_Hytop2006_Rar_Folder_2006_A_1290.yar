rule WebShell_BackDoor_Unlimit_Hytop2006_Rar_Folder_2006_A_1290 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2006.asp"
    family = "Hytop2006"
    hacker = "None"
    hash = "c19d6f4e069188f19b08fa94d44bc283"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop2006.Rar.Folder.2006.A"
    threattype = "BackDoor"
  strings:
    $s6 = "strBackDoor = strBackDoor "
  condition:
    all of them
}