rule WebShell_BackDoor_Unlimit_Hytop2006_Rar_Folder_2006Z_A_1293 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2006Z.exe"
    family = "Hytop2006"
    hacker = "None"
    hash = "fd1b6129abd4ab177fed135e3b665488"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop2006.Rar.Folder.2006Z.A"
    threattype = "BackDoor"
  strings:
    $s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
    $s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
  condition:
    all of them
}