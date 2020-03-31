rule WebShell_BackDoor_Unlimit_Hytop2006_Rar_Folder_2006X_A_1291 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2006X.exe"
    family = "Hytop2006"
    hacker = "None"
    hash = "cf3ee0d869dd36e775dfcaa788db8e4b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop2006.Rar.Folder.2006X.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<input name=\"password\" type=\"password\" id=\"password\""
    $s6 = "name=\"theAction\" type=\"text\" id=\"theAction\""
  condition:
    all of them
}