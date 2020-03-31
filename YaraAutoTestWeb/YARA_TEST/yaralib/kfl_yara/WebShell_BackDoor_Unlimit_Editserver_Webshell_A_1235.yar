rule WebShell_BackDoor_Unlimit_Editserver_Webshell_A_1235 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file EditServer.exe"
    family = "Editserver"
    hacker = "None"
    hash = "f945de25e0eba3bdaf1455b3a62b9832"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Editserver.Webshell.A"
    threattype = "BackDoor"
  strings:
    $s2 = "Server %s Have Been Configured"
    $s5 = "The Server Password Exceeds 32 Characters"
    $s8 = "9--Set Procecess Name To Inject DLL"
  condition:
    all of them
}