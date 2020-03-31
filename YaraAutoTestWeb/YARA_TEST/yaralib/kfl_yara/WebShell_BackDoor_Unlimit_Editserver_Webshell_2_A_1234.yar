rule WebShell_BackDoor_Unlimit_Editserver_Webshell_2_A_1234 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file EditServer.exe"
    family = "Editserver"
    hacker = "None"
    hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Editserver.Webshell.2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "@HOTMAIL.COM"
    $s1 = "Press Any Ke"
    $s3 = "glish MenuZ"
  condition:
    all of them
}