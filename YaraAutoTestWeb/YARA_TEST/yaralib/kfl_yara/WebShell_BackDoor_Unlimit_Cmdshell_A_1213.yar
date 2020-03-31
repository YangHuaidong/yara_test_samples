rule WebShell_BackDoor_Unlimit_Cmdshell_A_1213 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file cmdShell.asp"
    family = "Cmdshell"
    hacker = "None"
    hash = "8a9fef43209b5d2d4b81dfbb45182036"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Cmdshell.A"
    threattype = "BackDoor"
  strings:
    $s1 = "if cmdPath=\"wscriptShell\" then"
  condition:
    all of them
}