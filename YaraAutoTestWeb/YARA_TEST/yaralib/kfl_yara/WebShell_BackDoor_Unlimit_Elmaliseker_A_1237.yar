rule WebShell_BackDoor_Unlimit_Elmaliseker_A_1237 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file elmaliseker.asp"
    family = "Elmaliseker"
    hacker = "None"
    hash = "ccf48af0c8c09bbd038e610a49c9862e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Elmaliseker.A"
    threattype = "BackDoor"
  strings:
    $s0 = "javascript:Command('Download'"
    $s5 = "zombie_array=array("
  condition:
    all of them
}