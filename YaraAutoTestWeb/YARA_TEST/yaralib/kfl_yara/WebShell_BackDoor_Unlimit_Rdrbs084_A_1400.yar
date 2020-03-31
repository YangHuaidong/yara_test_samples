rule WebShell_BackDoor_Unlimit_Rdrbs084_A_1400 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file rdrbs084.exe"
    family = "Rdrbs084"
    hacker = "None"
    hash = "ed30327b255816bdd7590bf891aa0020"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Rdrbs084.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Create mapped port. You have to specify domain when using HTTP type."
    $s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"
  condition:
    all of them
}