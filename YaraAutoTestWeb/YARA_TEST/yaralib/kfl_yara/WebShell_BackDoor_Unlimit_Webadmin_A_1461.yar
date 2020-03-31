rule WebShell_BackDoor_Unlimit_Webadmin_A_1461 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file webadmin.php"
    family = "Webadmin"
    hacker = "None"
    hash = "3a90de401b30e5b590362ba2dde30937"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webadmin.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu"
  condition:
    all of them
}