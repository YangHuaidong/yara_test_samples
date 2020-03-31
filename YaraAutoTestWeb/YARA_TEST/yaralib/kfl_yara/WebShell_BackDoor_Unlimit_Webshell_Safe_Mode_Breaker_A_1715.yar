rule WebShell_BackDoor_Unlimit_Webshell_Safe_Mode_Breaker_A_1715 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Safe mode breaker.php"
    family = "Webshell"
    hacker = "None"
    hash = "5bd07ccb1111950a5b47327946bfa194"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Safe.Mode.Breaker.A"
    threattype = "BackDoor"
  strings:
    $s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is("
    $s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."
  condition:
    1 of them
}