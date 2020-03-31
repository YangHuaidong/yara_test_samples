rule WebShell_BackDoor_Unlimit_Webshell_Php_Redcod_A_1670 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file redcod.php"
    family = "Webshell"
    hacker = "None"
    hash = "5c1c8120d82f46ff9d813fbe3354bac5"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Redcod.A"
    threattype = "BackDoor"
  strings:
    $s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
    $s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
  condition:
    all of them
}