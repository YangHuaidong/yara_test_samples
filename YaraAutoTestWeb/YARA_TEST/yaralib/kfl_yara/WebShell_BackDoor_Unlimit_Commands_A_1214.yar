rule WebShell_BackDoor_Unlimit_Commands_A_1214 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file commands.asp"
    family = "Commands"
    hacker = "None"
    hash = "174486fe844cb388e2ae3494ac2d1ec2"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Commands.A"
    threattype = "BackDoor"
  strings:
    $s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID"
    $s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F"
  condition:
    all of them
}