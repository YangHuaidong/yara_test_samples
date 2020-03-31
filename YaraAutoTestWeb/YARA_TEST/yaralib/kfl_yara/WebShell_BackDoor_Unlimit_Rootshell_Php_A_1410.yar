rule WebShell_BackDoor_Unlimit_Rootshell_Php_A_1410 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file rootshell.php.txt"
    family = "Rootshell"
    hacker = "None"
    hash = "265f3319075536030e59ba2f9ef3eac6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Rootshell.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "shells.dl.am"
    $s1 = "This server has been infected by $owner"
    $s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>"
    $s4 = "Could not write to file! (Maybe you didn't enter any text?)"
  condition:
    2 of them
}