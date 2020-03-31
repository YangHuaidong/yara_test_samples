rule WebShell_BackDoor_Unlimit_Webshell_A_1490 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file webshell.php"
    family = "Webshell"
    hacker = "None"
    hash = "f2f8c02921f29368234bfb4d4622ad19"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "RhViRYOzz"
    $s1 = "d\\O!jWW"
    $s2 = "bc!jWW"
    $s3 = "0W[&{l"
    $s4 = "[INhQ@\\"
  condition:
    all of them
}