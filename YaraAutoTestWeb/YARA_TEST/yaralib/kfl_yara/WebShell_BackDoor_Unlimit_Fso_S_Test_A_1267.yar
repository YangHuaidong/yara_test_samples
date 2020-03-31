rule WebShell_BackDoor_Unlimit_Fso_S_Test_A_1267 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file test.php"
    family = "Fso"
    hacker = "None"
    hash = "82cf7b48da8286e644f575b039a99c26"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Test.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$yazi = \"test\" . \"\\r\\n\";"
    $s2 = "fwrite ($fp, \"$yazi\");"
  condition:
    all of them
}