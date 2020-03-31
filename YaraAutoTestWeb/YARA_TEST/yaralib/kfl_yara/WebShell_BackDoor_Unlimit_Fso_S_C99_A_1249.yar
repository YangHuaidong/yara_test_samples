rule WebShell_BackDoor_Unlimit_Fso_S_C99_A_1249 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file c99.php"
    family = "Fso"
    hacker = "None"
    hash = "5f9ba02eb081bba2b2434c603af454d0"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.C99.A"
    threattype = "BackDoor"
  strings:
    $s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"
  condition:
    all of them
}