rule WebShell_BackDoor_Unlimit_Fso_S_Remview_2_A_1264 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file remview.php"
    family = "Fso"
    hacker = "None"
    hash = "b4a09911a5b23e00b55abe546ded691c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Remview.2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<xmp>$out</"
    $s1 = ".mm(\"Eval PHP code\")."
  condition:
    all of them
}