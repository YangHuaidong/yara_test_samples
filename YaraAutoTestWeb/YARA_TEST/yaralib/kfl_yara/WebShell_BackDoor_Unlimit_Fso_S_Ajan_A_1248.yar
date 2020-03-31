rule WebShell_BackDoor_Unlimit_Fso_S_Ajan_A_1248 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ajan.asp"
    family = "Fso"
    hacker = "None"
    hash = "22194f8c44524f80254e1b5aec67b03e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Ajan.A"
    threattype = "BackDoor"
  strings:
    $s4 = "entrika.write \"BinaryStream.SaveToFile"
  condition:
    all of them
}