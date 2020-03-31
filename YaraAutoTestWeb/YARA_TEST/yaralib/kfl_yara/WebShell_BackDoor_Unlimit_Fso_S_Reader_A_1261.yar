rule WebShell_BackDoor_Unlimit_Fso_S_Reader_A_1261 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file reader.asp"
    family = "Fso"
    hacker = "None"
    hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Reader.A"
    threattype = "BackDoor"
  strings:
    $s2 = "mailto:mailbomb@hotmail."
  condition:
    all of them
}