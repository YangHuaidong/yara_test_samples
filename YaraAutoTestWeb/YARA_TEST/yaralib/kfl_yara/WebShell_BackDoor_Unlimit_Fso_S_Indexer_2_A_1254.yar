rule WebShell_BackDoor_Unlimit_Fso_S_Indexer_2_A_1254 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file indexer.asp"
    family = "Fso"
    hacker = "None"
    hash = "135fc50f85228691b401848caef3be9e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Indexer.2.A"
    threattype = "BackDoor"
  strings:
    $s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"
  condition:
    all of them
}