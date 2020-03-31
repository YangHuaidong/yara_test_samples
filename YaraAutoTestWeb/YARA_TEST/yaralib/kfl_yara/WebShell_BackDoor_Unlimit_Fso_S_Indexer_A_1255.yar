rule WebShell_BackDoor_Unlimit_Fso_S_Indexer_A_1255 {
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
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Indexer.A"
    threattype = "BackDoor"
  strings:
    $s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"
  condition:
    all of them
}