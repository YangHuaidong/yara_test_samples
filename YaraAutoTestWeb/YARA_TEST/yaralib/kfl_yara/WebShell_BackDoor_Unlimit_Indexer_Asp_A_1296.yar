rule WebShell_BackDoor_Unlimit_Indexer_Asp_A_1296 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file indexer.asp.txt"
    family = "Indexer"
    hacker = "None"
    hash = "9ea82afb8c7070817d4cdf686abe0300"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Indexer.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
    $s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit"
  condition:
    1 of them
}