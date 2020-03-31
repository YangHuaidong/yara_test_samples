rule WebShell_BackDoor_Unlimit_Hytop_Devpack_Server_A_1288 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file server.asp"
    family = "Hytop"
    hacker = "None"
    hash = "1d38526a215df13c7373da4635541b43"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop.Devpack.Server.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<!-- PageServer Below -->"
  condition:
    all of them
}