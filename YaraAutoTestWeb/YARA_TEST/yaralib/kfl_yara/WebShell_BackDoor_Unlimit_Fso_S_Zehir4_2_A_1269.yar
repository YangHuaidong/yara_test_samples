rule WebShell_BackDoor_Unlimit_Fso_S_Zehir4_2_A_1269 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file zehir4.asp"
    family = "Fso"
    hacker = "None"
    hash = "5b496a61363d304532bcf52ee21f5d55"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Zehir4.2.A"
    threattype = "BackDoor"
  strings:
    $s4 = "\"Program Files\\Serv-u\\Serv"
  condition:
    all of them
}