rule WebShell_BackDoor_Unlimit_Webshell_Inderxer_A_1596 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Inderxer.asp"
    family = "Webshell"
    hacker = "None"
    hash = "9ea82afb8c7070817d4cdf686abe0300"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Inderxer.A"
    threattype = "BackDoor"
  strings:
    $s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
  condition:
    all of them
}