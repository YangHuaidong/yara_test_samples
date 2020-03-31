rule WebShell_BackDoor_Unlimit_Webshell_Asp_Zehir_A_1518 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file zehir.asp"
    family = "Webshell"
    hacker = "None"
    hash = "0061d800aee63ccaf41d2d62ec15985d"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Zehir.A"
    threattype = "BackDoor"
  strings:
    $s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"
  condition:
    all of them
}