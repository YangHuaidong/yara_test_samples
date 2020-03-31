rule WebShell_BackDoor_Unlimit_Webshell_Asp_Rader_A_1513 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Rader.asp"
    family = "Webshell"
    hacker = "None"
    hash = "ad1a362e0a24c4475335e3e891a01731"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Rader.A"
    threattype = "BackDoor"
  strings:
    $s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
    $s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "
  condition:
    all of them
}