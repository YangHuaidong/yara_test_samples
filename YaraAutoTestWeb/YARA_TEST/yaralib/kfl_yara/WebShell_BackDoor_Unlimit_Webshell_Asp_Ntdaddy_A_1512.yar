rule WebShell_BackDoor_Unlimit_Webshell_Asp_Ntdaddy_A_1512 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ntdaddy.asp"
    family = "Webshell"
    hacker = "None"
    hash = "c5e6baa5d140f73b4e16a6cfde671c68"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Ntdaddy.A"
    threattype = "BackDoor"
  strings:
    $s9 = "if  FP  =  \"RefreshFolder\"  or  "
    $s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "
  condition:
    1 of them
}