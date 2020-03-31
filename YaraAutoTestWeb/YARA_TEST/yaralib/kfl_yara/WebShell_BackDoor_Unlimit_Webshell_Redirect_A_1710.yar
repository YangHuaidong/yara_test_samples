rule WebShell_BackDoor_Unlimit_Webshell_Redirect_A_1710 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file redirect.asp"
    family = "Webshell"
    hacker = "None"
    hash = "97da83c6e3efbba98df270cc70beb8f8"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Redirect.A"
    threattype = "BackDoor"
  strings:
    $s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "
  condition:
    all of them
}