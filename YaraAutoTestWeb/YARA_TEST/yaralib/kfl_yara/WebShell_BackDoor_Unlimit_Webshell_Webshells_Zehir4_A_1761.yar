rule WebShell_BackDoor_Unlimit_Webshell_Webshells_Zehir4_A_1761 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Github Archive - file zehir4"
    family = "Webshell"
    hacker = "None"
    hash = "788928ae87551f286d189e163e55410acbb90a64"
    judge = "unknown"
    reference = "None"
    score = 55
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.Zehir4.A"
    threattype = "BackDoor"
  strings:
    $s0 = "frames.byZehir.document.execCommand(command, false, option);" fullword
    $s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"
  condition:
    1 of them
}