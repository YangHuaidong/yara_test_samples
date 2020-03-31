rule WebShell_BackDoor_Unlimit_Xssshell_A_1774 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file xssshell.asp"
    family = "Xssshell"
    hacker = "None"
    hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Xssshell.A"
    threattype = "BackDoor"
  strings:
    $s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"
  condition:
    all of them
}