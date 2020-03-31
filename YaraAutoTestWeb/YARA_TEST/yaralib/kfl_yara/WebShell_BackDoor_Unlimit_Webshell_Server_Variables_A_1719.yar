rule WebShell_BackDoor_Unlimit_Webshell_Server_Variables_A_1719 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Server Variables.asp"
    family = "Webshell"
    hacker = "None"
    hash = "47fb8a647e441488b30f92b4d39003d7"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Server.Variables.A"
    threattype = "BackDoor"
  strings:
    $s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
    $s9 = "Variable Name</B></font></p>" fullword
  condition:
    all of them
}