rule WebShell_BackDoor_Unlimit_Webshell_Jspshell_A_1626 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file jspShell.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "0d5b5a17552254be6c1c8f1eb3a5fdc1"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jspshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on"
    $s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;"
  condition:
    all of them
}