rule WebShell_BackDoor_Unlimit_Webshell_Cmd_Asp_5_1_A_1554 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmd-asp-5.1.asp"
    family = "Webshell"
    hacker = "None"
    hash = "8baa99666bf3734cbdfdd10088e0cd9f"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Cmd.Asp.5.1.A"
    threattype = "BackDoor"
  strings:
    $s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
  condition:
    all of them
}