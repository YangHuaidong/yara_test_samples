rule WebShell_BackDoor_Unlimit_Cmd_Asp_5_1_Asp_A_1210 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file cmd-asp-5.1.asp.txt"
    family = "Cmd"
    hacker = "None"
    hash = "8baa99666bf3734cbdfdd10088e0cd9f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Cmd.Asp.5.1.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
    $s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
  condition:
    1 of them
}