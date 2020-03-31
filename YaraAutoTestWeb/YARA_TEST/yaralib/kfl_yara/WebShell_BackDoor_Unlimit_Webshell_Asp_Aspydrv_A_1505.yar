rule WebShell_BackDoor_Unlimit_Webshell_Asp_Aspydrv_A_1505 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file aspydrv.asp"
    family = "Webshell"
    hacker = "None"
    hash = "de0a58f7d1e200d0b2c801a94ebce330"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Aspydrv.A"
    threattype = "BackDoor"
  strings:
    $s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi"
  condition:
    all of them
}