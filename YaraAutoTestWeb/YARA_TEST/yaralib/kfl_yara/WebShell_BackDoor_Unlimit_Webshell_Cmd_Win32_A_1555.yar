rule WebShell_BackDoor_Unlimit_Webshell_Cmd_Win32_A_1555 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmd_win32.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "cc4d4d6cc9a25984aa9a7583c7def174"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Cmd.Win32.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam"
    $s1 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
  condition:
    2 of them
}