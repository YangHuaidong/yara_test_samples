rule WebShell_BackDoor_Unlimit_Warfiles_Cmd_A_1459 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file cmd.jsp"
    family = "Warfiles"
    hacker = "None"
    hash = "3ae3d837e7b362de738cf7fad78eded0dccf601f"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Warfiles.Cmd.A"
    threattype = "BackDoor"
  strings:
    $s1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
    $s4 = "String disr = dis.readLine();" fullword ascii
  condition:
    filesize < 2KB and all of them
}