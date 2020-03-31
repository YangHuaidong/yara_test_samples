rule WebShell_BackDoor_Unlimit_Webshell_Jsp_K81_A_1616 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file k81.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "41efc5c71b6885add9c1d516371bd6af"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.K81.A"
    threattype = "BackDoor"
  strings:
    $s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
    $s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword
  condition:
    1 of them
}