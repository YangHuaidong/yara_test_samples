rule WebShell_BackDoor_Unlimit_Webshell_Minupload_A_1635 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file minupload.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "ec905a1395d176c27f388d202375bdf9"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Minupload.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
    $s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"
  condition:
    all of them
}