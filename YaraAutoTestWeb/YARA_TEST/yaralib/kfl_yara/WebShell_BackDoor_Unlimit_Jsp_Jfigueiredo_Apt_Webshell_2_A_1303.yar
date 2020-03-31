rule WebShell_BackDoor_Unlimit_Jsp_Jfigueiredo_Apt_Webshell_2_A_1303 {
  meta:
    author = "Spider"
    comment = "None"
    date = "12.10.2014"
    description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
    family = "Jsp"
    hacker = "None"
    judge = "unknown"
    reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"
    score = 60
    threatname = "WebShell[BackDoor]/Unlimit.Jsp.Jfigueiredo.Apt.Webshell.2.A"
    threattype = "BackDoor"
  strings:
    $a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
    $a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
    $s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
    $s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
  condition:
    all of ($a*) or all of ($s*)
}