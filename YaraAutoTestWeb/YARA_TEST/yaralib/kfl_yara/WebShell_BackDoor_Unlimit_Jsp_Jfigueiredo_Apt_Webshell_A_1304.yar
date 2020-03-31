rule WebShell_BackDoor_Unlimit_Jsp_Jfigueiredo_Apt_Webshell_A_1304 {
  meta:
    author = "Spider"
    comment = "None"
    date = "12.10.2014"
    description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
    family = "Jsp"
    hacker = "None"
    judge = "unknown"
    reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"
    score = 60
    threatname = "WebShell[BackDoor]/Unlimit.Jsp.Jfigueiredo.Apt.Webshell.A"
    threattype = "BackDoor"
  strings:
    $a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
    $a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
  condition:
    all of them
}