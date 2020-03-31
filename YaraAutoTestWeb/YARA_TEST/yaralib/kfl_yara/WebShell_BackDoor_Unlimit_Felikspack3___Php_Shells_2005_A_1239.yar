rule WebShell_BackDoor_Unlimit_Felikspack3___Php_Shells_2005_A_1239 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2005.asp"
    family = "Felikspack3"
    hacker = "None"
    hash = "97f2552c2fafc0b2eb467ee29cc803c8"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Felikspack3...Php.Shells.2005.A"
    threattype = "BackDoor"
  strings:
    $s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp"
    $s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">"
  condition:
    all of them
}