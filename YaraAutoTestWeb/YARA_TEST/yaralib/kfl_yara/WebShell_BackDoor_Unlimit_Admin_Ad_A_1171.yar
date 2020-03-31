rule WebShell_BackDoor_Unlimit_Admin_Ad_A_1171 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file admin-ad.asp"
    family = "Admin"
    hacker = "None"
    hash = "e6819b8f8ff2f1073f7d46a0b192f43b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Admin.Ad.A"
    threattype = "BackDoor"
  strings:
    $s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
    $s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"
  condition:
    all of them
}