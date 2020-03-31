rule WebShell_BackDoor_Unlimit_Webshell_Remexp_Asp_Php_A_1711 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
    family = "Webshell"
    hacker = "None"
    hash = "d9919dcf94a70d5180650de8b81669fa1c10c5a2"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Remexp.Asp.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
    $s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
    $s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
    $s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
    $s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
  condition:
    all of them
}