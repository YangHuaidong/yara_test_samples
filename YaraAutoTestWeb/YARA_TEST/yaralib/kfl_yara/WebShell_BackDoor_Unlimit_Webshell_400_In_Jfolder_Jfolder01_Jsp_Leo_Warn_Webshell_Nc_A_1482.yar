rule WebShell_BackDoor_Unlimit_Webshell_400_In_Jfolder_Jfolder01_Jsp_Leo_Warn_Webshell_Nc_A_1482 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "36331f2c81bad763528d0ae00edf55be"
    hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
    hash2 = "8979594423b68489024447474d113894"
    hash3 = "ec482fc969d182e5440521c913bab9bd"
    hash4 = "f98d2b33cd777e160d1489afed96de39"
    hash5 = "4b4c12b3002fad88ca6346a873855209"
    hash6 = "e9a5280f77537e23da2545306f6a19ad"
    hash7 = "598eef7544935cf2139d1eada4375bb5"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.400.In.Jfolder.Jfolder01.Jsp.Leo.Warn.Webshell.Nc.A"
    threattype = "BackDoor"
  strings:
    $s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");" fullword
    $s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword
    $s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword
    $s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword
  condition:
    2 of them
}