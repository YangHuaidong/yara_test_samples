rule WebShell_BackDoor_Unlimit_Webshell_807_Dm_Jspspyjdk5_M_Cofigrue_A_1487 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
    hash1 = "14e9688c86b454ed48171a9d4f48ace8"
    hash2 = "341298482cf90febebb8616426080d1d"
    hash3 = "88fc87e7c58249a398efd5ceae636073"
    hash4 = "349ec229e3f8eda0f9eb918c74a8bf4c"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.807.Dm.Jspspyjdk5.M.Cofigrue.A"
    threattype = "BackDoor"
  strings:
    $s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
    $s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword
  condition:
    1 of them
}