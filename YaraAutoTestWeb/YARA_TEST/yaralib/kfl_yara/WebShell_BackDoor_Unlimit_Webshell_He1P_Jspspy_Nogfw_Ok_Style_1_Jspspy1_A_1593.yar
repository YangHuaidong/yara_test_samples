rule WebShell_BackDoor_Unlimit_Webshell_He1P_Jspspy_Nogfw_Ok_Style_1_Jspspy1_A_1593 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files he1p.jsp, JspSpy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, JspSpy.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "b330a6c2d49124ef0729539761d6ef0b"
    hash1 = "d71716df5042880ef84427acee8b121e"
    hash2 = "344f9073576a066142b2023629539ebd"
    hash3 = "32dea47d9c13f9000c4c807561341bee"
    hash4 = "b9744f6876919c46a29ea05b1d95b1c3"
    hash5 = "3ea688e3439a1f56b16694667938316d"
    hash6 = "2434a7a07cb47ce25b41d30bc291cacc"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.He1P.Jspspy.Nogfw.Ok.Style.1.Jspspy1.A"
    threattype = "BackDoor"
  strings:
    $s0 = "\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+" fullword
    $s4 = "out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?"
    $s7 = "String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";" fullword
    $s8 = "\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>"
  condition:
    2 of them
}