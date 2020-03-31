rule WebShell_BackDoor_Unlimit_Webshell_000_403_C5_Querydong_Spyjsp2010_T00Ls_A_1474 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
    hash1 = "059058a27a7b0059e2c2f007ad4675ef"
    hash2 = "8b457934da3821ba58b06a113e0d53d9"
    hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
    hash4 = "655722eaa6c646437c8ae93daac46ae0"
    hash5 = "9c94637f76e68487fa33f7b0030dd932"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.000.403.C5.Querydong.Spyjsp2010.T00Ls.A"
    threattype = "BackDoor"
  strings:
    $s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')"
    $s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\""
  condition:
    all of them
}