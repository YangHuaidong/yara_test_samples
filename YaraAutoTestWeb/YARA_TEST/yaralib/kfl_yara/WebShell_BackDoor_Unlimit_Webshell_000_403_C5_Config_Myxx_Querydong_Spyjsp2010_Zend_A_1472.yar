rule WebShell_BackDoor_Unlimit_Webshell_000_403_C5_Config_Myxx_Querydong_Spyjsp2010_Zend_A_1472 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
    hash1 = "059058a27a7b0059e2c2f007ad4675ef"
    hash2 = "8b457934da3821ba58b06a113e0d53d9"
    hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
    hash4 = "e0354099bee243702eb11df8d0e046df"
    hash5 = "90a5ba0c94199269ba33a58bc6a4ad99"
    hash6 = "655722eaa6c646437c8ae93daac46ae0"
    hash7 = "591ca89a25f06cf01e4345f98a22845c"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.000.403.C5.Config.Myxx.Querydong.Spyjsp2010.Zend.A"
    threattype = "BackDoor"
  strings:
    $s0 = "return new Double(format.format(value)).doubleValue();" fullword
    $s5 = "File tempF = new File(savePath);" fullword
    $s9 = "if (tempF.isDirectory()) {" fullword
  condition:
    2 of them
}