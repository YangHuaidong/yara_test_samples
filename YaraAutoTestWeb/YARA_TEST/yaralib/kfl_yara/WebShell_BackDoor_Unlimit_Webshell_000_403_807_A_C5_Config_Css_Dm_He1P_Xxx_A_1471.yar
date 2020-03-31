rule WebShell_BackDoor_Unlimit_Webshell_000_403_807_A_C5_Config_Css_Dm_He1P_Xxx_A_1471 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
    hash1 = "059058a27a7b0059e2c2f007ad4675ef"
    hash10 = "341298482cf90febebb8616426080d1d"
    hash11 = "29aebe333d6332f0ebc2258def94d57e"
    hash12 = "42654af68e5d4ea217e6ece5389eb302"
    hash13 = "88fc87e7c58249a398efd5ceae636073"
    hash14 = "4a812678308475c64132a9b56254edbc"
    hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
    hash16 = "e0354099bee243702eb11df8d0e046df"
    hash17 = "344f9073576a066142b2023629539ebd"
    hash18 = "32dea47d9c13f9000c4c807561341bee"
    hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
    hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
    hash20 = "655722eaa6c646437c8ae93daac46ae0"
    hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
    hash22 = "6acc82544be056580c3a1caaa4999956"
    hash23 = "6aa32a6392840e161a018f3907a86968"
    hash24 = "591ca89a25f06cf01e4345f98a22845c"
    hash25 = "349ec229e3f8eda0f9eb918c74a8bf4c"
    hash26 = "3ea688e3439a1f56b16694667938316d"
    hash27 = "ab77e4d1006259d7cbc15884416ca88c"
    hash28 = "71097537a91fac6b01f46f66ee2d7749"
    hash29 = "2434a7a07cb47ce25b41d30bc291cacc"
    hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
    hash30 = "7a4b090619ecce6f7bd838fe5c58554b"
    hash4 = "8b457934da3821ba58b06a113e0d53d9"
    hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
    hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
    hash7 = "14e9688c86b454ed48171a9d4f48ace8"
    hash8 = "b330a6c2d49124ef0729539761d6ef0b"
    hash9 = "d71716df5042880ef84427acee8b121e"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.000.403.807.A.C5.Config.Css.Dm.He1P.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s3 = "String savePath = request.getParameter(\"savepath\");" fullword
    $s4 = "URL downUrl = new URL(downFileUrl);" fullword
    $s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))" fullword
    $s6 = "String downFileUrl = request.getParameter(\"url\");" fullword
    $s7 = "FileInputStream fInput = new FileInputStream(f);" fullword
    $s8 = "URLConnection conn = downUrl.openConnection();" fullword
    $s9 = "sis = request.getInputStream();" fullword
  condition:
    4 of them
}