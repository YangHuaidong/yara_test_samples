rule WebShell_BackDoor_Unlimit_Webshell_807_A_Css_Dm_He1P_Jspspy_Xxx_A_1486 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 807.jsp, a.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, style.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
    hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
    hash10 = "4a812678308475c64132a9b56254edbc"
    hash11 = "9626eef1a8b9b8d773a3b2af09306a10"
    hash12 = "344f9073576a066142b2023629539ebd"
    hash13 = "32dea47d9c13f9000c4c807561341bee"
    hash14 = "b9744f6876919c46a29ea05b1d95b1c3"
    hash15 = "6acc82544be056580c3a1caaa4999956"
    hash16 = "6aa32a6392840e161a018f3907a86968"
    hash17 = "349ec229e3f8eda0f9eb918c74a8bf4c"
    hash18 = "3ea688e3439a1f56b16694667938316d"
    hash19 = "ab77e4d1006259d7cbc15884416ca88c"
    hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
    hash20 = "71097537a91fac6b01f46f66ee2d7749"
    hash21 = "2434a7a07cb47ce25b41d30bc291cacc"
    hash22 = "7a4b090619ecce6f7bd838fe5c58554b"
    hash3 = "14e9688c86b454ed48171a9d4f48ace8"
    hash4 = "b330a6c2d49124ef0729539761d6ef0b"
    hash5 = "d71716df5042880ef84427acee8b121e"
    hash6 = "341298482cf90febebb8616426080d1d"
    hash7 = "29aebe333d6332f0ebc2258def94d57e"
    hash8 = "42654af68e5d4ea217e6ece5389eb302"
    hash9 = "88fc87e7c58249a398efd5ceae636073"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.807.A.Css.Dm.He1P.Jspspy.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var"
    $s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu"
    $s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i"
  condition:
    all of them
}