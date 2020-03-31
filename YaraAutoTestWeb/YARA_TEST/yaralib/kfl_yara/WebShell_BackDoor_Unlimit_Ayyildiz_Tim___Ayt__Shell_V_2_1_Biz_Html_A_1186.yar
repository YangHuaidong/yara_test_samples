rule WebShell_BackDoor_Unlimit_Ayyildiz_Tim___Ayt__Shell_V_2_1_Biz_Html_A_1186 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
    family = "Ayyildiz"
    hacker = "None"
    hash = "8a8c8bb153bd1ee097559041f2e5cf0a"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Ayyildiz.Tim...Ayt..Shell.V.2.1.Biz.Html.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Ayyildiz"
    $s1 = "TouCh By iJOo"
    $s2 = "First we check if there has been asked for a working directory"
    $s3 = "http://ayyildiz.org/images/whosonline2.gif"
  condition:
    2 of them
}