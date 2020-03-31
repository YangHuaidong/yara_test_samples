rule WebShell_BackDoor_Unlimit_Webshell_Bypass_Iisuser_P_A_1531 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file bypass-iisuser-p.asp"
    family = "Webshell"
    hacker = "None"
    hash = "924d294400a64fa888a79316fb3ccd90"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Bypass.Iisuser.P.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"
  condition:
    all of them
}