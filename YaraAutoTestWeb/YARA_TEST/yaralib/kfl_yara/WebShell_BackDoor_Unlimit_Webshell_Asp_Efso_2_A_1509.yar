rule WebShell_BackDoor_Unlimit_Webshell_Asp_Efso_2_A_1509 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file EFSO_2.asp"
    family = "Webshell"
    hacker = "None"
    hash = "a341270f9ebd01320a7490c12cb2e64c"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Efso.2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"
  condition:
    all of them
}