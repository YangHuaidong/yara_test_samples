rule WebShell_BackDoor_Unlimit_Webshell_Webshell_Cnseay_X_A_1740 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file webshell-cnseay-x.php"
    family = "Webshell"
    hacker = "None"
    hash = "a0f9f7f5cd405a514a7f3be329f380e5"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshell.Cnseay.X.A"
    threattype = "BackDoor"
  strings:
    $s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_"
  condition:
    all of them
}