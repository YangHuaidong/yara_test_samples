rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Con2_A_1746 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file con2.asp"
    family = "Webshell"
    hacker = "None"
    hash = "d3584159ab299d546bd77c9654932ae3"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Con2.A"
    threattype = "BackDoor"
  strings:
    $s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e"
    $s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n"
  condition:
    1 of them
}