rule WebShell_BackDoor_Unlimit_Webshell_Asp_1D_A_1501 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 1d.asp"
    family = "Webshell"
    hacker = "None"
    hash = "fad7504ca8a55d4453e552621f81563c"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.1D.A"
    threattype = "BackDoor"
  strings:
    $s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
  condition:
    all of them
}