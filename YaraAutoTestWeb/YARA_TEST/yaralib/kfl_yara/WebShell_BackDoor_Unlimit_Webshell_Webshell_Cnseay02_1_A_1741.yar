rule WebShell_BackDoor_Unlimit_Webshell_Webshell_Cnseay02_1_A_1741 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file webshell-cnseay02-1.php"
    family = "Webshell"
    hacker = "None"
    hash = "95fc76081a42c4f26912826cb1bd24b1"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshell.Cnseay02.1.A"
    threattype = "BackDoor"
  strings:
    $s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU"
  condition:
    all of them
}