rule WebShell_BackDoor_Unlimit_Webshell_B374Kphp_B374K_A_1525 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file B374k.php"
    family = "Webshell"
    hacker = "None"
    hash = "bed7388976f8f1d90422e8795dff1ea6"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.B374Kphp.B374K.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Http://code.google.com/p/b374k-shell" fullword
    $s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'"
    $s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
    $s4 = "B374k Vip In Beautify Just For Self" fullword
  condition:
    1 of them
}