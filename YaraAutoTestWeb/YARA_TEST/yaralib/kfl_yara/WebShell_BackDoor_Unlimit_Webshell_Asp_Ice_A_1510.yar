rule WebShell_BackDoor_Unlimit_Webshell_Asp_Ice_A_1510 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ice.asp"
    family = "Webshell"
    hacker = "None"
    hash = "d141e011a92f48da72728c35f1934a2b"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Ice.A"
    threattype = "BackDoor"
  strings:
    $s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"
  condition:
    all of them
}