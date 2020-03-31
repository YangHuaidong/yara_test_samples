rule WebShell_BackDoor_Unlimit_Unpack_Tback_A_1453 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file TBack.dll"
    family = "Unpack"
    hacker = "None"
    hash = "a9d1007823bf96fb163ab38726b48464"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Unpack.Tback.A"
    threattype = "BackDoor"
  strings:
    $s5 = "\\final\\new\\lcc\\public.dll"
  condition:
    all of them
}