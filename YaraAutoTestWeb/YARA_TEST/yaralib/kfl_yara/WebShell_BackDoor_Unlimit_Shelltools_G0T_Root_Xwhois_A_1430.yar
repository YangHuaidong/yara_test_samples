rule WebShell_BackDoor_Unlimit_Shelltools_G0T_Root_Xwhois_A_1430 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file xwhois.exe"
    family = "Shelltools"
    hacker = "None"
    hash = "0bc98bd576c80d921a3460f8be8816b4"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Shelltools.G0T.Root.Xwhois.A"
    threattype = "BackDoor"
  strings:
    $s1 = "rting! "
    $s2 = "aTypCog("
    $s5 = "Diamond"
    $s6 = "r)r=rQreryr"
  condition:
    all of them
}