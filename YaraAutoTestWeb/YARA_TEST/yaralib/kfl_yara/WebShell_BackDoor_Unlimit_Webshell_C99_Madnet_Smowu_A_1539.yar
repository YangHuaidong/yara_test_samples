rule WebShell_BackDoor_Unlimit_Webshell_C99_Madnet_Smowu_A_1539 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file smowu.php"
    family = "Webshell"
    hacker = "None"
    hash = "3aaa8cad47055ba53190020311b0fb83"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.C99.Madnet.Smowu.A"
    threattype = "BackDoor"
  strings:
    $s0 = "//Authentication" fullword
    $s1 = "$login = \"" fullword
    $s2 = "eval(gzinflate(base64_decode('"
    $s4 = "//Pass"
    $s5 = "$md5_pass = \""
    $s6 = "//If no pass then hash"
  condition:
    all of them
}