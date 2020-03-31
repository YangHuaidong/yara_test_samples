rule WebShell_BackDoor_Unlimit_Webshell_C99_Madnet_A_1538 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file c99_madnet.php"
    family = "Webshell"
    hacker = "None"
    hash = "17613df393d0a99fd5bea18b2d4707f566cff219"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.C99.Madnet.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
    $s1 = "eval(gzinflate(base64_decode('"
    $s2 = "$pass = \"pass\";  //Pass" fullword
    $s3 = "$login = \"user\"; //Login" fullword
    $s4 = "             //Authentication" fullword
  condition:
    all of them
}